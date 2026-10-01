//! Shared ONNX inference infrastructure for SENTINEL Neural Layer
//!
//! Provides [`WordPieceTokenizer`] and [`OnnxModel`] used by both
//! [`PromptInjectionDetector`](crate::prompt_injection::PromptInjectionDetector)
//! and [`ToxicityAnalyzer`](crate::toxicity::ToxicityAnalyzer).
//!
//! Also provides [`HotReloadableModel`] for the threat classifier (XGBoost → ONNX)
//! with automatic hot-reload via symlink watching and shadow mode for safe rollout.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use sentinel_core::SentinelError;

/// Padding id. `[UNK]`, `[CLS]` and `[SEP]` are NOT hardcoded any more: they are
/// read from the vocabulary, so a vocab that does not place them at 100/101/102
/// fails loudly at load instead of silently feeding the model the wrong ids.
const PAD_TOKEN_ID: i64 = 0;

// ─────────────────────────────────────────────────────────────────────────────
// WordPieceTokenizer
// ─────────────────────────────────────────────────────────────────────────────

/// A word longer than this is a single `[UNK]` (HuggingFace: max_input_chars_per_word)
const MAX_INPUT_CHARS_PER_WORD: usize = 100;

/// Characters HuggingFace treats as control characters and deletes.
fn is_control_char(c: char) -> bool {
    if c == '\t' || c == '\n' || c == '\r' {
        return false;
    }
    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
    )
}

/// Whitespace per BERT: the three ASCII ones plus Unicode space separators.
fn is_bert_whitespace(c: char) -> bool {
    c == ' '
        || c == '\t'
        || c == '\n'
        || c == '\r'
        || get_general_category(c) == GeneralCategory::SpaceSeparator
}

/// Punctuation per BERT: all ASCII symbol ranges (so `$`, `+`, `^` count) plus every Unicode P* category.
fn is_punctuation(c: char) -> bool {
    let cp = c as u32;
    if (33..=47).contains(&cp) || (58..=64).contains(&cp) || (91..=96).contains(&cp) || (123..=126).contains(&cp) {
        return true;
    }
    matches!(
        get_general_category(c),
        GeneralCategory::ConnectorPunctuation
            | GeneralCategory::DashPunctuation
            | GeneralCategory::OpenPunctuation
            | GeneralCategory::ClosePunctuation
            | GeneralCategory::InitialPunctuation
            | GeneralCategory::FinalPunctuation
            | GeneralCategory::OtherPunctuation
    )
}

fn is_chinese_char(cp: u32) -> bool {
    (0x4E00..=0x9FFF).contains(&cp)
        || (0x3400..=0x4DBF).contains(&cp)
        || (0x20000..=0x2A6DF).contains(&cp)
        || (0x2A700..=0x2B73F).contains(&cp)
        || (0x2B740..=0x2B81F).contains(&cp)
        || (0x2B820..=0x2CEAF).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0x2F800..=0x2FA1F).contains(&cp)
}

/// Drop NUL, U+FFFD and control characters; turn every whitespace into a plain space.
fn clean_text(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '\0' && *c != '\u{FFFD}' && !is_control_char(*c))
        .map(|c| if is_bert_whitespace(c) { ' ' } else { c })
        .collect()
}

/// CJK ideographs are tokenized one character at a time.
fn pad_chinese_chars(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_chinese_char(c as u32) {
            out.push(' ');
            out.push(c);
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn strip_accents(text: &str) -> String {
    text.nfd()
        .filter(|c| get_general_category(*c) != GeneralCategory::NonspacingMark)
        .collect()
}

fn split_on_punctuation(token: &str) -> Vec<String> {
    let mut pieces: Vec<String> = Vec::new();
    let mut start_new = true;
    for c in token.chars() {
        if is_punctuation(c) {
            pieces.push(c.to_string());
            start_new = true;
        } else {
            if start_new {
                pieces.push(String::new());
                start_new = false;
            }
            pieces
                .last_mut()
                .expect("a piece was pushed before writing into it")
                .push(c);
        }
    }
    pieces.retain(|p| !p.is_empty());
    pieces
}

/// HuggingFace `BasicTokenizer(do_lower_case=True, tokenize_chinese_chars=True)`.
pub fn basic_tokenize(text: &str) -> Vec<String> {
    let prepared = pad_chinese_chars(&clean_text(text));
    let mut tokens = Vec::new();
    for word in prepared.split_whitespace() {
        tokens.extend(split_on_punctuation(&strip_accents(&word.to_lowercase())));
    }
    tokens
}

/// BERT WordPiece tokenizer — the tokenizer the models were TRAINED with.
///
/// This used to implement the Node.js `SimpleTokenizer` instead: lowercase, then
/// replace every non-alphanumeric ASCII character with a space. The ONNX models,
/// however, are trained with `DistilBertTokenizer(do_lower_case=True)`, which
/// keeps punctuation as tokens of its own. So `<script>alert(1)</script>` reached
/// the model as `script alert 1 script`, and `/api/v1/posts` as `api v1 posts`:
/// the punctuation, which is the most telling part of an injection payload and
/// the whole structure of a path, never arrived. Measured on NHA's
/// prompt-injection test split, that train/serve skew cost about 14 points of F1
/// (0.819 → 0.937, recall 0.782 → 0.945, missed attacks 12 → 3).
///
/// The pipeline below reproduces HuggingFace exactly:
/// clean text → spaces around CJK → split on whitespace → lowercase + strip
/// accents (NFD, drop Mn) → split on punctuation → WordPiece greedy
/// longest-match → `[CLS]` … `[SEP]` → pad.
///
/// Parity is pinned by `tests/fixtures/bert_tokenizer_golden.json`, whose ids come
/// from HuggingFace itself: if either side of the port drifts, a test fails
/// instead of detection quality dropping in silence.
pub struct WordPieceTokenizer {
    vocab: HashMap<String, i64>,
    max_length: usize,
    unk_id: i64,
    cls_id: i64,
    sep_id: i64,
}

impl WordPieceTokenizer {
    /// Load vocabulary from a `vocab.txt` file (one token per line, line number = token ID).
    pub fn new(vocab_path: &str, max_length: usize) -> Result<Self, SentinelError> {
        if max_length < 2 {
            return Err(SentinelError::Configuration(
                "max_length must leave room for [CLS] and [SEP]".to_string(),
            ));
        }

        let path = Path::new(vocab_path);
        if !path.exists() {
            return Err(SentinelError::Configuration(format!(
                "Vocab file not found: {}",
                vocab_path
            )));
        }

        let content = std::fs::read_to_string(path).map_err(|e| {
            SentinelError::Configuration(format!(
                "Failed to read vocab file {}: {}",
                vocab_path, e
            ))
        })?;

        // Line number = token id. Only the line ending is stripped — `trim()` would
        // corrupt any token that legitimately carries surrounding characters — and
        // the first entry wins on a duplicate.
        let mut vocab: HashMap<String, i64> = HashMap::with_capacity(32_000);
        for (idx, line) in content.split('\n').enumerate() {
            let token = line.strip_suffix('\r').unwrap_or(line);
            if !token.is_empty() {
                vocab.entry(token.to_string()).or_insert(idx as i64);
            }
        }

        let special = |name: &str| -> Result<i64, SentinelError> {
            vocab.get(name).copied().ok_or_else(|| {
                SentinelError::Configuration(format!("Vocab {} is missing {}", vocab_path, name))
            })
        };
        let unk_id = special("[UNK]")?;
        let cls_id = special("[CLS]")?;
        let sep_id = special("[SEP]")?;

        tracing::info!(
            vocab_size = vocab.len(),
            max_length = max_length,
            "WordPieceTokenizer loaded"
        );

        Ok(Self {
            vocab,
            max_length,
            unk_id,
            cls_id,
            sep_id,
        })
    }

    /// Greedy longest-match-first WordPiece over one basic token.
    fn wordpiece(&self, word: &str) -> Vec<i64> {
        let chars: Vec<char> = word.chars().collect();
        if chars.len() > MAX_INPUT_CHARS_PER_WORD {
            return vec![self.unk_id];
        }

        let mut pieces = Vec::new();
        let mut start = 0;
        while start < chars.len() {
            let mut end = chars.len();
            let mut matched: Option<i64> = None;
            while start < end {
                let piece: String = chars[start..end].iter().collect();
                let candidate = if start == 0 { piece } else { format!("##{}", piece) };
                if let Some(&id) = self.vocab.get(&candidate) {
                    matched = Some(id);
                    break;
                }
                end -= 1;
            }
            match matched {
                Some(id) => {
                    pieces.push(id);
                    start = end;
                }
                // A single unmatched piece makes the WHOLE word unknown. The
                // previous loop advanced one character and kept going, emitting
                // partial pieces for a word WordPiece considers unknown.
                None => return vec![self.unk_id],
            }
        }
        pieces
    }

    /// Encode text into `(input_ids, attention_mask)` — both `Vec<i64>` of length `max_length`.
    pub fn encode(&self, text: &str) -> (Vec<i64>, Vec<i64>) {
        let body_limit = self.max_length - 2;
        let mut token_ids: Vec<i64> = Vec::with_capacity(self.max_length);
        token_ids.push(self.cls_id);

        'words: for word in basic_tokenize(text) {
            for id in self.wordpiece(&word) {
                if token_ids.len() - 1 >= body_limit {
                    break 'words;
                }
                token_ids.push(id);
            }
        }

        token_ids.push(self.sep_id);

        // Attention mask: 1 for real tokens, 0 for padding
        let real_len = token_ids.len();
        let attention_mask: Vec<i64> = (0..self.max_length)
            .map(|i| if i < real_len { 1 } else { 0 })
            .collect();

        // Pad token_ids to max_length
        token_ids.resize(self.max_length, PAD_TOKEN_ID);

        (token_ids, attention_mask)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OnnxModel
// ─────────────────────────────────────────────────────────────────────────────

/// ONNX model wrapper for classification tasks.
///
/// Thread-safe via `parking_lot::Mutex` (ort v2 `Session::run` requires `&mut self`).
/// Wraps an `ort::Session` and provides a high-level [`classify()`](Self::classify)
/// that runs inference and returns softmax probabilities.
pub struct OnnxModel {
    session: Mutex<Session>,
    output_name: String,
}

impl OnnxModel {
    /// Compute SHA-256 hex di un file su disco (per integrity check pre-load).
    ///
    /// Usato da `load_with_checksum` per verificare che il modello ONNX non
    /// sia stato manipolato dopo il deploy (insider, ransomware, container
    /// escape). Streaming reader (no full-buffer) → safe anche per modelli
    /// da 200+ MB.
    pub fn compute_sha256(model_path: &str) -> Result<String, SentinelError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut file = std::fs::File::open(model_path).map_err(|e| {
            SentinelError::ModelInference(format!(
                "Failed to open {} for sha256: {}",
                model_path, e
            ))
        })?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to read {} for sha256: {}",
                    model_path, e
                ))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Load an ONNX model from disk con integrity checksum opzionale.
    ///
    /// N11 audit (2026-05-29): se `expected_sha256` e\` Some, verifichiamo
    /// il SHA-256 del file PRIMA di passarlo a ONNX Runtime. Su mismatch
    /// → Err (no fallback regex silente, perche\` un modello modificato
    /// e\` un security event esplicito che richiede investigazione).
    pub fn load_with_checksum(
        model_path: &str,
        expected_sha256: Option<&str>,
    ) -> Result<Option<Self>, SentinelError> {
        let path = Path::new(model_path);
        if !path.exists() {
            tracing::info!(path = model_path, "ONNX model file not found, skipping");
            return Ok(None);
        }
        if let Some(expected) = expected_sha256 {
            let actual = Self::compute_sha256(model_path)?;
            let eq_bool: bool = subtle::ConstantTimeEq::ct_eq(
                actual.as_bytes(),
                expected.as_bytes(),
            ).into();
            if !eq_bool {
                tracing::error!(
                    path = model_path,
                    expected = expected,
                    actual = actual.as_str(),
                    "ONNX model checksum mismatch — refusing to load (possible tamper)"
                );
                return Err(SentinelError::ModelInference(format!(
                    "ONNX model {} checksum mismatch: integrity violation",
                    model_path
                )));
            }
            tracing::info!(
                path = model_path,
                sha256 = expected,
                "ONNX model integrity verified"
            );
        }
        Self::load_inner(model_path)
    }

    /// Backward-compatible loader (no integrity check).
    /// Equivalent to `load_with_checksum(path, None)`.
    pub fn load(model_path: &str) -> Result<Option<Self>, SentinelError> {
        Self::load_with_checksum(model_path, None)
    }

    fn load_inner(model_path: &str) -> Result<Option<Self>, SentinelError> {
        let path = Path::new(model_path);
        if !path.exists() {
            return Ok(None);
        }

        let session = Session::builder()
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to create session builder: {}",
                    e
                ))
            })?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to set optimization level: {}",
                    e
                ))
            })?
            .with_intra_threads(4)
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to set intra-op thread count: {}",
                    e
                ))
            })?
            .commit_from_file(model_path)
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to load ONNX model {}: {}",
                    model_path, e
                ))
            })?;

        let output_name = session
            .outputs()
            .first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "logits".to_string());

        tracing::info!(
            path = model_path,
            inputs = ?session.inputs().iter().map(|i| i.name().to_string()).collect::<Vec<_>>(),
            outputs = ?session.outputs().iter().map(|o| o.name().to_string()).collect::<Vec<_>>(),
            "ONNX model loaded successfully"
        );

        Ok(Some(Self {
            session: Mutex::new(session),
            output_name,
        }))
    }

    /// Run classification inference and return softmax probabilities.
    ///
    /// Input: token IDs and attention mask (both `i64` slices of length `max_seq_len`).
    /// Output: softmax probability vector (e.g. `[prob_class_0, prob_class_1]` for binary).
    pub fn classify(
        &self,
        input_ids: &[i64],
        attention_mask: &[i64],
    ) -> Result<Vec<f32>, SentinelError> {
        let seq_len = input_ids.len();

        // Create ONNX Value tensors using (shape, data) tuple form
        let ids_value = ort::value::Value::from_array(
            ([1usize, seq_len], input_ids.to_vec()),
        )
        .map_err(|e| {
            SentinelError::ModelInference(format!(
                "Failed to create input_ids tensor: {}",
                e
            ))
        })?;

        let mask_value = ort::value::Value::from_array(
            ([1usize, seq_len], attention_mask.to_vec()),
        )
        .map_err(|e| {
            SentinelError::ModelInference(format!(
                "Failed to create attention_mask tensor: {}",
                e
            ))
        })?;

        // Run inference (mutex-guarded because Session::run needs &mut self)
        let mut session = self.session.lock();
        let outputs = session
            .run(
                ort::inputs! {
                    "input_ids" => ids_value,
                    "attention_mask" => mask_value,
                }
            )
            .map_err(|e| {
                SentinelError::ModelInference(format!("ONNX inference failed: {}", e))
            })?;

        // Extract logits from the first output tensor
        // try_extract_tensor returns (&Shape, &[f32]) — .1 is the data slice
        let output = &outputs[self.output_name.as_str()];
        let (_shape, data) = output
            .try_extract_tensor::<f32>()
            .map_err(|e| {
                SentinelError::ModelInference(format!("Failed to extract logits: {}", e))
            })?;
        let logits: Vec<f32> = data.to_vec();

        Ok(softmax(&logits))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HotReloadableModel — Threat Classifier with Shadow Mode
// ─────────────────────────────────────────────────────────────────────────────

/// Shadow mode state for canary rollout of new models.
///
/// When a new model version is detected (via symlink change), it runs in
/// shadow mode for 1 hour: both old and new models produce predictions,
/// but only the old model's predictions are used. If predictions diverge
/// >20% during the shadow period, the new model is rolled back.
struct ShadowState {
    /// The shadow (candidate) model session
    shadow_session: Mutex<Session>,
    /// Output name for the shadow model
    shadow_output_name: String,
    /// Input name for the shadow model (letto dal modello, non hardcoded)
    shadow_input_name: String,
    /// Path of the shadow model file
    shadow_path: String,
    /// When shadow mode started
    started_at: Instant,
    /// Total predictions during shadow
    total_predictions: AtomicU64,
    /// Divergent predictions (old != new class)
    divergent_predictions: AtomicU64,
}

/// Versioned model wrapper holding a session + version metadata.
struct VersionedModel {
    session: Mutex<Session>,
    output_name: String,
    input_name: String,
    model_path: String,
}

/// Hot-reloadable ONNX model for the threat classifier.
///
/// Designed for XGBoost → ONNX models that take float feature vectors as input.
/// Unlike [`OnnxModel`] (which takes BERT token IDs), this accepts `&[f32]` features.
///
/// # Hot-Reload Protocol
///
/// The model directory is expected to contain a `current` symlink pointing to
/// the active model file (e.g. `threat-classifier-v2.onnx`). Every 60 seconds,
/// the symlink target is checked. If it changed:
///
/// 1. New model loads in background
/// 2. Shadow mode activates: both models predict, only old model decides
/// 3. After 1 hour: if divergence < 20% → promote new model; otherwise → rollback
///
/// # Thread Safety
///
/// Uses `parking_lot::RwLock` for the active model (read-heavy, rare writes)
/// and `Mutex` for shadow model sessions.
pub struct HotReloadableModel {
    /// Currently active model
    active: RwLock<Option<VersionedModel>>,
    /// Shadow model (canary) — present only during shadow mode
    shadow: RwLock<Option<ShadowState>>,
    /// Model directory containing the `current` symlink
    model_dir: PathBuf,
    /// Last resolved symlink target
    last_symlink_target: Mutex<Option<PathBuf>>,
    /// Last symlink check timestamp
    last_check: Mutex<Instant>,
    /// Whether hot-reload is enabled
    enabled: AtomicBool,
    /// Shadow mode duration
    shadow_duration: Duration,
    /// Maximum divergence ratio before rollback
    max_divergence_ratio: f32,
}

/// Check interval for symlink changes
const RELOAD_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Default shadow mode duration
const DEFAULT_SHADOW_DURATION: Duration = Duration::from_secs(3600); // 1 hour
/// Default max divergence ratio
const DEFAULT_MAX_DIVERGENCE: f32 = 0.20;

impl HotReloadableModel {
    /// Create a new hot-reloadable model.
    ///
    /// `model_dir` should contain a `current` symlink pointing to the active ONNX file.
    /// Returns `Ok` even if no model exists yet (graceful degradation).
    pub fn new(model_dir: &str) -> Result<Self, SentinelError> {
        let dir = PathBuf::from(model_dir);
        let model = Self {
            active: RwLock::new(None),
            shadow: RwLock::new(None),
            model_dir: dir.clone(),
            last_symlink_target: Mutex::new(None),
            last_check: Mutex::new(Instant::now()),
            enabled: AtomicBool::new(true),
            shadow_duration: DEFAULT_SHADOW_DURATION,
            max_divergence_ratio: DEFAULT_MAX_DIVERGENCE,
        };

        // Try initial load
        let symlink_path = dir.join("current");
        if symlink_path.exists() {
            match model.load_from_symlink(&symlink_path) {
                Ok(Some((session, output_name, input_name, resolved))) => {
                    let resolved_str = resolved.to_string_lossy().to_string();
                    *model.active.write() = Some(VersionedModel {
                        session: Mutex::new(session),
                        output_name,
                        input_name,
                        model_path: resolved_str.clone(),
                    });
                    *model.last_symlink_target.lock() = Some(resolved);
                    tracing::info!(
                        path = %resolved_str,
                        "Threat classifier ONNX model loaded"
                    );
                }
                Ok(None) => {
                    tracing::info!(
                        dir = model_dir,
                        "No threat classifier model found, will check periodically"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to load initial threat classifier model"
                    );
                }
            }
        } else {
            tracing::info!(
                dir = model_dir,
                "Threat classifier model directory has no 'current' symlink"
            );
        }

        Ok(model)
    }

    /// Check for model updates and manage shadow mode transitions.
    ///
    /// Call this periodically (e.g. from the main analyze loop).
    /// Returns quickly if the check interval hasn't elapsed.
    pub fn check_for_updates(&self) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        let now = Instant::now();

        // Rate-limit checks to every 60s
        {
            let mut last = self.last_check.lock();
            if now.duration_since(*last) < RELOAD_CHECK_INTERVAL {
                return;
            }
            *last = now;
        }

        // Check shadow mode transitions first
        self.check_shadow_promotion();

        // Check symlink for changes
        let symlink_path = self.model_dir.join("current");
        if !symlink_path.exists() {
            return;
        }

        let resolved = match std::fs::canonicalize(&symlink_path) {
            Ok(p) => p,
            Err(_) => return,
        };

        let last_target = self.last_symlink_target.lock().clone();
        if last_target.as_ref() == Some(&resolved) {
            return; // No change
        }

        // COLD START (fix 2026-08-04): se non c'è ancora NESSUN modello attivo, il nuovo
        // va promosso SUBITO, non messo in shadow.
        //
        // Lo shadow esiste per proteggere un modello GIÀ in produzione: si confrontano le
        // due predizioni e si promuove solo se divergono poco. Senza un modello attivo non
        // c'è niente da confrontare e niente da rischiare — il classificatore è semplicemente
        // spento, quindi qualunque modello validato è meglio del nulla.
        //
        // Mettere il PRIMO modello in shadow creava un deadlock perfetto, mai emerso perché
        // fino a oggi il flywheel non aveva mai prodotto un modello:
        //   1. il modello entra in shadow;
        //   2. la promozione richiede ≥10 predizioni shadow;
        //   3. ma `predict()` esce subito se `active` è None → lo shadow non gira MAI
        //      → total resta 0 → mai promosso, all'infinito.
        // Il primo modello non sarebbe MAI potuto entrare in produzione.
        let cold_start = self.active.read().is_none();

        tracing::info!(
            old = ?last_target,
            new = %resolved.display(),
            cold_start,
            "Threat classifier symlink changed, loading new model"
        );

        match self.load_from_symlink(&symlink_path) {
            Ok(Some((session, output_name, input_name, resolved_path))) if cold_start => {
                let resolved_str = resolved_path.to_string_lossy().to_string();
                *self.active.write() = Some(VersionedModel {
                    session: Mutex::new(session),
                    output_name,
                    input_name,
                    model_path: resolved_str.clone(),
                });
                *self.last_symlink_target.lock() = Some(resolved_path);
                tracing::info!(
                    path = %resolved_str,
                    "Primo modello del flywheel: promosso DIRETTAMENTE ad attivo (nessun modello da proteggere)"
                );
            }
            Ok(Some((session, output_name, input_name, resolved_path))) => {
                let shadow = ShadowState {
                    shadow_session: Mutex::new(session),
                    shadow_output_name: output_name,
                    shadow_input_name: input_name,
                    shadow_path: resolved_path.to_string_lossy().to_string(),
                    started_at: Instant::now(),
                    total_predictions: AtomicU64::new(0),
                    divergent_predictions: AtomicU64::new(0),
                };
                *self.shadow.write() = Some(shadow);
                *self.last_symlink_target.lock() = Some(resolved_path);

                tracing::info!("Shadow mode activated for new threat classifier model");
            }
            Ok(None) => {
                tracing::warn!("Symlink target does not exist, skipping reload");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load new threat classifier model");
            }
        }
    }

    /// Predict threat class from feature vector.
    ///
    /// Input: feature vector `&[f32]` (e.g. from ML pipeline feature extraction).
    /// Output: softmax probability vector `[prob_benign, prob_threat]`.
    ///
    /// If no model is loaded, returns `None` (graceful degradation).
    /// If shadow mode is active, runs both models and logs divergence.
    pub fn predict(&self, features: &[f32]) -> Option<Vec<f32>> {
        // Run active model
        let active_result = {
            let active_guard = self.active.read();
            let active = active_guard.as_ref()?;
            Self::run_inference(&active.session, &active.output_name, &active.input_name, features).ok()?
        };

        // Run shadow model if present (non-blocking, best-effort)
        if let Some(shadow) = self.shadow.read().as_ref() {
            if let Ok(shadow_result) = Self::run_inference(
                &shadow.shadow_session,
                &shadow.shadow_output_name,
                &shadow.shadow_input_name,
                features,
            ) {
                shadow.total_predictions.fetch_add(1, Ordering::Relaxed);

                // Compare: class with highest probability
                let active_class = active_result
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(i, _)| i)
                    .unwrap_or(0);

                let shadow_class = shadow_result
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(i, _)| i)
                    .unwrap_or(0);

                if active_class != shadow_class {
                    shadow.divergent_predictions.fetch_add(1, Ordering::Relaxed);
                }

                tracing::debug!(
                    active_class,
                    shadow_class,
                    active_prob = ?active_result,
                    shadow_prob = ?shadow_result,
                    "Shadow mode prediction comparison"
                );
            }
        }

        Some(active_result)
    }

    /// Whether any model is loaded and available for prediction.
    pub fn is_loaded(&self) -> bool {
        self.active.read().is_some()
    }

    /// Get the current model path (if loaded).
    pub fn current_model_path(&self) -> Option<String> {
        self.active.read().as_ref().map(|m| m.model_path.clone())
    }

    /// Whether shadow mode is currently active.
    pub fn is_shadow_active(&self) -> bool {
        self.shadow.read().is_some()
    }

    /// Get shadow mode statistics.
    pub fn shadow_stats(&self) -> Option<(u64, u64, f32)> {
        let guard = self.shadow.read();
        let shadow = guard.as_ref()?;
        let total = shadow.total_predictions.load(Ordering::Relaxed);
        let divergent = shadow.divergent_predictions.load(Ordering::Relaxed);
        let ratio = if total > 0 {
            divergent as f32 / total as f32
        } else {
            0.0
        };
        Some((total, divergent, ratio))
    }

    // ─── Internal ───────────────────────────────────────────────────────────

    /// Check if shadow mode should be promoted or rolled back.
    fn check_shadow_promotion(&self) {
        let should_promote;
        let shadow_info;

        {
            let guard = self.shadow.read();
            let shadow = match guard.as_ref() {
                Some(s) => s,
                None => return,
            };

            if shadow.started_at.elapsed() < self.shadow_duration {
                return; // Not yet time to decide
            }

            let total = shadow.total_predictions.load(Ordering::Relaxed);
            let divergent = shadow.divergent_predictions.load(Ordering::Relaxed);

            shadow_info = (
                shadow.shadow_path.clone(),
                total,
                divergent,
            );

            if total < 10 {
                // Not enough data points — extend shadow
                tracing::info!(
                    total,
                    "Shadow mode: insufficient predictions ({}/10), extending",
                    total
                );
                return;
            }

            let ratio = divergent as f32 / total as f32;
            should_promote = ratio <= self.max_divergence_ratio;

            if should_promote {
                tracing::info!(
                    total,
                    divergent,
                    ratio = format!("{:.1}%", ratio * 100.0),
                    path = %shadow_info.0,
                    "Shadow mode: PROMOTING new model (divergence within threshold)"
                );
            } else {
                tracing::warn!(
                    total,
                    divergent,
                    ratio = format!("{:.1}%", ratio * 100.0),
                    max_allowed = format!("{:.1}%", self.max_divergence_ratio * 100.0),
                    path = %shadow_info.0,
                    "Shadow mode: ROLLING BACK new model (divergence too high)"
                );
            }
        }

        if should_promote {
            // Promote: swap shadow → active
            let shadow_taken = self.shadow.write().take();
            if let Some(shadow) = shadow_taken {
                *self.active.write() = Some(VersionedModel {
                    session: shadow.shadow_session,
                    output_name: shadow.shadow_output_name,
                    input_name: shadow.shadow_input_name,
                    model_path: shadow.shadow_path,
                });
            }
        } else {
            // Rollback: just drop the shadow model, keep old active
            *self.shadow.write() = None;
            // Reset symlink target to force re-check later if model is updated again
            // (don't reset — the bad model stays at the symlink until operator fixes it)
        }
    }

    /// Load an ONNX session from a symlink, resolving the real path.
    fn load_from_symlink(
        &self,
        symlink_path: &Path,
    ) -> Result<Option<(Session, String, String, PathBuf)>, SentinelError> {
        let resolved = std::fs::canonicalize(symlink_path).map_err(|e| {
            SentinelError::ModelInference(format!(
                "Failed to resolve symlink {}: {}",
                symlink_path.display(),
                e
            ))
        })?;

        if !resolved.exists() {
            return Ok(None);
        }

        let session = Session::builder()
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to create session builder: {}",
                    e
                ))
            })?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to set optimization level: {}",
                    e
                ))
            })?
            .with_intra_threads(2)
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to set intra-op thread count: {}",
                    e
                ))
            })?
            .commit_from_file(resolved.to_str().unwrap_or_default())
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to load ONNX model {}: {}",
                    resolved.display(),
                    e
                ))
            })?;

        let output_name = session
            .outputs()
            .first()
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| "probabilities".to_string());

        // Nome dell'input ONNX letto DINAMICAMENTE (era hardcoded "features" in run_inference
        // → inference fallita: skl2onnx esporta "float_input"/"input"). Default "input".
        let input_name = session
            .inputs()
            .first()
            .map(|i| i.name().to_string())
            .unwrap_or_else(|| "input".to_string());

        tracing::info!(
            path = %resolved.display(),
            input = %input_name,
            output = %output_name,
            "Loaded threat classifier ONNX model"
        );

        Ok(Some((session, output_name, input_name, resolved)))
    }

    /// Run inference on a model session with float features.
    fn run_inference(
        session_mutex: &Mutex<Session>,
        output_name: &str,
        input_name: &str,
        features: &[f32],
    ) -> Result<Vec<f32>, SentinelError> {
        let feature_count = features.len();

        let input_value = ort::value::Value::from_array(
            ([1usize, feature_count], features.to_vec()),
        )
        .map_err(|e| {
            SentinelError::ModelInference(format!(
                "Failed to create feature tensor: {}",
                e
            ))
        })?;

        let mut session = session_mutex.lock();
        let outputs = session
            .run(
                // input_name DINAMICO (dal modello), non hardcoded "features": skl2onnx esporta
                // tipicamente "float_input"/"input" → l'hardcode faceva fallire ogni inferenza.
                ort::inputs! {
                    input_name => input_value,
                }
            )
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Threat classifier inference failed: {}",
                    e
                ))
            })?;

        let output = &outputs[output_name];
        let (_shape, data) = output
            .try_extract_tensor::<f32>()
            .map_err(|e| {
                SentinelError::ModelInference(format!(
                    "Failed to extract classifier output: {}",
                    e
                ))
            })?;

        Ok(softmax(&data.to_vec()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Softmax
// ─────────────────────────────────────────────────────────────────────────────

/// Numerically stable softmax (subtracts max before exponentiation).
fn softmax(logits: &[f32]) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }

    let max_logit = logits
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, f32::max);

    let exps: Vec<f32> = logits.iter().map(|&x| (x - max_logit).exp()).collect();
    let sum: f32 = exps.iter().sum();

    if sum == 0.0 {
        return vec![1.0 / logits.len() as f32; logits.len()];
    }

    exps.iter().map(|&e| e / sum).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Cargo runs a crate's tests as parallel threads of ONE process, so a path
    /// keyed on the pid alone is a single shared file for the whole suite and the
    /// tests delete it from under each other. The counter gives each call its own.
    fn temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentinel-waf-ml-{}-{}-{}",
            std::process::id(),
            seq,
            name
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// The tokenizer must reproduce the ids the models were TRAINED with: these
    /// come from HuggingFace itself (DistilBertTokenizer over the same vocab.txt).
    /// Without this test the port silently drifts and costs detection quality —
    /// which is exactly what the previous SimpleTokenizer-derived version did.
    #[test]
    fn bert_tokenizer_matches_huggingface_golden() {
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let fixture: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{}/bert_tokenizer_golden.json", fixtures)).unwrap(),
        )
        .unwrap();

        let max_length = fixture["max_length"].as_u64().unwrap() as usize;
        let tokenizer =
            WordPieceTokenizer::new(&format!("{}/vocab.txt", fixtures), max_length).unwrap();

        for case in fixture["cases"].as_array().unwrap() {
            let text = case["text"].as_str().unwrap();
            let (ids, mask) = tokenizer.encode(text);
            let expected_ids: Vec<i64> = case["input_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap())
                .collect();
            let expected_mask: Vec<i64> = case["attention_mask"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap())
                .collect();
            assert_eq!(ids, expected_ids, "input_ids mismatch for {:?}", text);
            assert_eq!(mask, expected_mask, "attention_mask mismatch for {:?}", text);
        }
    }

    /// The payload shape the previous tokenizer destroyed.
    #[test]
    fn basic_tokenize_keeps_punctuation_as_separate_tokens() {
        assert_eq!(
            basic_tokenize("<script>alert(1)</script>"),
            vec!["<", "script", ">", "alert", "(", "1", ")", "<", "/", "script", ">"]
        );
    }

    /// And the path structure it flattened: /api/v1/posts was becoming "api v1 posts".
    #[test]
    fn basic_tokenize_keeps_the_slashes_of_a_path() {
        assert_eq!(
            basic_tokenize("/api/v1/posts"),
            vec!["/", "api", "/", "v1", "/", "posts"]
        );
    }

    #[test]
    fn basic_tokenize_lowercases_and_strips_accents() {
        assert_eq!(basic_tokenize("Perché Città"), vec!["perche", "citta"]);
    }

    #[test]
    fn basic_tokenize_splits_cjk_and_drops_invisible_characters() {
        assert_eq!(basic_tokenize("你好世界"), vec!["你", "好", "世", "界"]);
        // Zero-width space, BOM and soft hyphen are Format characters: deleted
        assert_eq!(
            basic_tokenize("zero\u{200B}width\u{FEFF} soft\u{00AD}hyphen"),
            vec!["zerowidth", "softhyphen"]
        );
    }

    fn fixture_tokenizer() -> (WordPieceTokenizer, std::path::PathBuf) {
        // Minimal BERT vocab: the three special tokens are mandatory
        let vocab_path = temp_file("slot-vocab.txt", b"[PAD]\n[UNK]\n[CLS]\n[SEP]\nhello\nworld");
        let tokenizer = WordPieceTokenizer::new(vocab_path.to_str().unwrap(), 8).unwrap();
        (tokenizer, vocab_path)
    }

    #[test]
    fn word_longer_than_the_limit_is_a_single_unknown() {
        let (tokenizer, vocab_path) = fixture_tokenizer();
        let (ids, mask) = tokenizer.encode(&"a".repeat(MAX_INPUT_CHARS_PER_WORD + 1));

        // [CLS] [UNK] [SEP] then padding
        // SAFE-SLICE: ids is a Vec<i64>, not a &str — no UTF-8 boundary to hit —
        // and encode() always pads to max_length (8 here), so [..3] is in range.
        assert_eq!(&ids[..3], &[2, 1, 3]);
        assert_eq!(mask.iter().sum::<i64>(), 3);

        let _ = std::fs::remove_file(vocab_path);
    }

    /// An unmatched piece makes the whole word unknown — the previous loop emitted
    /// partial pieces instead, so the model saw fragments of a word it never learned.
    #[test]
    fn a_word_with_an_unmatched_piece_is_entirely_unknown() {
        let (tokenizer, vocab_path) = fixture_tokenizer();
        let (ids, _) = tokenizer.encode("helloxyz");

        // SAFE-SLICE: Vec<i64> padded to max_length by encode(), never a &str.
        assert_eq!(&ids[..3], &[2, 1, 3], "expected [CLS] [UNK] [SEP]");

        let _ = std::fs::remove_file(vocab_path);
    }

    #[test]
    fn truncation_keeps_room_for_the_special_tokens() {
        let (tokenizer, vocab_path) = fixture_tokenizer();
        let (ids, mask) = tokenizer.encode("hello world hello world hello world");

        assert_eq!(ids.len(), 8);
        assert_eq!(ids[0], 2, "[CLS] first");
        assert_eq!(ids[7], 3, "[SEP] last, never truncated away");
        assert_eq!(mask.iter().sum::<i64>(), 8);

        let _ = std::fs::remove_file(vocab_path);
    }

    /// Special token ids are no longer hardcoded to 100/101/102: a vocab without
    /// them must be rejected at load instead of mislabelling every inference.
    #[test]
    fn vocab_without_special_tokens_is_rejected() {
        let vocab_path = temp_file("bad-vocab.txt", b"hello\nworld");
        let err = match WordPieceTokenizer::new(vocab_path.to_str().unwrap(), 8) {
            Ok(_) => panic!("a vocab without [UNK]/[CLS]/[SEP] must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("[UNK]"), "got: {}", err);
        let _ = std::fs::remove_file(vocab_path);
    }

    #[test]
    fn test_softmax_basic() {
        let probs = softmax(&[2.0, 1.0]);
        assert!(probs[0] > probs[1]);
        assert!((probs[0] + probs[1] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_softmax_equal() {
        let probs = softmax(&[1.0, 1.0]);
        assert!((probs[0] - 0.5).abs() < 1e-6);
        assert!((probs[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_softmax_large_values() {
        let probs = softmax(&[1000.0, 1001.0]);
        assert!(probs[1] > probs[0]);
        assert!((probs[0] + probs[1] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_softmax_empty() {
        let probs = softmax(&[]);
        assert!(probs.is_empty());
    }

    #[test]
    fn test_hot_reloadable_no_dir() {
        // Non-existent directory → graceful: model created, no prediction available
        let model = HotReloadableModel::new("/tmp/sentinel-test-nonexistent-dir-12345");
        assert!(model.is_ok());
        let model = model.unwrap();
        assert!(!model.is_loaded());
        assert!(model.predict(&[1.0, 2.0, 3.0]).is_none());
    }

    #[test]
    fn test_hot_reloadable_no_symlink() {
        // Directory exists but no 'current' symlink
        let dir = std::env::temp_dir().join("sentinel-test-hotreload-empty");
        let _ = std::fs::create_dir_all(&dir);
        let model = HotReloadableModel::new(dir.to_str().unwrap());
        assert!(model.is_ok());
        let model = model.unwrap();
        assert!(!model.is_loaded());
        assert!(!model.is_shadow_active());
        assert!(model.shadow_stats().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hot_reloadable_check_updates_no_crash() {
        // check_for_updates should not crash even with no model
        let dir = std::env::temp_dir().join("sentinel-test-hotreload-check");
        let _ = std::fs::create_dir_all(&dir);
        let model = HotReloadableModel::new(dir.to_str().unwrap()).unwrap();
        model.check_for_updates(); // Should not panic
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 🔒 COLD START — il primo modello del flywheel NON deve finire in shadow.
    ///
    /// Regressione del 2026-08-04, rimasta invisibile per mesi perché il flywheel non
    /// aveva mai prodotto un modello che superasse i quality gate. Il deadlock:
    ///   1. il modello nuovo entra sempre in shadow;
    ///   2. la promozione richiede ≥10 predizioni shadow;
    ///   3. `predict()` esce subito quando `active` è None → lo shadow non gira mai
    ///      → il contatore resta 0 → promozione mai raggiunta, all'infinito.
    /// Risultato: il primo modello non sarebbe MAI entrato in produzione.
    ///
    /// Il test lavora sulla LOGICA di decisione (cold_start = nessun modello attivo)
    /// senza bisogno di un ONNX reale: è quel ramo ad aver sbagliato, non il caricamento.
    #[test]
    fn cold_start_il_primo_modello_va_in_active_non_in_shadow() {
        let dir = std::env::temp_dir().join("sentinel-test-coldstart");
        let _ = std::fs::create_dir_all(&dir);
        let model = HotReloadableModel::new(dir.to_str().unwrap()).unwrap();

        // Stato di partenza reale: nessun modello, né attivo né shadow.
        assert!(!model.is_loaded(), "nessun modello attivo all'avvio");
        assert!(!model.is_shadow_active(), "nessuno shadow all'avvio");

        // È QUESTA la condizione che decide il ramo: senza modello attivo si è in
        // cold start, e un modello validato deve entrare in servizio subito perché non
        // c'è nulla da proteggere — il classificatore è semplicemente spento.
        let cold_start = model.active.read().is_none();
        assert!(cold_start, "senza modello attivo si DEVE essere in cold start");

        // E il motivo per cui lo shadow non può auto-promuoversi da solo: senza active,
        // predict() esce subito, quindi nessuna predizione shadow verrebbe mai contata.
        assert!(
            model.predict(&[0.0; FEATURE_VECTOR_LEN_FOR_TEST]).is_none(),
            "senza modello attivo predict() ritorna None: lo shadow non girerebbe mai"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lunghezza del vettore usata solo dai test (il contratto vero è FEATURE_NAMES).
    const FEATURE_VECTOR_LEN_FOR_TEST: usize = 13;
}
