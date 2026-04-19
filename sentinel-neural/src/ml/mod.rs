//! Shared ONNX inference infrastructure for SENTINEL Neural Layer
//!
//! Provides [`WordPieceTokenizer`] and [`OnnxModel`] used by both
//! [`PromptInjectionDetector`](crate::prompt_injection::PromptInjectionDetector)
//! and [`ToxicityAnalyzer`](crate::toxicity::ToxicityAnalyzer).

use std::collections::HashMap;
use std::path::Path;

use parking_lot::Mutex;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use sentinel_core::SentinelError;

/// Special token IDs (BERT standard, matching Node.js MLInferenceService)
const PAD_TOKEN_ID: i64 = 0;
const UNK_TOKEN_ID: i64 = 100;
const CLS_TOKEN_ID: i64 = 101;
const SEP_TOKEN_ID: i64 = 102;

// ─────────────────────────────────────────────────────────────────────────────
// WordPieceTokenizer
// ─────────────────────────────────────────────────────────────────────────────

/// WordPiece tokenizer compatible with BERT `vocab.txt`.
///
/// Implements the same tokenization as Node.js `SimpleTokenizer`:
/// lowercase → remove non-alphanumeric → split whitespace →
/// vocab lookup → `##subword` fallback → UNK → prepend CLS → append SEP → pad
pub struct WordPieceTokenizer {
    vocab: HashMap<String, i64>,
    max_length: usize,
}

impl WordPieceTokenizer {
    /// Load vocabulary from a `vocab.txt` file (one token per line, line number = token ID).
    pub fn new(vocab_path: &str, max_length: usize) -> Result<Self, SentinelError> {
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

        let mut vocab = HashMap::with_capacity(32_000);
        for (idx, line) in content.lines().enumerate() {
            let token = line.trim();
            if !token.is_empty() {
                vocab.insert(token.to_string(), idx as i64);
            }
        }

        tracing::info!(
            vocab_size = vocab.len(),
            max_length = max_length,
            "WordPieceTokenizer loaded"
        );

        Ok(Self { vocab, max_length })
    }

    /// Encode text into `(input_ids, attention_mask)` — both `Vec<i64>` of length `max_length`.
    ///
    /// Algorithm (matches Node.js `SimpleTokenizer.encode()`):
    /// 1. Lowercase + replace non-alphanumeric with space
    /// 2. Split whitespace into words
    /// 3. Per word: full-word vocab lookup → WordPiece `##subword` fallback → `[UNK]`
    /// 4. Prepend `[CLS]` (101), append `[SEP]` (102)
    /// 5. Pad with `[PAD]` (0) to `max_length`
    pub fn encode(&self, text: &str) -> (Vec<i64>, Vec<i64>) {
        // Normalize: lowercase, replace non-alphanumeric with space
        let normalized: String = text
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c.is_whitespace() {
                    c
                } else {
                    ' '
                }
            })
            .collect();

        let mut token_ids: Vec<i64> = Vec::with_capacity(self.max_length);
        token_ids.push(CLS_TOKEN_ID);

        for word in normalized.split_whitespace() {
            if token_ids.len() >= self.max_length - 1 {
                break; // Reserve space for [SEP]
            }

            // Try full word lookup first
            if let Some(&id) = self.vocab.get(word) {
                token_ids.push(id);
                continue;
            }

            // WordPiece subword tokenization
            let chars: Vec<char> = word.chars().collect();
            let mut start = 0;
            let mut found_any = false;

            while start < chars.len() {
                if token_ids.len() >= self.max_length - 1 {
                    break;
                }

                let mut end = chars.len();
                let mut matched = false;

                while start < end {
                    let substr: String = if start == 0 {
                        chars[start..end].iter().collect()
                    } else {
                        format!("##{}", chars[start..end].iter().collect::<String>())
                    };

                    if let Some(&id) = self.vocab.get(&substr) {
                        token_ids.push(id);
                        start = end;
                        matched = true;
                        found_any = true;
                        break;
                    }
                    end -= 1;
                }

                if !matched {
                    start += 1;
                }
            }

            if !found_any {
                token_ids.push(UNK_TOKEN_ID);
            }
        }

        token_ids.push(SEP_TOKEN_ID);

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
    /// Load an ONNX model from disk.
    ///
    /// Returns `Ok(None)` if the model file does not exist (graceful skip).
    /// Returns `Err` if the file exists but fails to load (corrupt/incompatible).
    pub fn load(model_path: &str) -> Result<Option<Self>, SentinelError> {
        let path = Path::new(model_path);
        if !path.exists() {
            tracing::info!(path = model_path, "ONNX model file not found, skipping");
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
}
