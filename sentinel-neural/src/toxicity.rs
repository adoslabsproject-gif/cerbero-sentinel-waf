//! Content Toxicity Analysis
//!
//! Detects toxic, harmful, or inappropriate content:
//! - Hate speech
//! - Harassment
//! - Violence
//! - Self-harm content
//! - Adult content
//!
//! Uses regex patterns as baseline, with optional ONNX ML model
//! for higher-accuracy detection (gracefully degrades when model is absent).

use std::sync::Arc;

use sentinel_core::{NeuralConfig, SentinelError};
use regex::Regex;
use once_cell::sync::Lazy;

use crate::ml;

/// Result of toxicity analysis
#[derive(Debug, Clone)]
pub struct ToxicityResult {
    /// Whether content is toxic
    pub is_toxic: bool,
    /// Toxicity score (0.0 - 1.0)
    pub score: f64,
    /// Categories detected
    pub categories: Vec<ToxicityCategory>,
}

/// Categories of toxic content
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToxicityCategory {
    HateSpeech,
    Harassment,
    Violence,
    SelfHarm,
    Adult,
    Spam,
    Scam,
}

/// Patterns for toxicity detection
static HATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Placeholder patterns - in production, use comprehensive word lists
        // and ML models for accurate detection
        Regex::new(r"(?i)\b(hate|kill|murder)\s+(all|every)\s+\w+s\b").unwrap(),
        Regex::new(r"(?i)\b(exterminate|eliminate|eradicate)\s+(the\s+)?\w+s\b").unwrap(),
    ]
});

static VIOLENCE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\bhow\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive)").unwrap(),
        Regex::new(r"(?i)\bhow\s+to\s+(kill|murder|assassinate)").unwrap(),
        Regex::new(r"(?i)instructions?\s+(for|to)\s+(making|building)\s+weapons?").unwrap(),
    ]
});

static SELF_HARM_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\bhow\s+to\s+(commit\s+)?suicide\b").unwrap(),
        Regex::new(r"(?i)\bways\s+to\s+(hurt|harm)\s+(myself|yourself)\b").unwrap(),
        Regex::new(r"(?i)\bbest\s+(way|method)\s+to\s+(die|end\s+it)\b").unwrap(),
    ]
});

static SCAM_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)send\s+\d+\s*(btc|eth|crypto|bitcoin)").unwrap(),
        Regex::new(r"(?i)wire\s+(me|us)\s+\$?\d+").unwrap(),
        Regex::new(r"(?i)nigerian\s+prince").unwrap(),
        Regex::new(r"(?i)you'?ve?\s+won\s+\$?\d+").unwrap(),
        Regex::new(r"(?i)claim\s+your\s+(prize|reward|winnings)").unwrap(),
    ]
});

/// Maximum sequence length for BERT tokenization
const MAX_SEQ_LENGTH: usize = 512;

/// Toxicity analyzer with regex + optional ONNX ML model
pub struct ToxicityAnalyzer {
    /// Detection threshold
    threshold: f64,
    /// Whether ML is enabled
    ml_enabled: bool,
    /// ONNX model for ML-based detection (None if model file missing)
    model: Option<Arc<ml::OnnxModel>>,
    /// Tokenizer for the ONNX model (None if vocab file missing)
    tokenizer: Option<Arc<ml::WordPieceTokenizer>>,
}

impl ToxicityAnalyzer {
    /// Create a new analyzer, attempting to load the ONNX model from `config.models_path`.
    ///
    /// If `toxicity.onnx` is not found, the analyzer gracefully falls back to regex-only.
    /// To enable ML: just drop `toxicity.onnx` in the models directory and restart.
    pub fn new(config: &NeuralConfig) -> Result<Self, SentinelError> {
        let mut model = None;
        let mut tokenizer = None;

        if config.enable_ml_detection {
            let model_path = format!("{}/toxicity.onnx", config.models_path);
            let vocab_path = format!("{}/vocab.txt", config.models_path);

            // Load ONNX model (Ok(None) if file doesn't exist — expected for now)
            match ml::OnnxModel::load(&model_path) {
                Ok(Some(m)) => {
                    tracing::info!("ONNX model loaded: toxicity");
                    model = Some(Arc::new(m));
                }
                Ok(None) => {
                    tracing::info!(
                        path = model_path.as_str(),
                        "Toxicity ONNX model not found, using regex-only detection"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to load toxicity ONNX model, falling back to regex-only"
                    );
                }
            }

            // Load tokenizer only if model loaded
            if model.is_some() {
                match ml::WordPieceTokenizer::new(&vocab_path, MAX_SEQ_LENGTH) {
                    Ok(t) => {
                        tokenizer = Some(Arc::new(t));
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Failed to load vocab.txt for toxicity model, disabling ML detection"
                        );
                        model = None;
                    }
                }
            }
        }

        Ok(Self {
            threshold: config.toxicity_threshold as f64,
            ml_enabled: config.enable_ml_detection,
            model,
            tokenizer,
        })
    }

    /// Minimum content length for ML inference (saves ~200ms on short requests)
    const ML_MIN_CONTENT_LEN: usize = 30;

    /// Analyze content for toxicity
    pub async fn analyze(&self, content: &str) -> Result<ToxicityResult, SentinelError> {
        let mut result = ToxicityResult {
            is_toxic: false,
            score: 0.0,
            categories: Vec::new(),
        };

        // Pattern-based detection (always runs, <1ms)
        self.detect_patterns(content, &mut result);

        // ML-based detection if enabled and content is substantial
        if self.ml_enabled && content.len() >= Self::ML_MIN_CONTENT_LEN {
            self.detect_ml(content, &mut result).await?;
        }

        // Determine if toxic based on threshold
        result.is_toxic = result.score >= self.threshold;

        Ok(result)
    }

    /// Pattern-based detection
    fn detect_patterns(&self, content: &str, result: &mut ToxicityResult) {
        // Check hate speech
        for pattern in HATE_PATTERNS.iter() {
            if pattern.is_match(content) {
                result.categories.push(ToxicityCategory::HateSpeech);
                result.score += 0.4;
                break;
            }
        }

        // Check violence
        for pattern in VIOLENCE_PATTERNS.iter() {
            if pattern.is_match(content) {
                result.categories.push(ToxicityCategory::Violence);
                result.score += 0.5;
                break;
            }
        }

        // Check self-harm
        for pattern in SELF_HARM_PATTERNS.iter() {
            if pattern.is_match(content) {
                result.categories.push(ToxicityCategory::SelfHarm);
                result.score += 0.6;
                break;
            }
        }

        // Check scams
        for pattern in SCAM_PATTERNS.iter() {
            if pattern.is_match(content) {
                result.categories.push(ToxicityCategory::Scam);
                result.score += 0.3;
                break;
            }
        }

        // Normalize score
        result.score = result.score.min(1.0);
    }

    /// ML-based toxicity detection using ONNX model.
    ///
    /// If model is None (file not deployed), returns Ok(()) — no-op.
    /// Ready for future: just drop `toxicity.onnx` in the models directory and restart.
    async fn detect_ml(&self, content: &str, result: &mut ToxicityResult) -> Result<(), SentinelError> {
        let (model, tokenizer) = match (&self.model, &self.tokenizer) {
            (Some(m), Some(t)) => (m.clone(), t.clone()),
            _ => return Ok(()),
        };

        let content = content.to_string();

        let ml_score = tokio::task::spawn_blocking(move || {
            let (input_ids, attention_mask) = tokenizer.encode(&content);
            let probs = model.classify(&input_ids, &attention_mask)?;

            // Binary classification: probs[1] = toxic probability
            let toxic_score = probs.get(1).copied().unwrap_or(0.0);

            tracing::warn!(
                toxic_score = toxic_score,
                "ML toxicity inference completed"
            );

            Ok::<f32, SentinelError>(toxic_score)
        })
        .await
        .map_err(|e| SentinelError::ModelInference(format!("Toxicity inference task panicked: {}", e)))??;

        // Blend ML score with regex score: take the maximum
        let ml_score_f64 = ml_score as f64;
        if ml_score_f64 > result.score {
            result.score = ml_score_f64;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_analyzer() -> ToxicityAnalyzer {
        let config = NeuralConfig::default();
        ToxicityAnalyzer::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_clean_content() {
        let analyzer = create_analyzer();
        let result = analyzer.analyze("Hello, how are you today?").await.unwrap();
        assert!(!result.is_toxic);
        assert!(result.score < 0.1);
    }

    #[tokio::test]
    async fn test_violence_detection() {
        let analyzer = create_analyzer();
        let result = analyzer
            .analyze("How to make a bomb at home")
            .await
            .unwrap();
        assert!(result.score > 0.3);
        assert!(result.categories.contains(&ToxicityCategory::Violence));
    }

    #[tokio::test]
    async fn test_scam_detection() {
        let analyzer = create_analyzer();
        let result = analyzer
            .analyze("You've won $1000000! Claim your prize now!")
            .await
            .unwrap();
        assert!(result.categories.contains(&ToxicityCategory::Scam));
    }
}
