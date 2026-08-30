//! SENTINEL Neural Defense - Layer 2
//!
//! Provides ML-powered threat detection for AI agents:
//! - Prompt injection detection
//! - Content toxicity analysis
//! - Semantic pattern matching
//! - Encoding attack detection (Base64, Unicode, homoglyphs)

pub mod ml;
pub mod prompt_injection;
pub mod toxicity;
pub mod llm_output_safety;
pub mod encoding;
pub mod patterns;
pub mod web_attacks;
pub mod threat_features;

use sentinel_core::{Request, LayerRiskScore as RiskScore, RiskLevel, RiskFlag, SentinelError, NeuralConfig};
use std::sync::Arc;

pub use prompt_injection::{PromptInjectionDetector, InjectionType};
pub use toxicity::{ToxicityAnalyzer, ToxicityResult};
pub use llm_output_safety::{LLMOutputSafetyAnalyzer, LLMOutputSafetyResult};
pub use encoding::{EncodingDetector, EncodingAttack};
pub use patterns::{PatternMatcher, SuspiciousPattern};
pub use web_attacks::{WebAttackDetector, WebAttack, WebAttackCategory};

/// Neural Defense - ML-powered threat detection
pub struct NeuralDefense {
    config: NeuralConfig,
    injection_detector: Arc<PromptInjectionDetector>,
    toxicity_analyzer: Arc<ToxicityAnalyzer>,
    llm_output_safety: Arc<LLMOutputSafetyAnalyzer>,
    encoding_detector: Arc<EncodingDetector>,
    pattern_matcher: Arc<PatternMatcher>,
    web_attack_detector: Arc<WebAttackDetector>,
}

impl NeuralDefense {
    /// Create a new Neural Defense layer
    pub fn new(config: NeuralConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            injection_detector: Arc::new(PromptInjectionDetector::new(&config)?),
            toxicity_analyzer: Arc::new(ToxicityAnalyzer::new(&config)?),
            llm_output_safety: Arc::new(LLMOutputSafetyAnalyzer::new(&config)?),
            encoding_detector: Arc::new(EncodingDetector::new()),
            pattern_matcher: Arc::new(PatternMatcher::new()),
            web_attack_detector: Arc::new(WebAttackDetector::new()),
            config,
        })
    }

    /// Hot-reload (flywheel Fase 5): controlla se il modello ONNX di prompt-injection è stato
    /// ripubblicato dal cron di retrain e, in tal caso, lo ricarica. Rate-limitato internamente.
    /// Chiamare periodicamente dal loop del server (accanto a threat_classifier.check_for_updates).
    pub fn check_prompt_injection_updates(&self) {
        self.injection_detector.maybe_reload();
    }

    /// Analyze request content for threats
    /// Target latency: < 5ms
    pub async fn analyze(&self, request: &Request) -> Result<RiskScore, SentinelError> {
        let mut score = RiskScore::default();

        // Get content to analyze
        let content = self.extract_content(request);
        if content.is_empty() {
            return Ok(score);
        }

        // 1. Check for encoding attacks first (fast)
        let encoding_attacks = self.encoding_detector.detect(&content).await;
        for attack in &encoding_attacks {
            match attack {
                EncodingAttack::Base64Obfuscation => {
                    score.add_flag(RiskFlag::Base64Obfuscation);
                    score.neural_score += 0.4;
                }
                EncodingAttack::UnicodeHomoglyph => {
                    score.add_flag(RiskFlag::UnicodeHomoglyph);
                    score.neural_score += 0.5;
                }
                EncodingAttack::InvisibleCharacters => {
                    score.add_flag(RiskFlag::InvisibleChars);
                    score.neural_score += 0.6;
                }
                EncodingAttack::ControlCharacters => {
                    score.add_flag(RiskFlag::ControlChars);
                    score.neural_score += 0.3;
                }
                EncodingAttack::RtlOverride => {
                    score.add_flag(RiskFlag::RtlOverride);
                    score.neural_score += 0.7;
                }
                // New encoding bypass variants
                EncodingAttack::UrlEncodedPayload => {
                    score.add_flag(RiskFlag::UrlEncodedPayload);
                    score.neural_score += 0.3;
                }
                EncodingAttack::DoubleUrlEncoding => {
                    score.add_flag(RiskFlag::DoubleUrlEncoding);
                    score.neural_score += 0.6;
                }
                EncodingAttack::HtmlEntityEncoding => {
                    score.add_flag(RiskFlag::HtmlEntityEncoding);
                    score.neural_score += 0.4;
                }
                EncodingAttack::NullByteInjection => {
                    score.add_flag(RiskFlag::NullByteInjection);
                    score.neural_score += 0.7;
                }
                EncodingAttack::OverlongUtf8 => {
                    score.add_flag(RiskFlag::OverlongUtf8);
                    score.neural_score += 0.8;
                }
                EncodingAttack::MixedEncoding => {
                    score.add_flag(RiskFlag::MixedEncoding);
                    score.neural_score += 0.5;
                }
                EncodingAttack::CommentInsertion => {
                    score.add_flag(RiskFlag::CommentInsertion);
                    score.neural_score += 0.4;
                }
                EncodingAttack::CaseMutationEncoding => {
                    score.add_flag(RiskFlag::CaseMutationEncoding);
                    score.neural_score += 0.3;
                }
            }
        }

        // 1.5 Comprehensive normalization (ANALYSIS COPY ONLY — original never modified)
        // Pipeline: URL decode (iterative) → HTML entity decode → null strip → Unicode → whitespace → lowercase
        let norm = self.encoding_detector.normalize_comprehensive(&content);

        // Flag encoding depth as additional risk indicators
        if norm.url_decode_depth >= 2 {
            score.add_flag(RiskFlag::DoubleUrlEncoding);
            score.neural_score += 0.4;
        }
        if norm.had_comments {
            score.add_flag(RiskFlag::CommentInsertion);
            score.neural_score += 0.2;
        }

        // 1.6 Web attack detection (fast, RegexSet O(n) across 120+ patterns)
        // Scan BOTH original and normalized content, plus comment-stripped version
        let web_attacks_original = self.web_attack_detector.detect(&content).await;
        let web_attacks_normalized = self.web_attack_detector.detect(&norm.normalized).await;
        let web_attacks_stripped = if norm.had_comments {
            self.web_attack_detector.detect(&norm.comment_stripped).await
        } else {
            Vec::new()
        };

        // Merge: take highest severity per category from any scan
        let mut web_attack_map = std::collections::HashMap::new();
        for attack in web_attacks_original.iter()
            .chain(web_attacks_normalized.iter())
            .chain(web_attacks_stripped.iter())
        {
            let entry = web_attack_map.entry(attack.category).or_insert(attack.clone());
            if attack.severity > entry.severity {
                *entry = attack.clone();
            }
        }

        for attack in web_attack_map.values() {
            score.add_flag(attack.to_risk_flag());
            score.neural_score += attack.severity_score();
        }

        // 2. Pattern matching (fast regex-based detection)
        // Run on normalized content to catch encoded prompt injection / jailbreak
        let patterns = self.pattern_matcher.find(&norm.normalized).await;
        for pattern in &patterns {
            match pattern {
                SuspiciousPattern::SystemPromptLeak => {
                    score.add_flag(RiskFlag::SystemPromptLeak);
                    score.neural_score += 0.8;
                }
                SuspiciousPattern::JailbreakAttempt => {
                    score.add_flag(RiskFlag::JailbreakAttempt);
                    score.neural_score += 0.9;
                }
                SuspiciousPattern::PromptLeakage => {
                    score.add_flag(RiskFlag::PromptLeakage);
                    score.neural_score += 0.7;
                }
                SuspiciousPattern::RolePlayExploit => {
                    score.add_flag(RiskFlag::RolePlayExploit);
                    score.neural_score += 0.6;
                }
                SuspiciousPattern::InstructionOverride => {
                    score.add_flag(RiskFlag::InstructionOverride);
                    score.neural_score += 0.85;
                }
            }
        }

        // 3. Prompt injection detection
        // Strategy: regex runs always (<1ms), ML only on substantial content (>30 chars)
        // This saves ~200ms for trivial GET requests with short paths
        if self.config.enable_ml_detection {
            let injection = self.injection_detector.detect(&content).await?;
            if let Some(injection_type) = injection {
                match injection_type {
                    InjectionType::Direct => {
                        score.add_flag(RiskFlag::DirectInjection);
                        score.neural_score += 0.9;
                    }
                    InjectionType::Indirect => {
                        score.add_flag(RiskFlag::IndirectInjection);
                        score.neural_score += 0.7;
                    }
                    InjectionType::Recursive => {
                        score.add_flag(RiskFlag::RecursiveInjection);
                        score.neural_score += 0.95;
                    }
                }
            }
        }

        // 4. Toxicity analysis (if enabled, only on substantial content)
        if self.config.enable_toxicity_check {
            let toxicity = self.toxicity_analyzer.analyze(&content).await?;
            if toxicity.is_toxic {
                score.add_flag(RiskFlag::ToxicContent);
                score.neural_score += toxicity.score * 0.5;
            }
        }

        // 5. LLM output safety analysis (detects compromised LLM output)
        if self.config.enable_llm_output_safety {
            let safety = self.llm_output_safety.analyze(&content).await?;
            if safety.is_malicious {
                score.add_flag(RiskFlag::MaliciousLLMOutput);
                score.neural_score += safety.score * 0.8;
            }
        }

        // Normalize score
        score.neural_score = score.neural_score.min(1.0);

        // Set risk level
        score.level = if score.neural_score >= 0.8 {
            RiskLevel::Critical
        } else if score.neural_score >= 0.6 {
            RiskLevel::High
        } else if score.neural_score >= 0.4 {
            RiskLevel::Medium
        } else if score.neural_score >= 0.2 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        Ok(score)
    }

    /// Get LLM output safety analyzer (for direct content analysis)
    pub fn llm_output_safety(&self) -> &LLMOutputSafetyAnalyzer {
        &self.llm_output_safety
    }

    /// Get toxicity analyzer (for direct content analysis)
    pub fn toxicity(&self) -> &ToxicityAnalyzer {
        &self.toxicity_analyzer
    }

    /// Extract content to analyze from request
    fn extract_content(&self, request: &Request) -> String {
        let mut content = String::new();

        // Add path
        content.push_str(&request.path);
        content.push('\n');

        // Add query params
        if let Some(query) = &request.query_string {
            content.push_str(query);
            content.push('\n');
        }

        // Add body if present
        if let Some(body) = &request.body {
            match body {
                sentinel_core::RequestBody::Text(text) => {
                    content.push_str(text);
                }
                sentinel_core::RequestBody::Json(value) => {
                    content.push_str(&value.to_string());
                }
                _ => {}
            }
        }

        content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_neural_defense_creation() {
        let config = NeuralConfig::default();
        let defense = NeuralDefense::new(config);
        assert!(defense.is_ok());
    }

    #[tokio::test]
    async fn test_clean_request() {
        let config = NeuralConfig::default();
        let defense = NeuralDefense::new(config).unwrap();

        let request = Request {
            path: "/api/posts".to_string(),
            body: Some(sentinel_core::RequestBody::Text("Hello world".to_string())),
            ..Default::default()
        };

        let score = defense.analyze(&request).await.unwrap();
        assert!(score.neural_score < 0.2);
    }
}
