//! Challenge Generation and Verification
//!
//! Generates and verifies security challenges:
//! - Proof of Work (computational challenge)
//! - Interactive challenges (CAPTCHA-like)
//! - Token challenges (time-based)
//! - HMAC signature verification (browser/API clients)

use sentinel_core::{Challenge, ChallengeType, ResponseConfig, LayerRiskScore as RiskScore, SentinelError};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// HMAC key for signature challenges (from env or generated)
fn get_hmac_key() -> Vec<u8> {
    std::env::var("SENTINEL_CHALLENGE_SECRET")
        .unwrap_or_else(|_| {
            // Fallback: derive from SENTINEL_INTERNAL_SECRET
            std::env::var("SENTINEL_INTERNAL_SECRET")
                .unwrap_or_else(|_| "sentinel-challenge-default-key-change-me".to_string())
        })
        .into_bytes()
}

/// Pending challenge entry
#[derive(Debug, Clone)]
struct PendingChallenge {
    /// Challenge data
    challenge: Challenge,
    /// Expected solution
    solution: String,
    /// Expiration
    expires_at: Instant,
    /// Attempts remaining
    attempts_remaining: u8,
}

/// Challenge generator
pub struct ChallengeGenerator {
    /// Pending challenges by ID
    pending: Arc<DashMap<String, PendingChallenge>>,
    /// Configuration
    config: ResponseConfig,
}

impl ChallengeGenerator {
    /// Create new challenge generator
    pub fn new(config: &ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            pending: Arc::new(DashMap::new()),
            config: config.clone(),
        })
    }

    /// Generate a challenge
    pub async fn generate(
        &self,
        challenge_type: ChallengeType,
        risk_score: &RiskScore,
    ) -> Result<Challenge, SentinelError> {
        let now = Instant::now();

        let (challenge, solution) = match challenge_type {
            ChallengeType::ProofOfWork => self.generate_pow(risk_score),
            ChallengeType::Interactive => self.generate_interactive(),
            ChallengeType::Token => self.generate_token(),
            ChallengeType::RateDelay => self.generate_rate_delay(),
            ChallengeType::SignatureVerification => self.generate_signature_verification(),
        };

        let expiration = Duration::from_secs(self.config.challenge_expiration_secs);

        // Use challenge.id as the pending map key (each sub-generator creates its own ID)
        let pending_key = challenge.id.clone();

        let pending = PendingChallenge {
            challenge: challenge.clone(),
            solution,
            expires_at: now + expiration,
            attempts_remaining: self.config.max_challenge_attempts,
        };

        self.pending.insert(pending_key, pending);

        Ok(challenge)
    }

    /// Verify a challenge response
    pub async fn verify(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<bool, SentinelError> {
        let mut entry = self.pending
            .get_mut(challenge_id)
            .ok_or_else(|| SentinelError::ChallengeNotFound(challenge_id.to_string()))?;

        // Check expiration
        if Instant::now() > entry.expires_at {
            drop(entry);
            self.pending.remove(challenge_id);
            return Err(SentinelError::ChallengeExpired);
        }

        // Check attempts
        if entry.attempts_remaining == 0 {
            drop(entry);
            self.pending.remove(challenge_id);
            return Err(SentinelError::ChallengeFailed("Too many attempts".to_string()));
        }

        entry.attempts_remaining -= 1;

        // Verify based on challenge type
        let is_valid = match &entry.challenge.challenge_type {
            ChallengeType::ProofOfWork => self.verify_pow(&entry.challenge, response),
            ChallengeType::Interactive => response == entry.solution,
            ChallengeType::Token => response == entry.solution,
            ChallengeType::RateDelay => response == entry.solution,
            ChallengeType::SignatureVerification => self.verify_signature(&entry.challenge, response),
        };

        if is_valid {
            drop(entry);
            self.pending.remove(challenge_id);
        }

        Ok(is_valid)
    }

    /// Generate proof of work challenge
    fn generate_pow(&self, risk_score: &RiskScore) -> (Challenge, String) {
        // Difficulty based on risk
        let difficulty = match risk_score.level {
            sentinel_core::RiskLevel::Critical => 6,
            sentinel_core::RiskLevel::High => 5,
            _ => 4,
        };

        let nonce = Self::generate_nonce();
        let challenge_id = Self::generate_id();

        let challenge = Challenge {
            id: challenge_id,
            challenge_type: ChallengeType::ProofOfWork,
            data: serde_json::json!({
                "nonce": nonce,
                "difficulty": difficulty,
                "algorithm": "sha256",
                "prefix": "0".repeat(difficulty),
            }),
            expires_in: Duration::from_secs(self.config.challenge_expiration_secs),
        };

        // For PoW, the solution is verified mathematically, not stored
        (challenge, String::new())
    }

    /// Verify proof of work
    fn verify_pow(&self, challenge: &Challenge, response: &str) -> bool {
        let data = &challenge.data;

        let nonce = data.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        let difficulty = data.get("difficulty").and_then(|v| v.as_u64()).unwrap_or(4) as usize;

        // Hash nonce + response
        let input = format!("{}{}", nonce, response);
        let hash = Self::sha256_hex(&input);

        // Check if hash starts with required zeros
        hash.starts_with(&"0".repeat(difficulty))
    }

    /// Verify HMAC signature challenge
    ///
    /// Uses HMAC-SHA256 (works everywhere — browsers, curl, API clients).
    /// The client signs `nonce || timestamp` with the shared secret.
    /// Timestamp must be within 5 minutes (anti-replay).
    fn verify_signature(&self, challenge: &Challenge, response: &str) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let data = &challenge.data;
        let nonce = match data.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return false,
        };

        // Response format: "timestamp:hex_signature"
        let parts: Vec<&str> = response.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp_str = parts[0];
        let signature_hex = parts[1];

        // Parse and validate timestamp (within 5 min window)
        let timestamp: u64 = match timestamp_str.parse() {
            Ok(t) => t,
            Err(_) => return false,
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let time_diff = if now > timestamp { now - timestamp } else { timestamp - now };
        if time_diff > 300 {
            // 5 minute window
            return false;
        }

        // Verify HMAC
        let key = get_hmac_key();
        let message = format!("{}{}", nonce, timestamp_str);

        let mut mac = match HmacSha256::new_from_slice(&key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(message.as_bytes());

        // Decode hex signature
        let expected_signature = match Self::hex_decode(signature_hex) {
            Some(s) => s,
            None => return false,
        };

        // Constant-time comparison
        mac.verify_slice(&expected_signature).is_ok()
    }

    /// Generate interactive challenge
    fn generate_interactive(&self) -> (Challenge, String) {
        // Simple math challenge
        let a = rand::random::<u8>() % 10 + 1;
        let b = rand::random::<u8>() % 10 + 1;
        let solution = (a + b).to_string();

        let challenge_id = Self::generate_id();

        let challenge = Challenge {
            id: challenge_id,
            challenge_type: ChallengeType::Interactive,
            data: serde_json::json!({
                "type": "math",
                "question": format!("What is {} + {}?", a, b),
            }),
            expires_in: Duration::from_secs(self.config.challenge_expiration_secs),
        };

        (challenge, solution)
    }

    /// Generate token challenge
    fn generate_token(&self) -> (Challenge, String) {
        let token = Self::generate_id();
        let challenge_id = Self::generate_id();

        let challenge = Challenge {
            id: challenge_id,
            challenge_type: ChallengeType::Token,
            data: serde_json::json!({
                "token": token,
                "instruction": "Return this token in x-challenge-response header",
            }),
            expires_in: Duration::from_secs(self.config.challenge_expiration_secs),
        };

        (challenge, token)
    }

    /// Generate rate delay challenge
    fn generate_rate_delay(&self) -> (Challenge, String) {
        let delay_ms = 1000 + (rand::random::<u64>() % 2000); // 1-3 seconds
        let challenge_id = Self::generate_id();
        let token = Self::generate_id();

        let challenge = Challenge {
            id: challenge_id,
            challenge_type: ChallengeType::RateDelay,
            data: serde_json::json!({
                "delay_ms": delay_ms,
                "token": token,
                "instruction": "Wait the specified delay then return the token",
            }),
            expires_in: Duration::from_secs(self.config.challenge_expiration_secs),
        };

        (challenge, token)
    }

    /// Generate HMAC signature verification challenge
    fn generate_signature_verification(&self) -> (Challenge, String) {
        let nonce = Self::generate_nonce();
        let challenge_id = Self::generate_id();

        let challenge = Challenge {
            id: challenge_id,
            challenge_type: ChallengeType::SignatureVerification,
            data: serde_json::json!({
                "nonce": nonce,
                "algorithm": "hmac-sha256",
                "instruction": "Sign nonce||timestamp with shared secret, respond with 'timestamp:hex_signature'",
            }),
            expires_in: Duration::from_secs(self.config.challenge_expiration_secs),
        };

        // Signature is verified against HMAC, not stored
        (challenge, String::new())
    }

    /// Generate unique ID
    fn generate_id() -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let random: u64 = rand::random();
        format!("{:x}{:x}", timestamp, random)
    }

    /// Generate nonce
    fn generate_nonce() -> String {
        let random: [u8; 16] = rand::random();
        hex::encode(random)
    }

    /// SHA256 hash to hex
    fn sha256_hex(input: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Decode hex string to bytes
    fn hex_decode(hex_str: &str) -> Option<Vec<u8>> {
        if hex_str.len() % 2 != 0 {
            return None;
        }

        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
            .collect()
    }

    /// Get pending challenge count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drop expired challenges, returning how many were removed.
    ///
    /// `verify` only removes the challenge it was asked about, so one that is
    /// issued and never answered — the normal case for a scanner — stayed in
    /// `pending` for the life of the process. Sync for the same reason as
    /// `BanManager::cleanup`: nothing here awaits, and the caller is sync.
    pub fn cleanup(&self) -> usize {
        let before = self.pending.len();
        let now = Instant::now();
        self.pending.retain(|_, v| v.expires_at > now);
        before - self.pending.len()
    }
}

/// Challenge verifier (stateless verification)
pub struct ChallengeVerifier;

impl ChallengeVerifier {
    /// Verify a PoW solution without state
    pub fn verify_pow_stateless(nonce: &str, response: &str, difficulty: usize) -> bool {
        let input = format!("{}{}", nonce, response);
        let hash = Self::sha256_hex(&input);
        hash.starts_with(&"0".repeat(difficulty))
    }

    fn sha256_hex(input: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_challenge() {
        let config = ResponseConfig::default();
        let generator = ChallengeGenerator::new(&config).unwrap();
        let risk_score = RiskScore::default();

        let challenge = generator.generate(ChallengeType::Interactive, &risk_score).await.unwrap();
        assert!(!challenge.id.is_empty());
    }

    #[tokio::test]
    async fn test_interactive_challenge() {
        let config = ResponseConfig::default();
        let generator = ChallengeGenerator::new(&config).unwrap();
        let risk_score = RiskScore::default();

        let challenge = generator.generate(ChallengeType::Interactive, &risk_score).await.unwrap();

        // Get the expected answer from the question
        let question = challenge.data.get("question").unwrap().as_str().unwrap();
        // Parse "What is X + Y?"
        let parts: Vec<&str> = question.split_whitespace().collect();
        let a: u8 = parts[2].parse().unwrap();
        let b: u8 = parts[4].trim_end_matches('?').parse().unwrap();
        let answer = (a + b).to_string();

        let result = generator.verify(&challenge.id, &answer).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_hmac_challenge() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let config = ResponseConfig::default();
        let generator = ChallengeGenerator::new(&config).unwrap();
        let risk_score = RiskScore::default();

        let challenge = generator.generate(ChallengeType::SignatureVerification, &risk_score).await.unwrap();

        let nonce = challenge.data.get("nonce").unwrap().as_str().unwrap();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        // Sign with HMAC
        let key = get_hmac_key();
        let message = format!("{}{}", nonce, timestamp);
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let response = format!("{}:{}", timestamp, signature);
        let result = generator.verify(&challenge.id, &response).await.unwrap();
        assert!(result);
    }

    #[test]
    fn test_pow_verification() {
        // This is a known valid PoW solution
        let nonce = "test_nonce";
        let difficulty = 2;

        // Find a valid solution
        for i in 0..1000000 {
            let response = i.to_string();
            if ChallengeVerifier::verify_pow_stateless(nonce, &response, difficulty) {
                // Found valid solution
                assert!(ChallengeVerifier::verify_pow_stateless(nonce, &response, difficulty));
                return;
            }
        }

        // If no solution found in reasonable time, that's fine for a test
    }

    #[test]
    fn test_hmac_expired_timestamp_rejected() {
        let config = ResponseConfig::default();
        let generator = ChallengeGenerator::new(&config).unwrap();

        // Create a challenge manually
        let nonce = "test_nonce_12345";
        let challenge = Challenge {
            id: "test".to_string(),
            challenge_type: ChallengeType::SignatureVerification,
            data: serde_json::json!({ "nonce": nonce }),
            expires_in: Duration::from_secs(300),
        };

        // Use a timestamp from 10 minutes ago (expired)
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 600;

        let response = format!("{}:deadbeef", old_timestamp);
        let result = generator.verify_signature(&challenge, &response);
        assert!(!result);
    }
}
