//! Coordinated Attack Detection
//!
//! Detects distributed attacks using clustering:
//! - Botnet detection
//! - Distributed probing
//! - Sybil attacks (multiple fake identities)

use sentinel_core::{BehaviorConfig, Request, SentinelError};
use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Types of coordinated attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatedAttack {
    /// Multiple IPs acting in coordination
    BotNet,
    /// Distributed path/parameter probing
    DistributedProbing,
    /// Multiple identities from same source
    SybilAttack,
}

/// Request signature for clustering
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RequestSignature {
    /// Path (normalized)
    path: String,
    /// Method
    method: String,
    /// User agent hash
    ua_hash: u64,
    /// Has similar body structure
    body_structure: String,
}

impl RequestSignature {
    fn from_request(request: &Request) -> Self {
        // Normalize path (remove dynamic segments)
        let path = Self::normalize_path(&request.path);

        // Hash user agent
        let ua = request.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        let ua_hash = Self::hash_string(ua);

        // Extract body structure (keys only for JSON)
        let body_structure = match &request.body {
            Some(sentinel_core::RequestBody::Json(v)) => Self::extract_structure(v),
            _ => String::new(),
        };

        Self {
            path,
            method: request.method.clone(),
            ua_hash,
            body_structure,
        }
    }

    fn normalize_path(path: &str) -> String {
        // Replace UUIDs and numbers with placeholders
        let re_uuid = regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
        let re_num = regex::Regex::new(r"/\d+").unwrap();

        let path = re_uuid.replace_all(path, "{id}");
        let path = re_num.replace_all(&path, "/{num}");

        path.to_string()
    }

    fn hash_string(s: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    fn extract_structure(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                keys.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
            }
            _ => String::new(),
        }
    }
}

/// Request cluster for detecting coordinated behavior
#[derive(Debug)]
struct RequestCluster {
    /// Signature for this cluster
    signature: RequestSignature,
    /// IPs in this cluster
    ips: Vec<IpAddr>,
    /// Timestamps
    timestamps: VecDeque<Instant>,
    /// First seen
    #[allow(dead_code)]
    first_seen: Instant,
}

impl RequestCluster {
    fn new(signature: RequestSignature, ip: IpAddr) -> Self {
        Self {
            signature,
            ips: vec![ip],
            timestamps: VecDeque::new(),
            first_seen: Instant::now(),
        }
    }

    fn add(&mut self, ip: IpAddr, window: Duration) {
        let now = Instant::now();

        // Clean old timestamps
        let cutoff = now - window;
        while let Some(front) = self.timestamps.front() {
            if *front < cutoff {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        self.timestamps.push_back(now);

        if !self.ips.contains(&ip) {
            self.ips.push(ip);
        }
    }

    fn unique_ips(&self) -> usize {
        self.ips.len()
    }

    fn request_rate(&self) -> f64 {
        if self.timestamps.len() < 2 {
            return 0.0;
        }

        let duration = self.timestamps.back().unwrap().duration_since(*self.timestamps.front().unwrap());
        if duration.as_secs_f64() == 0.0 {
            return 0.0;
        }

        self.timestamps.len() as f64 / duration.as_secs_f64()
    }
}

/// Coordination detector
pub struct CoordinationDetector {
    /// Request clusters by signature
    clusters: Arc<DashMap<RequestSignature, RequestCluster>>,
    /// IP to signature mapping for Sybil detection
    ip_signatures: Arc<DashMap<IpAddr, Vec<RequestSignature>>>,
    /// Configuration
    config: BehaviorConfig,
    /// Detection window
    window: Duration,
}

impl CoordinationDetector {
    /// Create new coordination detector
    pub fn new(config: &BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            clusters: Arc::new(DashMap::new()),
            ip_signatures: Arc::new(DashMap::new()),
            config: config.clone(),
            window: Duration::from_secs(config.coordination_window_secs),
        })
    }

    /// Detect coordinated attacks
    pub async fn detect(&self, request: &Request) -> Result<Option<CoordinatedAttack>, SentinelError> {
        let signature = RequestSignature::from_request(request);
        let ip = request.client_ip;

        // Check for botnet (many IPs, same request pattern)
        if let Some(cluster) = self.clusters.get(&signature) {
            let unique_ips = cluster.unique_ips();
            let rate = cluster.request_rate();

            // Many IPs making same request at high rate
            if unique_ips >= self.config.botnet_ip_threshold && rate >= self.config.botnet_rate_threshold {
                return Ok(Some(CoordinatedAttack::BotNet));
            }

            // Distributed probing (many IPs scanning similar paths)
            if unique_ips >= self.config.probing_ip_threshold {
                return Ok(Some(CoordinatedAttack::DistributedProbing));
            }
        }

        // Check for Sybil attack (one IP, many different request patterns)
        if let Some(signatures) = self.ip_signatures.get(&ip) {
            if signatures.len() >= self.config.sybil_signature_threshold {
                // Same IP with many different behavioral patterns
                return Ok(Some(CoordinatedAttack::SybilAttack));
            }
        }

        Ok(None)
    }

    /// Record a request for clustering
    pub async fn record(&self, request: &Request) {
        let signature = RequestSignature::from_request(request);
        let ip = request.client_ip;

        // Update cluster
        self.clusters
            .entry(signature.clone())
            .or_insert_with(|| RequestCluster::new(signature.clone(), ip))
            .add(ip, self.window);

        // Update IP signatures
        self.ip_signatures
            .entry(ip)
            .or_insert_with(Vec::new)
            .push(signature);
    }

    /// Cleanup old data
    pub async fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();

        self.clusters.retain(|_, cluster| {
            now.duration_since(cluster.first_seen) < max_age
        });

        // Limit signatures per IP
        self.ip_signatures.iter_mut().for_each(|mut entry| {
            if entry.value().len() > 1000 {
                entry.value_mut().truncate(1000);
            }
        });
    }

    /// Get cluster info for monitoring
    pub fn get_cluster_stats(&self) -> Vec<(String, usize, f64)> {
        self.clusters
            .iter()
            .map(|entry| {
                let cluster = entry.value();
                (
                    cluster.signature.path.clone(),
                    cluster.unique_ips(),
                    cluster.request_rate(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_detector() -> CoordinationDetector {
        let config = BehaviorConfig::default();
        CoordinationDetector::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_single_request() {
        let detector = create_detector();
        let request = Request {
            path: "/api/posts".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };

        let attack = detector.detect(&request).await.unwrap();
        assert!(attack.is_none());
    }

    #[tokio::test]
    async fn test_record_and_cluster() {
        let detector = create_detector();

        // Record requests from different IPs
        for i in 0..5 {
            let request = Request {
                path: "/api/posts".to_string(),
                method: "GET".to_string(),
                client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, i)),
                ..Default::default()
            };
            detector.record(&request).await;
        }

        // Check cluster stats
        let stats = detector.get_cluster_stats();
        assert!(!stats.is_empty());
    }

    #[test]
    fn test_path_normalization() {
        let path1 = "/api/posts/550e8400-e29b-41d4-a716-446655440000";
        let path2 = "/api/users/123/posts";

        let normalized1 = RequestSignature::normalize_path(path1);
        let normalized2 = RequestSignature::normalize_path(path2);

        assert!(normalized1.contains("{id}"));
        assert!(normalized2.contains("{num}"));
    }
}
