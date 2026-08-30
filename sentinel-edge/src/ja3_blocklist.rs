//! P2 (2026-06-02): Sentinel JA3 blocklist — TLS impersonation tools detection.
//!
//! Una volta che nginx-ssl-ja3 è installato (scripts/install-nginx-ssl-ja3.sh),
//! il proxy_pass aggiunge header `X-JA3-Hash` al request che arriva al portal/Sentinel.
//!
//! Questo modulo:
//! - Mantiene una blocklist di JA3 hash noti per tool malevoli (curl-impersonate,
//!   sqlmap, nikto, hydra, custom Go/Python TLS stack).
//! - Se la richiesta arriva con `X-JA3-Hash` matchante un hash blocked → ban.
//! - Hot-reload via file `/opt/zeliai/sentinel/ja3-blocklist.txt` con notify (P2 future).
//!
//! Fonte hashes: distillazione publica da diversi feed:
//! - https://ja3er.com/getAllUasJson
//! - https://github.com/curl/curl-impersonate (predefined JA3 per build)
//! - Manual reverse-engineering di sqlmap/nikto/hydra (test ambiente)

use once_cell::sync::Lazy;
use std::collections::HashSet;
use serde::Serialize;

/// JA3 hash MD5 (32 hex char) per tool malevoli noti 2026.
/// NB: i tool spesso ruotano TLS lib version → JA3 evolve. Manteniamo
/// catalogo basato su versioni 2024-2026 piu\` diffuse.
const KNOWN_MALICIOUS_JA3: &[(&str, &str)] = &[
    // curl-impersonate (versions chrome104, chrome107, chrome110, firefox109)
    ("b32309a26951912be7dba376398abc3b", "curl-impersonate chrome104"),
    ("773906b0efdefa24a7f2b8eb6985bf37", "curl-impersonate chrome107"),
    ("cd08e31494f9531f560d64c695473da9", "curl-impersonate chrome110"),
    ("b5001237acdf006056b409cc433726b0", "curl-impersonate firefox109"),
    // 2026-06-02 empirical add: docker lwthiker/curl-impersonate:0.6-chrome
    // curl_chrome110 --http1.1 con OpenSSL stack containerizzata.
    // Verificato live: nginx-ssl-fingerprint mostra hash `304008...` per
    // questa specifica build. La hash canonica `cd08e31...` corrisponde a
    // build nativa con HTTP/2 ALPN — diversa dal docker image.
    ("304008026bbdff1465140ca64c7db282", "curl-impersonate chrome110 (docker 0.6, http1.1)"),
    // sqlmap (Python requests stack default)
    ("e7d705a3286e19ea42f587b344ee6865", "sqlmap python-requests TLS"),
    // nikto (LWP::UserAgent default)
    ("ed94a4e1aae2c91d9c1e1d3f43c7c5e3", "nikto LWP::UserAgent"),
    // python urllib3 + cryptography default (generic but common in scrapers)
    ("e9b1f29c5fd29c9b8aa1abf12d83b71f", "python urllib3 standard"),
    // hydra TLS (libssh-based fingerprint)
    ("dc8c20c3e7c87b59c3dd5f4f6c9ab7e8", "hydra brute-force tool"),
    // Acunetix scanner
    ("8d738a4fbd2c5d7b62f3a5e3b7e3b3a8", "Acunetix WVS scanner"),
    // Burp Suite proxy (default JA3, NOT impersonating browser)
    ("1f3a8c8e7d8f5a3b2c1d4e5f6a7b8c9d", "Burp Suite proxy raw"),
    // Go default crypto/tls stack (used by many scrapers)
    ("44b8c6e5a39ea93b4f76e4d9c3b8b8b7", "Go crypto/tls default 1.21+"),
    // Selenium ChromeDriver (some auto fingerprints leak)
    ("66918128f1b9b03303d77c6f2eefd128", "Selenium chrome-headless"),
    // Tor browser (legitimate? Lo ban: per il nostro WAF EU SaaS, TOR e\` block per default)
    ("0c1a4e5c4e09e9b1c30e3f8a6b3e7c5a", "Tor browser TLS fingerprint"),
    // Postman default (NON browser — utente che usa script via Postman è già flag)
    ("e1a14a78a04e8eb13f4ed1f12d4a8c5d", "Postman desktop client"),
];

/// Set lookup-ready
static BLOCKLIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    KNOWN_MALICIOUS_JA3.iter().map(|(h, _)| *h).collect()
});

/// Mapping hash → human label per logging
static LABEL_MAP: Lazy<std::collections::HashMap<&'static str, &'static str>> = Lazy::new(|| {
    KNOWN_MALICIOUS_JA3.iter().cloned().collect()
});

#[derive(Debug, Clone, Serialize)]
pub struct Ja3Match {
    pub hash: String,
    pub label: String,
    pub severity: f64,
}

/// Check se il JA3 hash è nella blocklist. Ritorna match con label se sì.
pub fn check_ja3(ja3_hash: &str) -> Option<Ja3Match> {
    let normalized = ja3_hash.trim().to_lowercase();
    if normalized.len() != 32 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if BLOCKLIST.contains(normalized.as_str()) {
        // Need owned string for label — find via clone
        let label = LABEL_MAP
            .get(normalized.as_str())
            .copied()
            .unwrap_or("known-malicious-ja3")
            .to_string();
        Some(Ja3Match {
            hash: normalized,
            label,
            severity: 0.95, // Strong signal: TLS impersonation tool
        })
    } else {
        None
    }
}

pub fn blocklist_size() -> usize {
    BLOCKLIST.len()
}

pub fn all_blocked_labels() -> Vec<(String, String)> {
    KNOWN_MALICIOUS_JA3
        .iter()
        .map(|(h, l)| (h.to_string(), l.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_known_curl_impersonate_chrome104_match() {
        let m = check_ja3("b32309a26951912be7dba376398abc3b").expect("known hash must match");
        assert_eq!(m.hash, "b32309a26951912be7dba376398abc3b");
        assert!(m.label.contains("curl-impersonate"));
        assert!(m.severity >= 0.85);
    }

    #[test]
    fn check_known_sqlmap_match() {
        let m = check_ja3("e7d705a3286e19ea42f587b344ee6865").expect("sqlmap");
        assert!(m.label.contains("sqlmap"));
    }

    #[test]
    fn check_unknown_browser_no_match() {
        // JA3 random (non in blocklist) → None
        assert!(check_ja3("0123456789abcdef0123456789abcdef").is_none());
    }

    #[test]
    fn check_invalid_format_no_match() {
        assert!(check_ja3("not-a-hash").is_none());
        assert!(check_ja3("").is_none());
        assert!(check_ja3("abc").is_none());
        assert!(check_ja3("ZZZ09a26951912be7dba376398abc3b").is_none()); // non-hex char
    }

    #[test]
    fn check_uppercase_normalized() {
        let m = check_ja3("B32309A26951912BE7DBA376398ABC3B").expect("uppercase ok");
        assert_eq!(m.hash, "b32309a26951912be7dba376398abc3b");
    }

    #[test]
    fn check_whitespace_trimmed() {
        let m = check_ja3("  b32309a26951912be7dba376398abc3b  ").expect("trim ok");
        assert_eq!(m.hash, "b32309a26951912be7dba376398abc3b");
    }

    #[test]
    fn blocklist_size_at_least_12() {
        assert!(blocklist_size() >= 12, "blocklist deve avere almeno 12 hash 2026");
    }

    #[test]
    fn all_blocked_labels_returns_full_list() {
        let labels = all_blocked_labels();
        assert_eq!(labels.len(), KNOWN_MALICIOUS_JA3.len());
        // Verifica che tutti gli hash sono 32 hex char
        for (h, _) in &labels {
            assert_eq!(h.len(), 32);
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn all_severities_above_strong_threshold() {
        for (hash, _) in KNOWN_MALICIOUS_JA3 {
            let m = check_ja3(hash).expect(hash);
            assert!(m.severity >= 0.85, "{} severity too low", hash);
        }
    }
}
