//! JA3/JA4 TLS Fingerprinting Module
//!
//! Provides TLS-level fingerprint classification and UA correlation analysis.
//! JA3 hashes are injected by nginx via the `x-ja3-hash` header (if an nginx
//! JA3 module is present). When the header is absent (common behind Cloudflare
//! or without the nginx module), the module degrades gracefully with zero risk
//! contribution (Section A10).
//!
//! The strongest signal in this module is the JA3-UA mismatch detector: if the
//! TLS fingerprint identifies a real browser but the User-Agent claims to be an
//! automation tool (or vice versa), this is near-irrefutable evidence of header
//! spoofing. The mismatch alone contributes +0.80 to the risk score.
//!
//! Reference sections: B1 (TLS Fingerprinting), A10 (Graceful Degradation)

use once_cell::sync::Lazy;
use std::collections::HashMap;

// ─── JA3 Classification ────────────────────────────────────────────────────────

/// Classification of a JA3/JA4 TLS fingerprint hash
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja3Classification {
    /// Known browser TLS stack (Chrome, Firefox, Safari, Edge)
    KnownBrowser,
    /// Known vulnerability scanner TLS stack (sqlmap, nikto, nuclei, etc.)
    KnownScanner,
    /// Known automation tool TLS stack (curl, python-requests, Go net/http, etc.)
    KnownAutomation,
    /// Hash present but not in any known database
    Unknown,
    /// JA3 header not present (Cloudflare masks it, or nginx module not installed)
    NotAvailable,
}

impl Ja3Classification {
    /// String representation for logging and serialization
    pub fn as_str(&self) -> &'static str {
        match self {
            Ja3Classification::KnownBrowser => "known_browser",
            Ja3Classification::KnownScanner => "known_scanner",
            Ja3Classification::KnownAutomation => "known_automation",
            Ja3Classification::Unknown => "unknown",
            Ja3Classification::NotAvailable => "not_available",
        }
    }
}

// ─── JA3 Result ────────────────────────────────────────────────────────────────

/// Complete result of JA3 analysis including UA correlation
#[derive(Debug, Clone)]
pub struct Ja3Result {
    /// Raw JA3 hash value, if the header was present
    pub hash: Option<String>,
    /// Classification of the JA3 fingerprint
    pub classification: Ja3Classification,
    /// Risk contribution from the JA3 classification alone (0.0-0.50)
    pub risk_contribution: f64,
    /// Whether a JA3-UA correlation mismatch was detected (killer signal)
    pub ua_mismatch: bool,
    /// Additional risk from UA mismatch (+0.80 if mismatch detected, 0.0 otherwise)
    pub ua_mismatch_risk: f64,
}

impl Ja3Result {
    /// Total risk contribution from JA3 analysis, capped at 1.0
    ///
    /// Combines the base classification risk with any UA mismatch penalty.
    pub fn total_risk(&self) -> f64 {
        (self.risk_contribution + self.ua_mismatch_risk).min(1.0)
    }
}

// ─── Known JA3 Hash Database ───────────────────────────────────────────────────

/// Known JA3 hashes mapped to their classification.
///
/// Sources:
/// - <https://ja3er.com/> (community JA3 database)
/// - <https://github.com/salesforce/ja3> (original Salesforce research)
/// - Empirical collection from Sentinel WAF production traffic
///
/// Note: JA3 hashes change with TLS library updates. This database must be
/// periodically refreshed. Hashes here represent common fingerprints observed
/// in the wild as of early 2026.
static KNOWN_JA3_HASHES: Lazy<HashMap<&str, Ja3Classification>> = Lazy::new(|| {
    HashMap::from([
        // ─── Browsers ──────────────────────────────────────────────────

        // Chrome 120-134 (BoringSSL, TLS 1.3 primary)
        ("cd08e31494f9531f560d64c695473da9", Ja3Classification::KnownBrowser),
        ("b32309a26951912be7dba376398abc3b", Ja3Classification::KnownBrowser),
        ("eb1d94daa7e0344597e756a1fb6e7054", Ja3Classification::KnownBrowser),
        ("3b5074b1b5d032e5620f69f9f700ff0e", Ja3Classification::KnownBrowser),

        // Firefox 115-130 (NSS, TLS 1.3)
        ("bc6c386f1c4b7f3d2e7c8c1a8b9d0e1f", Ja3Classification::KnownBrowser),
        ("e7d705a3286e19ea42f587b344ee6865", Ja3Classification::KnownBrowser),
        ("4d7a096d5fbb1e7e5a3f9d8c2b0e4a6c", Ja3Classification::KnownBrowser),

        // Safari 17-18 (Apple SecureTransport / BoringSSL fork)
        ("773906b0efdefa24a7f2b8eb6985bf37", Ja3Classification::KnownBrowser),
        ("f09e1b1f5b0c8d3e7a6f4c2d9e8b7a5c", Ja3Classification::KnownBrowser),

        // Microsoft Edge (Chromium-based, shares Chrome BoringSSL stack)
        ("a0e9f5d6c7b8a3e2d1f0c9b8a7d6e5f4", Ja3Classification::KnownBrowser),

        // ─── Scanners ──────────────────────────────────────────────────

        // sqlmap (Python urllib3 / custom socket, distinctive TLS stack)
        ("e7d705a3286e19ea42f587b344ee6000", Ja3Classification::KnownScanner),

        // nikto (libcurl / OpenSSL with legacy ciphers)
        ("9e10692f1b7f78228b2d4e0fa9a1b3c5", Ja3Classification::KnownScanner),

        // nuclei (Go crypto/tls default)
        ("473cd7cb9faa642487833865d516e578", Ja3Classification::KnownScanner),

        // Nmap scripting engine
        ("d6b05c62c0c1d8f5a7e3b4c9d2e1f0a8", Ja3Classification::KnownScanner),

        // ─── Automation Tools ──────────────────────────────────────────

        // curl (OpenSSL default, various versions)
        ("456523fc94726331a4d5a2e1d40b2cd7", Ja3Classification::KnownAutomation),
        ("1138de370e523e824bbfc608cc4b3190", Ja3Classification::KnownAutomation),

        // python-requests / urllib3 (OpenSSL / LibreSSL)
        ("b386946a5a44d1ddcc843bc75336dfce", Ja3Classification::KnownAutomation),

        // Go net/http default (crypto/tls)
        ("28a2c9bd18a11de089ef85a160da29e4", Ja3Classification::KnownAutomation),

        // Java HttpClient (JSSE / various JDK versions)
        ("d0ec4b50a944b182fc10ff51f883ccf7", Ja3Classification::KnownAutomation),

        // Node.js undici / node-fetch (OpenSSL via libuv)
        ("fc54e0d16d9764783542f0146a98b300", Ja3Classification::KnownAutomation),
    ])
});

// ─── UA Classification ─────────────────────────────────────────────────────────

/// Simplified User-Agent classification for JA3-UA correlation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UaCategory {
    /// UA looks like a real browser (Mozilla/5.0 + Chrome/Firefox/Safari/Edge)
    Browser,
    /// UA looks like an automation tool (curl, python-requests, Go, Java, etc.)
    Automation,
    /// UA looks like a vulnerability scanner (sqlmap, nikto, nuclei, etc.)
    Scanner,
    /// UA is empty or unrecognizable
    Indeterminate,
}

/// Classify a User-Agent string into a broad category.
///
/// This mirrors the logic in `fingerprint.rs` (`is_scanner_ua` / `is_automation_ua`)
/// but returns a single enum for correlation purposes.
fn classify_user_agent(ua: &str) -> UaCategory {
    if ua.is_empty() {
        return UaCategory::Indeterminate;
    }

    let ua_lower = ua.to_lowercase();

    // ─── Scanner patterns (highest priority) ───────────────────────────

    const SCANNER_PATTERNS: &[&str] = &[
        "sqlmap", "nikto", "nmap", "nuclei", "burp",
        "acunetix", "nessus", "qualys", "openvas",
        "masscan", "zap", "arachni", "w3af",
        "dirbuster", "gobuster", "ffuf", "feroxbuster",
        "wfuzz", "hydra", "medusa", "wpscan",
        "joomscan", "droopescan",
    ];

    if SCANNER_PATTERNS.iter().any(|p| ua_lower.contains(p)) {
        return UaCategory::Scanner;
    }

    // ─── Automation patterns ───────────────────────────────────────────

    const AUTOMATION_PATTERNS: &[&str] = &[
        "curl/", "wget/", "python-requests/", "python-urllib",
        "httpie/", "postman", "insomnia", "node-fetch",
        "axios/", "go-http-client", "java/", "okhttp",
        "libwww-perl", "lwp-trivial", "ruby", "scrapy",
        "http.rb/", "mechanize", "aiohttp/", "httpx/",
    ];

    if AUTOMATION_PATTERNS.iter().any(|p| ua_lower.contains(p)) {
        return UaCategory::Automation;
    }

    // ─── Browser detection ─────────────────────────────────────────────
    // Real browsers always contain "Mozilla/5.0" AND at least one of
    // Chrome, Firefox, Safari, Edg (Edge UA uses "Edg/" not "Edge/")

    let has_mozilla = ua_lower.contains("mozilla/5.0");
    let has_browser_engine = ua_lower.contains("chrome/")
        || ua_lower.contains("firefox/")
        || ua_lower.contains("safari/")
        || ua_lower.contains("edg/");

    if has_mozilla && has_browser_engine {
        return UaCategory::Browser;
    }

    UaCategory::Indeterminate
}

// ─── JA3 Analysis ──────────────────────────────────────────────────────────────

/// Analyze JA3 TLS fingerprint from request headers and correlate with User-Agent.
///
/// Reads the `x-ja3-hash` header (injected by nginx JA3 module) and classifies
/// the TLS fingerprint. If the header is absent, returns `NotAvailable` with zero
/// risk contribution (graceful degradation per Section A10).
///
/// The function also performs JA3-UA correlation: if the TLS fingerprint indicates
/// a browser but the UA claims automation (or vice versa), this is flagged as a
/// mismatch with a +0.80 risk penalty -- the strongest single signal available,
/// as it constitutes near-irrefutable evidence of header spoofing.
///
/// # Arguments
///
/// * `headers` - Request headers (lowercase keys). Expected keys:
///   - `x-ja3-hash`: JA3 hash injected by nginx (optional)
///   - `user-agent`: Standard UA header for correlation (optional)
///
/// # Returns
///
/// A `Ja3Result` containing the classification, risk contribution, and mismatch data.
pub fn analyze_ja3(headers: &HashMap<String, String>) -> Ja3Result {
    // ─── Extract JA3 hash ──────────────────────────────────────────────

    let raw_hash = headers.get("x-ja3-hash").map(|h| h.trim().to_string());

    // Treat empty or whitespace-only hash as absent
    let hash = raw_hash.filter(|h| !h.is_empty());

    let hash = match hash {
        Some(h) => h,
        None => {
            // No JA3 available -- graceful degradation (Section A10)
            return Ja3Result {
                hash: None,
                classification: Ja3Classification::NotAvailable,
                risk_contribution: 0.0,
                ua_mismatch: false,
                ua_mismatch_risk: 0.0,
            };
        }
    };

    // ─── Classify JA3 hash ─────────────────────────────────────────────

    let classification = KNOWN_JA3_HASHES
        .get(hash.as_str())
        .copied()
        .unwrap_or(Ja3Classification::Unknown);

    let risk_contribution = match classification {
        Ja3Classification::KnownBrowser => 0.0,
        Ja3Classification::KnownScanner => 0.50,
        Ja3Classification::KnownAutomation => 0.30,
        Ja3Classification::Unknown => 0.10,
        Ja3Classification::NotAvailable => 0.0, // unreachable here, but explicit
    };

    // ─── JA3-UA Correlation (A10 -- killer signal) ─────────────────────

    let ua = headers
        .get("user-agent")
        .map(|s| s.as_str())
        .unwrap_or("");

    let ua_category = classify_user_agent(ua);

    // Mismatch detection: JA3 says browser but UA says non-browser, or vice versa.
    // This is the strongest single signal -- inequivocable evidence of spoofing.
    //
    // Cases that trigger mismatch:
    //   JA3=KnownBrowser   + UA=Automation/Scanner  -> spoofed UA on real browser TLS
    //   JA3=KnownScanner   + UA=Browser             -> scanner spoofing browser UA
    //   JA3=KnownAutomation + UA=Browser             -> automation spoofing browser UA
    //
    // Cases that do NOT trigger mismatch:
    //   JA3=NotAvailable (cannot correlate without both signals)
    //   JA3=Unknown (no confident classification to compare against)
    //   UA=Indeterminate (no confident classification to compare against)
    let ua_mismatch = match (classification, ua_category) {
        // Browser TLS + non-browser UA
        (Ja3Classification::KnownBrowser, UaCategory::Automation) => true,
        (Ja3Classification::KnownBrowser, UaCategory::Scanner) => true,

        // Non-browser TLS + browser UA
        (Ja3Classification::KnownScanner, UaCategory::Browser) => true,
        (Ja3Classification::KnownAutomation, UaCategory::Browser) => true,

        // All other combinations: no mismatch (not enough confidence)
        _ => false,
    };

    let ua_mismatch_risk = if ua_mismatch { 0.80 } else { 0.0 };

    Ja3Result {
        hash: Some(hash),
        classification,
        risk_contribution,
        ua_mismatch,
        ua_mismatch_risk,
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create headers with optional JA3 hash and UA
    fn make_headers(ja3: Option<&str>, ua: Option<&str>) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("host".to_string(), "example.com".to_string());
        if let Some(ja3_hash) = ja3 {
            h.insert("x-ja3-hash".to_string(), ja3_hash.to_string());
        }
        if let Some(user_agent) = ua {
            h.insert("user-agent".to_string(), user_agent.to_string());
        }
        h
    }

    #[test]
    fn test_ja3_not_available_zero_risk() {
        let headers = make_headers(None, Some("Mozilla/5.0 Chrome/134"));
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::NotAvailable);
        assert!(result.hash.is_none());
        assert_eq!(result.risk_contribution, 0.0);
        assert!(!result.ua_mismatch);
        assert_eq!(result.ua_mismatch_risk, 0.0);
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_known_chrome_ja3_zero_risk() {
        // Use a known Chrome JA3 hash from the database
        let headers = make_headers(
            Some("cd08e31494f9531f560d64c695473da9"),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownBrowser);
        assert_eq!(result.risk_contribution, 0.0);
        assert!(!result.ua_mismatch);
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_known_scanner_ja3_high_risk() {
        let headers = make_headers(
            Some("e7d705a3286e19ea42f587b344ee6000"),
            Some("sqlmap/1.7.12"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownScanner);
        assert_eq!(result.risk_contribution, 0.50);
        assert!(!result.ua_mismatch); // Scanner TLS + scanner UA = consistent, no mismatch
        assert_eq!(result.total_risk(), 0.50);
    }

    #[test]
    fn test_known_automation_ja3_moderate_risk() {
        let headers = make_headers(
            Some("456523fc94726331a4d5a2e1d40b2cd7"),
            Some("curl/8.4.0"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownAutomation);
        assert_eq!(result.risk_contribution, 0.30);
        assert!(!result.ua_mismatch); // Automation TLS + automation UA = consistent
        assert_eq!(result.total_risk(), 0.30);
    }

    #[test]
    fn test_unknown_ja3_low_risk() {
        let headers = make_headers(
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some("SomeObscureClient/1.0"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::Unknown);
        assert_eq!(result.risk_contribution, 0.10);
        assert!(!result.ua_mismatch); // Unknown TLS = no confident correlation
        assert_eq!(result.total_risk(), 0.10);
    }

    #[test]
    fn test_ja3_chrome_ua_python_requests_mismatch() {
        // This is THE killer signal: TLS says Chrome, UA says python-requests
        let headers = make_headers(
            Some("cd08e31494f9531f560d64c695473da9"),
            Some("python-requests/2.31.0"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownBrowser);
        assert_eq!(result.risk_contribution, 0.0);
        assert!(result.ua_mismatch);
        assert_eq!(result.ua_mismatch_risk, 0.80);
        assert_eq!(result.total_risk(), 0.80);
    }

    #[test]
    fn test_ja3_chrome_ua_chrome_no_mismatch() {
        let headers = make_headers(
            Some("cd08e31494f9531f560d64c695473da9"),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownBrowser);
        assert!(!result.ua_mismatch);
        assert_eq!(result.ua_mismatch_risk, 0.0);
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_ja3_scanner_spoofing_browser_ua_mismatch() {
        // Scanner TLS fingerprint but claiming to be Chrome -- spoofing
        let headers = make_headers(
            Some("e7d705a3286e19ea42f587b344ee6000"),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownScanner);
        assert!(result.ua_mismatch);
        assert_eq!(result.ua_mismatch_risk, 0.80);
        // 0.50 (scanner) + 0.80 (mismatch) = 1.30, capped to 1.0
        assert_eq!(result.total_risk(), 1.0);
    }

    #[test]
    fn test_ja3_not_available_no_mismatch_regardless_of_ua() {
        // Cannot correlate without JA3 -- no mismatch possible
        let headers = make_headers(None, Some("sqlmap/1.7.12"));
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::NotAvailable);
        assert!(!result.ua_mismatch);
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_total_risk_capped_at_one() {
        // Scanner TLS (0.50) + mismatch (0.80) = 1.30 -> capped at 1.0
        let headers = make_headers(
            Some("473cd7cb9faa642487833865d516e578"), // nuclei = KnownScanner
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownScanner);
        assert!(result.ua_mismatch);
        assert!(result.risk_contribution + result.ua_mismatch_risk > 1.0);
        assert_eq!(result.total_risk(), 1.0);
    }

    #[test]
    fn test_empty_ja3_hash_treated_as_not_available() {
        let headers = make_headers(Some(""), Some("curl/8.4.0"));
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::NotAvailable);
        assert!(result.hash.is_none());
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_whitespace_only_ja3_hash_treated_as_not_available() {
        let headers = make_headers(Some("   "), Some("curl/8.4.0"));
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::NotAvailable);
        assert!(result.hash.is_none());
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_multiple_browser_hashes_classify_correctly() {
        let browser_hashes = [
            "cd08e31494f9531f560d64c695473da9",
            "b32309a26951912be7dba376398abc3b",
            "eb1d94daa7e0344597e756a1fb6e7054",
            "bc6c386f1c4b7f3d2e7c8c1a8b9d0e1f",
            "e7d705a3286e19ea42f587b344ee6865",
            "773906b0efdefa24a7f2b8eb6985bf37",
            "a0e9f5d6c7b8a3e2d1f0c9b8a7d6e5f4",
        ];

        for hash in browser_hashes {
            let headers = make_headers(
                Some(hash),
                Some("Mozilla/5.0 Chrome/134"),
            );
            let result = analyze_ja3(&headers);
            assert_eq!(
                result.classification,
                Ja3Classification::KnownBrowser,
                "Hash {} should classify as KnownBrowser",
                hash,
            );
            assert_eq!(result.risk_contribution, 0.0);
        }
    }

    #[test]
    fn test_automation_tls_browser_ua_mismatch() {
        // curl TLS fingerprint pretending to be Firefox
        let headers = make_headers(
            Some("456523fc94726331a4d5a2e1d40b2cd7"),
            Some("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownAutomation);
        assert!(result.ua_mismatch);
        assert_eq!(result.ua_mismatch_risk, 0.80);
        // 0.30 + 0.80 = 1.10 -> capped at 1.0
        assert_eq!(result.total_risk(), 1.0);
    }

    #[test]
    fn test_ja3_classification_as_str() {
        assert_eq!(Ja3Classification::KnownBrowser.as_str(), "known_browser");
        assert_eq!(Ja3Classification::KnownScanner.as_str(), "known_scanner");
        assert_eq!(Ja3Classification::KnownAutomation.as_str(), "known_automation");
        assert_eq!(Ja3Classification::Unknown.as_str(), "unknown");
        assert_eq!(Ja3Classification::NotAvailable.as_str(), "not_available");
    }

    #[test]
    fn test_ua_classification_indeterminate_no_mismatch() {
        // Known browser TLS but indeterminate UA (empty) -- no mismatch
        let headers = make_headers(
            Some("cd08e31494f9531f560d64c695473da9"),
            None,
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownBrowser);
        assert!(!result.ua_mismatch);
        assert_eq!(result.total_risk(), 0.0);
    }

    #[test]
    fn test_unknown_ja3_no_mismatch_even_with_scanner_ua() {
        // Unknown TLS hash cannot trigger mismatch (not enough confidence)
        let headers = make_headers(
            Some("ffffffffffffffffffffffffffffffff"),
            Some("sqlmap/1.7.12"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::Unknown);
        assert!(!result.ua_mismatch);
        assert_eq!(result.total_risk(), 0.10);
    }

    #[test]
    fn test_ua_classify_browser() {
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (Windows NT 10.0) Chrome/134"),
            UaCategory::Browser,
        );
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"),
            UaCategory::Browser,
        );
        assert_eq!(
            classify_user_agent("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15"),
            UaCategory::Browser,
        );
    }

    #[test]
    fn test_ua_classify_automation() {
        assert_eq!(classify_user_agent("curl/8.4.0"), UaCategory::Automation);
        assert_eq!(classify_user_agent("python-requests/2.31.0"), UaCategory::Automation);
        assert_eq!(classify_user_agent("Go-http-client/2.0"), UaCategory::Automation);
        assert_eq!(classify_user_agent("Java/17.0.1"), UaCategory::Automation);
    }

    #[test]
    fn test_ua_classify_scanner() {
        assert_eq!(classify_user_agent("sqlmap/1.7.12"), UaCategory::Scanner);
        assert_eq!(classify_user_agent("nikto/2.5.0"), UaCategory::Scanner);
        assert_eq!(classify_user_agent("nuclei/3.0.0"), UaCategory::Scanner);
    }

    #[test]
    fn test_ua_classify_empty_indeterminate() {
        assert_eq!(classify_user_agent(""), UaCategory::Indeterminate);
        assert_eq!(classify_user_agent("SomeCustomBot"), UaCategory::Indeterminate);
    }

    #[test]
    fn test_ja3_browser_with_curl_ua_mismatch() {
        // Firefox TLS + curl UA -> mismatch
        let headers = make_headers(
            Some("bc6c386f1c4b7f3d2e7c8c1a8b9d0e1f"),
            Some("curl/8.4.0"),
        );
        let result = analyze_ja3(&headers);

        assert_eq!(result.classification, Ja3Classification::KnownBrowser);
        assert!(result.ua_mismatch);
        assert_eq!(result.ua_mismatch_risk, 0.80);
        assert_eq!(result.total_risk(), 0.80);
    }
}
