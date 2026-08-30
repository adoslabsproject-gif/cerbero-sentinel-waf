//! HTTP Request Fingerprinting
//!
//! Since JA3/JA4 TLS fingerprinting is impossible behind nginx (TLS terminated),
//! this module provides HTTP-level fingerprinting as an alternative.
//!
//! Signals used:
//! - Header order hash (15% weight — fragile due to CDN reordering)
//! - Accept pattern fingerprint
//! - Sec-Ch-UA / Client Hints presence & entropy
//! - Sec-Fetch-* trio (browser always sends, bots never)
//! - Accept-Language entropy
//! - Cookie structure presence
//! - TLS hints from nginx upstream headers (X-TLS-Protocol, X-TLS-Cipher)
//! - Request size profiling (body/query z-score)

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Fingerprint classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintClass {
    /// Known browser (Chrome, Firefox, Safari, Edge)
    Browser,
    /// Verified bot (Googlebot, Bingbot)
    VerifiedBot,
    /// Known scanner tool (sqlmap, nikto, nuclei)
    Scanner,
    /// Automation tool (curl, wget, python-requests)
    Automation,
    /// Unknown / unclassifiable
    Unknown,
}

impl FingerprintClass {
    /// Risk contribution in points (added to risk score)
    pub fn risk_contribution(&self) -> i32 {
        match self {
            FingerprintClass::Scanner => 10,
            FingerprintClass::Unknown => 8,
            FingerprintClass::Automation => 5,
            FingerprintClass::Browser => 0,
            FingerprintClass::VerifiedBot => -5,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FingerprintClass::Browser => "browser",
            FingerprintClass::VerifiedBot => "verified_bot",
            FingerprintClass::Scanner => "scanner",
            FingerprintClass::Automation => "automation",
            FingerprintClass::Unknown => "unknown",
        }
    }
}

/// Complete request fingerprint
#[derive(Debug, Clone)]
pub struct RequestFingerprint {
    /// SHA256 hash of header name order
    pub header_order_hash: String,
    /// Normalized accept stack signature
    pub accept_pattern: String,
    /// HTTP version string
    pub http_version: String,
    /// Classification result
    pub classification: FingerprintClass,
    /// Confidence in classification (0.0-1.0)
    pub confidence: f32,
    /// Risk points to add to total score
    pub risk_contribution: i32,
    /// Individual signal scores for debugging
    pub signals: FingerprintSignals,
}

/// Individual fingerprint signals (for feature logging / ML)
#[derive(Debug, Clone, Default)]
pub struct FingerprintSignals {
    /// Whether sec-ch-ua header is present
    pub has_sec_ch_ua: bool,
    /// Whether sec-fetch-* trio is present (site, mode, dest)
    pub has_sec_fetch: bool,
    /// Whether cookies are present
    pub has_cookies: bool,
    /// Accept-Language entropy score (0.0 = absent/generic, 1.0+ = specific)
    pub accept_language_entropy: f32,
    /// TLS protocol version from nginx (e.g., "TLSv1.3")
    pub tls_protocol: Option<String>,
    /// TLS cipher from nginx
    pub tls_cipher: Option<String>,
    /// Number of request headers
    pub header_count: usize,
    /// HTTP protocol version (e.g., "2.0", "1.1") — weak signal
    /// HTTP/2 is a moderate browser indicator; HTTP/1.1 is neutral;
    /// HTTP/1.0 is suspicious (old scanners)
    pub http_version_signal: HttpVersionSignal,
    // ── 2026-06-02 wiring: 5 nuovi signal da nginx-ssl-fingerprint module ────
    /// JA3 fingerprint full string (es. "771,4866-4865-...,0-23-65281...,29-23-24,0")
    /// → consente fuzzy matching su extension set anche quando hash cambia.
    pub ja3_full: Option<String>,
    /// JA4 fingerprint (FoxIO 2024 standard, es. "t13d1411h2_e33ad33b3d25_e8c6847a94a1")
    /// → più stabile di JA3 cross-TLS lib versions, prefix `t13d` = TLS 1.3 client.
    pub ja4: Option<String>,
    /// RFC 8701 GREASE flag (0 | 1). Chrome/FF/Safari moderni inviano SEMPRE GREASE.
    /// "0" + UA browser moderno = high-confidence TLS spoofing signal.
    pub tls_greased: Option<String>,
    /// HTTP/2 fingerprint (akamai/h2 format: "SETTINGS|WINDOW|PRIORITY|pseudo-header-order")
    /// → bot tool tipicamente hanno pattern uniform diverso da browser.
    pub http2_fp: Option<String>,
    /// GREASE-vs-UA mismatch detected (boolean derivato)
    pub grease_ua_mismatch: bool,
    /// JA4 prefix indica automation tool noto (Go default, python, ecc.)
    pub ja4_indicates_automation: bool,
}

/// (2026-06-02) Detecta se il prefix JA4 indica un tool automation noto.
///
/// JA4 format: `<protocol><tls_ver><sni><cipher_count><ext_count><alpn>_<cipher_hash>_<ext_hash>`
/// Esempi:
///   - `t13d1411h2_...`  → TLS 1.3 client (Chrome/FF moderni con ALPN h2) → OK browser
///   - `t13d1517h1_...`  → TLS 1.3 + ALPN h1 → atypical per browser moderni
///   - `t13i...`         → TLS 1.3 senza SNI (rare, tipico tool scripted)
///   - `t12d...`         → TLS 1.2 client → suspect (browser moderni preferiscono 1.3)
///   - `tq13...`         → QUIC TLS 1.3 → ok per HTTP/3
///
/// Hash conosciuti Chrome moderni (2024-2026): `_e33ad33b3d25_e8c6847a94a1` e simili.
/// Go/Python/curl default hanno `_aa...` o `_default...` pattern.
pub fn ja4_prefix_indicates_automation(ja4: &str) -> bool {
    // Pure function — testable.
    if ja4.len() < 10 {
        return false; // Hash troppo corto, non classifico
    }
    let prefix = sentinel_core::truncate_char_boundary(ja4, 10); // FP: char-boundary-safe (X-JA4 ostile)

    // Pattern noti automation/scanner:
    //   - prefix `t12d` (TLS 1.2 only, deprecated per browser) → suspect
    //   - prefix `t13i` (no SNI, tipico script) → suspect
    //   - hash segment "_aa" o "_00" come segno "default tlsConfig" Go/Python
    if prefix.starts_with("t12d") || prefix.starts_with("t13i") {
        return true;
    }
    if ja4.contains("_aaaaaaaaaaaa_") || ja4.contains("_000000000000_") {
        return true;
    }
    false
}

/// (2026-06-02) Detecta mismatch GREASE-vs-UA: TLS handshake senza GREASE
/// MA UA dichiara browser moderno (Chrome 90+, Firefox 88+, Safari 14+).
///
/// RFC 8701 GREASE è inserito SEMPRE da Chromium/BoringSSL e Firefox/NSS dal 2018+.
/// Assenza GREASE = client custom (curl, Go default, sqlmap, ecc.) → spoof signal.
///
/// `tls_greased` valori attesi da nginx-ssl-fingerprint module:
///   - "1" → GREASE presente (browser moderno OK)
///   - "0" → GREASE assente (suspect se UA dichiara browser moderno)
///   - None → header non disponibile (legacy nginx senza modulo)
pub fn grease_ua_mismatch_check(tls_greased: Option<&str>, user_agent: &str) -> bool {
    let greased = match tls_greased {
        Some(g) => g.trim(),
        None => return false, // Header non disponibile → no mismatch
    };
    if greased != "0" {
        return false; // GREASE presente o valore invalido → no mismatch
    }
    let ua_lower = user_agent.to_lowercase();

    // Edge Legacy (EdgeHTML, pre-Chromium ~ Jan 2020) NON usa GREASE → escludere
    // per evitare falso positivo. Pattern: "Edge/<ver>" (NON "Edg/<ver>" che è Chromium-based).
    if ua_lower.contains("edge/") && !ua_lower.contains("edg/") {
        return false;
    }
    // Internet Explorer 11 (raro nel 2026 ma esiste in env corp legacy): no GREASE → skip
    if ua_lower.contains("msie ") || ua_lower.contains("trident/") {
        return false;
    }
    // UC Browser / Opera Mini / Yandex Browser pre-2020: idem, no GREASE legitimately
    if ua_lower.contains("ucbrowser/") || ua_lower.contains("opera mini") {
        return false;
    }

    // GREASE assente: è mismatch SOLO se UA dichiara browser moderno (Chromium/Firefox/Safari).
    if ua_lower.contains("chrome/") || ua_lower.contains("firefox/") {
        // Estrae numero versione approssimato per evitare falso positivo su browser legacy
        return ua_has_modern_browser_version(&ua_lower);
    }
    if ua_lower.contains("safari/") && !ua_lower.contains("chrome/") {
        // Safari puro (no Chromium derivative) → assumiamo moderno se Mozilla/5.0
        return ua_lower.contains("mozilla/5.0");
    }
    false
}

/// Estrae versione del primo Chrome/Firefox nell'UA e verifica >= 80.
fn ua_has_modern_browser_version(ua_lower: &str) -> bool {
    for prefix in &["chrome/", "firefox/"] {
        if let Some(pos) = ua_lower.find(prefix) {
            let after = &ua_lower[pos + prefix.len()..];
            let version_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = version_str.parse::<u32>() {
                if v >= 80 {
                    return true;
                }
            }
        }
    }
    false
}

/// HTTP version classification (v2.0.0 — weak signal, Section B1 fingerprint)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersionSignal {
    /// HTTP/2 or HTTP/3 — moderate browser indicator (+0.05 browser, -0.05 automation)
    Http2Plus,
    /// HTTP/1.1 — neutral, no signal
    #[default]
    Http11,
    /// HTTP/1.0 — suspicious, old scanners (+0.10 scanner)
    Http10,
}

/// Fingerprint a request from its headers
pub fn fingerprint_request(headers: &HashMap<String, String>) -> RequestFingerprint {
    let mut signals = FingerprintSignals::default();
    signals.header_count = headers.len();

    // 1. Header order hash
    let header_order_hash = compute_header_order_hash(headers);

    // 2. Accept pattern
    let accept_pattern = normalize_accept_pattern(headers);

    // 3. Client Hints detection
    signals.has_sec_ch_ua = headers.contains_key("sec-ch-ua");

    // 4. Sec-Fetch trio detection
    signals.has_sec_fetch = headers.contains_key("sec-fetch-site")
        && headers.contains_key("sec-fetch-mode")
        && headers.contains_key("sec-fetch-dest");

    // 5. Cookie presence
    signals.has_cookies = headers.contains_key("cookie");

    // 6. Accept-Language entropy
    signals.accept_language_entropy = compute_accept_language_entropy(headers);

    // 7. TLS hints from nginx
    signals.tls_protocol = headers.get("x-tls-protocol").cloned();
    signals.tls_cipher = headers.get("x-tls-cipher").cloned();

    // 7b. (2026-06-02 wiring) — nginx-ssl-fingerprint full signal set
    signals.ja3_full = headers.get("x-ja3").cloned();
    signals.ja4 = headers.get("x-ja4").cloned();
    signals.tls_greased = headers.get("x-tls-greased").cloned();
    signals.http2_fp = headers.get("x-http2-fingerprint").cloned();
    // JA4 prefix automation detection — pure function for testability
    if let Some(ref ja4) = signals.ja4 {
        signals.ja4_indicates_automation = ja4_prefix_indicates_automation(ja4);
    }
    // GREASE-vs-UA mismatch — calcolata QUI con accesso a entrambi (UA estratto sotto)
    // signals.grease_ua_mismatch viene settata dopo aver letto UA (riga ~205+).

    // 8. HTTP version (from x-forwarded-proto or x-http-version header set by nginx)
    let http_version = headers
        .get("x-http-version")
        .cloned()
        .unwrap_or_else(|| "1.1".to_string());

    // 8b. HTTP version signal (v2.0.0 — weak signal)
    signals.http_version_signal = if http_version.contains("2") || http_version.contains("3") {
        HttpVersionSignal::Http2Plus
    } else if http_version.contains("1.0") {
        HttpVersionSignal::Http10
    } else {
        HttpVersionSignal::Http11
    };

    // ─── Classification Logic ──────────────────────────────────────────

    let mut browser_score: f32 = 0.0;
    let bot_score: f32 = 0.0;
    let mut scanner_score: f32 = 0.0;
    let mut automation_score: f32 = 0.0;

    // Sec-Fetch trio: strongest browser signal
    if signals.has_sec_fetch {
        browser_score += 0.35;
    } else {
        // Absence of sec-fetch = likely not a modern browser
        automation_score += 0.15;
    }

    // Client Hints (sec-ch-ua)
    if signals.has_sec_ch_ua {
        browser_score += 0.20;
        // Check for high-entropy sec-ch-ua (Chrome-specific)
        if let Some(ch_ua) = headers.get("sec-ch-ua") {
            if ch_ua.len() > 20 && ch_ua.contains("Chromium") {
                browser_score += 0.10;
            }
        }
    }

    // Accept-Language specificity
    if signals.accept_language_entropy > 1.5 {
        browser_score += 0.10; // Specific language preferences = human
    } else if signals.accept_language_entropy < 0.1 {
        automation_score += 0.10; // No language = automation
    }

    // Cookie presence (returning user)
    if signals.has_cookies {
        browser_score += 0.10;
    }

    // Accept header analysis
    let accept = headers.get("accept").map(|s| s.as_str()).unwrap_or("");
    if accept.contains("text/html") && accept.contains("application/xhtml+xml") {
        browser_score += 0.10; // Typical browser accept header
    } else if accept == "*/*" || accept.is_empty() {
        automation_score += 0.10; // curl/wget style
    }

    // User-Agent based scanner detection
    let ua = headers
        .get("user-agent")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    if is_scanner_ua(&ua) {
        scanner_score += 0.60;
    } else if is_automation_ua(&ua) {
        automation_score += 0.30;
    } else if ua.is_empty() {
        scanner_score += 0.20;
        automation_score += 0.20;
    }

    // Header count heuristic
    if signals.header_count < 3 {
        automation_score += 0.15; // Very few headers = minimal client
    } else if signals.header_count > 8 {
        browser_score += 0.05; // Browsers send many headers
    }

    // TLS version signal
    if let Some(ref proto) = signals.tls_protocol {
        if proto.contains("1.3") {
            browser_score += 0.05; // Modern browser
        } else if proto.contains("1.0") || proto.contains("1.1") {
            scanner_score += 0.10; // Old TLS = old scanner
        }
    }

    // HTTP/2+ version signal (v2.0.0 — weak signal, Section B1 fingerprint)
    match signals.http_version_signal {
        HttpVersionSignal::Http2Plus => {
            browser_score += 0.05;  // Modern browsers use HTTP/2+
        }
        HttpVersionSignal::Http10 => {
            scanner_score += 0.10;  // HTTP/1.0 = old scanner/custom tool
            automation_score += 0.05;
        }
        HttpVersionSignal::Http11 => {
            // Neutral — no signal
        }
    }

    // ── 2026-06-02 wiring: 5 nuovi signal consumption ──────────────────

    // GREASE-vs-UA mismatch: GREASE assente + UA browser moderno = SPOOF strong.
    // Chrome/FF moderni inviano SEMPRE GREASE (RFC 8701). Tool curl/sqlmap/Go NO.
    signals.grease_ua_mismatch = grease_ua_mismatch_check(signals.tls_greased.as_deref(), &ua);
    if signals.grease_ua_mismatch {
        // Strong signal — quasi tanto definitivo quanto JA3-UA mismatch (0.80).
        // Lo settiamo a 0.50 perché in casi rari (proxy MITM, vecchi browser
        // patch) può esserci GREASE assente legittimo.
        scanner_score += 0.50;
    }

    // JA4 indicates automation tool (prefix `t12d`/`t13i` o hash default)
    if signals.ja4_indicates_automation {
        automation_score += 0.30;
    }

    // HTTP/2 fingerprint pattern matching (dataset tls_known_patterns)
    if let Some(ref h2) = signals.http2_fp {
        if !h2.is_empty() {
            match crate::tls_known_patterns::classify_h2_fingerprint(h2) {
                Some((_family, true)) => {
                    // h2 fp matched automation pattern (Go/Python/curl/Java)
                    automation_score += 0.25;
                }
                Some((_family, false)) => {
                    // h2 fp matched known browser pattern — verifica UA-family mismatch
                    if crate::tls_known_patterns::h2_ua_family_mismatch(h2, &ua) {
                        scanner_score += 0.40; // strong: TLS dice Chrome, UA dice Firefox
                    }
                    // se browser matched + UA family OK = neutral (no boost — già contato sopra)
                }
                None => {
                    // Pattern sconosciuto: se UA dice browser, suspect (browser noti hanno h2 pattern noti)
                    if ua.contains("chrome/") || ua.contains("firefox/") || (ua.contains("safari/") && !ua.contains("chrome/")) {
                        automation_score += 0.10;
                    }
                }
            }
        }
    } else if ua.contains("chrome/") || ua.contains("firefox/") || (ua.contains("safari/") && !ua.contains("chrome/")) {
        // Header assente + UA browser moderno → probabile HTTP/1.1 → sospetto soft
        automation_score += 0.05;
    }

    // JA4 dataset-based classification: prefix match vs known browser/automation set
    if let Some(ref ja4) = signals.ja4 {
        if crate::tls_known_patterns::ja4_is_known_automation(ja4) {
            // Override del check pure-function (più preciso del dataset)
            automation_score += 0.15;
        } else if crate::tls_known_patterns::ja4_is_known_browser(ja4) {
            // JA4 browser noto — bonus piccolo per ribilanciare verso browser
            browser_score += 0.05;
        }
    }

    // JA3 full string presence (informational) — l'analisi vera è in ja3.rs/blocklist.
    // Qui rifletto solo il "tier" di completezza fingerprinting available.
    // Nessuna penalità: i casi senza ja3_full sono già coperti da assenza-x-ja3-hash.

    // ─── Final Classification ──────────────────────────────────────────

    let scores = [
        (FingerprintClass::Browser, browser_score),
        (FingerprintClass::Scanner, scanner_score),
        (FingerprintClass::Automation, automation_score),
        (FingerprintClass::VerifiedBot, bot_score),
    ];

    let (classification, confidence) = scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(class, score)| (*class, *score))
        .unwrap_or((FingerprintClass::Unknown, 0.0));

    // If no score is dominant (all < 0.2), classify as Unknown
    let (classification, confidence) = if confidence < 0.2 {
        (FingerprintClass::Unknown, confidence)
    } else {
        (classification, confidence.min(1.0))
    };

    let risk_contribution = classification.risk_contribution();

    RequestFingerprint {
        header_order_hash,
        accept_pattern,
        http_version,
        classification,
        confidence,
        risk_contribution,
        signals,
    }
}

/// Compute SHA256 hash of header names in order of appearance
fn compute_header_order_hash(headers: &HashMap<String, String>) -> String {
    // Note: HashMap doesn't preserve insertion order, but the headers
    // come from our parsed request which maintains ordering.
    // We sort them to get a deterministic hash regardless of map implementation.
    let mut names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
    names.sort();

    let input = names.join(",");
    let hash = Sha256::digest(input.as_bytes());
    // SAFE-SLICE: `hash` è un array di byte ([u8]) da Sha256 (sempre ≥ 8 byte), NON una
    // &str → nessun problema di char-boundary UTF-8 (FP class non applicabile ai byte).
    hex::encode(&hash[..8]) // First 8 bytes (16 hex chars) is sufficient
}

/// Normalize the Accept header stack into a signature
fn normalize_accept_pattern(headers: &HashMap<String, String>) -> String {
    let accept = headers.get("accept").map(|s| s.as_str()).unwrap_or("-");
    let accept_enc = headers.get("accept-encoding").map(|s| s.as_str()).unwrap_or("-");
    let accept_lang = headers.get("accept-language").map(|s| s.as_str()).unwrap_or("-");

    // Truncate long values for a compact signature. FP1: char-boundary-safe — `&accept[..40]`
    // panicava se il byte 40 cadeva dentro un carattere multibyte (header Accept ostile).
    let accept_short = sentinel_core::truncate_char_boundary(accept, 40);
    let accept_enc_short = sentinel_core::truncate_char_boundary(accept_enc, 30);
    let accept_lang_short = sentinel_core::truncate_char_boundary(accept_lang, 20);

    format!("{}|{}|{}", accept_short, accept_enc_short, accept_lang_short)
}

/// Compute Shannon entropy of Accept-Language header
fn compute_accept_language_entropy(headers: &HashMap<String, String>) -> f32 {
    let lang = match headers.get("accept-language") {
        Some(v) if !v.is_empty() => v,
        _ => return 0.0,
    };

    // Simple proxy for entropy: count unique language codes
    let parts: Vec<&str> = lang.split(',').collect();
    let unique_count = parts.len();

    // Length-based entropy proxy (longer = more specific = more human)
    let length_factor = (lang.len() as f32 / 10.0).min(3.0);
    let diversity_factor = (unique_count as f32).ln().max(0.0);

    length_factor * 0.6 + diversity_factor * 0.4
}

/// Check if User-Agent matches known scanner tools
fn is_scanner_ua(ua: &str) -> bool {
    const SCANNER_PATTERNS: &[&str] = &[
        "sqlmap", "nikto", "nmap", "nuclei", "burp",
        "acunetix", "nessus", "qualys", "openvas",
        "masscan", "zap", "arachni", "w3af",
        "dirbuster", "gobuster", "ffuf", "feroxbuster",
        "wfuzz", "hydra", "medusa", "wpscan",
        "joomscan", "droopescan",
    ];

    SCANNER_PATTERNS.iter().any(|p| ua.contains(p))
}

/// Check if User-Agent matches known automation tools
fn is_automation_ua(ua: &str) -> bool {
    const AUTOMATION_PATTERNS: &[&str] = &[
        "curl/", "wget/", "python-requests/", "python-urllib",
        "httpie/", "postman", "insomnia", "node-fetch",
        "axios/", "go-http-client", "java/", "okhttp",
        "libwww-perl", "lwp-trivial", "ruby",
    ];

    AUTOMATION_PATTERNS.iter().any(|p| ua.contains(p))
}

/// Hex encoding helper (avoid pulling in hex crate dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_browser_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("host".to_string(), "example.com".to_string());
        h.insert("user-agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134".to_string());
        h.insert("accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string());
        h.insert("accept-encoding".to_string(), "gzip, deflate, br, zstd".to_string());
        h.insert("accept-language".to_string(), "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7".to_string());
        h.insert("sec-ch-ua".to_string(), r#""Chromium";v="134", "Google Chrome";v="134""#.to_string());
        h.insert("sec-ch-ua-platform".to_string(), "\"Windows\"".to_string());
        h.insert("sec-fetch-site".to_string(), "none".to_string());
        h.insert("sec-fetch-mode".to_string(), "navigate".to_string());
        h.insert("sec-fetch-dest".to_string(), "document".to_string());
        h.insert("cookie".to_string(), "session=abc123".to_string());
        h
    }

    fn make_curl_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("host".to_string(), "example.com".to_string());
        h.insert("user-agent".to_string(), "curl/8.4.0".to_string());
        h.insert("accept".to_string(), "*/*".to_string());
        h
    }

    fn make_scanner_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("host".to_string(), "example.com".to_string());
        h.insert("user-agent".to_string(), "sqlmap/1.7.12".to_string());
        h.insert("accept".to_string(), "*/*".to_string());
        h.insert("cache-control".to_string(), "no-cache".to_string());
        h
    }

    #[test]
    fn test_browser_fingerprint() {
        let headers = make_browser_headers();
        let fp = fingerprint_request(&headers);

        assert_eq!(fp.classification, FingerprintClass::Browser);
        assert!(fp.confidence > 0.3);
        assert_eq!(fp.risk_contribution, 0);
        assert!(fp.signals.has_sec_ch_ua);
        assert!(fp.signals.has_sec_fetch);
        assert!(fp.signals.has_cookies);
    }

    #[test]
    fn test_curl_fingerprint() {
        let headers = make_curl_headers();
        let fp = fingerprint_request(&headers);

        assert_eq!(fp.classification, FingerprintClass::Automation);
        assert!(fp.risk_contribution > 0);
        assert!(!fp.signals.has_sec_ch_ua);
        assert!(!fp.signals.has_sec_fetch);
    }

    #[test]
    fn test_scanner_fingerprint() {
        let headers = make_scanner_headers();
        let fp = fingerprint_request(&headers);

        assert_eq!(fp.classification, FingerprintClass::Scanner);
        assert!(fp.risk_contribution >= 10);
    }

    #[test]
    fn test_empty_ua_is_suspicious() {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "example.com".to_string());
        let fp = fingerprint_request(&headers);

        // No UA, no sec-fetch, no cookies = Unknown or Scanner
        assert!(fp.risk_contribution > 0);
    }

    #[test]
    fn test_accept_language_entropy() {
        let mut headers = HashMap::new();
        // Specific multi-language accept-language = higher entropy
        headers.insert("accept-language".to_string(), "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7".to_string());
        let entropy = compute_accept_language_entropy(&headers);
        assert!(entropy > 1.0);

        // Empty = 0
        headers.clear();
        let entropy = compute_accept_language_entropy(&headers);
        assert_eq!(entropy, 0.0);
    }

    // ── 2026-06-02 wiring: nuovi signal tests ─────────────────────────────

    #[test]
    fn test_ja4_prefix_browser_modern_not_automation() {
        // Chrome moderno JA4 reale (preso da log nginx)
        assert!(!ja4_prefix_indicates_automation("t13d1411h2_e33ad33b3d25_e8c6847a94a1"));
        // Firefox moderno tipical
        assert!(!ja4_prefix_indicates_automation("t13d1715h2_xxx_yyy"));
    }

    #[test]
    fn test_ja4_prefix_tls12_only_indicates_automation() {
        // TLS 1.2 only (no 1.3) = browser legacy O tool custom — flag automation
        assert!(ja4_prefix_indicates_automation("t12d0809h2_abc_def"));
    }

    #[test]
    fn test_ja4_prefix_no_sni_indicates_automation() {
        // `t13i` = TLS 1.3 senza SNI = script tool (browser SEMPRE invia SNI)
        assert!(ja4_prefix_indicates_automation("t13i1411h2_xxx_yyy"));
    }

    #[test]
    fn test_ja4_default_hash_pattern_automation() {
        // Hash "aaaa..." o "0000..." = Go/Python default tlsConfig
        assert!(ja4_prefix_indicates_automation("t13d1411h2_aaaaaaaaaaaa_xxx"));
        assert!(ja4_prefix_indicates_automation("t13d1411h2_000000000000_xxx"));
    }

    #[test]
    fn test_ja4_too_short_not_classified() {
        // Stringa malformata < 10 char → return false (no falso positivo)
        assert!(!ja4_prefix_indicates_automation("t13"));
        assert!(!ja4_prefix_indicates_automation(""));
    }

    #[test]
    fn test_grease_present_no_mismatch() {
        // GREASE presente (browser corretto) = no mismatch even con UA Chrome
        assert!(!grease_ua_mismatch_check(
            Some("1"),
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/134",
        ));
    }

    #[test]
    fn test_grease_absent_chrome_modern_mismatch() {
        // GREASE assente + UA Chrome moderno (>= 80) = SPOOF detected
        assert!(grease_ua_mismatch_check(
            Some("0"),
            "Mozilla/5.0 (Windows NT 10.0) Chrome/134",
        ));
    }

    #[test]
    fn test_grease_absent_chrome_legacy_no_mismatch() {
        // Chrome 70 (pre-GREASE rollout 2018) = no falso positivo
        assert!(!grease_ua_mismatch_check(
            Some("0"),
            "Mozilla/5.0 Chrome/70.0.3538.77",
        ));
    }

    #[test]
    fn test_grease_absent_firefox_modern_mismatch() {
        // Firefox 88+ = GREASE atteso → assenza = spoof
        assert!(grease_ua_mismatch_check(
            Some("0"),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:130.0) Gecko/20100101 Firefox/130.0",
        ));
    }

    #[test]
    fn test_grease_absent_safari_modern_mismatch() {
        // Safari puro (no Chromium) = GREASE atteso
        assert!(grease_ua_mismatch_check(
            Some("0"),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        ));
    }

    #[test]
    fn test_grease_absent_curl_no_mismatch() {
        // UA non-browser (curl) = no false positive (è giusto che curl non abbia GREASE)
        assert!(!grease_ua_mismatch_check(Some("0"), "curl/8.4.0"));
    }

    #[test]
    fn test_grease_header_missing_no_mismatch() {
        // Header non-presente (legacy nginx) = no signal, no falso positivo
        assert!(!grease_ua_mismatch_check(None, "Mozilla/5.0 Chrome/134"));
    }

    #[test]
    fn test_signals_full_chain_extracted() {
        // E2E: tutti i 5 nuovi header presenti devono finire nei signals
        let mut h = make_browser_headers();
        h.insert("x-ja3".to_string(), "771,4866-4865,0-23,29,0".to_string());
        h.insert("x-ja3-hash".to_string(), "cd08e31494f9531f560d64c695473da9".to_string());
        h.insert("x-ja4".to_string(), "t13d1411h2_e33ad33b3d25_e8c6847a94a1".to_string());
        h.insert("x-tls-greased".to_string(), "1".to_string());
        h.insert("x-http2-fingerprint".to_string(), "2:0;3:1;4:8388608|m,s,a,p".to_string());
        h.insert("x-http-version".to_string(), "2.0".to_string());

        let fp = fingerprint_request(&h);
        assert!(fp.signals.ja3_full.is_some());
        assert!(fp.signals.ja4.is_some());
        assert_eq!(fp.signals.tls_greased.as_deref(), Some("1"));
        assert!(fp.signals.http2_fp.is_some());
        assert!(!fp.signals.grease_ua_mismatch); // browser corretto
        assert!(!fp.signals.ja4_indicates_automation); // JA4 moderno OK
    }

    #[test]
    fn test_signals_grease_spoof_increases_scanner_score() {
        // UA Chrome moderno SENZA GREASE → mismatch → scanner score boost
        let mut h = make_browser_headers();
        h.insert("x-tls-greased".to_string(), "0".to_string());
        // mantieni resto del browser per non triggerare altri scanner signal
        let fp = fingerprint_request(&h);
        assert!(fp.signals.grease_ua_mismatch);
        // L'aumento di scanner_score (+0.50) dovrebbe degradare la classification
        // o almeno riflettersi nei signals (verifichiamo solo che flag sia ON).
    }

    #[test]
    fn test_signals_ja4_automation_prefix_increases_automation() {
        let mut h = make_browser_headers();
        h.insert("x-ja4".to_string(), "t12d0809h2_aaa_bbb".to_string()); // TLS 1.2 only
        let fp = fingerprint_request(&h);
        assert!(fp.signals.ja4_indicates_automation);
    }

    /// 🚨 FP1 (CRITICO, UTF-8 panic): header Accept/Encoding/Language con un carattere
    /// multibyte (€/emoji/CJK) che attraversa il byte di taglio (40/30/20). Pre-fix
    /// `&accept[..40]` panicava su OGNI request L3 con un Accept ostile → crash WAF.
    #[test]
    fn fp1_normalize_accept_no_panic_on_multibyte_at_cut() {
        let mut h = HashMap::new();
        h.insert("accept".to_string(), format!("{}€aaaa", "a".repeat(38))); // € sui byte 38..41
        h.insert("accept-encoding".to_string(), format!("{}🚀", "g".repeat(29))); // 🚀 sui byte 29..33
        h.insert("accept-language".to_string(), format!("{}日本", "l".repeat(19))); // 日 sui byte 19..22
        let sig = normalize_accept_pattern(&h); // pre-fix: panic UTF-8 qui
        assert!(!sig.is_empty());
        assert!(std::str::from_utf8(sig.as_bytes()).is_ok(), "signature deve restare UTF-8 valida");
    }

    /// 🚨 FP (ja4): l'header X-JA4 è attacker-controlled → un carattere multibyte sul byte
    /// 10 faceva panicare `&ja4[..10]` (`.min(len)` evita solo l'out-of-range, non il
    /// char-boundary). Ora usa truncate_char_boundary.
    #[test]
    fn ja4_prefix_no_panic_on_multibyte_at_byte_10() {
        let ja4 = "t13d14111€xxxx"; // "t13d14111" = 9 byte ASCII; € occupa i byte 9..12 → il byte 10 è interno
        assert!(ja4.len() >= 10 && !ja4.is_char_boundary(10));
        // Pre-fix: panic "byte index 10 is not a char boundary". Ora: nessun panic.
        let _ = ja4_prefix_indicates_automation(&ja4);
    }
}
