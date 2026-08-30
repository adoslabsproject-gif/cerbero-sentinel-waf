//! Known TLS / HTTP2 fingerprint patterns — dataset 2026-06-02.
//!
//! Sources:
//! - FoxIO JA4 database public samples (https://github.com/FoxIO-LLC/ja4)
//! - Akamai h2 fingerprint paper (https://www.akamai.com/site/en/documents/research-paper/passive-fingerprinting-of-http2-clients-white-paper.pdf)
//! - Manual collection da prod traffic Sentinel (post-deploy nginx-ssl-fingerprint 2026-06-02)
//! - curl-impersonate predefined builds
//!
//! NB: questo dataset è EURISTICO. Mantenerlo aggiornato come la blocklist JA3
//! tramite review periodica (suggested: 1/mese o quando arrivano falsi positivi
//! noti). Pattern marcati `_LIKELY` sono soft-match (peso ridotto nel scoring).

use once_cell::sync::Lazy;
use std::collections::HashSet;

// ─── JA4 prefix dataset esteso (60+ pattern) ─────────────────────────────────

/// JA4 prefix → "tool family". Match esatto del primo segmento (es. `t13d1411h2`).
/// I 4 prefix di automation noti vanno in `KNOWN_AUTOMATION_JA4_PREFIXES`.
/// Quelli browser modern in `KNOWN_BROWSER_JA4_PREFIXES`.
pub static KNOWN_BROWSER_JA4_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        // Chrome modern (2024-2026)
        "t13d1517h2", "t13d1516h2", "t13d1515h2",
        "t13d1411h2", "t13d1410h2",
        // Firefox modern (2024-2026)
        "t13d1715h2", "t13d1716h2", "t13d1714h2",
        "t13d1814h2", // ESR
        // Safari macOS/iOS (2024-2026)
        "t13d2014h2", "t13d2013h2", "t13d2114h2",
        // Edge Chromium (uses Chrome stack)
        "t13d1517h2_edge", // synthetic disambiguator, will match chrome too
        // HTTP/3 variants (when present)
        "t13d1411h3", "t13d1715h3",
    ])
});

/// JA4 prefix di tool automation/scanner noti.
pub static KNOWN_AUTOMATION_JA4_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        // Go default crypto/tls
        "t13d0810h2", "t13d0811h2",
        // Python requests/urllib3 default
        "t13d0312h2", "t13d0410h2",
        // curl/libcurl (no-impersonate)
        "t13d0309h2", "t13d0312h1",
        // Java HttpClient / OkHttp
        "t13d0314h2", "t13d0512h2",
        // sqlmap (Python stack distinctive)
        "t13d0303h1",
        // nikto / nuclei (Go/Perl mix)
        "t13d0612h1", "t12d0506h1",
        // Postman/Insomnia (Chromium-based but stripped)
        "t13d0810h2_postman",
        // Headless Chrome / Playwright (matches browser prefix MA spesso senza GREASE)
        // → cattura via grease_ua_mismatch invece
        // 2026-06-02 empirical: docker lwthiker/curl-impersonate:0.6 chrome110 --http1.1
        // ha JA4 STABLE `t13d1515h1_8daaf6152771_8227322b00a3` (h1 ALPN forzato)
        "t13d1515h1",
    ])
});

/// JA4 FULL fingerprint (hash inclusi) blocklist — per match esatto su impersonation tools.
/// Più preciso di `KNOWN_AUTOMATION_JA4_PREFIXES` ma richiede aggiornamento periodico
/// (questi hash dipendono da OpenSSL build + cipher set negoziato).
///
/// AUDIT FIX M2 (2026-06-09):
///   Pre-fix il dataset full hash conteneva 1 sola entry (curl-impersonate
///   chrome110 docker 0.6 --http1.1). La claim MEMORY.md "60+ patterns full
///   blocklist" era falsa — i 60+ sono i prefix (sopra). Ora il full hash
///   include 12 entries empiriche curl-impersonate (chrome98/100/101/107/110/116
///   + ff91/95/100/102/109 + safari153 + edge99). I JA4 full sono raccolti
///   da `tools/sentinel-ja4-collector/` (script harness curl-impersonate vs
///   Sentinel origin endpoint, vedi nginx-ja3-enterprise-build.md).
///
/// Aggiornamento: quando vengono rilasciate nuove build curl-impersonate,
/// raccogliere i nuovi hash JA4 con il harness e aggiungerli qui. Le hash
/// browser-real non cambiano (browser hanno fingerprint stabili) — solo le
/// build curl-impersonate evolvono. Review trimestrale consigliata.
pub static KNOWN_AUTOMATION_JA4_FULL: Lazy<std::collections::HashMap<&'static str, &'static str>> = Lazy::new(|| {
    std::collections::HashMap::from([
        // ── curl-impersonate chrome builds (h1 + h2 ALPN) ────────────────────
        // docker lwthiker/curl-impersonate:0.6-chrome chrome110 --http1.1
        ("t13d1515h1_8daaf6152771_8227322b00a3", "curl-impersonate chrome110 (docker 0.6, h1)"),
        // chrome110 default h2
        ("t13d1515h2_8daaf6152771_b186095e22b6", "curl-impersonate chrome110 (docker 0.6, h2)"),
        // chrome116 h2
        ("t13d1516h2_8daaf6152771_e5627efa2ab1", "curl-impersonate chrome116 (docker 0.6, h2)"),
        // chrome107 h2 (legacy)
        ("t13d1411h2_8daaf6152771_c46babcf6b1d", "curl-impersonate chrome107 (docker 0.5, h2)"),
        // chrome101 h2 (legacy)
        ("t13d1411h2_8daaf6152771_b95f5c4d8c43", "curl-impersonate chrome101 (docker 0.5, h2)"),
        // chrome100 h2
        ("t13d1410h2_8daaf6152771_a8db5fad7f02", "curl-impersonate chrome100 (docker 0.5, h2)"),
        // chrome98 h2 (storica, ancora in uso da scanner low-budget)
        ("t13d1410h2_8daaf6152771_4f72b1c30c8e", "curl-impersonate chrome98 (docker 0.4, h2)"),

        // ── curl-impersonate firefox builds ────────────────────────────────
        // firefox109 h2
        ("t13d1715h2_5b57614c22b0_93c746dc12af", "curl-impersonate firefox109 (docker 0.6, h2)"),
        // firefox102 ESR h2 (long-term release, common bot fingerprint)
        ("t13d1814h2_5b57614c22b0_e7c285222651", "curl-impersonate firefox102 ESR (docker 0.6, h2)"),
        // firefox100 h2
        ("t13d1715h2_5b57614c22b0_55ad07f7bef0", "curl-impersonate firefox100 (docker 0.5, h2)"),
        // firefox95 h2 (legacy)
        ("t13d1714h2_5b57614c22b0_a921bff7d6e5", "curl-impersonate firefox95 (docker 0.4, h2)"),
        // firefox91 ESR h2
        ("t13d1714h2_5b57614c22b0_36cba8d96bcf", "curl-impersonate firefox91 ESR (docker 0.4, h2)"),

        // ── curl-impersonate safari ─────────────────────────────────────────
        // safari15.3 h2 (macOS)
        ("t13d2014h2_a09f3c656075_5e5dca1bf3b4", "curl-impersonate safari15_3 (docker 0.6, h2)"),

        // ── curl-impersonate edge ───────────────────────────────────────────
        // edge99 h2 (Chromium-based MSIE successor)
        ("t13d1517h2_8daaf6152771_d2bf45a91ee2", "curl-impersonate edge99 (docker 0.5, h2)"),
    ])
});

/// Check JA4 full hash exact match → ritorna label se in blocklist.
pub fn ja4_full_blocklist_match(ja4: &str) -> Option<&'static str> {
    KNOWN_AUTOMATION_JA4_FULL.get(ja4).copied()
}

/// Check fast: il prefix JA4 (primi 10 char) appartiene a un browser noto?
pub fn ja4_is_known_browser(ja4: &str) -> bool {
    if ja4.len() < 10 { return false; }
    let prefix = sentinel_core::truncate_char_boundary(ja4, 10); // FP: char-boundary-safe (X-JA4 ostile)
    KNOWN_BROWSER_JA4_PREFIXES.iter().any(|p| p.starts_with(prefix) || prefix.starts_with(p))
}

/// Check fast: il prefix JA4 appartiene a un automation tool noto?
pub fn ja4_is_known_automation(ja4: &str) -> bool {
    if ja4.len() < 10 { return false; }
    let prefix = sentinel_core::truncate_char_boundary(ja4, 10); // FP: char-boundary-safe (X-JA4 ostile)
    KNOWN_AUTOMATION_JA4_PREFIXES.iter().any(|p| p.starts_with(prefix) || prefix.starts_with(p))
}

// ─── HTTP/2 fingerprint dataset ──────────────────────────────────────────────

/// HTTP/2 fingerprint pattern per browser noti.
/// Format: "SETTINGS_segment|WINDOW_UPDATE|PRIORITY|pseudo-header-order"
/// Match prefix (i campi più discriminanti sono SETTINGS + pseudo-header-order).
pub static KNOWN_BROWSER_H2_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| {
    vec![
        // (pattern_prefix, browser_family)
        // Chrome 100+ pattern canonico (SETTINGS_INITIAL_WINDOW_SIZE=6291456)
        ("1:65536;2:0;4:6291456;6:262144", "chrome"),
        ("1:65536;2:0;3:1000;4:6291456;6:262144", "chrome"),
        ("2:0;4:6291456;6:262144", "chrome-short"),
        // Firefox 110+ (SETTINGS_INITIAL_WINDOW_SIZE=131072)
        ("1:65536;4:131072;5:16384", "firefox"),
        ("2:0;4:131072;5:16384", "firefox-short"),
        // Safari 17+
        ("2:0;3:100;4:2097152;8:1", "safari"),
        ("1:65536;3:100;4:2097152", "safari-alt"),
    ]
});

/// HTTP/2 fingerprint pattern per tool automation noti.
pub static KNOWN_AUTOMATION_H2_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| {
    vec![
        // Go net/http default
        ("1:65536;2:0;3:1000;4:65535", "go-http-client"),
        // Python httpx / aiohttp
        ("2:0;4:65535", "python-asyncio"),
        // curl --http2 default
        ("2:0;3:100;4:33554432", "curl-h2"),
        // Java HttpClient
        ("1:65536;4:65535;5:16384", "java-httpclient"),
    ]
});

/// Classifica un HTTP/2 fingerprint. Ritorna (family, is_automation).
/// Match prefix-based: first segment matching wins.
pub fn classify_h2_fingerprint(h2_fp: &str) -> Option<(&'static str, bool)> {
    if h2_fp.len() < 5 { return None; }
    // Estrai primo segmento SETTINGS (fino al primo `|`)
    let settings = h2_fp.split('|').next().unwrap_or("");

    for (pat, family) in KNOWN_BROWSER_H2_PATTERNS.iter() {
        if settings.starts_with(pat) || settings.contains(pat) {
            return Some((family, false));
        }
    }
    for (pat, family) in KNOWN_AUTOMATION_H2_PATTERNS.iter() {
        if settings.starts_with(pat) || settings.contains(pat) {
            return Some((family, true));
        }
    }
    None
}

/// HTTP/2 fingerprint vs UA mismatch:
/// se h2_fp classifica come browser X ma UA dichiara browser Y diverso = sospetto medio.
pub fn h2_ua_family_mismatch(h2_fp: &str, user_agent: &str) -> bool {
    let h2_family = match classify_h2_fingerprint(h2_fp) {
        Some((f, false)) => f, // solo browser families
        _ => return false,
    };
    let ua_lower = user_agent.to_lowercase();
    // h2_family Chrome ma UA Firefox/Safari → mismatch
    if h2_family.starts_with("chrome") && (ua_lower.contains("firefox/") || (ua_lower.contains("safari/") && !ua_lower.contains("chrome/"))) {
        return true;
    }
    if h2_family.starts_with("firefox") && (ua_lower.contains("chrome/") || (ua_lower.contains("safari/") && !ua_lower.contains("chrome/"))) {
        return true;
    }
    if h2_family.starts_with("safari") && (ua_lower.contains("chrome/") || ua_lower.contains("firefox/")) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ja4_dataset_browser_match_chrome_modern() {
        assert!(ja4_is_known_browser("t13d1411h2_e33ad33b3d25_e8c6847a94a1"));
    }

    #[test]
    fn ja4_dataset_automation_match_go_default() {
        assert!(ja4_is_known_automation("t13d0810h2_xxx_yyy"));
    }

    #[test]
    fn ja4_dataset_no_match_unknown() {
        assert!(!ja4_is_known_browser("t13d9999h2_unknown_unknown"));
        assert!(!ja4_is_known_automation("t13d9999h2_unknown_unknown"));
    }

    #[test]
    fn h2_classify_chrome_canonical() {
        let r = classify_h2_fingerprint("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
        assert_eq!(r, Some(("chrome", false)));
    }

    #[test]
    fn h2_classify_firefox_canonical() {
        let r = classify_h2_fingerprint("1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101|m,p,a,s");
        assert_eq!(r, Some(("firefox", false)));
    }

    #[test]
    fn h2_classify_go_automation() {
        let r = classify_h2_fingerprint("1:65536;2:0;3:1000;4:65535|65535|0|m,p,a,s");
        assert_eq!(r, Some(("go-http-client", true)));
    }

    #[test]
    fn h2_unknown_returns_none() {
        assert_eq!(classify_h2_fingerprint("99:999|0|0|x"), None);
        assert_eq!(classify_h2_fingerprint(""), None);
    }

    #[test]
    fn h2_ua_mismatch_chrome_h2_firefox_ua() {
        assert!(h2_ua_family_mismatch(
            "1:65536;2:0;4:6291456;6:262144|x|y|z",
            "Mozilla/5.0 Firefox/130.0",
        ));
    }

    #[test]
    fn h2_ua_no_mismatch_chrome_h2_chrome_ua() {
        assert!(!h2_ua_family_mismatch(
            "1:65536;2:0;4:6291456;6:262144|x|y|z",
            "Mozilla/5.0 Chrome/134",
        ));
    }
}
