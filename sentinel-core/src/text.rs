//! Utility di troncamento stringhe SAFE per UTF-8 (anti-panic su input ostile).
//!
//! CLASSE DI PANIC (audit 2026-06-20, FP1/FP2/FP3): `&s[..N]` su una `&str` panica se il
//! byte `N` cade in MEZZO a un carattere multibyte (€, emoji, CJK…). La guardia di
//! lunghezza `if s.len() > N` NON basta: garantisce ≥N byte, non che N sia un confine di
//! carattere. Su input attacker-controlled (header Accept/User-Agent, request BODY) un
//! singolo carattere multibyte piazzato sul byte di taglio → crash del WAF su quella
//! richiesta. Regola: su input non-ASCII MAI `&s[..N]`, sempre [`truncate_char_boundary`].

/// Tronca `s` ad AL PIÙ `max_bytes`, sempre su un confine di carattere UTF-8 (MAI panic).
///
/// - `s.len() <= max_bytes` → ritorna `s` intero.
/// - altrimenti retrocede dal `max_bytes` al più grande confine di carattere ≤ `max_bytes`
///   (può essere `""` se il primo carattere è più largo di `max_bytes`).
///
/// Garanzia: l'output è sempre UTF-8 valido, `output.len() <= max_bytes`, è un PREFISSO di
/// `s`, e la funzione non panica per nessun input.
#[must_use]
pub fn truncate_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    // is_char_boundary(0) è sempre true → il loop termina sempre.
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Un singolo passo di decodifica percent-encoding (`%XX` → byte). Le sequenze `%XX`
/// malformate (non-hex, o `%` a fine stringa) restano LETTERALI. NON tocca `+` (nel path
/// è un carattere literal, non spazio). I byte risultanti possono non essere UTF-8 validi
/// → `from_utf8_lossy` (per il match regex anti-evasion va benissimo).
fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodifica percent-encoding iterativamente fino a `max_depth` passi, fermandosi quando
/// non cambia più (cattura il DOPPIO-encoding `%253C` → `%3C` → `<`). Anti-evasion del WAF:
/// un payload `%3Cscript%3E` passa il match CRS sul path RAW ma viene decodificato a valle
/// (Hono/Node) ed eseguito → il CRS deve scansionare anche la forma decodificata.
///
/// PURA, mai panic, depth-cap per evitare lavoro illimitato su input ostile.
#[must_use]
pub fn percent_decode_iterative(input: &str, max_depth: u8) -> String {
    // Fast-path: nessun '%' → nulla da decodificare (evita allocazioni sul caso comune).
    if !input.as_bytes().contains(&b'%') {
        return input.to_string();
    }
    let mut cur = input.to_string();
    for _ in 0..max_depth {
        let next = percent_decode_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_truncates_exactly() {
        assert_eq!(truncate_char_boundary("hello world", 5), "hello");
    }

    #[test]
    fn shorter_than_max_returns_whole() {
        assert_eq!(truncate_char_boundary("hi", 40), "hi");
        assert_eq!(truncate_char_boundary("", 10), "");
        assert_eq!(truncate_char_boundary("exact", 5), "exact");
    }

    #[test]
    fn max_zero_returns_empty() {
        assert_eq!(truncate_char_boundary("anything", 0), "");
    }

    /// 🚨 FP1/FP2/FP3 — il taglio cade in MEZZO a un carattere multibyte: `&s[..N]`
    /// panicherebbe; qui retrocede al boundary. "a€b": a=1B, €=3B (byte 1..4), b=1B.
    #[test]
    fn mid_multibyte_retreats_to_boundary_euro() {
        let s = "a€b"; // 5 byte
        assert_eq!(s.len(), 5);
        assert_eq!(truncate_char_boundary(s, 2), "a"); // byte 2 è dentro €
        assert_eq!(truncate_char_boundary(s, 3), "a"); // byte 3 è dentro €
        assert_eq!(truncate_char_boundary(s, 4), "a€"); // byte 4 = boundary dopo €
    }

    #[test]
    fn mid_emoji_retreats() {
        let s = "x🚀"; // x=1B, 🚀=4B → 5 byte
        assert_eq!(truncate_char_boundary(s, 2), "x"); // mid-emoji
        assert_eq!(truncate_char_boundary(s, 3), "x");
        assert_eq!(truncate_char_boundary(s, 4), "x");
        assert_eq!(truncate_char_boundary(s, 5), "x🚀");
    }

    #[test]
    fn first_char_wider_than_max_returns_empty() {
        assert_eq!(truncate_char_boundary("€uro", 2), ""); // € (3B) > max 2 → ""
    }

    /// Caso FP2 reale: N byte ASCII + un multibyte ESATTAMENTE sul cap → no panic, ≤ cap,
    /// UTF-8 valido. (Pre-fix: &b[..8192] panicava.)
    #[test]
    fn multibyte_exactly_at_cap_no_panic() {
        let cap = 8192;
        let mut body = "a".repeat(cap - 1); // 8191 byte ASCII
        body.push('€'); // € (3B) inizia al byte 8191, attraversa il byte 8192
        assert!(body.len() > cap);
        let out = truncate_char_boundary(&body, cap);
        assert!(out.len() <= cap, "deve rispettare il cap");
        assert!(std::str::from_utf8(out.as_bytes()).is_ok(), "deve essere UTF-8 valido");
        assert_eq!(out.len(), cap - 1, "retrocede al boundary prima del €");
    }

    /// Fuzz leggero: per ogni offset di taglio su una stringa mista, MAI panic + invarianti.
    #[test]
    fn never_panics_across_all_cut_points() {
        let s = "ASCII-€-🚀-日本語-end";
        for n in 0..=s.len() + 5 {
            let out = truncate_char_boundary(s, n);
            assert!(out.len() <= n.min(s.len()) || n >= s.len());
            assert!(s.starts_with(out), "deve essere un prefisso");
            assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        }
    }

    // ── percent_decode_iterative (anti-evasion CRS) ──────────────────────────
    #[test]
    fn decode_plain_passthrough_no_percent() {
        assert_eq!(percent_decode_iterative("/api/login", 3), "/api/login");
        assert_eq!(percent_decode_iterative("", 3), "");
    }

    #[test]
    fn decode_single_level_xss_payload() {
        // %3Cscript%3E → <script>  (il bypass del finding)
        assert_eq!(percent_decode_iterative("%3Cscript%3E", 3), "<script>");
        assert_eq!(percent_decode_iterative("/q=%27%20OR%201%3D1", 3), "/q=' OR 1=1");
    }

    #[test]
    fn decode_double_encoding_is_caught() {
        // %253C → %3C → <  (richiede >= 2 passi; depth-cap 3 lo prende)
        assert_eq!(percent_decode_iterative("%253Cscript%253E", 3), "<script>");
    }

    #[test]
    fn decode_depth_cap_is_respected() {
        // con depth 1, il doppio-encoding resta a metà (%3C), non esplode né cicla.
        assert_eq!(percent_decode_iterative("%253C", 1), "%3C");
    }

    #[test]
    fn decode_malformed_sequences_stay_literal() {
        assert_eq!(percent_decode_iterative("%zz", 3), "%zz"); // non-hex
        assert_eq!(percent_decode_iterative("100%", 3), "100%"); // % a fine stringa
        assert_eq!(percent_decode_iterative("%3", 3), "%3"); // troncata
        assert_eq!(percent_decode_iterative("a%2", 3), "a%2");
    }

    #[test]
    fn decode_does_not_touch_plus() {
        // '+' nel path è literal, NON spazio (a differenza della query) → non lo tocchiamo.
        assert_eq!(percent_decode_iterative("a+b", 3), "a+b");
    }

    #[test]
    fn decode_never_panics_on_hostile_input() {
        for s in ["%", "%%%%", "%c0%af", "%FF%FE", "%00", "/%2e%2e/%2e%2e/etc/passwd"] {
            let _ = percent_decode_iterative(s, 3); // no panic
        }
        // %2e%2e → .. (path traversal in forma encodata)
        assert_eq!(percent_decode_iterative("%2e%2e/", 3), "../");
    }
}
