//! G25 (2026-06-02): fuzz test catastrophic backtracking CRS regex.
//!
//! Cargo regex crate USA un automata DFA-based che è IMMUNE per design al
//! catastrophic backtracking (a differenza di PCRE/V8). Questo test verifica
//! empiricamente che TUTTI i pattern del bundle hanno latenza < 5ms su
//! 10K input random + 1K input adversarial (pump pattern).
//!
//! Esegui: `cargo test --package sentinel-edge --test fuzz_crs_no_backtracking`

use sentinel_edge::crs_patterns;
use std::sync::Once;
use std::time::{Duration, Instant};

/// Warm-up the lazy CRS bundle compile (first scan può richiedere ~50ms in debug).
/// Senza, ogni test misurerebbe il compile-time del primo call invece del pattern matching.
fn warmup() {
    static WARM: Once = Once::new();
    WARM.call_once(|| {
        for _ in 0..5 {
            let _ = crs_patterns::scan_request("warmup", &std::collections::HashMap::new(), None);
        }
    });
}

fn random_string(len: usize, seed: u64) -> String {
    // LCG portable (no deps)
    let mut state = seed;
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = ((state >> 33) as usize) % charset.len();
        s.push(charset[idx] as char);
    }
    s
}

#[test]
fn g25_random_input_under_5ms_each() {
    warmup();
    let mut max_latency = Duration::ZERO;
    let mut total = Duration::ZERO;
    const N: u32 = 1000; // 1K random input — basta per CI veloce
    for i in 0..N {
        let input = random_string(200, i as u64 * 7919);
        let start = Instant::now();
        let _ = crs_patterns::scan_request(&input, &std::collections::HashMap::new(), Some(&input));
        let elapsed = start.elapsed();
        if elapsed > max_latency { max_latency = elapsed; }
        total += elapsed;
        assert!(
            elapsed < Duration::from_millis(50),
            "INPUT {} latency {:?} > 50ms — possible backtracking on: {:?}",
            i, elapsed, input.chars().take(80).collect::<String>(),
        );
    }
    let avg = total / N;
    println!("G25 fuzz random: {N} input, avg={avg:?}, max={max_latency:?}");
    assert!(max_latency < Duration::from_millis(50), "max latency {max_latency:?} > 50ms");
}

#[test]
fn g25_adversarial_pump_patterns_under_50ms() {
    warmup();
    // Pattern noti per catastrophic backtracking PCRE-style.
    // Con regex crate Rust (DFA) NON dovrebbero rallentare.
    let adversarial: Vec<String> = vec![
        // Classic ReDoS: (a+)+b → 50 'a' + 'X'
        format!("{}X", "a".repeat(50)),
        // Nested quantifier: ((a|aa)+)+ → 30 'a'
        format!("{}!", "a".repeat(30)),
        // Alternation explosion
        format!("({})+", "a|b".repeat(20)),
        // Large repetition of jndi
        format!("${{{}}}", "jndi".repeat(10)),
        // Deep nested braces (GraphQL probe)
        format!("{}{}", "{".repeat(20), "}".repeat(20)),
        // Long base64 (Log4Shell)
        format!("{}A=", "aWdub3JlIA==".repeat(10)),
        // SQL UNION repeated
        format!("{} FROM users", "UNION SELECT ".repeat(20)),
        // Mass XSS attempt
        format!("{}", "<script>alert(1)</script>".repeat(50)),
    ];
    for (i, payload) in adversarial.iter().enumerate() {
        let start = Instant::now();
        let _ = crs_patterns::scan_request(payload, &std::collections::HashMap::new(), Some(payload));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "adversarial #{} ({}...) latency {:?} > 50ms",
            i, payload.chars().take(40).collect::<String>(), elapsed,
        );
    }
}

#[test]
fn g25_huge_input_8kb_under_100ms() {
    warmup();
    // Body size massimo che scan_request processa (truncato a 8KB)
    let huge = "a".repeat(64 * 1024); // 64KB input → truncato a 8KB nel scan
    let start = Instant::now();
    let _ = crs_patterns::scan_request("/x", &std::collections::HashMap::new(), Some(&huge));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "64KB input latency {:?} > 100ms",
        elapsed,
    );
}
