#![allow(dead_code)]
//! Encoding Attack Detection
//!
//! Detects obfuscation attempts using encoding tricks:
//! - Base64 encoded payloads
//! - Unicode homoglyphs
//! - Invisible characters
//! - Control characters
//! - RTL override attacks

use regex::Regex;
use once_cell::sync::Lazy;

/// Types of encoding attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingAttack {
    /// Base64 encoded suspicious content
    Base64Obfuscation,
    /// Unicode characters that look like ASCII
    UnicodeHomoglyph,
    /// Zero-width or invisible characters
    InvisibleCharacters,
    /// Control characters in content
    ControlCharacters,
    /// Right-to-left override attacks
    RtlOverride,
}

/// Patterns for encoding detection
static BASE64_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Matches potential base64 strings (at least 20 chars, valid chars, multiple of 4 or with padding)
    Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap()
});

/// Known homoglyph characters (Unicode that looks like ASCII)
const HOMOGLYPHS: &[(char, char)] = &[
    ('А', 'A'), // Cyrillic
    ('В', 'B'),
    ('С', 'C'),
    ('Е', 'E'),
    ('Н', 'H'),
    ('І', 'I'),
    ('К', 'K'),
    ('М', 'M'),
    ('О', 'O'),
    ('Р', 'P'),
    ('Т', 'T'),
    ('Х', 'X'),
    ('а', 'a'),
    ('с', 'c'),
    ('е', 'e'),
    ('о', 'o'),
    ('р', 'p'),
    ('х', 'x'),
    ('у', 'y'),
    ('ѕ', 's'),
    ('і', 'i'),
    // Greek
    ('Α', 'A'),
    ('Β', 'B'),
    ('Ε', 'E'),
    ('Ζ', 'Z'),
    ('Η', 'H'),
    ('Ι', 'I'),
    ('Κ', 'K'),
    ('Μ', 'M'),
    ('Ν', 'N'),
    ('Ο', 'O'),
    ('Ρ', 'P'),
    ('Τ', 'T'),
    ('Υ', 'Y'),
    ('Χ', 'X'),
    ('ο', 'o'),
    ('ν', 'v'),
    // Math symbols
    ('ⅰ', 'i'),
    ('ⅴ', 'v'),
    ('ⅹ', 'x'),
    ('ℓ', 'l'),
    ('№', 'N'),
];

/// Invisible Unicode characters
const INVISIBLE_CHARS: &[char] = &[
    '\u{200B}', // Zero Width Space
    '\u{200C}', // Zero Width Non-Joiner
    '\u{200D}', // Zero Width Joiner
    '\u{2060}', // Word Joiner
    '\u{FEFF}', // Byte Order Mark / Zero Width No-Break Space
    '\u{00AD}', // Soft Hyphen
    '\u{034F}', // Combining Grapheme Joiner
    '\u{2061}', // Function Application
    '\u{2062}', // Invisible Times
    '\u{2063}', // Invisible Separator
    '\u{2064}', // Invisible Plus
    '\u{180E}', // Mongolian Vowel Separator
];

/// RTL override characters
const RTL_CHARS: &[char] = &[
    '\u{202A}', // Left-to-Right Embedding
    '\u{202B}', // Right-to-Left Embedding
    '\u{202C}', // Pop Directional Formatting
    '\u{202D}', // Left-to-Right Override
    '\u{202E}', // Right-to-Left Override
    '\u{2066}', // Left-to-Right Isolate
    '\u{2067}', // Right-to-Left Isolate
    '\u{2068}', // First Strong Isolate
    '\u{2069}', // Pop Directional Isolate
];

/// Encoding attack detector
pub struct EncodingDetector {
    /// Whether to decode and check base64
    check_base64_content: bool,
}

impl EncodingDetector {
    /// Create a new detector
    pub fn new() -> Self {
        Self {
            check_base64_content: true,
        }
    }

    /// Detect encoding attacks in content
    pub async fn detect(&self, content: &str) -> Vec<EncodingAttack> {
        let mut attacks = Vec::new();

        // Check for base64 obfuscation
        if self.detect_base64_obfuscation(content) {
            attacks.push(EncodingAttack::Base64Obfuscation);
        }

        // Check for homoglyphs
        if self.detect_homoglyphs(content) {
            attacks.push(EncodingAttack::UnicodeHomoglyph);
        }

        // Check for invisible characters
        if self.detect_invisible_chars(content) {
            attacks.push(EncodingAttack::InvisibleCharacters);
        }

        // Check for control characters
        if self.detect_control_chars(content) {
            attacks.push(EncodingAttack::ControlCharacters);
        }

        // Check for RTL override
        if self.detect_rtl_override(content) {
            attacks.push(EncodingAttack::RtlOverride);
        }

        attacks
    }

    /// Detect base64 obfuscated content
    fn detect_base64_obfuscation(&self, content: &str) -> bool {
        for capture in BASE64_PATTERN.find_iter(content) {
            let potential_b64 = capture.as_str();

            // Try to decode
            if let Ok(decoded) = base64_decode(potential_b64) {
                // Check if decoded content looks suspicious
                if self.is_suspicious_decoded(&decoded) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if decoded base64 content is suspicious
    fn is_suspicious_decoded(&self, decoded: &str) -> bool {
        let lower = decoded.to_lowercase();

        // Check for common injection patterns in decoded content
        lower.contains("ignore") && lower.contains("instruction")
            || lower.contains("system")
            || lower.contains("prompt")
            || lower.contains("<script")
            || lower.contains("javascript:")
            || lower.contains("eval(")
            || lower.contains("exec(")
    }

    /// Detect Unicode homoglyphs
    fn detect_homoglyphs(&self, content: &str) -> bool {
        for c in content.chars() {
            for (homoglyph, _) in HOMOGLYPHS {
                if c == *homoglyph {
                    return true;
                }
            }
        }
        false
    }

    /// Detect invisible characters
    fn detect_invisible_chars(&self, content: &str) -> bool {
        for c in content.chars() {
            if INVISIBLE_CHARS.contains(&c) {
                return true;
            }
        }
        false
    }

    /// Detect control characters (except common ones like tab, newline)
    fn detect_control_chars(&self, content: &str) -> bool {
        for c in content.chars() {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                return true;
            }
        }
        false
    }

    /// Detect RTL override attacks
    fn detect_rtl_override(&self, content: &str) -> bool {
        for c in content.chars() {
            if RTL_CHARS.contains(&c) {
                return true;
            }
        }
        false
    }

    /// Normalize content by removing encoding attacks
    pub fn normalize(&self, content: &str) -> String {
        let mut result = String::with_capacity(content.len());

        for c in content.chars() {
            // Skip invisible chars
            if INVISIBLE_CHARS.contains(&c) {
                continue;
            }

            // Skip RTL overrides
            if RTL_CHARS.contains(&c) {
                continue;
            }

            // Replace homoglyphs with ASCII equivalents
            let mut found_homoglyph = false;
            for (homoglyph, ascii) in HOMOGLYPHS {
                if c == *homoglyph {
                    result.push(*ascii);
                    found_homoglyph = true;
                    break;
                }
            }

            if !found_homoglyph {
                result.push(c);
            }
        }

        result
    }
}

impl Default for EncodingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple base64 decode helper
fn base64_decode(input: &str) -> Result<String, ()> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    STANDARD
        .decode(input)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clean_content() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("Hello, world!").await;
        assert!(attacks.is_empty());
    }

    #[tokio::test]
    async fn test_homoglyph_detection() {
        let detector = EncodingDetector::new();
        // Using Cyrillic 'а' which looks like ASCII 'a'
        let attacks = detector.detect("Hellо, wоrld!").await; // 'о' is Cyrillic
        assert!(attacks.contains(&EncodingAttack::UnicodeHomoglyph));
    }

    #[tokio::test]
    async fn test_invisible_char_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("Hello\u{200B}World").await;
        assert!(attacks.contains(&EncodingAttack::InvisibleCharacters));
    }

    #[tokio::test]
    async fn test_rtl_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("Hello\u{202E}World").await;
        assert!(attacks.contains(&EncodingAttack::RtlOverride));
    }

    #[tokio::test]
    async fn test_normalize() {
        let detector = EncodingDetector::new();

        // Content with invisible chars and homoglyphs
        let dirty = "Hеllo\u{200B}Wоrld"; // Cyrillic е and о, zero-width space
        let clean = detector.normalize(dirty);

        assert!(!clean.contains('\u{200B}'));
    }
}
