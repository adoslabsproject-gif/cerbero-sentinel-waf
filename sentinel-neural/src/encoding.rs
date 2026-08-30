//! Encoding Attack Detection
//!
//! Detects obfuscation attempts using encoding tricks:
//! - Base64 encoded payloads
//! - Unicode homoglyphs
//! - Invisible characters
//! - Control characters
//! - RTL override attacks
//! - URL encoding evasion (single + double)
//! - HTML entity encoding
//! - Null byte injection
//! - Overlong UTF-8
//! - Mixed encoding
//! - Comment insertion (SQL/JS)
//! - Case mutation with encoding

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
    /// URL encoding used to hide payload (e.g., %3Cscript%3E)
    UrlEncodedPayload,
    /// Double URL encoding (e.g., %253Cscript%253E)
    DoubleUrlEncoding,
    /// HTML entity encoding (e.g., &#60;script&#62;)
    HtmlEntityEncoding,
    /// Null byte injection (%00, \0)
    NullByteInjection,
    /// Overlong UTF-8 sequences (e.g., 0xC0 0xAF for '/')
    OverlongUtf8,
    /// Multiple encoding types combined
    MixedEncoding,
    /// Comment insertion to split keywords (e.g., SEL/**/ECT)
    CommentInsertion,
    /// Case mutation with encoding tricks
    CaseMutationEncoding,
}

/// Result of comprehensive normalization (ANALYSIS ONLY — never modifies original)
#[derive(Debug, Clone)]
pub struct NormalizedContent {
    /// Content normalized: URL decoded, HTML decoded, lowercase, whitespace collapsed
    pub normalized: String,
    /// Content with SQL/JS comments removed (separate version for pattern matching)
    pub comment_stripped: String,
    /// Flag: contained suspicious comments (/* */, --)
    pub had_comments: bool,
    /// Number of URL decoding levels needed (0=none, 2+=suspicious)
    pub url_decode_depth: u8,
}

/// Patterns for encoding detection
static BASE64_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap()
});

/// URL-encoded payload patterns (percent-encoded chars that form attack payloads)
static URL_ENCODED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(%3[cC]|%3[eE]|%22|%27|%28|%29|%2[fF]|%5[cC]|%0[aAdD])").unwrap()
});

/// Double URL encoding pattern
static DOUBLE_URL_ENCODED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)%25[0-9a-fA-F]{2}").unwrap()
});

/// HTML entity patterns (numeric + named)
static HTML_ENTITY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(&#x?[0-9a-fA-F]{1,6};|&(?:lt|gt|amp|quot|apos|tab|newline|sol|bsol|lpar|rpar|lcub|rcub);)").unwrap()
});

/// Null byte pattern
static NULL_BYTE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(%00|\\0|\\x00|\x00)").unwrap()
});

/// SQL/JS comment patterns (potential comment insertion attack: SEL/**/ECT)
static COMMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|/\*.*?\*/|--\s)").unwrap()
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

/// Named HTML entities to their character equivalents
const HTML_NAMED_ENTITIES: &[(&str, char)] = &[
    ("&lt;", '<'),
    ("&gt;", '>'),
    ("&amp;", '&'),
    ("&quot;", '"'),
    ("&apos;", '\''),
    ("&tab;", '\t'),
    ("&newline;", '\n'),
    ("&sol;", '/'),
    ("&bsol;", '\\'),
    ("&lpar;", '('),
    ("&rpar;", ')'),
    ("&lcub;", '{'),
    ("&rcub;", '}'),
];

/// Encoding attack detector
pub struct EncodingDetector {}

impl EncodingDetector {
    /// Create a new detector
    pub fn new() -> Self {
        Self {}
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

        // Check for URL encoded payloads
        if URL_ENCODED_PATTERN.is_match(content) {
            attacks.push(EncodingAttack::UrlEncodedPayload);
        }

        // Check for double URL encoding
        if DOUBLE_URL_ENCODED_PATTERN.is_match(content) {
            attacks.push(EncodingAttack::DoubleUrlEncoding);
        }

        // Check for HTML entity encoding
        if HTML_ENTITY_PATTERN.is_match(content) {
            attacks.push(EncodingAttack::HtmlEntityEncoding);
        }

        // Check for null bytes
        if NULL_BYTE_PATTERN.is_match(content) {
            attacks.push(EncodingAttack::NullByteInjection);
        }

        // Check for overlong UTF-8 (bytes that shouldn't appear in valid UTF-8)
        if self.detect_overlong_utf8(content) {
            attacks.push(EncodingAttack::OverlongUtf8);
        }

        // Check for comment insertion
        if COMMENT_PATTERN.is_match(content) {
            attacks.push(EncodingAttack::CommentInsertion);
        }

        // Mixed encoding: multiple encoding types detected simultaneously
        let encoding_count = [
            URL_ENCODED_PATTERN.is_match(content),
            HTML_ENTITY_PATTERN.is_match(content),
            self.detect_homoglyphs(content),
            DOUBLE_URL_ENCODED_PATTERN.is_match(content),
        ].iter().filter(|&&v| v).count();

        if encoding_count >= 2 {
            attacks.push(EncodingAttack::MixedEncoding);
        }

        attacks
    }

    /// Detect base64 obfuscated content
    fn detect_base64_obfuscation(&self, content: &str) -> bool {
        for capture in BASE64_PATTERN.find_iter(content) {
            let potential_b64 = capture.as_str();
            if let Ok(decoded) = base64_decode(potential_b64) {
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

    /// Detect overlong UTF-8 sequences.
    /// In Rust, strings are always valid UTF-8, but we can detect patterns that
    /// indicate someone tried to use overlong encoding (e.g., 0xC0 0xAF byte sequences
    /// in URL-encoded form: %c0%af for '/').
    fn detect_overlong_utf8(&self, content: &str) -> bool {
        // Check for URL-encoded overlong UTF-8 patterns
        // %c0%af = overlong encoding of '/' (U+002F)
        // %c0%ae = overlong encoding of '.' (U+002E)
        // %c1%9c = overlong encoding of '\' (U+005C)
        let lower = content.to_lowercase();
        lower.contains("%c0%af") || lower.contains("%c0%ae") || lower.contains("%c1%9c")
            || lower.contains("%c0%2f") || lower.contains("%e0%80%af")
    }

    /// Normalize content by removing encoding attacks (basic — invisible + homoglyphs)
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

    /// Comprehensive normalization pipeline (ANALYSIS ONLY — never modifies original request).
    ///
    /// Pipeline:
    /// 1. URL decode (iterative, max 3 levels — stops when result doesn't change)
    /// 2. HTML entity decode (&#60; → <, &#x3C; → <, &lt; → <)
    /// 3. Strip null bytes
    /// 4. Normalize Unicode (homoglyph replacement, invisible char removal)
    /// 5. Normalize whitespace (collapse tabs/newlines/multiple spaces)
    /// 6. Lowercase
    ///
    /// Also produces a `comment_stripped` version with SQL/JS comments removed.
    ///
    /// INVARIANT: This is ONLY for analysis. The original content is NEVER modified.
    pub fn normalize_comprehensive(&self, content: &str) -> NormalizedContent {
        // Step 1: Iterative URL decode
        let (url_decoded, url_decode_depth) = iterative_url_decode(content, 3);

        // Step 2: HTML entity decode
        let html_decoded = decode_html_entities(&url_decoded);

        // Step 3: Strip null bytes
        let null_stripped = html_decoded.replace('\0', "").replace("%00", "");

        // Step 4: Unicode normalization (homoglyphs + invisible chars)
        let unicode_normalized = self.normalize(&null_stripped);

        // Step 5: Normalize whitespace
        let whitespace_normalized = normalize_whitespace(&unicode_normalized);

        // Step 6: Lowercase
        let normalized = whitespace_normalized.to_lowercase();

        // Produce comment-stripped version (separate)
        let had_comments = COMMENT_PATTERN.is_match(&normalized);
        let comment_stripped = if had_comments {
            COMMENT_PATTERN.replace_all(&normalized, "").to_string()
        } else {
            normalized.clone()
        };

        NormalizedContent {
            normalized,
            comment_stripped,
            had_comments,
            url_decode_depth,
        }
    }
}

impl Default for EncodingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterative URL decode — converges when result stops changing.
/// Returns (decoded_string, depth).
/// Depth >= 2 → flag DoubleUrlEncoding.
fn iterative_url_decode(input: &str, max_depth: u8) -> (String, u8) {
    let mut current = input.to_string();
    let mut depth: u8 = 0;

    for _ in 0..max_depth {
        let decoded = percent_decode(&current);
        if decoded == current {
            break; // Converged — no encoding remaining
        }
        current = decoded;
        depth += 1;
    }

    (current, depth)
}

/// Simple percent-decode implementation
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                if byte.is_ascii() {
                    result.push(byte as char);
                    i += 3;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

/// Decode HTML entities (both numeric and named)
fn decode_html_entities(input: &str) -> String {
    let mut result = input.to_string();

    // Named entities
    for (entity, ch) in HTML_NAMED_ENTITIES {
        result = result.replace(entity, &ch.to_string());
        // Case-insensitive
        let upper = entity.to_uppercase();
        if upper != *entity {
            result = result.replace(&upper, &ch.to_string());
        }
    }

    // Numeric entities: &#60; (decimal) and &#x3C; (hex)
    // Process hex entities first
    let hex_re = Regex::new(r"&#x([0-9a-fA-F]{1,6});").unwrap();
    result = hex_re.replace_all(&result, |caps: &regex::Captures| {
        let hex = &caps[1];
        u32::from_str_radix(hex, 16)
            .ok()
            .and_then(char::from_u32)
            .map(|c| c.to_string())
            .unwrap_or_else(|| caps[0].to_string())
    }).to_string();

    // Decimal entities
    let dec_re = Regex::new(r"&#(\d{1,7});").unwrap();
    result = dec_re.replace_all(&result, |caps: &regex::Captures| {
        let num = &caps[1];
        num.parse::<u32>()
            .ok()
            .and_then(char::from_u32)
            .map(|c| c.to_string())
            .unwrap_or_else(|| caps[0].to_string())
    }).to_string();

    result
}

/// Collapse multiple whitespace characters (tabs, newlines, spaces) into single spaces
fn normalize_whitespace(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut last_was_space = false;

    for c in input.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                result.push(' ');
                last_was_space = true;
            }
        } else {
            result.push(c);
            last_was_space = false;
        }
    }

    result
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
    async fn test_url_encoded_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("%3Cscript%3Ealert(1)%3C/script%3E").await;
        assert!(attacks.contains(&EncodingAttack::UrlEncodedPayload));
    }

    #[tokio::test]
    async fn test_double_url_encoded_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("%253Cscript%253E").await;
        assert!(attacks.contains(&EncodingAttack::DoubleUrlEncoding));
    }

    #[tokio::test]
    async fn test_html_entity_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("&#60;script&#62;alert(1)&#60;/script&#62;").await;
        assert!(attacks.contains(&EncodingAttack::HtmlEntityEncoding));
    }

    #[tokio::test]
    async fn test_null_byte_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("test%00.php").await;
        assert!(attacks.contains(&EncodingAttack::NullByteInjection));
    }

    #[tokio::test]
    async fn test_comment_insertion_detection() {
        let detector = EncodingDetector::new();
        let attacks = detector.detect("SEL/**/ECT * FROM users").await;
        assert!(attacks.contains(&EncodingAttack::CommentInsertion));
    }

    #[tokio::test]
    async fn test_mixed_encoding() {
        let detector = EncodingDetector::new();
        // URL encoding + HTML entities
        let attacks = detector.detect("%3C&#115;cript%3E").await;
        assert!(attacks.contains(&EncodingAttack::MixedEncoding));
    }

    #[tokio::test]
    async fn test_normalize() {
        let detector = EncodingDetector::new();
        let dirty = "Hеllo\u{200B}Wоrld"; // Cyrillic е and о, zero-width space
        let clean = detector.normalize(dirty);
        assert!(!clean.contains('\u{200B}'));
    }

    #[test]
    fn test_normalize_comprehensive_url_decode() {
        let detector = EncodingDetector::new();
        let result = detector.normalize_comprehensive("%3Cscript%3Ealert(1)%3C/script%3E");
        assert!(result.normalized.contains("<script>alert(1)</script>"));
        assert_eq!(result.url_decode_depth, 1);
    }

    #[test]
    fn test_normalize_comprehensive_double_url() {
        let detector = EncodingDetector::new();
        let result = detector.normalize_comprehensive("%253Cscript%253E");
        assert!(result.normalized.contains("<script>"));
        assert_eq!(result.url_decode_depth, 2);
    }

    #[test]
    fn test_normalize_comprehensive_html_entities() {
        let detector = EncodingDetector::new();
        let result = detector.normalize_comprehensive("&#60;script&#62;");
        assert!(result.normalized.contains("<script>"));
    }

    #[test]
    fn test_normalize_comprehensive_comment_stripped() {
        let detector = EncodingDetector::new();
        let result = detector.normalize_comprehensive("SEL/**/ECT * FROM users");
        assert!(result.had_comments);
        assert!(result.comment_stripped.contains("select * from users"));
    }

    #[test]
    fn test_normalize_comprehensive_clean() {
        let detector = EncodingDetector::new();
        let result = detector.normalize_comprehensive("Hello World");
        assert_eq!(result.url_decode_depth, 0);
        assert!(!result.had_comments);
        assert_eq!(result.normalized, "hello world");
    }

    #[test]
    fn test_iterative_url_decode_convergence() {
        let (decoded, depth) = iterative_url_decode("hello%20world", 3);
        assert_eq!(decoded, "hello world");
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_html_entity_decode_numeric() {
        let result = decode_html_entities("&#60;div&#62;");
        assert_eq!(result, "<div>");
    }

    #[test]
    fn test_html_entity_decode_hex() {
        let result = decode_html_entities("&#x3C;div&#x3E;");
        assert_eq!(result, "<div>");
    }

    #[test]
    fn test_html_entity_decode_named() {
        let result = decode_html_entities("&lt;div&gt;");
        assert_eq!(result, "<div>");
    }
}
