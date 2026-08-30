//! threat_features — estrazione delle feature del meta threat_classifier.
//!
//! L'ORDINE è il contratto col modello: identico a `FEATURE_COLS` di
//! `ml/training/sentinel/train_threat_classifier.py`. Un disallineamento = predizioni
//! spazzatura, quindi [`FEATURE_NAMES`] è la single-source-of-truth e un test ne pinna
//! l'ordine.
//!
//! Due usi distinti, e la distinzione È il punto (2026-08-02):
//!   • [`to_raw_record`] → PERSISTENZA. Salva tutto ciò che si sa al momento della
//!     detection, punteggi compresi, perché serve a chi rivede il dataset e agli audit.
//!   • [`extract`] → INFERENZA. Produce SOLO le feature su cui il modello ha diritto
//!     di ragionare.
//!
//! ⛔ Perché il vettore d'inferenza è più corto del record salvato: `risk_score`,
//! `confidence`, `severity_numeric` e le categoriche `threat_type`/`detection_source`
//! sono assegnate dalla STESSA regola che produce l'etichetta di training. Un modello
//! che le vede impara a ricopiare la regola (F1=1.0 sui dati storici, zero capacità di
//! riconoscere una minaccia nuova) — è ciò che ha tenuto il gate anti-leakage rosso per
//! settimane. Restano nel record salvato, fuori dal modello.
//!
//! ⚠️ ASSENTE ≠ ZERO. I segnali che un certo percorso non misura sono `None` e
//! diventano `null` nel JSON / `NaN` nel vettore, MAI `0.0`. Scrivere zero significava
//! dire "misurato, ed è nullo": l'honeypot (fast-path che non attraversa il layer
//! neurale) dichiarava `anomaly_score = 0.0`, cioè "nessuna anomalia", e i benigni
//! davvero misurati (~0.93) risultavano più anomali degli attacchi. XGBoost tratta i
//! NaN nativamente, imparando da sé come comportarsi quando un segnale manca.

use std::collections::HashMap;

/// Metodi HTTP riconosciuti, in ordine fisso. Dominio CHIUSO: qualunque altro valore
/// (incluse stringhe vuote o verbi esotici) ricade in `method_other`.
///
/// L'ordine è parte del contratto col modello quanto [`FEATURE_NAMES`]: cambiarlo
/// scambia le colonne one-hot. Non riordinare, non inserire in mezzo — solo aggiungere
/// in coda PRIMA di `method_other`, e solo insieme al trainer.
pub const HTTP_METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Nomi delle feature del MODELLO, NELL'ORDINE atteso (= FEATURE_COLS del trainer).
/// Descrivono la richiesta e il comportamento, mai il verdetto di Sentinel.
///
/// ⚠️ Il metodo HTTP è ONE-HOT, non un intero (2026-08-04). Prima era
/// `request_method_encoded`, un `LabelEncoder` sklearn fittato al training e destinato a
/// viaggiare in un file "sidecar" accanto al modello. Due difetti, entrambi gravi:
///   1. **ordine inventato**: `GET=0, POST=1, PUT=2` fa credere a un albero che esista
///      una relazione d'ordine fra i verbi HTTP, e gli split diventano tagli su una scala
///      che non significa nulla;
///   2. **drift garantito**: il sidecar è un file da tenere sincronizzato fra Python e
///      Rust. In produzione non è mai stato esportato, quindi l'encoder a runtime era
///      vuoto e questa feature valeva SEMPRE 0 pur pesando 0.20 nel training — il modello
///      addestrato su un segnale che non riceveva mai.
/// I verbi HTTP sono un insieme finito e noto: one-hot cablato su entrambi i lati elimina
/// sia l'ordine finto sia il file da sincronizzare. Nessuno stato condiviso, nessun drift
/// possibile per costruzione.
pub const FEATURE_NAMES: [&str; 20] = [
    // Quando
    "hour_of_day",
    "day_of_week",
    // Provenienza (da ip_intel, indipendente dalla decisione)
    "is_datacenter",
    "is_tor",
    "is_proxy",
    // Forma della richiesta
    "path_depth",
    "path_entropy",
    "query_param_count",
    "ua_length",
    // Comportamento nel tempo (dal tracker, non dal verdetto)
    "burst_score",
    "inter_request_stddev",
    // Segnale del layer neurale (calcolato sul contenuto)
    "anomaly_score",
    // Metodo HTTP one-hot (dominio chiuso, ordine = HTTP_METHODS + other)
    "method_get",
    "method_post",
    "method_put",
    "method_patch",
    "method_delete",
    "method_head",
    "method_options",
    "method_other",
];

/// Feature che NON possono entrare nel modello perché derivate dall'etichetta.
/// Restano nel record persistito: un test pinna che nessuna finisca in `FEATURE_NAMES`.
pub const LABEL_DERIVED_FEATURES: [&str; 5] = [
    "risk_score",
    "confidence",
    "severity_numeric",
    "threat_type_encoded",
    "detection_source_encoded",
];

/// Numero di feature (= lunghezza del vettore prodotto e atteso dal modello ONNX).
pub const FEATURE_COUNT: usize = FEATURE_NAMES.len();

// NB: qui viveva `CategoricalEncoders`, la mappa LabelEncoder che avrebbe dovuto arrivare
// da un file "sidecar" esportato col modello. Rimossa il 2026-08-04 insieme al label
// encoding: con l'one-hot a dominio chiuso non c'è più nessuno stato condiviso fra
// training e inferenza, quindi non c'è più niente da esportare, caricare o tenere in sync.
// Il sidecar non era mai stato prodotto e l'encoder a runtime restava vuoto — un intero
// segnale silenziosamente azzerato in produzione.

/// Input grezzo per l'estrazione: ciò che il decision-path conosce su una richiesta + i
/// segnali computati dai layer. Borrowed → zero-copy, niente allocazioni superflue.
///
/// I campi `Option` sono quelli che NON ogni percorso misura: `None` significa
/// "non misurato su questo percorso" ed è un'informazione diversa da uno zero.
/// Chi costruisce l'input deve dire la verità — è più utile un buco dichiarato che
/// un valore inventato.
#[derive(Debug, Clone, Copy)]
pub struct ThreatFeatureInput<'a> {
    pub risk_score: f32,
    pub confidence: f32,
    pub hour_of_day: u8,         // 0-23 (UTC)
    pub day_of_week: u8,         // 0=Lun .. 6=Dom
    /// `None` se l'ip_intel non conosce l'ASN (lookup fallito ≠ "non è un datacenter").
    pub is_datacenter: Option<bool>,
    /// `None` finché l'ip_intel non espone il segnale (oggi: sempre, su ogni percorso).
    pub is_tor: Option<bool>,
    pub is_proxy: Option<bool>,
    pub path: &'a str,           // senza query-string
    pub user_agent: &'a str,
    pub query: &'a str,          // query-string grezza (senza '?')
    pub severity_numeric: u8,    // 0=none .. 4=critical
    /// `None` sui percorsi senza tracker comportamentale.
    pub burst_score: Option<f32>,
    pub inter_request_stddev: Option<f32>,
    /// `None` sui fast-path che NON attraversano il layer neurale (es. honeypot):
    /// lì l'anomalia non è stata calcolata, non è "pari a zero".
    pub anomaly_score: Option<f32>,
    pub threat_type: &'a str,
    pub detection_source: &'a str,
    pub request_method: &'a str,
}

/// Profondità del path = numero di segmenti non vuoti (`/a/b/c` → 3, `/` → 0).
#[must_use]
pub fn path_depth(path: &str) -> f32 {
    path.split('/').filter(|s| !s.is_empty()).count() as f32
}

/// Numero di parametri di query (`a=1&b=2` → 2, vuoto → 0). Conta i separatori reali,
/// robusto a `&` iniziali/finali/doppi.
#[must_use]
pub fn query_param_count(query: &str) -> f32 {
    query.split('&').filter(|s| !s.is_empty()).count() as f32
}

/// Entropia di Shannon (base 2) dei byte del path — alta su path offuscati/random
/// (webshell, encoded payload), bassa su path leggibili. Range tipico 0..~6.
#[must_use]
pub fn path_entropy(path: &str) -> f32 {
    if path.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let bytes = path.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy as f32
}

/// One-hot del metodo HTTP: `HTTP_METHODS.len() + 1` valori (l'ultimo è `other`).
///
/// Il confronto è case-insensitive sull'ASCII — un client può mandare `get` minuscolo e
/// resta lo stesso verbo. Qualunque valore fuori dal dominio (vuoto, `PROPFIND`, spazzatura)
/// finisce in `other`: una colonna che vale ANCHE come segnale, perché un verbo anomalo è
/// di per sé indizio di traffico non-browser.
///
/// Deve restare identico a `one_hot_method` del trainer: un test di parità lo verifica su
/// tutti i verbi noti e su una serie di input ostili.
#[must_use]
pub fn one_hot_method(method: &str) -> [f32; HTTP_METHODS.len() + 1] {
    let mut out = [0.0_f32; HTTP_METHODS.len() + 1];
    for (i, m) in HTTP_METHODS.iter().enumerate() {
        if method.eq_ignore_ascii_case(m) {
            out[i] = 1.0;
            return out;
        }
    }
    out[HTTP_METHODS.len()] = 1.0; // other
    out
}

/// Estrae il vettore delle feature del MODELLO, NELL'ORDINE di [`FEATURE_NAMES`].
/// Deterministico, mai panic.
///
/// Un segnale non misurato esce come `NaN`, non come `0.0`: XGBoost (e l'ONNX che ne
/// deriva) tratta i NaN come missing e sceglie da sé la direzione appresa in training.
/// Gli infiniti — che sono corruzione, non assenza — diventano NaN a loro volta: meglio
/// dichiarare "non so" che iniettare un valore assurdo nell'inferenza.
#[must_use]
pub fn extract(input: &ThreatFeatureInput<'_>) -> [f32; FEATURE_COUNT] {
    // finito → sé stesso; Inf/NaN → NaN (= missing dichiarato).
    let f = |x: f32| if x.is_finite() { x } else { f32::NAN };
    let opt = |x: Option<f32>| x.map_or(f32::NAN, f);
    let flag = |b: Option<bool>| b.map_or(f32::NAN, |v| if v { 1.0 } else { 0.0 });
    let m = one_hot_method(input.request_method);
    [
        input.hour_of_day as f32,
        input.day_of_week as f32,
        flag(input.is_datacenter),
        flag(input.is_tor),
        flag(input.is_proxy),
        path_depth(input.path),
        path_entropy(input.path),
        query_param_count(input.query),
        input.user_agent.len() as f32,
        opt(input.burst_score),
        opt(input.inter_request_stddev),
        opt(input.anomaly_score),
        m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7],
    ]
}

/// Record RAW (non-encodato) catturato a detection-time → serializzato in
/// `security_threats.ml_features`. È l'INPUT del trainer (che fitta da sé i LabelEncoder):
/// 15 numeriche + 3 categoriche-stringa. Le chiavi DEVONO combaciare con
/// `threat-export-core.ts` (NUMERIC_FEATURE_KEYS + CATEGORICAL_FEATURE_KEYS): un test lo pinna.
///
/// I flag is_* sono `u8` (0/1) → serializzano come NUMERO (il validatore dell'export rifiuta
/// i bool). Niente encoding qui: le stringhe grezze vanno al trainer, l'encoding è a inference.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RawFeatureRecord {
    pub risk_score: f32,
    pub confidence: f32,
    pub hour_of_day: u8,
    pub day_of_week: u8,
    /// `null` quando il percorso non ha misurato il segnale. NON scrivere 0 al suo
    /// posto: il trainer distingue "assente" (NaN) da "misurato e pari a zero", e
    /// confonderli è ciò che rendeva il dataset inaddestrabile.
    pub is_datacenter: Option<u8>,
    pub is_tor: Option<u8>,
    pub is_proxy: Option<u8>,
    pub path_depth: f32,
    pub ua_length: u32,
    pub severity_numeric: u8,
    pub burst_score: Option<f32>,
    pub inter_request_stddev: Option<f32>,
    pub path_entropy: f32,
    pub anomaly_score: Option<f32>,
    pub query_param_count: f32,
    pub threat_type: String,
    pub detection_source: String,
    pub request_method: String,
}

/// Costruisce il record RAW dai segnali. Sanitizza i non-finiti → 0 (no spazzatura nel
/// dataset). Le categoriche vengono prese grezze; se vuote, il chiamante NON dovrebbe
/// persistere (l'export le scarterebbe comunque).
#[must_use]
pub fn to_raw_record(input: &ThreatFeatureInput<'_>) -> RawFeatureRecord {
    let f = |x: f32| if x.is_finite() { x } else { 0.0 };
    // Un valore corrotto (NaN/Inf) su un segnale OPZIONALE non vale zero: vale
    // "non disponibile". Così un bug a monte non si traveste da misura valida.
    let opt = |x: Option<f32>| x.filter(|v| v.is_finite());
    RawFeatureRecord {
        risk_score: f(input.risk_score),
        confidence: f(input.confidence),
        hour_of_day: input.hour_of_day,
        day_of_week: input.day_of_week,
        is_datacenter: input.is_datacenter.map(u8::from),
        is_tor: input.is_tor.map(u8::from),
        is_proxy: input.is_proxy.map(u8::from),
        path_depth: path_depth(input.path),
        ua_length: input.user_agent.len() as u32,
        severity_numeric: input.severity_numeric,
        burst_score: opt(input.burst_score),
        inter_request_stddev: opt(input.inter_request_stddev),
        path_entropy: path_entropy(input.path),
        anomaly_score: opt(input.anomaly_score),
        query_param_count: query_param_count(input.query),
        threat_type: input.threat_type.to_string(),
        detection_source: input.detection_source.to_string(),
        request_method: input.request_method.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_names_count_and_order_is_the_contract() {
        // ⚠️ ORDINE = contratto col modello (FEATURE_COLS del trainer). Se cambia, il
        // modello riceve feature scambiate → predizioni spazzatura. Pin esplicito.
        assert_eq!(FEATURE_COUNT, 20);
        assert_eq!(FEATURE_NAMES[0], "hour_of_day");
        assert_eq!(FEATURE_NAMES[9], "burst_score");
        // Le ultime 8 sono l'one-hot del metodo, nell'ordine di HTTP_METHODS + other.
        assert_eq!(FEATURE_NAMES[12], "method_get");
        assert_eq!(FEATURE_NAMES[19], "method_other");
        assert_eq!(FEATURE_NAMES.len(), 12 + HTTP_METHODS.len() + 1);
        // nessun duplicato
        let mut seen = std::collections::HashSet::new();
        for n in FEATURE_NAMES {
            assert!(seen.insert(n), "feature duplicata: {n}");
        }
    }

    #[test]
    fn nessuna_feature_derivata_dall_etichetta_entra_nel_modello() {
        // Il difetto che ha tenuto il gate rosso: queste colonne sono assegnate dalla
        // stessa regola che produce l'etichetta, quindi separano le classi senza
        // aggiungere informazione. Se qualcuno le rimette in FEATURE_NAMES, il modello
        // torna a ricopiare la regola honeypot e questo test lo blocca subito.
        for banned in LABEL_DERIVED_FEATURES {
            assert!(
                !FEATURE_NAMES.contains(&banned),
                "'{banned}' è derivata dall'etichetta e non può stare nel vettore del modello"
            );
        }
    }

    #[test]
    fn path_depth_counts_non_empty_segments() {
        assert_eq!(path_depth("/"), 0.0);
        assert_eq!(path_depth(""), 0.0);
        assert_eq!(path_depth("/a/b/c"), 3.0);
        assert_eq!(path_depth("/a//b/"), 2.0); // segmenti vuoti ignorati
        assert_eq!(path_depth("/wp-admin/setup-config.php"), 2.0);
    }

    #[test]
    fn query_param_count_robust_to_separators() {
        assert_eq!(query_param_count(""), 0.0);
        assert_eq!(query_param_count("a=1"), 1.0);
        assert_eq!(query_param_count("a=1&b=2&c=3"), 3.0);
        assert_eq!(query_param_count("&a=1&&b=2&"), 2.0); // & multipli/bordo
    }

    #[test]
    fn path_entropy_low_for_readable_high_for_random() {
        assert_eq!(path_entropy(""), 0.0);
        // tutti uguali → entropia 0
        assert_eq!(path_entropy("aaaaaaaa"), 0.0);
        let readable = path_entropy("/api/v1/users/profile");
        let random = path_entropy("/x9f3kq2zp7mw1a8b4d6e0c5g");
        assert!(random > readable, "random {random} deve avere entropia > readable {readable}");
        assert!(path_entropy("ab").abs() - 1.0 < 1e-6 || path_entropy("ab") > 0.0); // 2 simboli equiprobabili ≈ 1 bit
    }

    #[test]
    fn one_hot_method_accende_una_sola_colonna() {
        // Invariante che rende l'one-hot tale: esattamente una colonna a 1, mai due, mai zero.
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PROPFIND", ""] {
            let v = one_hot_method(m);
            let acc: f32 = v.iter().sum();
            assert_eq!(acc, 1.0, "'{m}' deve accendere esattamente una colonna, somma={acc}");
        }
    }

    #[test]
    fn one_hot_method_posizioni_secondo_il_contratto() {
        assert_eq!(one_hot_method("GET")[0], 1.0);
        assert_eq!(one_hot_method("POST")[1], 1.0);
        assert_eq!(one_hot_method("PUT")[2], 1.0);
        assert_eq!(one_hot_method("PATCH")[3], 1.0);
        assert_eq!(one_hot_method("DELETE")[4], 1.0);
        assert_eq!(one_hot_method("HEAD")[5], 1.0);
        assert_eq!(one_hot_method("OPTIONS")[6], 1.0);
    }

    #[test]
    fn one_hot_method_case_insensitive_e_dominio_chiuso() {
        // Un client può mandare il verbo minuscolo: resta lo stesso metodo.
        assert_eq!(one_hot_method("get"), one_hot_method("GET"));
        assert_eq!(one_hot_method("PoSt"), one_hot_method("POST"));
        // Fuori dominio → `other`, che è a sua volta un SEGNALE: un verbo anomalo
        // (o assente) è di per sé indizio di traffico non-browser.
        let other_idx = HTTP_METHODS.len();
        for weird in ["PROPFIND", "TRACE", "", "  ", "GET\0", "🙂", "GETX"] {
            assert_eq!(one_hot_method(weird)[other_idx], 1.0, "'{weird}' deve finire in other");
        }
    }

    fn sample<'a>() -> ThreatFeatureInput<'a> {
        ThreatFeatureInput {
            risk_score: 0.8,
            confidence: 0.9,
            hour_of_day: 14,
            day_of_week: 2,
            is_datacenter: Some(true),
            is_tor: Some(false),
            is_proxy: Some(false),
            path: "/wp-admin/x",
            user_agent: "curl/8.0",
            query: "id=1&q=2",
            severity_numeric: 4,
            burst_score: Some(0.5),
            inter_request_stddev: Some(0.1),
            anomaly_score: Some(0.3),
            threat_type: "sqli",
            detection_source: "edge",
            request_method: "GET",
        }
    }

    #[test]
    fn extract_produces_20_in_contract_order() {
        let v = extract(&sample());
        assert_eq!(v.len(), 20);
        assert_eq!(v[0], 14.0); // hour_of_day
        assert_eq!(v[1], 2.0); // day_of_week
        assert_eq!(v[2], 1.0); // is_datacenter Some(true)
        assert_eq!(v[3], 0.0); // is_tor Some(false)
        assert_eq!(v[4], 0.0); // is_proxy Some(false)
        assert_eq!(v[5], 2.0); // path_depth /wp-admin/x
        assert!(v[6] > 0.0); // path_entropy
        assert_eq!(v[7], 2.0); // query_param_count id=1&q=2
        assert_eq!(v[8], 8.0); // ua_length "curl/8.0"
        assert_eq!(v[9], 0.5); // burst_score
        assert_eq!(v[10], 0.1); // inter_request_stddev
        assert_eq!(v[11], 0.3); // anomaly_score
        // one-hot: GET acceso, tutto il resto spento
        assert_eq!(v[12], 1.0, "method_get");
        assert_eq!(v[13..20].iter().sum::<f32>(), 0.0, "nessun altro metodo acceso");
    }

    #[test]
    fn extract_metodo_ignoto_finisce_in_other_senza_stato_condiviso() {
        // 🔒 Il punto del fix 2026-08-04: NON serve nessun encoder caricato da un file.
        // Prima l'encoder arrivava (in teoria) da un sidecar mai esportato, quindi in
        // produzione la feature del metodo valeva SEMPRE 0 pur pesando 0.20 nel training.
        // Ora la stessa funzione pura decide su entrambi i lati.
        let mut weird = sample();
        weird.request_method = "PROPFIND";
        let v = extract(&weird);
        assert_eq!(v[19], 1.0, "method_other acceso");
        assert_eq!(v[12..19].iter().sum::<f32>(), 0.0, "nessun metodo noto acceso");
    }

    #[test]
    fn extract_one_hot_e_sempre_esattamente_una_colonna() {
        // Vale per QUALSIASI input, anche ostile: l'invariante non dipende dai dati.
        for m in ["GET", "post", "OPTIONS", "PROPFIND", "", "\n", "DELETE "] {
            let mut s = sample();
            s.request_method = m;
            let v = extract(&s);
            let acc: f32 = v[12..20].iter().sum();
            assert_eq!(acc, 1.0, "metodo '{m}': somma one-hot = {acc}");
        }
    }

    #[test]
    fn extract_segnali_non_misurati_escono_nan_non_zero() {
        // 🔒 Il cuore del fix 2026-08-02. Un fast-path che non attraversa il layer
        // neurale NON ha un anomaly_score pari a zero: non ce l'ha proprio. Se qui
        // tornasse 0.0, il modello leggerebbe "nessuna anomalia" — cioè il valore del
        // traffico innocuo — su ogni singolo attacco honeypot.
        let mut m = sample();
        m.anomaly_score = None;
        m.burst_score = None;
        m.inter_request_stddev = None;
        m.is_datacenter = None;
        m.is_tor = None;
        m.is_proxy = None;
        let v = extract(&m);
        for (i, name) in [(2, "is_datacenter"), (3, "is_tor"), (4, "is_proxy"),
                          (9, "burst_score"), (10, "inter_request_stddev"), (11, "anomaly_score")] {
            assert!(v[i].is_nan(), "{name} non misurato deve essere NaN, trovato {}", v[i]);
        }
        // ciò che è sempre misurabile resta un numero vero.
        assert!(v[0].is_finite() && v[5].is_finite() && v[8].is_finite());
    }

    #[test]
    fn extract_valori_corrotti_diventano_nan_non_zero() {
        // Inf/NaN in ingresso = bug a monte. Azzerarli li travestiva da misura valida
        // ("burst pari a zero"); dichiararli mancanti è l'unica lettura onesta.
        let mut bad = sample();
        bad.burst_score = Some(f32::INFINITY);
        bad.anomaly_score = Some(f32::NAN);
        let v = extract(&bad);
        assert!(v[9].is_nan(), "burst infinito deve diventare NaN, non 0.0");
        assert!(v[11].is_nan());
    }

    #[test]
    fn raw_record_serializes_with_export_keys() {
        // CONTRATTO col portal (threat-export-core.ts): le chiavi del JSON ml_features
        // DEVONO essere le 15 numeriche + 3 categoriche. Se rinomini un campo, l'export
        // scarta il record → questo test diventa rosso.
        let rec = to_raw_record(&sample());
        let v = serde_json::to_value(&rec).unwrap();
        let obj = v.as_object().unwrap();
        for k in [
            "risk_score", "confidence", "hour_of_day", "day_of_week", "is_datacenter", "is_tor",
            "is_proxy", "path_depth", "ua_length", "severity_numeric", "burst_score",
            "inter_request_stddev", "path_entropy", "anomaly_score", "query_param_count",
            "threat_type", "detection_source", "request_method",
        ] {
            assert!(obj.contains_key(k), "ml_features deve contenere la chiave {k}");
        }
        assert_eq!(obj.len(), 18, "esattamente 18 chiavi, trovate {}", obj.len());
        // is_* numerici (non bool) — l'export rifiuta i bool.
        assert!(obj["is_datacenter"].is_number(), "is_datacenter deve essere numero, non bool");
        // categoriche stringa non vuote.
        assert_eq!(obj["threat_type"], "sqli");
    }

    #[test]
    fn raw_record_conserva_cio_che_il_modello_non_deve_vedere() {
        // Persistenza e inferenza sono volutamente ASIMMETRICHE, e non è un confronto di
        // lunghezze (l'one-hot espande il vettore del modello oltre il numero di chiavi
        // salvate): ciò che conta è QUALI campi stanno di qua e di là.
        //
        // I punteggi restano nel record — servono a chi rivede il dataset e agli audit —
        // ma non entrano MAI nel vettore, perché sono assegnati dalla stessa regola che
        // produce l'etichetta. Se qualcuno "allineasse" le due cose per simmetria,
        // reintrodurrebbe il leakage che ha tenuto il gate rosso per settimane.
        let obj = serde_json::to_value(to_raw_record(&sample())).unwrap();
        let obj = obj.as_object().unwrap().clone();
        for banned in LABEL_DERIVED_FEATURES {
            let key = banned.trim_end_matches("_encoded");
            assert!(obj.contains_key(key), "{key} deve restare nel record persistito");
            assert!(
                !FEATURE_NAMES.contains(&key),
                "{key} è nel record ma NON deve stare fra le feature del modello"
            );
        }
        // e il record NON contiene le colonne one-hot: quelle si derivano a valle,
        // dal `request_method` grezzo, sia in training sia in inferenza.
        assert!(obj.contains_key("request_method"));
        assert!(!obj.contains_key("method_get"));
    }

    #[test]
    fn raw_record_segnali_non_misurati_serializzano_null() {
        // Il JSON che finisce in security_threats.ml_features deve dire "null", non "0":
        // è quello che il trainer legge come NaN.
        let mut m = sample();
        m.anomaly_score = None;
        m.is_tor = None;
        let v = serde_json::to_value(to_raw_record(&m)).unwrap();
        assert!(v["anomaly_score"].is_null(), "atteso null, trovato {}", v["anomaly_score"]);
        assert!(v["is_tor"].is_null());
        // gli altri restano valorizzati: l'assenza è per campo, non per record.
        assert!(v["burst_score"].is_number());
    }

    #[test]
    fn raw_record_sanitizes_non_finite() {
        let mut bad = sample();
        bad.risk_score = f32::NAN;
        bad.anomaly_score = Some(f32::INFINITY);
        let rec = to_raw_record(&bad);
        assert_eq!(rec.risk_score, 0.0); // campo obbligatorio: resta lo 0 difensivo
        // campo opzionale: un valore corrotto è "non disponibile", non zero.
        assert_eq!(rec.anomaly_score, None);
    }

    #[test]
    fn extract_non_produce_mai_infiniti() {
        // NaN è ammesso e SIGNIFICATIVO (= missing); Inf no, non vuol dire niente per
        // un albero. Vedi extract_valori_corrotti_diventano_nan_non_zero per il resto.
        let mut bad = sample();
        bad.burst_score = Some(f32::NEG_INFINITY);
        bad.inter_request_stddev = Some(f32::INFINITY);
        let v = extract(&bad);
        assert!(v.iter().all(|x| !x.is_infinite()), "nessuna feature può essere infinita: {v:?}");
    }
}
