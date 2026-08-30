//! Guard ISTITUZIONALIZZATO contro il lock-poisoning (audit 2026-06-20, rischio #1 WAF).
//!
//! Tutti i lock del WAF sono stati migrati da `std::sync::{Mutex,RwLock}` (che si
//! AVVELENANO su panic → ogni accesso successivo panica → outage del WAF) a
//! `parking_lot::{Mutex,RwLock}` (non-poisoning by design). Questi test impediscono
//! STRUTTURALMENTE la reintroduzione del pattern pericoloso:
//!
//!  1. `no_std_sync_locks_in_workspace`: scansione sorgente — nessun crate sentinel può
//!     dichiarare/usare `std::sync::Mutex`/`RwLock` né `.lock()/.read()/.write().unwrap()`.
//!     (Arc / atomic / OnceLock / mpsc restano leciti: non si avvelenano.)
//!  2. `parking_lot_mutex_survives_panic_while_held`: prova COMPORTAMENTALE che un panic
//!     mentre si tiene il lock NON lo rende inutilizzabile (cosa che std::sync farebbe).

use std::fs;
use std::path::{Path, PathBuf};

/// Radice del workspace sentinel (apps/sentinel): il manifest dir è .../sentinel-server.
fn sentinel_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("sentinel-server ha una parent dir")
        .to_path_buf()
}

/// Raccoglie ricorsivamente tutti i `.rs` sotto `dir`, saltando `target/` e questo file.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && !path.ends_with("lock_poisoning_guard.rs")
        {
            out.push(path);
        }
    }
}

/// `true` se la riga (non-commento) usa un lock std::sync poison-prone o un `.unwrap()`
/// su un guard di lock.
fn line_has_poison_prone_lock(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
        return false; // commento → non è codice
    }
    // std::sync::Mutex / RwLock in qualunque forma (tipo, ::new, use braced).
    if t.contains("std::sync") && (t.contains("Mutex") || t.contains("RwLock")) {
        return true;
    }
    // .lock()/.read()/.write().unwrap() su una riga (panic-on-poison).
    for needle in [".lock().unwrap()", ".read().unwrap()", ".write().unwrap()"] {
        if t.contains(needle) {
            return true;
        }
    }
    false
}

#[test]
fn no_std_sync_locks_in_workspace() {
    let mut files = Vec::new();
    collect_rs(&sentinel_root(), &mut files);
    assert!(files.len() > 20, "scansione sospetta: trovati solo {} file .rs", files.len());

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let Ok(src) = fs::read_to_string(file) else { continue };
        for (i, line) in src.lines().enumerate() {
            if line_has_poison_prone_lock(line) {
                offenders.push(format!("{}:{} → {}", file.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "Lock std::sync poison-prone reintrodotti (usa parking_lot::{{Mutex,RwLock}}):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn parking_lot_mutex_survives_panic_while_held() {
    use parking_lot::Mutex;
    use std::sync::Arc;

    let m = Arc::new(Mutex::new(0u32));
    let m2 = Arc::clone(&m);

    // Un thread panica MENTRE tiene il lock. Con std::sync::Mutex il lock resterebbe
    // AVVELENATO → ogni .lock() successivo darebbe Err (e con .unwrap() panicherebbe).
    let joined = std::thread::spawn(move || {
        let mut g = m2.lock();
        *g += 1;
        panic!("boom mentre tengo il lock");
    })
    .join();
    assert!(joined.is_err(), "il thread doveva panicare");

    // parking_lot: il lock è ancora perfettamente usabile (nessun poisoning).
    *m.lock() += 41;
    assert_eq!(*m.lock(), 42, "parking_lot Mutex non deve avvelenarsi su panic");
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard ISTITUZIONALIZZATO contro la CLASSE PANIC UTF-8 (audit FP1/FP2/FP3): uno slice
// di byte numerico `&s[..N]` / `&s[N..]` su una &str panica se il byte cade in mezzo a
// un carattere multibyte. Regola: su input ostile usa `truncate_char_boundary`; ogni
// slice numerico residuo (es. byte-array sicuri) DEVE essere giustificato con un marker
// `SAFE-SLICE:` che spiega il meccanismo per cui non può panicare.

/// `true` se la riga contiene uno slice di byte numerico: `[..<digit>` o `<digit>..]`.
fn has_numeric_byte_slice(line: &str) -> bool {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i + 3 < n {
        if &b[i..i + 3] == b"[.." && b[i + 3].is_ascii_digit() {
            return true; // [..N
        }
        if b[i].is_ascii_digit() && &b[i + 1..i + 4] == b"..]" {
            return true; // N..]
        }
        i += 1;
    }
    false
}

#[test]
fn numeric_str_slices_must_be_justified_or_use_char_boundary_helper() {
    let mut files = Vec::new();
    collect_rs(&sentinel_root(), &mut files);

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let Ok(src) = fs::read_to_string(file) else { continue };
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            // Salta i commenti (i doc citano `&b[..8192]` come esempio).
            if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                continue;
            }
            if !has_numeric_byte_slice(line) {
                continue;
            }
            // Giustificato se `SAFE-SLICE` è sulla riga o nelle 3 righe sopra (commento).
            let justified = line.contains("SAFE-SLICE")
                || (i >= 1 && lines[i - 1].contains("SAFE-SLICE"))
                || (i >= 2 && lines[i - 2].contains("SAFE-SLICE"))
                || (i >= 3 && lines[i - 3].contains("SAFE-SLICE"));
            if !justified {
                offenders.push(format!("{}:{} → {}", file.display(), i + 1, t));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "Slice di byte numerico NON giustificato (panic UTF-8 su &str ostile → usa \
         sentinel_core::truncate_char_boundary, oppure annota `// SAFE-SLICE: <perché \
         non panica>` se è un byte-array/ASCII garantito):\n{}",
        offenders.join("\n")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard ISTITUZIONALIZZATO contro la CLASSE INNER-LEAK (audit BG1/LIDENT-IPS/SP1/L3-1).
//
// ── INVARIANTE (la regola che difendiamo) ────────────────────────────────────
// Ogni collezione (Vec/VecDeque/HashSet/HashMap) usata come VALORE di una mappa
// attacker-keyed è una bomba di memoria SEPARATA. Cappare la CHIAVE (la mappa esterna
// ShardedLru/DashMap) NON bounda il VALORE-collezione, che cresce con input infiniti
// dell'attaccante (UA, path, IP, signal). Perciò: ogni mutazione di crescita
// (`recv.field.{push,push_back,insert}(`) su un CAMPO-collezione DEVE avere un bound —
// un pop/truncate/clear/retain dello stesso campo, una guardia `if field.len() < CAP`,
// oppure (se bounded per costruzione/altrove) una giustificazione esplicita.
//
// ── PERCHÉ È UN GUARD EURISTICO BEST-EFFORT (e non strutturale come il lock-poisoning) ─
// Il lock-poisoning si rileva con un grep di STRINGA esatta (`.lock().unwrap()`):
// decidibile. "Collezione-valore senza cap" invece richiede ANALISI SEMANTICA (tipi,
// flusso, raggiungibilità del cap) che un test su testo non può fare in modo affidabile.
// Quindi questo guard è una RETE, non una prova: cattura il pattern comune (cap LOCALE
// entro una finestra di righe), ma ha BLIND SPOT NOTI — vedi sotto. La sua incompletezza
// è DICHIARATA, non nascosta: la difesa completa è invariante + questo test + checklist.
//
// ── BLIND SPOT NOTI (NON catturati dal test → coprire in REVIEW) ──────────────
//  1. `map.entry(k).or_insert_with(..).push(x)` / `.or_default().insert(x)`: la crescita
//     è sul VALORE ritornato da entry(), non su `recv.field` → non matchato. (entry() è
//     anche la classe SESSION1 sulla CHIAVE: vedi OUTER_MAP_OUT_OF_SCOPE.)
//  2. Receiver = parametro di closure: `with_entry_mut(k, .., |v| v.insert(x))` — `v` è
//     un binding locale (un livello), non `recv.field` → non matchato. (Es. i set inner
//     di behavior_graph: SONO cappati, ma il guard non lo verifica.)
//  3. Falso-negativo semantico: un `field.len() <>` nella finestra che è un confronto di
//     DETECTION (non un cap) viene scambiato per evidenza di bound.
//  4. Cap in un'ALTRA funzione (non entro la finestra) → richiede allowlist BOUNDED_FIELDS.
//  5. Scope = solo sentinel-behavior + sentinel-edge.
//
// ── CHECKLIST DI REVIEW (per ogni PR che tocca un tracker/detector) ───────────
//  [ ] Ho aggiunto/mutato un Vec/VecDeque/HashSet/HashMap che è VALORE di una mappa o
//      campo di uno struct-valore? → deve avere un cap hard vicino alla mutazione.
//  [ ] Il valore-collezione è keyed/popolato da input attacker-controlled (UA, path, IP,
//      header, signal)? → il cap è OBBLIGATORIO (≫ soglia di detection, non = ad essa).
//  [ ] Sto crescendo via `entry().or_*()` o dentro una closure (`|v| v.push`)? → il guard
//      NON ti copre: verifica il cap A MANO (blind spot #1/#2).
//  [ ] Una mappa ESTERNA nuova keyed da attacker → è ShardedLru (o ha eviction)? (SESSION1)
//
// Scope tecnico: esclusi i Vec/Set LOCALI di funzione (un livello, es. `detections.push`):
// non sono campi persistenti.

/// I "metodi di crescita" di una collezione-VALORE. `.push(`/`.push_back(` sono SEMPRE
/// su un Vec/VecDeque interno (le mappe esterne DashMap/ShardedLru non li hanno);
/// `.insert(` cattura anche i HashSet/HashMap interni. NB: `.entry(` (get-or-create
/// sulla mappa ESTERNA) è la classe SESSION1 (bound della CHIAVE) — fuori scope di
/// questo guard, che è sugli inner-VALUE.
const GROWTH_CALLS: &[&str] = &[".push(", ".push_back(", ".insert("];

/// Campi-collezione VERIFICATI bounded "altrove" (cap lontano dal punto di mutazione) o
/// "per costruzione" (≤ N varianti enum). Centralizzati qui (con motivo) invece di
/// spargere marker. Ogni voce è una PROMESSA verificata: se diventa falsa, è un bug.
const BOUNDED_FIELDS: &[(&str, &str)] = &[
    // inner bounded PER TIPO (chiave = enum a N varianti → la mappa/set è ≤ N):
    ("detected_intents", "HashSet<RecognizedIntent>: <= varianti enum"),
    ("intent_timestamps", "HashMap<RecognizedIntent,_>: <= varianti enum"),
    // inner cappato, ma la guardia `len()` è nell'if che apre il blocco (fuori finestra):
    ("weak_associations", "Vec cappato a MAX_WEAK_ASSOCIATIONS (push solo nel ramo len<MAX)"),
    // mappe ESTERNE cappate in manutenzione periodica (cap lontano dall'insert):
    ("event_log", "DashMap cappata a 50_000 in maintenance() (lib.rs)"),
    ("identities", "DashMap cappata a MAX_IDENTITIES (register inline + cleanup)"),
];

/// Mappe ESTERNE keyed-by-attacker = classe SESSION1 (bound della CHIAVE), NON inner-value:
/// fuori scope di questo guard (sugli inner-VALUE). Le outer-map ShardedLru usano
/// `.put()`/`.with_entry_mut()` (non `.insert(` su campo) e le DashMap residue usano
/// `.entry()` → nessuna è matchata dai GROWTH_CALLS, quindi l'allowlist è VUOTA.
/// (`ip_intel.cache/blocklist`, che usavano `.insert(`, sono migrate a ShardedLru.)
const OUTER_MAP_OUT_OF_SCOPE: &[&str] = &[];

/// Estrae il nome del CAMPO da `recv.field.method(` (due livelli) per una data growth
/// call presente nella riga. `None` se è un accumulatore locale a un livello
/// (`local.push(`) o non un pattern campo.
fn field_of_growth(line: &str, call: &str) -> Option<String> {
    let idx = line.find(call)?;
    let before = &line[..idx]; // "...recv.field"
    // Ultimo token = field; deve esistere un '.' prima (cioè recv.field, due livelli).
    let field: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if field.is_empty() {
        return None;
    }
    let head = &before[..before.len() - field.len()];
    if !head.ends_with('.') {
        return None; // un solo livello (accumulatore locale) → non un campo
    }
    // Il carattere prima del '.' deve far parte di un identificatore (recv) — esclude
    // `).field` (catene tipo or_default().push già gestite altrove).
    let recv_tail = head[..head.len() - 1]
        .chars()
        .last()
        .map(|c| c.is_alphanumeric() || c == '_')
        .unwrap_or(false);
    if !recv_tail {
        return None;
    }
    Some(field)
}

/// Cerca, nella finestra `[lo, hi]`, evidenza LOCALE di bound per `field`.
fn has_local_bound(lines: &[&str], lo: usize, hi: usize, field: &str) -> bool {
    let pops = [
        format!("{field}.pop_front("),
        format!("{field}.pop_back("),
        format!("{field}.truncate("),
        format!("{field}.clear("),
        format!("{field}.retain("),
        format!("{field}.split_off("),
    ];
    let len_call = format!("{field}.len()");
    let contains_call = format!("{field}.contains");
    for l in &lines[lo..=hi] {
        if l.contains("BOUNDED:") {
            return true;
        }
        for p in &pops {
            if l.contains(p.as_str()) {
                return true;
            }
        }
        // guardia `field.len()` seguita (sulla stessa riga) da un confronto.
        if let Some(pos) = l.find(len_call.as_str()) {
            let rest = &l[pos + len_call.len()..];
            let rest = rest.trim_start();
            if rest.starts_with('<') || rest.starts_with('>') {
                return true;
            }
        }
        // pattern skip-insert: `if field.contains(k) || field.len() < CAP {`
        if l.contains(contains_call.as_str()) {
            return true;
        }
    }
    false
}

#[test]
fn inner_value_collections_must_be_capped() {
    // Scope: solo i crate dei tracker attacker-keyed.
    let root = sentinel_root();
    let mut files = Vec::new();
    for crate_dir in ["sentinel-behavior/src", "sentinel-edge/src"] {
        collect_rs(&root.join(crate_dir), &mut files);
    }
    assert!(files.len() > 8, "scansione sospetta: solo {} file", files.len());

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let Ok(src) = fs::read_to_string(file) else { continue };
        let lines: Vec<&str> = src.lines().collect();
        let mut in_test = false;
        let mut test_depth: i32 = 0;
        for (i, raw) in lines.iter().enumerate() {
            let t = raw.trim_start();
            // Salta i moduli di test (#[cfg(test)] mod tests { ... }).
            if t.contains("#[cfg(test)]") {
                in_test = true;
            }
            if in_test {
                test_depth += raw.matches('{').count() as i32;
                test_depth -= raw.matches('}').count() as i32;
                if test_depth <= 0 && raw.contains('}') {
                    in_test = false;
                    test_depth = 0;
                }
                continue;
            }
            if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                continue;
            }
            for call in GROWTH_CALLS {
                if !raw.contains(call) {
                    continue;
                }
                let Some(field) = field_of_growth(raw, call) else { continue };
                if BOUNDED_FIELDS.iter().any(|(f, _)| *f == field)
                    || OUTER_MAP_OUT_OF_SCOPE.contains(&field.as_str())
                {
                    continue;
                }
                let lo = i.saturating_sub(6);
                let hi = (i + 20).min(lines.len() - 1);
                if !has_local_bound(&lines, lo, hi, &field) {
                    offenders.push(format!("{}:{} → {}", file.display(), i + 1, t));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "Collezione-VALORE senza cap LOCALE (classe inner-leak BG1/LIDENT-IPS/SP1/L3-1). \
         Aggiungi un cap hard (pop_front/truncate/retain o guardia `if field.len() < CAP`) \
         vicino alla mutazione, oppure `// BOUNDED: <perché è già bounded>`:\n{}",
        offenders.join("\n")
    );
}
