//! TOR Exit Node Loader — hot-reload from /opt/zeliai/data/tor-exit-nodes.txt
//!
//! Architecture:
//!   • Bootstrap: load_initial() chiamato all'avvio Sentinel — popola
//!     IpIntelligence.tor_exits dal file
//!   • Hot-reload: spawn_watcher() registra inotify watch via `notify` crate
//!     → on file change (cron weekly update), ricarica atomicamente
//!   • Atomicity: replace_tor_exits() prende single write lock + clear cache
//!   • Resilience: malformed IP linee → warn log, no fail-fast
//!   • Zero-downtime: file change non richiede restart Sentinel
//!
//! File format (compatibile col cron update-tor-exit-nodes.sh):
//!   /opt/zeliai/data/tor-exit-nodes.txt
//!     1.2.3.4
//!     # comment
//!     2001:db8::1
//!     ...
//!
//! Env var:
//!   TOR_EXIT_LIST_PATH (default: /opt/zeliai/data/tor-exit-nodes.txt)

use crate::ip_intel::IpIntelligence;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;
use tokio::task;

/// Default path TOR exit list — sovrascrivibile via env TOR_EXIT_LIST_PATH.
const DEFAULT_TOR_PATH: &str = "/opt/zeliai/data/tor-exit-nodes.txt";

/// Helper: resolve effective TOR list path da env o default.
pub fn tor_list_path() -> PathBuf {
    PathBuf::from(std::env::var("TOR_EXIT_LIST_PATH").unwrap_or_else(|_| DEFAULT_TOR_PATH.to_string()))
}

/// Bootstrap: load TOR exits dal file all'avvio Sentinel.
/// Chiamato una volta in `EdgeShield::new()` o `main()`.
/// Returns Ok(count) o Err se file unreadable.
///
/// Failure mode: se file missing/unreadable, log warn e ritorna Ok(0)
/// (Sentinel funziona comunque, solo senza blocco TOR — graceful degradation).
pub fn load_initial(ip_intel: &IpIntelligence) -> std::io::Result<usize> {
    let path = tor_list_path();
    let path_str = path.to_string_lossy().to_string();
    match ip_intel.load_tor_exits_from_file(&path_str) {
        Ok(count) => {
            tracing::info!(path = %path_str, count = count, "TOR exit list bootstrap OK");
            Ok(count)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %path_str,
                "TOR exit list file not found — Sentinel runs without TOR detection. \
                Run scripts/update-tor-exit-nodes.sh to populate."
            );
            Ok(0)
        }
        Err(e) => {
            tracing::error!(path = %path_str, error = %e, "TOR exit list load FAILED");
            Err(e)
        }
    }
}

/// Spawn background task che watch il file TOR e ricarica on change.
///
/// Pattern enterprise (Notify v6 cross-platform):
///   1. RecommendedWatcher su parent directory di tor-exit-nodes.txt
///      (watch sul file diretto può lose events se file replaced — atomic
///      rename pattern usato da cron sed/mv per safety).
///   2. Filter events: solo Modify | Create matchanti il filename target.
///   3. Debounce 1s — atomic rename genera 2-3 events ravvicinati.
///   4. On debounced event: ip_intel.load_tor_exits_from_file() atomico
///      (cache invalidation interna).
///
/// Task lifetime: ownership Arc<IpIntelligence> mantenuta dal task.
/// Termina solo se mpsc channel chiuso → EdgeShield drop.
pub fn spawn_watcher(ip_intel: Arc<IpIntelligence>) {
    let path = tor_list_path();
    let watch_dir = match path.parent() {
        Some(p) => p.to_path_buf(),
        None => {
            tracing::warn!(path = %path.display(), "TOR path has no parent — watcher disabled");
            return;
        }
    };
    let target_filename = match path.file_name() {
        Some(f) => f.to_os_string(),
        None => {
            tracing::warn!(path = %path.display(), "TOR path has no filename — watcher disabled");
            return;
        }
    };

    // Spawn blocking task — notify usa blocking I/O.
    task::spawn_blocking(move || {
        let (tx, rx) = channel::<notify::Result<Event>>();

        let watcher_config = Config::default()
            .with_poll_interval(Duration::from_secs(30)); // fallback poll se inotify fail
        let mut watcher: RecommendedWatcher = match Watcher::new(
            move |res| { let _ = tx.send(res); },
            watcher_config,
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "TOR watcher creation failed");
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!(dir = %watch_dir.display(), error = %e, "TOR watcher.watch() failed");
            return;
        }
        tracing::info!(dir = %watch_dir.display(), "TOR exit list watcher armed (notify v6)");

        // Debounce: accumula events 1s window, poi processa una sola volta.
        let mut last_reload = std::time::Instant::now();
        let debounce = Duration::from_millis(1000);

        for event_result in rx {
            let event = match event_result {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "TOR watcher event error");
                    continue;
                }
            };

            // Filter: solo Modify/Create che matchano il target filename
            let relevant = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
                && event.paths.iter().any(|p| p.file_name() == Some(&target_filename));
            if !relevant {
                continue;
            }

            // Debounce
            if last_reload.elapsed() < debounce {
                continue;
            }
            last_reload = std::time::Instant::now();

            // Reload (blocking I/O — ma siamo in spawn_blocking)
            let path = tor_list_path();
            let path_str = path.to_string_lossy().to_string();
            match ip_intel.load_tor_exits_from_file(&path_str) {
                Ok(count) => tracing::info!(count = count, "TOR exit list HOT-RELOAD ok"),
                Err(e) => tracing::error!(error = %e, "TOR exit list HOT-RELOAD failed"),
            }
        }
    });
}
