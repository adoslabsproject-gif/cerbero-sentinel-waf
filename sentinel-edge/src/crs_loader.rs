//! G2 (2026-06-02): CRS file loader + hot-reload watcher.
//!
//! Sostituisce/integra il bundle builtin con regole lette da
//! `/opt/zeliai/sentinel/crs-patterns.toml` (override env `SENTINEL_CRS_PATH`).
//!
//! Pattern: identico a `tor_loader.rs` — bootstrap + spawn_watcher + atomic swap.

use crate::crs_patterns::{parse_crs_file, swap_crs_bundle};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use tokio::task;

const DEFAULT_CRS_PATH: &str = "/opt/zeliai/sentinel/crs-patterns.txt";

fn crs_path() -> PathBuf {
    PathBuf::from(std::env::var("SENTINEL_CRS_PATH").unwrap_or_else(|_| DEFAULT_CRS_PATH.to_string()))
}

/// Bootstrap: leggi file una volta + swap se valido. Graceful: file missing
/// = bundle builtin resta attivo (no crash, log info).
pub fn load_initial() {
    let path = crs_path();
    if !path.exists() {
        tracing::info!(path = %path.display(), "G2: CRS override file not present, using builtin patterns");
        return;
    }
    match parse_crs_file(&path) {
        Ok(bundle) => {
            let count = bundle.patterns_count;
            swap_crs_bundle(bundle);
            tracing::info!(path = %path.display(), patterns = count, "G2: CRS bundle loaded from file");
        }
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "G2: CRS file invalid — KEEPING builtin (defense-in-depth)");
        }
    }
}

/// Hot-reload watcher: spawn task background che reagisce a modifiche file.
/// Debounce 1s per evitare reload multipli durante write atomic (tempfile+rename).
pub fn spawn_watcher() {
    let path = crs_path();
    let watch_dir = match path.parent() {
        Some(p) => p.to_path_buf(),
        None => {
            tracing::warn!(path = %path.display(), "G2: CRS path has no parent — watcher disabled");
            return;
        }
    };
    let target_filename = match path.file_name() {
        Some(f) => f.to_os_string(),
        None => {
            tracing::warn!(path = %path.display(), "G2: CRS path has no filename — watcher disabled");
            return;
        }
    };

    task::spawn_blocking(move || {
        let (tx, rx) = channel::<notify::Result<Event>>();
        let watcher_config = Config::default().with_poll_interval(Duration::from_secs(30));
        let mut watcher: RecommendedWatcher = match Watcher::new(
            move |res| { let _ = tx.send(res); },
            watcher_config,
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "G2: CRS watcher creation failed");
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!(dir = %watch_dir.display(), error = %e, "G2: CRS watcher.watch() failed");
            return;
        }
        tracing::info!(dir = %watch_dir.display(), "G2: CRS file watcher armed (notify v6)");

        let mut last_reload = std::time::Instant::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(std::time::Instant::now);
        let debounce = Duration::from_millis(1000);

        for event_result in rx {
            let event = match event_result {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "G2: CRS watcher event error");
                    continue;
                }
            };
            let relevant = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
                && event.paths.iter().any(|p| p.file_name() == Some(&target_filename));
            if !relevant { continue; }
            let now = std::time::Instant::now();
            if now.duration_since(last_reload) < debounce { continue; }
            last_reload = now;
            // Reload — riusa load_initial per logica unica
            load_initial();
        }
    });
}
