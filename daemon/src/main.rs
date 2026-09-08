//! omarkeyd — Omarkey's credential daemon.
//!
//! Owns the decrypted KeePass vault (in zeroized RAM), the Unix socket the shell
//! plugin talks to, and the auto-lock triggers (idle timeout, logind session
//! lock, pre-sleep). The QML side never sees a secret; see `PROTOCOL.md`.

mod actions;
mod config;
mod ipc;
mod security;
mod vault;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::ipc::Event;
use crate::vault::VaultState;

/// Shared handle every connection task clones.
pub struct Daemon {
    pub config: Config,
    pub vault: Mutex<VaultState>,
    /// Fan-out of daemon events to subscribed connections.
    pub events: broadcast::Sender<Event>,
    /// Bumped on any vault access; the idle-lock task watches it.
    pub activity: security::ActivityClock,
    pub clipboard: actions::Clipboard,
}

impl Daemon {
    pub fn emit(&self, event: Event) {
        // A send error just means nobody is subscribed right now.
        let _ = self.events.send(event);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("OMARKEY_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::load().context("loading configuration")?;
    info!(vault = %config.vault_path.display(), "starting omarkeyd");

    let socket_path = security::socket_path(&config)?;
    security::preflight_runtime_dir(&socket_path)
        .context("runtime directory failed security checks")?;

    // A stale socket from a crashed daemon would block bind(); remove it only
    // after confirming nothing is listening.
    security::reclaim_stale_socket(&socket_path).await?;

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    security::lock_down_socket(&socket_path)?;
    info!(socket = %socket_path.display(), "listening");

    let (events_tx, _) = broadcast::channel::<Event>(64);
    let daemon = Arc::new(Daemon {
        vault: Mutex::new(VaultState::locked(&config)),
        activity: security::ActivityClock::new(),
        clipboard: actions::Clipboard::new(),
        events: events_tx,
        config,
    });

    // Background: auto-lock on idle.
    tokio::spawn(security::idle_lock_task(daemon.clone()));

    // Background: auto-lock on logind session Lock + PrepareForSleep.
    match security::logind_lock_task(daemon.clone()).await {
        Ok(task) => {
            tokio::spawn(task);
        }
        Err(err) => warn!(%err, "logind integration unavailable; session-lock auto-lock disabled"),
    }

    // Background: watch the .kdbx file for external edits.
    tokio::spawn(vault::watch_vault_file(daemon.clone()));

    // Clean shutdown: lock the vault, then remove the socket.
    let shutdown = {
        let daemon = daemon.clone();
        let socket_path = socket_path.clone();
        async move {
            security::wait_for_shutdown_signal().await;
            info!("shutting down");
            daemon.vault.lock().await.lock_now(&daemon, ipc::LockReason::Manual);
            let _ = std::fs::remove_file(&socket_path);
        }
    };
    tokio::spawn(shutdown);

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                error!(%err, "accept failed");
                continue;
            }
        };

        if let Err(err) = security::verify_peer(&stream) {
            warn!(%err, "rejecting connection from unexpected peer");
            continue;
        }

        let daemon = daemon.clone();
        tokio::spawn(async move {
            if let Err(err) = ipc::serve_connection(daemon, stream).await {
                warn!(%err, "connection ended with error");
            }
        });
    }
}
