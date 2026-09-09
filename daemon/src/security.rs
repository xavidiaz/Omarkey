//! Socket hardening, peer checks, and the auto-lock triggers.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use tokio::net::UnixStream;
use tracing::{info, warn};

use crate::config::Config;
use crate::ipc::LockReason;
use crate::Daemon;

// ---------------------------------------------------------------- socket path

pub fn socket_path(config: &Config) -> Result<PathBuf> {
    if let Some(path) = &config.socket_path {
        return Ok(path.clone());
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR is not set; cannot place the socket safely")?;
    Ok(PathBuf::from(runtime).join("omarkey.sock"))
}

/// The directory holding the socket must exist, be a directory, be owned by us,
/// and not be group/other writable.
pub fn preflight_runtime_dir(socket_path: &Path) -> Result<()> {
    let dir = socket_path
        .parent()
        .context("socket path has no parent directory")?;
    let meta = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let uid = unsafe { libc::getuid() };
    if meta.uid() != uid {
        bail!("{} is not owned by uid {uid}", dir.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        bail!(
            "{} is writable by group or other (mode {mode:o})",
            dir.display()
        );
    }
    Ok(())
}

/// If a socket file is already there, connect to it: a live daemon means we
/// should exit, a dead socket gets removed.
pub async fn reclaim_stale_socket(socket_path: &Path) -> Result<()> {
    if !socket_path.exists() {
        return Ok(());
    }
    match UnixStream::connect(socket_path).await {
        Ok(_) => bail!(
            "another omarkeyd is already listening on {}",
            socket_path.display()
        ),
        Err(_) => {
            warn!(path = %socket_path.display(), "removing stale socket");
            std::fs::remove_file(socket_path)
                .with_context(|| format!("removing {}", socket_path.display()))?;
            Ok(())
        }
    }
}

pub fn lock_down_socket(socket_path: &Path) -> Result<()> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", socket_path.display()))
}

/// Reject any peer whose uid is not ours (defence in depth; 0600 already does
/// most of the work).
pub fn verify_peer(stream: &UnixStream) -> Result<()> {
    let creds = stream.peer_cred().context("reading peer credentials")?;
    let uid = unsafe { libc::getuid() };
    if creds.uid() != uid {
        bail!("peer uid {} != {uid}", creds.uid());
    }
    Ok(())
}

// ---------------------------------------------------------------- idle clock

pub struct ActivityClock {
    last: AtomicU64,
    start: Instant,
}

impl ActivityClock {
    pub fn new() -> Self {
        ActivityClock {
            last: AtomicU64::new(0),
            start: Instant::now(),
        }
    }

    pub fn touch(&self) {
        let millis = self.start.elapsed().as_millis() as u64;
        self.last.store(millis, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = self.last.load(Ordering::Relaxed);
        let now = self.start.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(last))
    }

    pub fn remaining_lock_secs(&self, config: &Config) -> Option<u64> {
        config
            .idle_lock
            .map(|limit| limit.saturating_sub(self.idle_for()).as_secs())
    }
}

pub async fn idle_lock_task(daemon: Arc<Daemon>) {
    let Some(limit) = daemon.config.idle_lock else {
        return;
    };
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        if daemon.activity.idle_for() < limit {
            continue;
        }
        let mut vault = daemon.vault.lock().await;
        if !vault.is_locked() {
            vault.lock_now(&daemon, LockReason::Idle);
        }
    }
}

// ---------------------------------------------------------------- logind

/// Subscribe to the current login session's `Lock` signal and to
/// `PrepareForSleep`, locking the vault on either. Returns a future to spawn.
pub async fn logind_lock_task(
    daemon: Arc<Daemon>,
) -> Result<impl std::future::Future<Output = ()>> {
    use zbus::Connection;

    let conn = Connection::system()
        .await
        .context("connecting to the system bus")?;

    // Resolve our session path via org.freedesktop.login1.Manager.GetSessionByPID.
    let manager = zbus::Proxy::new(
        &conn,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await?;

    let session_path = resolve_session_path(&manager).await?;
    info!(session = %session_path.as_str(), "watching logind session for Lock");

    let session = zbus::Proxy::new(
        &conn,
        "org.freedesktop.login1",
        session_path.clone(),
        "org.freedesktop.login1.Session",
    )
    .await?;

    let mut lock_stream = session.receive_signal("Lock").await?;
    let mut sleep_stream = manager.receive_signal("PrepareForSleep").await?;

    Ok(async move {
        loop {
            tokio::select! {
                Some(_) = lock_stream.next() => {
                    let mut vault = daemon.vault.lock().await;
                    if !vault.is_locked() {
                        vault.lock_now(&daemon, LockReason::SessionLock);
                    }
                }
                Some(msg) = sleep_stream.next() => {
                    // PrepareForSleep(true) fires just before suspend.
                    let about_to_sleep: bool = msg.body().deserialize().unwrap_or(true);
                    if about_to_sleep {
                        let mut vault = daemon.vault.lock().await;
                        if !vault.is_locked() {
                            vault.lock_now(&daemon, LockReason::Sleep);
                        }
                    }
                }
                else => break,
            }
        }
    })
}

/// Find our logind session object path. `GetSessionByPID` fails when the daemon
/// runs in the `user@.service` manager scope (systemd --user unit) rather than
/// the session scope, so try `$XDG_SESSION_ID` first and fall back to scanning
/// `ListSessions` for this uid's seated session.
async fn resolve_session_path(
    manager: &zbus::Proxy<'_>,
) -> Result<zbus::zvariant::OwnedObjectPath> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID") {
        if let Ok(path) = manager
            .call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSession", &(id.as_str()))
            .await
        {
            return Ok(path);
        }
    }

    if let Ok(path) = manager
        .call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSessionByPID", &(std::process::id()))
        .await
    {
        return Ok(path);
    }

    // (session_id, uid, user_name, seat_id, object_path)
    type SessionRow = (String, u32, String, String, zbus::zvariant::OwnedObjectPath);
    let sessions: Vec<SessionRow> = manager.call("ListSessions", &()).await?;
    let uid = unsafe { libc::getuid() };
    sessions
        .into_iter()
        .find(|(_, sess_uid, _, seat, _)| *sess_uid == uid && !seat.is_empty())
        .map(|(_, _, _, _, path)| path)
        .context("no seated logind session found for this user")
}

// ---------------------------------------------------------------- shutdown

pub async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

// ---------------------------------------------------------------- pinentry

pub mod pinentry {
    use anyhow::{bail, Context, Result};
    use secrecy::SecretString;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    use crate::config::{Config, VaultConfig};

    /// Drive an Assuan `pinentry` to collect the master password for `vault`. The
    /// password is read from pinentry's stdout and never touches a shell argument.
    pub async fn prompt_master_password(
        config: &Config,
        vault: &VaultConfig,
    ) -> Result<SecretString> {
        let program = config
            .pinentry_program
            .clone()
            .unwrap_or_else(|| "pinentry".to_string());

        let mut child = Command::new(&program)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {program}"))?;

        let mut stdin = child.stdin.take().context("pinentry stdin")?;
        let mut stdout = BufReader::new(child.stdout.take().context("pinentry stdout")?).lines();

        // First line is the greeting.
        let _ = stdout.next_line().await?;

        let file_name = vault
            .path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| vault.name.clone());

        for cmd in [
            format!("SETTITLE Omarkey — {}", vault.name),
            format!("SETDESC Unlock the KeePass vault ({file_name})"),
            format!("SETPROMPT {}:", vault.name),
            "GETPIN".to_string(),
        ] {
            stdin.write_all(cmd.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;

            let mut pin: Option<SecretString> = None;
            loop {
                let Some(line) = stdout.next_line().await? else {
                    bail!("pinentry closed unexpectedly");
                };
                if let Some(rest) = line.strip_prefix("D ") {
                    pin = Some(SecretString::from(rest.to_owned()));
                } else if line == "OK" || line.starts_with("OK ") {
                    break;
                } else if let Some(err) = line.strip_prefix("ERR ") {
                    if err.contains("83886179") || err.to_lowercase().contains("cancel") {
                        bail!("cancelled");
                    }
                    bail!("pinentry error: {err}");
                }
            }

            if cmd == "GETPIN" {
                let _ = stdin.write_all(b"BYE\n").await;
                let _ = child.wait().await;
                return pin.context("pinentry returned no PIN");
            }
        }

        unreachable!()
    }
}
