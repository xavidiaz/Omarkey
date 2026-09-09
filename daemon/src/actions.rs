//! Output side: put a secret on the Wayland clipboard (`wl-copy`) or type it
//! (`wtype`). Values are always handed over on **stdin**, never as a process
//! argument, so they never appear in `/proc/<pid>/cmdline` or `ps` output.

use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, warn};

use crate::ipc::Event;
use crate::vault::{TypeToken, TypeTokenRef};
use crate::Daemon;

// ---------------------------------------------------------------- clipboard

pub struct Clipboard {
    /// Every `copy` bumps this. A scheduled wipe only fires if it still owns the
    /// latest generation, so a newer copy silently supersedes an older wipe.
    generation: AtomicU64,
}

impl Clipboard {
    pub fn new() -> Self {
        Clipboard {
            generation: AtomicU64::new(0),
        }
    }

    pub async fn copy(
        &self,
        daemon: Arc<Daemon>,
        uuid: &str,
        field: &crate::vault::CopyField,
        value: SecretString,
        clear_after: Duration,
    ) -> Result<()> {
        wl_copy(value.expose_secret(), false)
            .await
            .context("wl-copy failed")?;

        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;

        if clear_after.is_zero() {
            return Ok(());
        }

        let uuid = uuid.to_string();
        let field_name = field.as_str();
        tokio::spawn(async move {
            tokio::time::sleep(clear_after).await;

            if daemon.clipboard.generation.load(Ordering::SeqCst) != generation {
                debug!("clipboard wipe superseded by a newer copy");
                return;
            }

            // Only wipe if the clipboard still holds exactly what we wrote — the
            // user may have copied something else in the meantime.
            match wl_paste().await {
                Ok(current) if current.expose_secret() == value.expose_secret() => {
                    if let Err(err) = wl_clear().await {
                        warn!(%err, "failed to clear clipboard");
                        return;
                    }
                    daemon.emit(Event::ClipboardCleared {
                        uuid,
                        field: field_name,
                    });
                }
                Ok(_) => debug!("clipboard changed by user; leaving it alone"),
                Err(err) => warn!(%err, "could not read clipboard to verify wipe"),
            }
        });

        Ok(())
    }
}

async fn wl_copy(value: &str, primary: bool) -> Result<()> {
    let mut cmd = Command::new("wl-copy");
    if primary {
        cmd.arg("--primary");
    }
    // `--` then read the value from stdin.
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning wl-copy")?;
    child
        .stdin
        .take()
        .context("wl-copy stdin")?
        .write_all(value.as_bytes())
        .await?;
    let status = child.wait().await?;
    if !status.success() {
        bail!("wl-copy exited with {status}");
    }
    Ok(())
}

async fn wl_paste() -> Result<SecretString> {
    let out = Command::new("wl-paste")
        .arg("--no-newline")
        .stderr(Stdio::null())
        .output()
        .await
        .context("spawning wl-paste")?;
    Ok(SecretString::from(
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

async fn wl_clear() -> Result<()> {
    let status = Command::new("wl-copy")
        .arg("--clear")
        .status()
        .await
        .context("spawning wl-copy --clear")?;
    if !status.success() {
        bail!("wl-copy --clear exited with {status}");
    }
    Ok(())
}

// ---------------------------------------------------------------- typing

/// Type a resolved sequence. Text runs go through `wtype -` (stdin); `Key`
/// tokens become `wtype -k <keysym>`; `Delay` tokens sleep between runs.
pub async fn type_tokens(tokens: &[TypeToken]) -> Result<()> {
    ensure_wtype().await?;

    for token in tokens {
        match token.expose() {
            TypeTokenRef::Text(text) => {
                let mut child = Command::new("wtype")
                    .args(["-s", "12", "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("spawning wtype")?;
                child
                    .stdin
                    .take()
                    .context("wtype stdin")?
                    .write_all(text.as_bytes())
                    .await?;
                let status = child.wait().await?;
                if !status.success() {
                    bail!("wtype exited with {status}");
                }
            }
            TypeTokenRef::Key(keysym) => {
                let status = Command::new("wtype")
                    .args(["-k", keysym])
                    .status()
                    .await
                    .context("spawning wtype -k")?;
                if !status.success() {
                    bail!("wtype -k {keysym} exited with {status}");
                }
            }
            TypeTokenRef::Delay(d) => tokio::time::sleep(d).await,
        }
    }
    Ok(())
}

async fn ensure_wtype() -> Result<()> {
    which("wtype")
        .await
        .context("wtype is not installed; install it or use `copy` instead of `type`")
}

async fn which(program: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        bail!("{program} not found on PATH")
    }
}
