//! Daemon configuration: `~/.config/omarkey/omarkeyd.toml`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    /// Absolute path to the `.kdbx` file.
    pub vault_path: PathBuf,
    /// Optional key file that pairs with the master password.
    pub keyfile_path: Option<PathBuf>,
    /// Lock the vault after this long with no requests. `None` disables it.
    pub idle_lock: Option<Duration>,
    /// How long a copied secret stays on the clipboard before it is wiped.
    pub clipboard_clear: Duration,
    /// Permit `unlock` with a password sent over the socket (headless setups).
    /// Off by default: normally the daemon runs its own pinentry.
    pub allow_inline_unlock: bool,
    /// `pinentry` program to run. Empty = autodetect (`pinentry` on PATH).
    pub pinentry_program: Option<String>,
    /// Override the socket path. Defaults to `$XDG_RUNTIME_DIR/omarkey.sock`.
    pub socket_path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    vault: Option<String>,
    keyfile: Option<String>,
    idle_lock_seconds: Option<u64>,
    clipboard_clear_seconds: Option<u64>,
    allow_inline_unlock: Option<bool>,
    pinentry_program: Option<String>,
    socket_path: Option<String>,
}

impl Config {
    pub fn config_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("com", "xavidiaz", "omarkey")
            .context("cannot determine config directory")?;
        Ok(dirs.config_dir().join("omarkeyd.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        let raw: RawConfig = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "no config at {}. Create it with at least:\n\n  vault = \"/home/you/secrets.kdbx\"\n",
                    path.display()
                );
            }
            Err(err) => return Err(err).context(format!("reading {}", path.display())),
        };

        let vault_path = raw
            .vault
            .map(expand_tilde)
            .context("`vault` is required in omarkeyd.toml")?;
        if !vault_path.is_absolute() {
            bail!("`vault` must be an absolute path");
        }

        Ok(Config {
            vault_path,
            keyfile_path: raw.keyfile.map(expand_tilde),
            idle_lock: match raw.idle_lock_seconds {
                Some(0) => None,
                Some(secs) => Some(Duration::from_secs(secs)),
                None => Some(Duration::from_secs(300)),
            },
            clipboard_clear: Duration::from_secs(raw.clipboard_clear_seconds.unwrap_or(20)),
            allow_inline_unlock: raw.allow_inline_unlock.unwrap_or(false),
            pinentry_program: raw.pinentry_program,
            socket_path: raw.socket_path.map(expand_tilde),
        })
    }
}

fn expand_tilde(input: String) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = directories::UserDirs::new().map(|d| d.home_dir().to_path_buf()) {
            return home.join(rest);
        }
    }
    PathBuf::from(input)
}
