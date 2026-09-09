//! Daemon configuration: `~/.config/omarkey/omarkeyd.toml`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// One configured KeePass database.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Short name used on the wire (`omarkey unlock <name>`). Unique.
    pub name: String,
    /// Absolute path to the `.kdbx` file.
    pub path: PathBuf,
    /// Optional key file that pairs with the master password.
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Configured databases. Non-empty; `vaults[0]` is the default/active one at
    /// startup.
    pub vaults: Vec<VaultConfig>,
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

impl Config {
    /// Index of the vault named `name`, or an error listing the valid names.
    pub fn vault_index(&self, name: &str) -> Result<usize, String> {
        self.vaults
            .iter()
            .position(|v| v.name == name)
            .ok_or_else(|| {
                let names: Vec<&str> = self.vaults.iter().map(|v| v.name.as_str()).collect();
                format!("no vault named `{name}` (have: {})", names.join(", "))
            })
    }
}

/// Common options shared by both config shapes.
#[derive(Debug, Default, Deserialize)]
struct RawCommon {
    idle_lock_seconds: Option<u64>,
    clipboard_clear_seconds: Option<u64>,
    allow_inline_unlock: Option<bool>,
    pinentry_program: Option<String>,
    socket_path: Option<String>,
}

/// `vault = "…"` (+ optional top-level `keyfile`) — the single-database form.
/// (`deny_unknown_fields` can't be combined with `flatten`; typos in top-level
/// keys are silently ignored.)
#[derive(Debug, Deserialize)]
struct RawSingle {
    vault: String,
    keyfile: Option<String>,
    #[serde(flatten)]
    common: RawCommon,
}

/// `[[vault]]` tables — the multi-database form.
#[derive(Debug, Deserialize)]
struct RawMulti {
    #[serde(default)]
    vault: Vec<RawVault>,
    #[serde(flatten)]
    common: RawCommon,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVault {
    name: Option<String>,
    path: String,
    keyfile: Option<String>,
}

impl Config {
    pub fn config_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("com", "xavidiaz", "omarkey")
            .context("cannot determine config directory")?;
        Ok(dirs.config_dir().join("omarkeyd.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "no config at {}. Create it with at least:\n\n  vault = \"/home/you/secrets.kdbx\"\n",
                    path.display()
                );
            }
            Err(err) => return Err(err).context(format!("reading {}", path.display())),
        };
        Self::from_toml_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Split out for tests.
    pub fn from_toml_str(text: &str) -> Result<Self> {
        // `vault` is either an array of tables ([[vault]]) or a single string.
        // Try the multi shape first; if `vault` is a string that fails and we
        // fall back to the single shape.
        let (vaults, common): (Vec<VaultConfig>, RawCommon) = match toml::from_str::<RawMulti>(text)
        {
            Ok(multi) => {
                let vaults = multi
                    .vault
                    .iter()
                    .map(|rv| build_vault(rv.name.as_deref(), &rv.path, rv.keyfile.as_deref()))
                    .collect::<Result<Vec<_>>>()?;
                (vaults, multi.common)
            }
            Err(multi_err) => {
                let single =
                    toml::from_str::<RawSingle>(text).map_err(|_| anyhow::anyhow!(multi_err))?;
                let v = build_vault(None, &single.vault, single.keyfile.as_deref())?;
                (vec![v], single.common)
            }
        };

        if vaults.is_empty() {
            bail!("no vault configured. Add `vault = \"/path/to.kdbx\"` or one or more [[vault]] tables");
        }
        // Reject duplicate names — `omarkey unlock <name>` must be unambiguous.
        for i in 0..vaults.len() {
            if vaults[i + 1..].iter().any(|v| v.name == vaults[i].name) {
                bail!("two vaults are both named `{}`", vaults[i].name);
            }
        }

        Ok(Config {
            vaults,
            idle_lock: match common.idle_lock_seconds {
                Some(0) => None,
                Some(secs) => Some(Duration::from_secs(secs)),
                None => Some(Duration::from_secs(300)),
            },
            clipboard_clear: Duration::from_secs(common.clipboard_clear_seconds.unwrap_or(20)),
            allow_inline_unlock: common.allow_inline_unlock.unwrap_or(false),
            pinentry_program: common.pinentry_program,
            socket_path: common.socket_path.map(|s| expand_tilde(&s)),
        })
    }
}

fn build_vault(name: Option<&str>, path: &str, keyfile: Option<&str>) -> Result<VaultConfig> {
    let path = expand_tilde(path);
    if !path.is_absolute() {
        bail!(
            "vault path `{}` must be absolute (or start with ~/)",
            path.display()
        );
    }
    let name = match name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "vault".to_string()),
    };
    Ok(VaultConfig {
        name,
        path,
        keyfile: keyfile.map(expand_tilde),
    })
}

fn expand_tilde(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = directories::UserDirs::new().map(|d| d.home_dir().to_path_buf()) {
            return home.join(rest);
        }
    }
    PathBuf::from(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_vault_shorthand() {
        let c = Config::from_toml_str(r#"vault = "/home/x/secrets.kdbx""#).unwrap();
        assert_eq!(c.vaults.len(), 1);
        assert_eq!(c.vaults[0].name, "secrets");
        assert_eq!(c.vaults[0].path, PathBuf::from("/home/x/secrets.kdbx"));
        assert_eq!(c.idle_lock, Some(Duration::from_secs(300)));
    }

    #[test]
    fn single_vault_with_keyfile() {
        let c = Config::from_toml_str(
            "vault = \"/v/a.kdbx\"\nkeyfile = \"/v/a.keyx\"\nidle_lock_seconds = 0\n",
        )
        .unwrap();
        assert_eq!(c.vaults[0].keyfile, Some(PathBuf::from("/v/a.keyx")));
        assert_eq!(c.idle_lock, None);
    }

    #[test]
    fn multi_vault_array() {
        let c = Config::from_toml_str(
            r#"
            allow_inline_unlock = true

            [[vault]]
            name = "personal"
            path = "/home/x/personal.kdbx"

            [[vault]]
            path = "/home/x/work.kdbx"
            keyfile = "/home/x/work.keyx"
            "#,
        )
        .unwrap();
        assert_eq!(c.vaults.len(), 2);
        assert_eq!(c.vaults[0].name, "personal");
        assert_eq!(c.vaults[1].name, "work"); // derived from file stem
        assert_eq!(
            c.vaults[1].keyfile,
            Some(PathBuf::from("/home/x/work.keyx"))
        );
        assert!(c.allow_inline_unlock);
        assert_eq!(c.vault_index("work"), Ok(1));
        assert!(c.vault_index("nope").is_err());
    }

    #[test]
    fn rejects_duplicate_names() {
        let err = Config::from_toml_str(
            r#"
            [[vault]]
            name = "a"
            path = "/x/one.kdbx"
            [[vault]]
            name = "a"
            path = "/x/two.kdbx"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("named `a`"));
    }

    #[test]
    fn rejects_empty() {
        assert!(Config::from_toml_str("idle_lock_seconds = 60").is_err());
    }
}
