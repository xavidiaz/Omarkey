//! The vault: locked/unlocked state plus all KeePass access.
//!
//! Secrets live only inside [`UnlockedVault`] and are wrapped in
//! [`secrecy::SecretString`] so they zeroize on drop. Metadata (`EntryMeta`)
//! carries no secret and is the only thing that leaves this module toward the
//! socket.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::config::Config;
use crate::ipc::{Event, IpcError, LockReason};
use crate::security::pinentry;
use crate::Daemon;

// ---------------------------------------------------------------- state

pub enum VaultState {
    Locked,
    Unlocked(UnlockedVault),
    /// An unlock (pinentry prompt) is in flight; reject concurrent attempts.
    Unlocking,
}

impl VaultState {
    pub fn locked(_config: &Config) -> Self {
        VaultState::Locked
    }

    pub fn is_locked(&self) -> bool {
        !matches!(self, VaultState::Unlocked(_))
    }

    pub fn entry_count(&self) -> usize {
        match self {
            VaultState::Unlocked(v) => v.entries.len(),
            _ => 0,
        }
    }

    fn unlocked(&self) -> Result<&UnlockedVault, IpcError> {
        match self {
            VaultState::Unlocked(v) => Ok(v),
            _ => Err(IpcError::Locked),
        }
    }

    /// Decrypt the vault. `password`/`keyfile` come from the request only when
    /// inline unlock is enabled; otherwise the master password is collected by
    /// the daemon's own pinentry.
    pub async fn unlock(
        &mut self,
        daemon: &Arc<Daemon>,
        password: Option<&str>,
        keyfile_override: Option<&str>,
    ) -> Result<usize, IpcError> {
        match self {
            VaultState::Unlocked(v) => return Ok(v.entries.len()),
            VaultState::Unlocking => return Err(IpcError::Busy),
            VaultState::Locked => {}
        }
        *self = VaultState::Unlocking;

        let result = Self::do_unlock(daemon, password, keyfile_override).await;

        match result {
            Ok(unlocked) => {
                let count = unlocked.entries.len();
                *self = VaultState::Unlocked(unlocked);
                daemon.activity.touch();
                daemon.emit(Event::Unlocked { entry_count: count });
                info!(entries = count, "vault unlocked");
                Ok(count)
            }
            Err(err) => {
                *self = VaultState::Locked;
                Err(err)
            }
        }
    }

    async fn do_unlock(
        daemon: &Arc<Daemon>,
        password: Option<&str>,
        keyfile_override: Option<&str>,
    ) -> Result<UnlockedVault, IpcError> {
        let config = &daemon.config;

        let secret: SecretString = match password {
            Some(p) => SecretString::from(p.to_owned()),
            None => pinentry::prompt_master_password(config)
                .await
                .map_err(|e| IpcError::IoError(format!("pinentry: {e}")))?,
        };

        let keyfile = keyfile_override
            .map(std::path::PathBuf::from)
            .or_else(|| config.keyfile_path.clone());

        // NOTE: exact `keepass` API surface depends on the crate version; this
        // is the shape (open with key elements, walk the group tree).
        let entries = open_kdbx(&config.vault_path, &secret, keyfile.as_deref())
            .map_err(|e| match e {
                KdbxError::WrongKey => IpcError::AuthFailed,
                KdbxError::Other(msg) => IpcError::VaultError(msg),
            })?;

        Ok(UnlockedVault { entries })
    }

    pub fn lock_now(&mut self, daemon: &Arc<Daemon>, reason: LockReason) {
        if matches!(self, VaultState::Locked) {
            return;
        }
        // Dropping UnlockedVault zeroizes every SecretString it holds.
        *self = VaultState::Locked;
        daemon.emit(Event::Locked { reason });
        info!(?reason, "vault locked");
    }

    // ---- metadata / secret access, all require Unlocked -----------------

    pub fn list(&self, query: &str, limit: usize) -> Result<Vec<EntryMeta>, IpcError> {
        let v = self.unlocked()?;
        let mut scored: Vec<(i64, &Entry)> = v
            .entries
            .iter()
            .filter_map(|e| fuzzy_score(query, e).map(|s| (s, e)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.title.cmp(&b.1.title)));
        Ok(scored.into_iter().take(limit).map(|(_, e)| e.meta()).collect())
    }

    pub fn get_fields(
        &self,
        uuid: &str,
        fields: &[String],
    ) -> Result<Value, IpcError> {
        let entry = self.unlocked()?.find(uuid)?;
        let mut out = serde_json::Map::new();
        for field in fields {
            match field.as_str() {
                "password" | "notes" => {
                    return Err(IpcError::Unsupported(format!(
                        "`{field}` is a secret; use copy or type"
                    )))
                }
                "username" => {
                    out.insert("username".into(), json!(entry.username));
                }
                "url" => {
                    out.insert("url".into(), json!(entry.url));
                }
                "title" => {
                    out.insert("title".into(), json!(entry.title));
                }
                "group" => {
                    out.insert("group".into(), json!(entry.group));
                }
                other => {
                    out.insert(other.to_string(), json!(entry.string_fields.get(other)));
                }
            }
        }
        Ok(Value::Object(out))
    }

    pub fn secret_for(&self, uuid: &str, field: &CopyField) -> Result<SecretString, IpcError> {
        let entry = self.unlocked()?.find(uuid)?;
        entry.secret(field)
    }

    pub fn resolve_type_sequence(
        &self,
        uuid: &str,
        sequence: &str,
    ) -> Result<Vec<TypeToken>, IpcError> {
        let entry = self.unlocked()?.find(uuid)?;
        let mut tokens = Vec::new();
        for raw in sequence.split_whitespace() {
            let token = match raw.to_ascii_lowercase().as_str() {
                "tab" => TypeToken::Key("Tab".into()),
                "enter" | "return" => TypeToken::Key("Return".into()),
                "escape" | "esc" => TypeToken::Key("Escape".into()),
                _ if raw.starts_with('~') => {
                    let ms = raw[1..].parse::<u64>().map_err(|_| {
                        IpcError::BadRequest(format!("bad delay token `{raw}`"))
                    })?;
                    TypeToken::Delay(Duration::from_millis(ms))
                }
                other => {
                    let field: CopyField = other.parse()?;
                    TypeToken::Text(entry.secret(&field)?)
                }
            };
            tokens.push(token);
        }
        Ok(tokens)
    }

    pub fn totp_meta(&self, uuid: &str) -> Result<Value, IpcError> {
        let entry = self.unlocked()?.find(uuid)?;
        match &entry.totp {
            Some(totp) => {
                let period = totp.step;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                Ok(json!({
                    "hasTotp": true,
                    "period": period,
                    "remainingSec": period - (now % period),
                    "digits": totp.digits,
                }))
            }
            None => Ok(json!({ "hasTotp": false })),
        }
    }
}

// ---------------------------------------------------------------- unlocked data

pub struct UnlockedVault {
    entries: Vec<Entry>,
}

impl UnlockedVault {
    fn find(&self, uuid: &str) -> Result<&Entry, IpcError> {
        self.entries
            .iter()
            .find(|e| e.uuid == uuid)
            .ok_or_else(|| IpcError::NotFound(uuid.to_string()))
    }
}

pub struct Entry {
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub group: String,
    pub tags: Vec<String>,
    pub password: Option<SecretString>,
    pub notes: Option<SecretString>,
    pub string_fields: std::collections::HashMap<String, SecretString>,
    pub totp: Option<totp_rs::TOTP>,
}

impl Entry {
    fn meta(&self) -> EntryMeta {
        EntryMeta {
            uuid: self.uuid.clone(),
            title: self.title.clone(),
            username: self.username.clone(),
            group: self.group.clone(),
            url: self.url.clone(),
            has_password: self.password.is_some(),
            has_totp: self.totp.is_some(),
            tags: self.tags.clone(),
        }
    }

    fn secret(&self, field: &CopyField) -> Result<SecretString, IpcError> {
        match field {
            CopyField::Password => self
                .password
                .clone()
                .ok_or_else(|| IpcError::NotFound("password".into())),
            CopyField::Username => Ok(SecretString::from(self.username.clone())),
            CopyField::Url => Ok(SecretString::from(self.url.clone())),
            CopyField::Notes => self
                .notes
                .clone()
                .ok_or_else(|| IpcError::NotFound("notes".into())),
            CopyField::Totp => {
                let totp = self
                    .totp
                    .as_ref()
                    .ok_or_else(|| IpcError::NotFound("totp".into()))?;
                totp.generate_current()
                    .map(SecretString::from)
                    .map_err(|e| IpcError::VaultError(e.to_string()))
            }
            CopyField::OtpUri => {
                let totp = self
                    .totp
                    .as_ref()
                    .ok_or_else(|| IpcError::NotFound("totp".into()))?;
                Ok(SecretString::from(totp.get_url()))
            }
            CopyField::Custom(name) => self
                .string_fields
                .get(name)
                .cloned()
                .ok_or_else(|| IpcError::NotFound(name.clone())),
        }
    }
}

/// Secret-free metadata. The only entry data that reaches the socket.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryMeta {
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub group: String,
    pub url: String,
    pub has_password: bool,
    pub has_totp: bool,
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------- copy fields

#[derive(Debug, Clone)]
pub enum CopyField {
    Password,
    Username,
    Url,
    Notes,
    Totp,
    OtpUri,
    Custom(String),
}

impl CopyField {
    pub fn as_str(&self) -> String {
        match self {
            CopyField::Password => "password".into(),
            CopyField::Username => "username".into(),
            CopyField::Url => "url".into(),
            CopyField::Notes => "notes".into(),
            CopyField::Totp => "totp".into(),
            CopyField::OtpUri => "otp-uri".into(),
            CopyField::Custom(s) => s.clone(),
        }
    }
}

impl FromStr for CopyField {
    type Err = IpcError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "password" | "pass" => CopyField::Password,
            "username" | "user" => CopyField::Username,
            "url" => CopyField::Url,
            "notes" | "note" => CopyField::Notes,
            "totp" | "otp" => CopyField::Totp,
            "otp-uri" | "otpauth" => CopyField::OtpUri,
            "" => return Err(IpcError::BadRequest("empty field name".into())),
            _ => CopyField::Custom(s.to_string()),
        })
    }
}

pub enum TypeToken {
    Text(SecretString),
    Key(String),
    Delay(Duration),
}

impl TypeToken {
    pub fn expose(&self) -> TypeTokenRef<'_> {
        match self {
            TypeToken::Text(s) => TypeTokenRef::Text(s.expose_secret()),
            TypeToken::Key(k) => TypeTokenRef::Key(k),
            TypeToken::Delay(d) => TypeTokenRef::Delay(*d),
        }
    }
}

pub enum TypeTokenRef<'a> {
    Text(&'a str),
    Key(&'a str),
    Delay(Duration),
}

// ---------------------------------------------------------------- kdbx loading

enum KdbxError {
    WrongKey,
    Other(String),
}

/// Open the database and flatten its group tree into `Entry` values.
///
/// Left as a focused seam: wire this to the installed `keepass` crate version.
/// The rest of the module only depends on the returned `Vec<Entry>`.
fn open_kdbx(
    _path: &Path,
    _password: &SecretString,
    _keyfile: Option<&Path>,
) -> Result<Vec<Entry>, KdbxError> {
    // Sketch with keepass 0.7:
    //
    //   let mut file = std::fs::File::open(path).map_err(|e| KdbxError::Other(e.to_string()))?;
    //   let key = {
    //       let mut k = keepass::DatabaseKey::new();
    //       k = k.with_password(password.expose_secret());
    //       if let Some(kf) = keyfile {
    //           let mut f = std::fs::File::open(kf).map_err(|e| KdbxError::Other(e.to_string()))?;
    //           k = k.with_keyfile(&mut f).map_err(|e| KdbxError::Other(e.to_string()))?;
    //       }
    //       k
    //   };
    //   let db = keepass::Database::open(&mut file, key).map_err(|e| match e {
    //       keepass::error::DatabaseOpenError::Crypto(_) => KdbxError::WrongKey,
    //       other => KdbxError::Other(other.to_string()),
    //   })?;
    //   let mut out = Vec::new();
    //   walk_group(&db.root, String::new(), &mut out);
    //   Ok(out)
    Err(KdbxError::Other(
        "open_kdbx not yet wired to the keepass crate".into(),
    ))
}

// ---------------------------------------------------------------- fuzzy match

fn fuzzy_score(query: &str, entry: &Entry) -> Option<i64> {
    if query.is_empty() {
        return Some(0);
    }
    let q = query.to_lowercase();
    let haystacks = [
        (&entry.title, 100),
        (&entry.username, 40),
        (&entry.url, 30),
        (&entry.group, 20),
    ];
    let mut best: Option<i64> = None;
    for (text, weight) in haystacks {
        let t = text.to_lowercase();
        if let Some(pos) = t.find(&q) {
            let score = weight - pos as i64 + if pos == 0 { 25 } else { 0 };
            best = Some(best.map_or(score, |b| b.max(score)));
        }
    }
    if best.is_none() {
        // subsequence match on the title as a fallback
        if is_subsequence(&q, &entry.title.to_lowercase()) {
            best = Some(5);
        }
    }
    best
}

fn is_subsequence(needle: &str, haystack: &str) -> bool {
    let mut hay = haystack.chars();
    needle.chars().all(|c| hay.any(|h| h == c))
}

// ---------------------------------------------------------------- file watch

pub async fn watch_vault_file(daemon: Arc<Daemon>) {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut watcher = match RecommendedWatcher::new(
        move |res| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        },
        notify::Config::default(),
    ) {
        Ok(w) => w,
        Err(err) => {
            warn!(%err, "vault file watch disabled");
            return;
        }
    };

    let path = daemon.config.vault_path.clone();
    if let Err(err) = watcher.watch(&path, RecursiveMode::NonRecursive) {
        warn!(%err, "cannot watch vault file");
        return;
    }

    let mut debounce = tokio::time::interval(Duration::from_millis(500));
    let mut dirty = false;
    loop {
        tokio::select! {
            Some(_event) = rx.recv() => { dirty = true; }
            _ = debounce.tick() => {
                if dirty {
                    dirty = false;
                    daemon.emit(Event::VaultChanged {});
                }
            }
            else => break,
        }
    }
}
