//! Wire protocol: newline-delimited JSON over the Unix socket.
//!
//! One [`Request`] per line in, one [`Response`] per line out, plus unsolicited
//! [`Event`] lines on connections that sent `subscribe`. See `PROTOCOL.md` for
//! the authoritative description.

use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::debug;

use crate::vault::CopyField;
use crate::Daemon;

pub const PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------- requests

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: Option<i64>,
    pub op: String,
    #[serde(flatten)]
    pub args: Value,
}

// ---------------------------------------------------------------- responses

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: Option<i64>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl Response {
    fn ok(id: Option<i64>, result: Value) -> Self {
        Response { id, ok: true, result: Some(result), error: None }
    }

    fn err(id: Option<i64>, err: IpcError) -> Self {
        Response {
            id,
            ok: false,
            result: None,
            error: Some(ErrorBody { code: err.code(), message: err.to_string() }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("vault is locked")]
    Locked,
    #[error("wrong master password or key file")]
    AuthFailed,
    #[error("no entry with uuid {0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("vault error: {0}")]
    VaultError(String),
    #[error("{0}")]
    IoError(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("another unlock is already in progress")]
    Busy,
}

impl IpcError {
    fn code(&self) -> &'static str {
        match self {
            IpcError::Locked => "locked",
            IpcError::AuthFailed => "auth-failed",
            IpcError::NotFound(_) => "not-found",
            IpcError::BadRequest(_) => "bad-request",
            IpcError::VaultError(_) => "vault-error",
            IpcError::IoError(_) => "io-error",
            IpcError::Unsupported(_) => "unsupported",
            IpcError::Busy => "busy",
        }
    }
}

// ---------------------------------------------------------------- events

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    Unlocked {
        #[serde(rename = "entryCount")]
        entry_count: usize,
    },
    Locked {
        reason: LockReason,
    },
    VaultChanged {},
    ClipboardCleared {
        uuid: String,
        field: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockReason {
    Idle,
    Manual,
    SessionLock,
    Sleep,
}

// ---------------------------------------------------------------- connection loop

pub async fn serve_connection(daemon: Arc<Daemon>, stream: UnixStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    let mut events = daemon.events.subscribe();
    let mut subscribed = false;

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { break };
                if line.trim().is_empty() { continue }

                let response = handle_line(&daemon, &line, &mut subscribed).await;
                let mut buf = serde_json::to_vec(&response)?;
                buf.push(b'\n');
                write_half.write_all(&buf).await?;
                write_half.flush().await?;
            }

            event = events.recv(), if subscribed => {
                match event {
                    Ok(event) => {
                        let mut buf = serde_json::to_vec(&event)?;
                        buf.push(b'\n');
                        write_half.write_all(&buf).await?;
                        write_half.flush().await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        debug!(dropped = n, "subscriber lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

async fn handle_line(daemon: &Arc<Daemon>, line: &str, subscribed: &mut bool) -> Response {
    let request: Request = match serde_json::from_str(line) {
        Ok(req) => req,
        Err(err) => {
            return Response::err(None, IpcError::BadRequest(format!("invalid JSON: {err}")));
        }
    };
    let id = request.id;
    daemon.activity.touch();

    match dispatch(daemon, &request, subscribed).await {
        Ok(result) => Response::ok(id, result),
        Err(err) => Response::err(id, err),
    }
}

async fn dispatch(
    daemon: &Arc<Daemon>,
    req: &Request,
    subscribed: &mut bool,
) -> Result<Value, IpcError> {
    match req.op.as_str() {
        "hello" => {
            let vault = daemon.vault.lock().await;
            Ok(json!({
                "daemonVersion": env!("CARGO_PKG_VERSION"),
                "protocol": PROTOCOL_VERSION,
                "vaultPath": daemon.config.vault_path.to_string_lossy(),
                "locked": vault.is_locked(),
                "capabilities": ["copy", "type", "totp", "pinentry"],
            }))
        }

        "status" => {
            let vault = daemon.vault.lock().await;
            Ok(json!({
                "locked": vault.is_locked(),
                "entryCount": vault.entry_count(),
                "vaultPath": daemon.config.vault_path.to_string_lossy(),
                "idleLockInSec": daemon.activity.remaining_lock_secs(&daemon.config),
            }))
        }

        "unlock" => {
            let password = req.args.get("password").and_then(Value::as_str);
            let keyfile = req.args.get("keyfile").and_then(Value::as_str);
            if password.is_some() && !daemon.config.allow_inline_unlock {
                return Err(IpcError::Unsupported(
                    "inline-password unlock is disabled; enable allow_inline_unlock or use pinentry"
                        .into(),
                ));
            }
            let mut vault = daemon.vault.lock().await;
            let count = vault
                .unlock(daemon, password, keyfile)
                .await?;
            Ok(json!({ "unlocked": true, "entryCount": count }))
        }

        "lock" => {
            let mut vault = daemon.vault.lock().await;
            vault.lock_now(daemon, LockReason::Manual);
            Ok(json!({ "locked": true }))
        }

        "list" => {
            let query = req.args.get("query").and_then(Value::as_str).unwrap_or("");
            let limit = req
                .args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(200) as usize;
            let vault = daemon.vault.lock().await;
            let entries = vault.list(query, limit)?;
            Ok(json!({ "entries": entries }))
        }

        "get" => {
            let uuid = require_str(req, "uuid")?;
            let fields: Vec<String> = req
                .args
                .get("fields")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let vault = daemon.vault.lock().await;
            let fields = vault.get_fields(uuid, &fields)?;
            Ok(json!({ "uuid": uuid, "fields": fields }))
        }

        "copy" => {
            let uuid = require_str(req, "uuid")?.to_string();
            let field: CopyField = require_str(req, "field")?.parse()?;
            let clear_after = req
                .args
                .get("clearAfterMs")
                .and_then(Value::as_u64)
                .map(std::time::Duration::from_millis)
                .unwrap_or(daemon.config.clipboard_clear);

            let value = {
                let vault = daemon.vault.lock().await;
                vault.secret_for(&uuid, &field)?
            };
            daemon
                .clipboard
                .copy(daemon.clone(), &uuid, &field, value, clear_after)
                .await
                .map_err(|e| IpcError::IoError(e.to_string()))?;

            Ok(json!({
                "copied": true,
                "field": field.as_str(),
                "clearsInMs": clear_after.as_millis() as u64,
            }))
        }

        "type" => {
            let uuid = require_str(req, "uuid")?.to_string();
            let sequence = req
                .args
                .get("sequence")
                .and_then(Value::as_str)
                .or_else(|| req.args.get("field").and_then(Value::as_str))
                .unwrap_or("password")
                .to_string();

            let tokens = {
                let vault = daemon.vault.lock().await;
                vault.resolve_type_sequence(&uuid, &sequence)?
            };
            crate::actions::type_tokens(&tokens)
                .await
                .map_err(|e| IpcError::IoError(e.to_string()))?;
            Ok(json!({ "typed": true }))
        }

        "totp" => {
            let uuid = require_str(req, "uuid")?;
            let vault = daemon.vault.lock().await;
            Ok(vault.totp_meta(uuid)?)
        }

        "subscribe" => {
            *subscribed = true;
            Ok(json!({ "subscribed": true }))
        }

        other => Err(IpcError::BadRequest(format!("unknown op: {other}"))),
    }
}

fn require_str<'a>(req: &'a Request, key: &str) -> Result<&'a str, IpcError> {
    req.args
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| IpcError::BadRequest(format!("missing string field `{key}`")))
}
