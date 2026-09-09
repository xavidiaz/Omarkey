//! `omarkey` — the command-line client for a running `omarkeyd`.
//!
//! Its main job is `omarkey unlock`: with no Omarkey overlay on screen, the
//! daemon's pinentry prompt is visible and focusable. Bind it to a key or run
//! it at login. The picker (`Menu.qml`) never triggers an unlock itself.
//!
//!   omarkey unlock          decrypt the vault (daemon shows pinentry)
//!   omarkey lock            drop the vault from memory
//!   omarkey status          print JSON state
//!   omarkey list [query]    print matching entry metadata (no secrets)
//!   omarkey hello           handshake / capability probe

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{json, Value};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("status");

    let request = match cmd {
        "unlock" => json!({ "id": 1, "op": "unlock" }),
        "lock" => json!({ "id": 1, "op": "lock" }),
        "status" => json!({ "id": 1, "op": "status" }),
        "hello" => json!({ "id": 1, "op": "hello" }),
        "list" => {
            json!({ "id": 1, "op": "list", "query": args.get(1).cloned().unwrap_or_default() })
        }
        "-h" | "--help" | "help" => {
            eprintln!(
                "omarkey <command>\n\n  \
                 unlock        decrypt the vault (daemon shows pinentry)\n  \
                 lock          drop the vault from memory\n  \
                 status        print JSON state\n  \
                 list [query]  print matching entry metadata\n  \
                 hello         handshake\n\n\
                 socket: $OMARKEY_SOCKET or $XDG_RUNTIME_DIR/omarkey.sock"
            );
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("omarkey: unknown command '{other}' (try --help)");
            return ExitCode::from(2);
        }
    };

    let socket = std::env::var("OMARKEY_SOCKET").unwrap_or_else(|_| {
        let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());
        format!("{runtime}/omarkey.sock")
    });

    let stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("omarkey: cannot reach omarkeyd at {socket}: {e}");
            eprintln!("        is the omarkeyd service running?");
            return ExitCode::from(1);
        }
    };
    // unlock blocks on a human typing into pinentry; give it room.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));

    let mut writer = &stream;
    if writeln!(writer, "{request}")
        .and_then(|_| writer.flush())
        .is_err()
    {
        eprintln!("omarkey: failed to send request");
        return ExitCode::from(1);
    }

    let mut line = String::new();
    if BufReader::new(&stream).read_line(&mut line).is_err() || line.trim().is_empty() {
        eprintln!("omarkey: no response from omarkeyd");
        return ExitCode::from(1);
    }

    let response: Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("omarkey: unparseable response: {e}");
            return ExitCode::from(1);
        }
    };

    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        match response.get("result") {
            Some(result) => println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            ),
            None => println!("ok"),
        }
        ExitCode::SUCCESS
    } else {
        let err = response.get("error");
        let code = err
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("error");
        let msg = err
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        eprintln!("omarkey: {msg} ({code})");
        ExitCode::from(1)
    }
}
