# CLAUDE.md

Guidance for Claude Code working in this repository.

## What Omarkey is

A KeePass (`.kdbx`) credential picker for the [Omarchy](https://omarchy.org)
Quickshell desktop. **Two processes, on purpose:**

| Part | Path | Language | Sees plaintext secrets? |
|------|------|----------|-------------------------|
| Overlay plugin | repo root (`manifest.json`, `Menu.qml`, `OmarkeyClient.qml`) | QML | **No** — metadata only (title, username, group) |
| `omarkeyd` daemon | `daemon/` | Rust (tokio) | Yes, and nothing else does |

They talk newline-delimited JSON over `$XDG_RUNTIME_DIR/omarkey.sock` (mode
0600). The wire contract is [`PROTOCOL.md`](PROTOCOL.md) — keep it in sync with
any change to `daemon/src/ipc.rs` or `OmarkeyClient.qml`.

## Architectural rules — do not violate

- **The QML side never receives a secret.** `list`/`get` return metadata only;
  passwords, notes, TOTP codes, and custom string fields leave the daemon only
  via `copy` (→ `wl-copy`) or `type` (→ `wtype`), with the value on **stdin**,
  never as a process argument.
- **The master password does not cross the socket** by default — `omarkeyd`
  runs its own `pinentry`. Inline-password `unlock` is gated behind
  `allow_inline_unlock` in the config and is for headless use only.
- Decrypted data lives only in `vault::UnlockedVault`, wrapped in
  `secrecy::SecretString` so it zeroizes on drop. Every lock path drops it.
- The plugin `kind` is **`overlay`**, NOT `menu`. `menu` is Omarchy's built-in
  JSONC command menu. Model the UI on the first-party `emojis` / `clipboard`
  overlays (`/usr/share/omarchy/shell/plugins/`).

## Layout

```
manifest.json          Omarchy plugin manifest (kind: overlay, keepLoaded)
Menu.qml               overlay surface: search field + entry ListView + keybinds
OmarkeyClient.qml      socket bridge — id-correlated requests, events, reconnect
PROTOCOL.md            authoritative IPC spec
daemon/
  src/main.rs          socket bind + hardening, accept loop, select! on shutdown
  src/config.rs        ~/.config/omarkey/omarkeyd.toml
  src/ipc.rs           Request/Response/Event types + dispatch for every op
  src/vault.rs         VaultState (Locked/Unlocking/Unlocked), keepass parsing,
                       fuzzy list, .kdbx file watch, tests
  src/security.rs      socket perms + peer-uid check, idle clock, logind
                       Lock/PrepareForSleep auto-lock, pinentry (Assuan)
  src/actions.rs       wl-copy / wl-paste-verify / wl-clear, wtype
  examples/make-sample-vault.rs   writes a throwaway .kdbx for testing
  omarkeyd.service     systemd user unit
  omarkeyd.example.toml
```

## Commands

All from `daemon/`:

```sh
cargo build
cargo test              # 3 round-trip tests in vault.rs; keep them green
cargo clippy --all-targets
cargo fmt

# generate a test database, then run the daemon against it
cargo run --example make-sample-vault -- /tmp/demo.kdbx demopass
```

There is no automated check for the QML — it must be exercised against a running
`omarchy-shell` (`omarchy-shell shell summon omarkey '{}'`).

## Dependencies of note

- **`keepass`** is the pure-Rust KDBX crate — no dependency on KeePassXC or any
  system library. `keepass = { features = ["totp"] }`; `save_kdbx4` is a
  dev-dependency for the tests/example.
- `totp-rs` needs `features = ["otpauth"]` for `TOTP::from_url` / `get_url`.
- Runtime tools the daemon shells out to: `wl-clipboard` (`wl-copy`/`wl-paste`),
  `wtype`, `pinentry`. `zbus` talks to `org.freedesktop.login1` for auto-lock.

## Status (2026-09-08)

Daemon works: build/test/clippy clean, verified end to end over the socket
against a real `.kdbx` (unlock → list → get → copy + clipboard wipe → totp).
Not yet proven: the QML side against a live shell, and the pinentry unlock path
(only inline-password has been exercised).

## Conventions

- Match the surrounding style. The Rust is plain tokio + `anyhow`/`thiserror`,
  no macros beyond derives. QML follows the first-party Omarchy plugin idiom
  (`qs.Commons` / `qs.Ui` tokens, `keyCatcher` Item, `Util.editsFilter`).
- Commit messages: imperative subject, a body explaining why + what was
  verified. Co-author trailer as configured.
- Update `PROTOCOL.md` and `CLAUDE.md` in the same commit as the code they
  describe.
