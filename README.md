# Omarkey

A KeePass picker for [Omarchy](https://omarchy.org). Press a key, search your
`.kdbx`, hit Enter — the password lands on your clipboard and wipes itself a few
seconds later.

Omarkey is **two processes on purpose**:

| Part | What it is | Sees secrets? |
|------|------------|---------------|
| **Menu.qml** (this repo root) | An Omarchy shell *overlay* plugin. Search field + entry list. | **No.** Only titles, usernames, groups. |
| **omarkeyd** (`daemon/`) | A standalone Rust daemon. Holds the decrypted vault in zeroized RAM, owns a Unix socket, runs `wl-copy` / `wtype` itself. | Yes, and nothing else does. |

The two talk newline-delimited JSON over `$XDG_RUNTIME_DIR/omarkey.sock`
(mode 0600). Protocol: [`PROTOCOL.md`](PROTOCOL.md).

```
┌─────────────────────────┐         ┌──────────────────────────┐
│      omarchy-shell      │  JSON   │        omarkeyd          │
│  ┌───────────────────┐  │ ◄─────► │  ┌────────────────────┐  │
│  │ Menu.qml          │  │  unix   │  │ vault (RAM, zeroized)│ │
│  │ OmarkeyClient.qml │──┼─socket──┼─►│ wl-copy / wtype     │  │
│  └───────────────────┘  │  0600   │  │ pinentry            │  │
│   metadata only         │         │  │ logind auto-lock    │  │
└─────────────────────────┘         └──────────────────────────┘
                                       reads ~/secrets.kdbx
```

## Install

### 1. The daemon (you build this — the plugin installer never runs code)

Requires a Rust toolchain, plus `wl-clipboard`, `wtype`, and `pinentry` on
`PATH`.

```sh
git clone https://github.com/xavidiaz/omarkey
cd omarkey
cargo install --path daemon           # → ~/.local/bin/omarkeyd

mkdir -p ~/.config/omarkey
cp daemon/omarkeyd.example.toml ~/.config/omarkey/omarkeyd.toml
$EDITOR ~/.config/omarkey/omarkeyd.toml   # set `vault = "..."`
```

Run it as a systemd user service:

```sh
mkdir -p ~/.config/systemd/user
cp daemon/omarkeyd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now omarkeyd.service
```

(Or add `~/.local/bin/omarkeyd &` to your Hyprland `exec-once`. Don't put it in
the plugin manifest — Omarchy would never start it anyway.)

### 2. The plugin

```sh
omarchy plugin add https://github.com/xavidiaz/omarkey
```

This clones the repo root to `~/.config/omarchy/plugins/omarkey/`. Only
`manifest.json`, `Menu.qml`, and `OmarkeyClient.qml` matter to Omarchy; the
`daemon/` directory is ignored.

### 3. A keybind

`~/.config/hypr/bindings.conf`:

```
bindd = SUPER, P, Omarkey, exec, omarchy-shell shell toggle omarkey '{}'
```

## Use

| Key | Action |
|-----|--------|
| type | filter |
| ↑ / ↓ | move | 
| Enter | copy password (auto-clears) |
| Shift+Enter | copy username |
| Alt+Enter | type `username ⇥ password` |
| Ctrl+Enter | type password only |
| Ctrl+T | copy TOTP |
| Ctrl+L | lock the vault now |
| Esc | clear filter, then close |

First open triggers an `unlock`: omarkeyd pops its own pinentry for the master
password. The vault re-locks on idle timeout, on session lock, and before sleep.

## Security notes

- The master password is collected by omarkeyd's pinentry and **never crosses
  the socket** (unless you set `allow_inline_unlock`).
- Secrets are passed to `wl-copy` / `wtype` on **stdin**, never argv — nothing
  shows up in `ps` or `/proc/<pid>/cmdline`.
- The decrypted vault is `zeroize`d on drop; every lock path drops it.
- The socket is `0600` and omarkeyd checks the peer uid and that
  `$XDG_RUNTIME_DIR` isn't group/world writable.
- The systemd unit sets `LimitCORE=0` and `MemoryDenyWriteExecute` to keep the
  vault out of core dumps.
- Omarkey does not protect against a compromised session: anything that can read
  your clipboard or inject keystrokes can get what Omarkey just typed.

## Status

The daemon is functional. `cargo build` / `cargo clippy` / `cargo test` are
clean, and it has been driven end to end over the socket against a real `.kdbx`:
`unlock` → `list` (fuzzy) → `get` → `copy` (with a verified clipboard wipe) →
`totp` (parsed from the entry's `otpauth://` URI), plus clean SIGTERM shutdown.

`daemon/src/vault.rs::open_kdbx` uses the pure-Rust
[`keepass`](https://crates.io/crates/keepass) crate — **no dependency on
KeePassXC** or any system library. `cargo run --example make-sample-vault --
/tmp/demo.kdbx demopass` writes a throwaway database to test against.

Not yet done: the QML side is unproven against a live `omarchy-shell`, and
`unlock` via pinentry hasn't been exercised (only inline-password unlock). See
[`PROTOCOL.md`](PROTOCOL.md) for the full IPC contract.
