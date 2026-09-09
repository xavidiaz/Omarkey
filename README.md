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
git clone https://github.com/xavidiaz/Omarkey
cd Omarkey
cargo install --path daemon           # → ~/.cargo/bin/omarkeyd and ~/.cargo/bin/omarkey

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

(Or add `omarkeyd &` to your Hyprland `exec-once`. Don't put it in the plugin
manifest — Omarchy would never start it anyway.)

### 2. The plugin

```sh
omarchy plugin add https://github.com/xavidiaz/omarkey
```

This clones the repo root to `~/.config/omarchy/plugins/omarkey/`. Only
`manifest.json`, `Menu.qml`, and `OmarkeyClient.qml` matter to Omarchy; the
`daemon/` directory is ignored.

### 3. Keybinds

`~/.config/hypr/bindings.conf`:

```
bindd = SUPER, P, Omarkey, exec, omarchy-shell shell toggle omarkey '{}'
bindd = SUPER SHIFT, P, Omarkey unlock, exec, omarkey unlock
```

## Use

**Unlock** (`omarkey unlock`, or Enter on the picker's locked screen): the
overlay closes and `omarkeyd` shows a `pinentry` dialog for the master password.
Unlock is kept separate from the picker on purpose — a fullscreen overlay would
render on top of the prompt. The vault re-locks on idle timeout, on session
lock, and before sleep.

**Picker** (`SUPER+P`):

| Key | Action |
|-----|--------|
| type | filter |
| ↑ / ↓ | move |
| Enter | copy password (auto-clears) — or, when locked, close + unlock |
| Shift+Enter | copy username |
| Alt+Enter | type `username ⇥ password` |
| Ctrl+Enter | type password only |
| Ctrl+T | copy TOTP |
| Ctrl+L | lock the vault now |
| Esc | clear filter, then close |

**CLI** (`omarkey`): `unlock`, `lock`, `status`, `list [query]`, `hello`.

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

Working, and tested live in `omarchy-shell`:

- **Daemon** — `cargo build` / `clippy` / `test` clean. Driven end to end over
  the socket against a real `.kdbx`: `unlock` → `list` (fuzzy) → `get` → `copy`
  (with a verified clipboard wipe) → `totp` (parsed from the entry's
  `otpauth://` URI), plus clean SIGTERM shutdown. `open_kdbx` uses the pure-Rust
  [`keepass`](https://crates.io/crates/keepass) crate — **no dependency on
  KeePassXC**.
- **Plugin** — loads in a running `omarchy-shell` with no QML errors; the
  overlay renders themed, filters live, and the picker → `copy`/`type` path
  works. `omarkey unlock` shows a focusable pinentry dialog with the overlay
  closed.

`cargo run --example make-sample-vault -- /tmp/demo.kdbx demopass` writes a
throwaway database for testing. Iterating on the QML needs
`omarchy-restart-shell` after each edit — the plugin file-watcher does not
reliably hot-reload. See [`PROTOCOL.md`](PROTOCOL.md) for the full IPC contract.
