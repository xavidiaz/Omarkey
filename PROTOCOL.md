# Omarkey IPC protocol

`Menu.qml` (running inside `omarchy-shell`) and `omarkeyd` speak **newline-delimited
JSON** over a Unix domain socket.

- Socket path: `$XDG_RUNTIME_DIR/omarkey.sock`
- Permissions: `0600`, owned by the session user. `omarkeyd` refuses to start if
  `$XDG_RUNTIME_DIR` is missing, world-writable, or not owned by the user.
- Encoding: UTF-8, one JSON value per line, `\n`-terminated. No embedded newlines
  (strings are escaped by the JSON encoder).
- Framing: `SplitParser { splitMarker: "\n" }` on the QML side; `BufReader::lines()`
  on the daemon side.
- Multiple concurrent clients are allowed. Every connection is independent; the
  vault state (locked/unlocked) is process-global.

Two clients ship: `OmarkeyClient.qml` (the picker's bridge) and the `omarkey`
CLI (`unlock [name]`, `use <name>`, `vaults`, `lock`, `status`, `list [query]`,
`hello`), which is what a keybind or login hook uses to unlock and switch
databases.

## Message shapes

### Request (client → daemon)

```json
{ "id": 7, "op": "list", "query": "git" }
```

- `id` — client-chosen integer, echoed in the matching response. Required for every
  request except fire-and-forget ones (none currently).
- `op` — the operation name (below).
- Remaining fields are operation-specific.

### Response (daemon → client)

Success:

```json
{ "id": 7, "ok": true, "result": { "...": "..." } }
```

Error:

```json
{ "id": 7, "ok": false, "error": { "code": "locked", "message": "vault is locked" } }
```

Error codes:

| code          | meaning                                                        |
|---------------|---------------------------------------------------------------|
| `locked`      | operation needs an unlocked vault                             |
| `auth-failed` | wrong master password / keyfile                               |
| `not-found`   | no entry with that `uuid`                                     |
| `bad-request` | malformed JSON, unknown `op`, missing/invalid field          |
| `vault-error` | kdbx parse/decrypt failure not caused by a wrong password    |
| `io-error`    | clipboard / `wtype` / filesystem failure                     |
| `unsupported` | op or field not implemented in this daemon build             |
| `busy`        | another unlock/pinentry prompt is already in flight          |

### Event (daemon → client, unsolicited)

No `id`. Sent only to connections that issued `subscribe`.

```json
{ "event": "locked" }
```

| event                | payload                                   | when                                      |
|----------------------|-------------------------------------------|-------------------------------------------|
| `unlocked`           | `{ "vault": "personal", "entryCount": 214 }` | a database transitioned locked → unlocked |
| `locked`             | `{ "reason": "idle" \| "manual" \| "session-lock" \| "sleep" }` | the active database was cleared from RAM |
| `vault-switched`     | `{ "name": "work" }`                      | the active database changed (left locked) |
| `vault-changed`      | `{}`                                      | a `.kdbx` on disk changed; reload suggested |
| `clipboard-cleared`  | `{ "uuid": "…", "field": "password" }`    | a scheduled clipboard wipe fired          |

## Operations

### `hello`

Handshake. Safe to call before unlock.

Request: `{ "id": 1, "op": "hello" }`

Result:
```json
{
  "daemonVersion": "0.1.0",
  "protocol": 1,
  "vault": "personal",
  "vaults": ["personal", "work"],
  "locked": true,
  "capabilities": ["copy", "type", "totp", "pinentry", "multi-vault"]
}
```
- `vault` — name of the active database. `vaults` — every configured name.

### `status`

Current state. Safe before unlock.

Result:
```json
{ "locked": false, "entryCount": 214, "vault": "personal", "idleLockInSec": 240 }
```

### `vaults`

List configured databases. Safe before unlock.

Result:
```json
{
  "vaults": [
    { "name": "personal", "path": "/home/u/personal.kdbx", "active": true,  "locked": false },
    { "name": "work",     "path": "/home/u/work.kdbx",     "active": false, "locked": true  }
  ]
}
```

### `use`

Make a different database active. Locks whatever was unlocked; the new one
starts locked. Idempotent.

Request: `{ "id": 4, "op": "use", "vault": "work" }`
Result: `{ "vault": "work", "locked": true }`
Errors: `not-found` (no such vault name).

Emits `vault-switched`.

### `unlock`

Decrypt a database into RAM.

Request: `{ "id": 3, "op": "unlock" }`
- Default: `omarkeyd` spawns its own `pinentry` to collect the master password.
  The password never crosses the socket.
- Optional `{ "vault": "work" }` — unlock a database other than the active one.
  Switches the active database first (locking whatever was unlocked).
- Optional `{ "password": "…", "keyfile": "/path" }` — inline unlock for headless
  setups. Discouraged; only honoured when `allow_inline_unlock = true` in the
  daemon config.

**The picker (`Menu.qml`) never sends this while it is on screen** — its
fullscreen layer-shell overlay would render on top of the pinentry prompt.
Unlock is triggered from the `omarkey unlock` CLI, or from the picker's locked
screen which closes the overlay first. Any client may still call it.

Result: `{ "unlocked": true, "entryCount": 214, "vault": "personal" }`
Errors: `auth-failed`, `vault-error`, `busy`, `not-found` (bad `vault` name).

Emits `unlocked` (and `vault-switched` first, if `vault` named a different one).

### `lock`

Zeroize and drop the vault. Always succeeds (idempotent).

Result: `{ "locked": true }` — emits `locked` with `reason: "manual"`.

### `list`

Metadata only. Never returns secrets.

Request: `{ "id": 5, "op": "list", "query": "git", "limit": 50 }`
- `query` — optional fuzzy match over title / username / url / group / tags.
- `limit` — optional, default 200.

Result:
```json
{
  "entries": [
    {
      "uuid": "a1b2c3d4-…",
      "title": "GitHub",
      "username": "octocat",
      "group": "Dev",
      "url": "https://github.com",
      "hasPassword": true,
      "hasTotp": true,
      "tags": ["work"]
    }
  ]
}
```

Errors: `locked`.

### `get`

Non-secret fields for one entry. `password` and `notes` are **never** returned
here — use `copy` / `type`.

Request: `{ "id": 6, "op": "get", "uuid": "a1b2c3d4-…", "fields": ["username", "url"] }`

Result: `{ "uuid": "…", "fields": { "username": "octocat", "url": "https://github.com" } }`

Errors: `locked`, `not-found`, `unsupported` (if a secret field is requested).

### `copy`

Daemon writes the value to the Wayland clipboard via `wl-copy` (value passed on
stdin, never argv) and schedules a wipe.

Request:
```json
{ "id": 8, "op": "copy", "uuid": "a1b2c3d4-…", "field": "password", "clearAfterMs": 20000 }
```
- `field` — `"password"` | `"username"` | `"url"` | `"totp"` | `"notes"` | `"otp-uri"` | custom string-field name.
- `clearAfterMs` — optional; default from daemon config (20 s). `0` disables the wipe.

Result: `{ "copied": true, "field": "password", "clearsInMs": 20000 }`
Errors: `locked`, `not-found`, `io-error`.

Emits `clipboard-cleared` when the wipe fires (only if the clipboard still holds
the value Omarkey wrote — a later copy by the user cancels the wipe).

### `type`

Daemon types the value with `wtype` (value on stdin).

Request:
```json
{ "id": 9, "op": "type", "uuid": "a1b2c3d4-…", "sequence": "username tab password enter" }
```
- `sequence` — space-separated tokens. Field names (`username`, `password`,
  `totp`, `url`, …) expand to their value; `tab` / `enter` / `escape` are keys;
  a `~250` token inserts a 250 ms delay. Default when omitted: `"password"`.
- Single field: `{ "field": "password" }` is shorthand for `sequence: "password"`.

Result: `{ "typed": true }`
Errors: `locked`, `not-found`, `io-error`, `unsupported` (no `wtype` on the system).

### `totp`

TOTP timing metadata. The code itself is delivered only through `copy` / `type`
(`field: "totp"`).

Request: `{ "id": 10, "op": "totp", "uuid": "a1b2c3d4-…" }`

Result: `{ "hasTotp": true, "period": 30, "remainingSec": 17, "digits": 6 }`
Errors: `locked`, `not-found`.

### `subscribe`

Opt this connection into events. Idempotent.

Request: `{ "id": 11, "op": "subscribe" }`
Result: `{ "subscribed": true }`

## Typical flows

**Open picker, copy a password**

```
→ {"id":1,"op":"hello"}
← {"id":1,"ok":true,"result":{"locked":true,...}}
→ {"id":2,"op":"unlock"}                         # daemon shows pinentry
← {"id":2,"ok":true,"result":{"unlocked":true,"entryCount":214}}
→ {"id":3,"op":"list","query":"git"}
← {"id":3,"ok":true,"result":{"entries":[{"uuid":"a1b2…","title":"GitHub",...}]}}
→ {"id":4,"op":"copy","uuid":"a1b2…","field":"password"}
← {"id":4,"ok":true,"result":{"copied":true,"clearsInMs":20000}}
   … 20 s later, to subscribers …
← {"event":"clipboard-cleared","uuid":"a1b2…","field":"password"}
```

**Session lock wipes the vault**

```
   (user locks screen; logind emits Session.Lock)
← {"event":"locked","reason":"session-lock"}
   (Menu.qml greys out the list, next action triggers unlock again)
```
