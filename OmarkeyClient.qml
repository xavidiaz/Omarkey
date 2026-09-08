// Client.qml — the only bridge between the shell and omarkeyd.
//
// Knows nothing about KeePass. It speaks the newline-delimited JSON protocol in
// PROTOCOL.md: dial the socket, correlate responses by `id`, fan out events to
// signal handlers, and reconnect when the daemon restarts.

import QtQuick
import Quickshell
import Quickshell.Io

Item {
  id: root

  readonly property string socketPath:
    (Quickshell.env("XDG_RUNTIME_DIR") || "/run/user/1000") + "/omarkey.sock"

  // Connection / vault state, bindable from Menu.qml.
  readonly property bool connected: sock.connected
  property bool locked: true
  property int entryCount: 0
  property string vaultPath: ""
  property string daemonVersion: ""
  property string lastError: ""

  // Emitted for daemon events (see PROTOCOL.md).
  signal unlockedChanged(int entryCount)          // vault -> unlocked
  signal lockedByDaemon(string reason)            // vault -> locked
  signal vaultChanged()                           // .kdbx changed on disk
  signal clipboardCleared(string uuid, string field)
  signal connectionChanged(bool up)

  property int _nextId: 1
  property var _pending: ({})                     // id -> { resolve, reject }

  function _send(op, args, cb) {
    if (!sock.connected) {
      if (cb) cb(null, { code: "io-error", message: "omarkeyd not connected" })
      return -1
    }
    var id = root._nextId++
    var msg = { id: id, op: op }
    if (args)
      for (var k in args) msg[k] = args[k]
    if (cb)
      root._pending[id] = cb
    sock.write(JSON.stringify(msg) + "\n")
    sock.flush()
    return id
  }

  // --- public API — thin wrappers over _send, cb(result, error) ---------------

  function hello(cb)                { return _send("hello", null, cb) }
  function status(cb)               { return _send("status", null, cb) }
  function unlock(cb)               { return _send("unlock", null, cb) }
  function unlockInline(password, keyfile, cb) {
    var a = { password: password }
    if (keyfile) a.keyfile = keyfile
    return _send("unlock", a, cb)
  }
  function lock(cb)                 { return _send("lock", null, cb) }
  function list(query, limit, cb)  { return _send("list", { query: query || "", limit: limit || 200 }, cb) }
  function get(uuid, fields, cb)    { return _send("get", { uuid: uuid, fields: fields }, cb) }
  function copyField(uuid, field, clearAfterMs, cb) {
    var a = { uuid: uuid, field: field }
    if (clearAfterMs !== undefined) a.clearAfterMs = clearAfterMs
    return _send("copy", a, cb)
  }
  function typeSequence(uuid, sequence, cb) {
    return _send("type", { uuid: uuid, sequence: sequence || "password" }, cb)
  }
  function totp(uuid, cb)           { return _send("totp", { uuid: uuid }, cb) }
  function subscribe(cb)            { return _send("subscribe", null, cb) }

  function connect()    { sock.connected = true }
  function disconnect() { sock.connected = false }

  // --- wire handling ---------------------------------------------------------

  function _handleLine(line) {
    if (!line) return
    var msg
    try {
      msg = JSON.parse(line)
    } catch (e) {
      console.warn("omarkey: unparseable line from daemon:", line)
      return
    }

    if (msg.event !== undefined) {
      _handleEvent(msg)
      return
    }

    var cb = root._pending[msg.id]
    if (cb) {
      delete root._pending[msg.id]
      if (msg.ok) cb(msg.result || {}, null)
      else {
        root.lastError = (msg.error && msg.error.message) || "unknown error"
        cb(null, msg.error || { code: "bad-request", message: "unknown error" })
      }
    }

    // Opportunistically track state from any response that carries it.
    var r = msg.result
    if (r) {
      if (r.locked !== undefined) root.locked = r.locked
      if (r.unlocked !== undefined) root.locked = !r.unlocked
      if (r.entryCount !== undefined) root.entryCount = r.entryCount
      if (r.vaultPath !== undefined) root.vaultPath = r.vaultPath
      if (r.daemonVersion !== undefined) root.daemonVersion = r.daemonVersion
    }
  }

  function _handleEvent(msg) {
    switch (msg.event) {
    case "unlocked":
      root.locked = false
      if (msg.entryCount !== undefined) root.entryCount = msg.entryCount
      root.unlockedChanged(root.entryCount)
      break
    case "locked":
      root.locked = true
      root.lockedByDaemon(msg.reason || "unknown")
      break
    case "vault-changed":
      root.vaultChanged()
      break
    case "clipboard-cleared":
      root.clipboardCleared(msg.uuid || "", msg.field || "")
      break
    default:
      console.warn("omarkey: unknown event", msg.event)
    }
  }

  Socket {
    id: sock
    path: root.socketPath
    connected: false

    parser: SplitParser {
      splitMarker: "\n"
      onRead: line => root._handleLine(line)
    }

    onConnectedChanged: {
      root.connectionChanged(connected)
      if (connected) {
        root.lastError = ""
        // Re-establish subscription + state on every (re)connect.
        root.subscribe(null)
        root.hello(null)
      } else {
        // Drop every pending callback so callers don't hang forever.
        for (var id in root._pending) {
          var cb = root._pending[id]
          delete root._pending[id]
          cb(null, { code: "io-error", message: "connection lost" })
        }
      }
    }

    onError: err => {
      root.lastError = "socket error: " + err
      sock.connected = false
    }
  }

  // omarkeyd may start after the shell, or restart under us. Keep dialing.
  Timer {
    interval: 2000
    repeat: true
    running: !sock.connected
    onTriggered: sock.connected = true
  }

  Component.onCompleted: sock.connected = true
}
