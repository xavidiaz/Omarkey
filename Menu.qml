// Menu.qml — Omarkey overlay: search field + entry list.
//
// Loaded into omarchy-shell. Summon with:
//   omarchy-shell shell summon omarkey '{}'
//   omarchy-shell shell toggle omarkey '{}'
//
// This file only ever handles metadata (title / username / group). Every secret
// stays inside omarkeyd — see Client.qml and PROTOCOL.md.

import Quickshell
import Quickshell.Wayland
import QtQuick
import qs.Commons
import qs.Ui

Item {
  id: root

  // Injected by the shell host.
  property string omarchyPath: Quickshell.env("OMARCHY_PATH")
  property var shell: null
  property var manifest: null

  property bool opened: false
  property string filterText: ""
  property int selectedIndex: 0
  property bool cursorActive: false
  property string statusLine: ""

  // Theme tokens — share the [menu] surface, like emojis/clipboard.
  property color background: Color.menu.background
  property color foreground: Color.menu.text
  property color border: Color.menu.border
  property var borderSpec: Border.surfaceSpec("menu", "border", border, Math.max(1, Style.space(2)))
  property color scrim: Color.menu.scrim
  property color selectedBackground: Color.menu.selectedBackground
  property color selectedText: Color.menu.selectedText
  readonly property int cornerRadius: Style.cornerRadius
  property string fontFamily: Style.font.menuFamily
  property int contentMargin: Style.spacing.panelPadding
  property int headerHeight: Math.max(Style.space(34), Style.font.title + Style.spacing.controlPaddingY * 2)
  property int rowHeight: Math.max(Style.space(44), Style.font.body * 2 + Style.spacing.md)
  property int contentSpacing: Style.spacing.md
  property int cardWidth: Math.min(Style.space(560), panel.width - Style.gapsOut * 2)
  property int cardHeight: Math.min(Style.space(560), panel.height - Style.gapsOut * 2)

  OmarkeyClient {
    id: client

    onUnlockedChanged: {
      root.statusLine = ""
      root.refresh()
    }
    onLockedByDaemon: reason => {
      resultModel.clear()
      root.statusLine = reason === "session-lock" ? "Locked with the session"
        : reason === "idle" ? "Locked after idle timeout"
        : reason === "sleep" ? "Locked before sleep"
        : "Vault locked"
    }
    onVaultChanged: if (root.opened && !client.locked) root.refresh()
    onConnectionChanged: up => {
      if (!up) root.statusLine = "Waiting for omarkeyd…"
      else if (client.locked) root.statusLine = ""
    }
    onClipboardCleared: (uuid, field) => {
      root.statusLine = "Clipboard cleared"
      clearStatusTimer.restart()
    }
  }

  Timer {
    id: clearStatusTimer
    interval: 1500
    onTriggered: if (!client.locked) root.statusLine = ""
  }

  // Debounce list queries while the user types.
  Timer {
    id: queryDebounce
    interval: 90
    onTriggered: root.refresh()
  }

  function open(payloadJson) {
    root.opened = true
    root.selectedIndex = 0
    root.cursorActive = false
    root.filterText = ""
    root.statusLine = ""
    Qt.callLater(() => keyCatcher.forceActiveFocus())

    if (!client.connected) {
      root.statusLine = "Waiting for omarkeyd…"
      return
    }
    if (client.locked) {
      resultModel.clear()
      client.unlock((res, err) => {
        if (err) root.statusLine = err.message || "Unlock failed"
      })
    } else {
      root.refresh()
    }
  }

  function close() {
    root.opened = false
  }

  function dismiss() {
    root.opened = false
    if (root.shell && typeof root.shell.hide === "function")
      root.shell.hide((root.manifest && root.manifest.id) || "omarkey")
  }

  function toggle() {
    if (root.opened) root.dismiss()
    else root.open("{}")
  }

  function setFilter(next) {
    root.filterText = next
    root.selectedIndex = 0
    root.cursorActive = true
    queryDebounce.restart()
  }

  function refresh() {
    if (client.locked) return
    client.list(root.filterText, 200, (res, err) => {
      if (err) {
        root.statusLine = err.message || "List failed"
        return
      }
      var entries = res.entries || []
      resultModel.clear()
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i]
        resultModel.append({
          uuid: e.uuid,
          title: e.title || "(untitled)",
          username: e.username || "",
          group: e.group || "",
          hasTotp: e.hasTotp === true
        })
      }
      root.statusLine = resultModel.count === 0 && root.filterText
        ? "No matches for “" + root.filterText + "”" : ""
      if (root.selectedIndex >= resultModel.count)
        root.selectedIndex = Math.max(0, resultModel.count - 1)
      root.cursorActive = resultModel.count > 0
      Qt.callLater(() => {
        if (resultModel.count > 0) resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
      })
    })
  }

  function select(delta) {
    if (resultModel.count === 0) return
    if (!cursorActive) {
      cursorActive = true
      selectedIndex = delta < 0 ? resultModel.count - 1 : 0
    } else {
      selectedIndex = (selectedIndex + delta + resultModel.count) % resultModel.count
    }
    resultList.positionViewAtIndex(selectedIndex, ListView.Contain)
  }

  function currentUuid() {
    if (selectedIndex < 0 || selectedIndex >= resultModel.count) return ""
    return resultModel.get(selectedIndex).uuid
  }

  // Enter        -> copy password (+ auto clear)
  // Shift+Enter  -> copy username
  // Alt+Enter    -> type "username tab password"
  // Ctrl+Enter   -> type password only
  // Ctrl+T       -> copy TOTP
  function activate(mods) {
    var uuid = currentUuid()
    if (!uuid) return

    if (mods & Qt.AltModifier) {
      client.typeSequence(uuid, "username tab password", _typed)
      return
    }
    if (mods & Qt.ControlModifier) {
      client.typeSequence(uuid, "password", _typed)
      return
    }
    if (mods & Qt.ShiftModifier) {
      client.copyField(uuid, "username", undefined, _copied)
      return
    }
    client.copyField(uuid, "password", undefined, _copied)
  }

  function copyTotp() {
    var uuid = currentUuid()
    if (uuid) client.copyField(uuid, "totp", undefined, _copied)
  }

  function _copied(res, err) {
    if (err) { root.statusLine = err.message || "Copy failed"; return }
    root.statusLine = "Copied " + (res.field || "value")
      + (res.clearsInMs ? " · clears in " + Math.round(res.clearsInMs / 1000) + "s" : "")
    root.dismiss()
  }

  function _typed(res, err) {
    if (err) { root.statusLine = err.message || "Type failed"; return }
    root.dismiss()
  }

  ListModel { id: resultModel }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "omarkey"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    Rectangle {
      anchors.fill: parent
      color: root.scrim
    }

    MouseArea {
      anchors.fill: parent
      onClicked: root.dismiss()
    }

    BorderSurface {
      id: card
      width: root.cardWidth
      height: root.cardHeight
      radius: root.cornerRadius
      anchors.centerIn: parent
      color: root.background
      borderSpec: root.borderSpec
      padding: root.contentMargin

      MouseArea { anchors.fill: parent; onClicked: {} }

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true

        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function (event) {
          if (event.key === Qt.Key_Escape) {
            if (root.filterText) root.setFilter("")
            else root.dismiss()
            event.accepted = true
          } else if (event.key === Qt.Key_L && (event.modifiers & Qt.ControlModifier)) {
            client.lock((res, err) => root.statusLine = "Vault locked")
            resultModel.clear()
            event.accepted = true
          } else if (event.key === Qt.Key_T && (event.modifiers & Qt.ControlModifier)) {
            root.copyTotp()
            event.accepted = true
          } else if (Util.editsFilter(event, root.filterText)) {
            root.setFilter(Util.editedFilter(event, root.filterText))
            event.accepted = true
          } else if (event.key === Qt.Key_Up) {
            root.select(-1); event.accepted = true
          } else if (event.key === Qt.Key_Down) {
            root.select(1); event.accepted = true
          } else if (event.key === Qt.Key_PageUp) {
            root.select(-8); event.accepted = true
          } else if (event.key === Qt.Key_PageDown) {
            root.select(8); event.accepted = true
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            if (root.cursorActive) root.activate(event.modifiers)
            else if (resultModel.count > 0) root.cursorActive = true
            event.accepted = true
          } else if (event.text && event.text.length === 1
                     && event.text.charCodeAt(0) >= 32 && event.text.charCodeAt(0) !== 127) {
            root.setFilter(root.filterText + event.text)
            event.accepted = true
          }
        }
      }

      Column {
        anchors.fill: parent
        anchors.topMargin: card.contentTopInset
        anchors.rightMargin: card.contentRightInset
        anchors.bottomMargin: card.contentBottomInset
        anchors.leftMargin: card.contentLeftInset
        spacing: root.contentSpacing

        // Search field
        Rectangle {
          width: parent.width
          height: root.headerHeight
          radius: root.cornerRadius
          color: "transparent"

          Text {
            textFormat: Text.PlainText
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: root.filterText || (client.locked ? "Vault locked" : "Search entries…")
            color: root.foreground
            opacity: root.filterText ? 1 : 0.58
            font.family: root.fontFamily
            font.pixelSize: Style.font.heading
            elide: Text.ElideRight
          }
        }

        // Result list
        Item {
          width: parent.width
          height: parent.height - root.headerHeight - root.contentSpacing
            - (root.statusLine ? statusText.height + root.contentSpacing : 0)

          ListView {
            id: resultList
            anchors.fill: parent
            model: resultModel
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            currentIndex: root.selectedIndex

            delegate: Rectangle {
              required property int index
              required property string title
              required property string username
              required property string group
              required property bool hasTotp

              readonly property bool hasCursor: root.cursorActive && index === root.selectedIndex

              width: resultList.width
              height: root.rowHeight
              radius: root.cornerRadius
              color: hasCursor ? root.selectedBackground : "transparent"

              Row {
                anchors.fill: parent
                anchors.leftMargin: Style.spacing.md
                anchors.rightMargin: Style.spacing.md
                spacing: Style.spacing.md

                Column {
                  width: parent.width - (totpBadge.visible ? totpBadge.width + parent.spacing : 0)
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(2)

                  Text {
                    textFormat: Text.PlainText
                    text: title
                    color: hasCursor ? root.selectedText : root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                    width: parent.width
                  }
                  Text {
                    textFormat: Text.PlainText
                    visible: username !== "" || group !== ""
                    text: [group, username].filter(s => s !== "").join("  ·  ")
                    color: hasCursor ? root.selectedText : root.foreground
                    opacity: 0.6
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                    width: parent.width
                  }
                }

                Text {
                  id: totpBadge
                  visible: hasTotp
                  text: "󰯄"
                  anchors.verticalCenter: parent.verticalCenter
                  color: hasCursor ? root.selectedText : root.foreground
                  opacity: 0.7
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
              }

              MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onContainsMouseChanged: if (containsMouse) {
                  root.cursorActive = true
                  root.selectedIndex = index
                }
                onClicked: mouse => {
                  root.cursorActive = true
                  root.selectedIndex = index
                  root.activate(mouse.modifiers)
                }
              }
            }
          }

          // Empty / locked / waiting state
          Column {
            anchors.centerIn: parent
            spacing: Style.space(8)
            visible: resultModel.count === 0

            Text {
              text: client.locked ? "󰌾" : "󰋱"
              color: root.selectedText
              opacity: 0.8
              font.family: root.fontFamily
              font.pixelSize: Style.font.displayLarge
              horizontalAlignment: Text.AlignHCenter
              width: parent.width
            }
            Text {
              textFormat: Text.PlainText
              text: !client.connected ? "omarkeyd is not running"
                : client.locked ? "Unlocking…"
                : root.filterText ? "No matches for “" + root.filterText + "”"
                : "Vault is empty"
              color: root.foreground
              opacity: 0.7
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              horizontalAlignment: Text.AlignHCenter
              width: parent.width
            }
          }
        }

        // Status line
        Text {
          id: statusText
          textFormat: Text.PlainText
          visible: root.statusLine !== ""
          text: root.statusLine
          color: root.foreground
          opacity: 0.7
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
          width: parent.width
        }
      }
    }
  }
}
