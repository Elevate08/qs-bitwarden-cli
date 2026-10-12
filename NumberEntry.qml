import QtQuick
import QtQuick.Controls as QQC
import qs.Commons
import qs.Ui

// Number spinner with the shell NumberField's chrome and call-site API (label,
// value, from, to, stepSize, foreground, accent, fontFamily, fontSize,
// fieldWidth, hasCursor, modified, hovered, field).
//
// The shell's NumberField types into an editable TextInput. On Qt 6.12 that
// control reads the Wayland clipboard offer on the GUI thread whenever the
// clipboard changes, with no total byte cap (QTBUG-149610), so any live one
// lets another clipboard owner stall the shell. This one types into a
// TextEdit, which only asks which formats are offered. A number needs no
// paste, so Ctrl+V, Shift+Insert and middle-click are swallowed rather than
// routed anywhere. The SpinBox stays non-editable: it keeps the buttons, the
// range and the step, and never owns a text input.
//
// A typed value is committed on Return/Enter and on focus loss. It is
// reported through modified() and never written to `value`, so a caller's
// `value:` binding survives; the caller stores it and the binding follows.
Column {
  id: root

  property string label: ""
  property int value: 0
  property int from: 0
  property int to: 100
  property int stepSize: 1
  property color foreground: Color.foreground
  property color accent: Color.accent
  property string fontFamily: Style.font.family
  property real fontSize: Style.font.body
  property real fieldWidth: Style.spacing.numberFieldWidth
  property bool hasCursor: false
  property bool _hovered: false
  property alias field: spin

  signal modified(int value)
  signal hovered(bool on)

  // Longer than any setting needs; keeps a held key from growing the document.
  readonly property int maxDigits: 10

  function shown() {
    return String(spin.value)
  }

  function refresh() {
    if (edit.text !== shown()) edit.text = shown()
  }

  // Digits only; a leading minus only when the range goes below zero.
  function parse(raw) {
    var s = String(raw).trim()
    var neg = root.from < 0 && s.charAt(0) === "-"
    var digits = s.replace(/[^0-9]/g, "")
    if (digits === "") return null
    var n = parseInt(digits, 10) * (neg ? -1 : 1)
    return Math.max(root.from, Math.min(root.to, n))
  }

  function commit() {
    var n = parse(edit.text)
    if (n !== null && n !== spin.value) root.modified(n)
    refresh()
    // A caller that does not store the value leaves the old one; show it.
    edit.text = shown()
  }

  // SpinBox.increase() does not signal valueModified, so the keys step here,
  // from whatever is typed, and report the same way a commit does.
  function step(dir) {
    var base = parse(edit.text)
    if (base === null) base = spin.value
    var n = Math.max(root.from, Math.min(root.to, base + dir * root.stepSize))
    if (n !== spin.value) root.modified(n)
    edit.text = shown()
  }

  // TextEdit inserts Tab as a character. Walk to the next control that takes
  // tab focus and skip this control's own parts.
  function focusFromTab(forward) {
    var item = edit
    for (var i = 0; i < 64; ++i) {
      item = item.nextItemInFocusChain(forward)
      if (!item || item === edit || item === spin) return
      if (item.activeFocusOnTab && item.enabled && item.visible) {
        item.forceActiveFocus()
        return
      }
    }
  }

  spacing: Style.spacing.md

  Text {
    textFormat: Text.PlainText
    visible: root.label !== ""
    text: root.label
    color: Qt.darker(root.foreground, 1.4)
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  QQC.SpinBox {
    id: spin
    width: root.fieldWidth
    implicitHeight: Math.max(Style.spacing.controlHeight, root.fontSize + Style.spacing.controlPaddingY * 2)
    from: root.from
    to: root.to
    stepSize: root.stepSize
    value: root.value
    editable: false
    font.family: root.fontFamily
    font.pixelSize: root.fontSize

    readonly property bool _focused: spin.activeFocus || edit.activeFocus
    readonly property bool _hot: root._hovered || root.hasCursor
    readonly property var _borderSpec: Border.controlSpec(_focused ? "focus" : (_hot ? "hover-cursor" : "normal"), root.foreground, root.accent)

    leftPadding: Border.left(_borderSpec) + Style.spacing.controlPaddingX
    rightPadding: Border.right(_borderSpec) + Style.spacing.controlPaddingX
    topPadding: Border.top(_borderSpec)
    bottomPadding: Border.bottom(_borderSpec)

    onValueChanged: root.refresh()
    onValueModified: root.modified(value)
    // The buttons and Tab focus the SpinBox; typing belongs to the editor.
    onActiveFocusChanged: if (activeFocus && !edit.activeFocus) edit.forceActiveFocus()
    Component.onCompleted: root.refresh()

    background: BorderSurface {
      color: Style.controlFill(spin._focused, spin._hot, root.foreground, root.accent)
      borderSpec: spin._borderSpec
      radius: Style.cornerRadius

      HoverHandler {
        onHoveredChanged: {
          root._hovered = hovered
          root.hovered(hovered)
        }
      }
    }

    contentItem: TextEdit {
      id: edit
      text: String(root.value)
      font: spin.font
      color: root.foreground
      selectionColor: Style.selectionFillFor(root.foreground, root.accent)
      selectedTextColor: root.foreground
      textFormat: TextEdit.PlainText
      wrapMode: TextEdit.NoWrap
      horizontalAlignment: Qt.AlignHCenter
      verticalAlignment: Qt.AlignVCenter
      selectByMouse: true
      inputMethodHints: Qt.ImhDigitsOnly
      clip: true

      onActiveFocusChanged: if (!activeFocus) root.commit()

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        // Accepted so the document never reads the clipboard offer itself.
        if (event.matches(StandardKey.Paste)) {
          event.accepted = true
          return
        }
        switch (event.key) {
        case Qt.Key_Return:
        case Qt.Key_Enter:
          event.accepted = true
          root.commit()
          return
        case Qt.Key_Tab:
          event.accepted = true
          root.focusFromTab(true)
          return
        case Qt.Key_Backtab:
          event.accepted = true
          root.focusFromTab(false)
          return
        case Qt.Key_Up:
          event.accepted = true
          root.step(1)
          return
        case Qt.Key_Down:
          event.accepted = true
          root.step(-1)
          return
        }
        // Printable text: digits, and a minus where the range allows one.
        // Chords (Ctrl+A, Ctrl+Z...) keep their editing meaning; AltGr arrives
        // as Ctrl+Alt and still carries a character.
        if (!event.text || event.text.charCodeAt(0) < 32) return
        var mods = event.modifiers
        var altGr = (mods & Qt.ControlModifier) && (mods & Qt.AltModifier)
        if ((mods & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)) && !altGr) return
        var ok = /^[0-9]$/.test(event.text)
        if (event.text === "-" && root.from < 0) {
          // Only as the first character: at the start with no minus there, or
          // replacing a selection that begins at the start.
          var selStart = Math.min(edit.selectionStart, edit.selectionEnd)
          ok = edit.selectionStart !== edit.selectionEnd ? selStart === 0
            : (edit.cursorPosition === 0 && edit.text.charAt(0) !== "-")
        }
        var room = edit.length - Math.abs(edit.selectionEnd - edit.selectionStart) < root.maxDigits + 1
        if (!ok || !room) event.accepted = true
      }

      // Left clicks pass through. Middle click is the Selection paste.
      MouseArea {
        parent: edit
        anchors.fill: parent
        acceptedButtons: Qt.MiddleButton
        z: 1
        onPressed: function(mouse) { mouse.accepted = true }
      }
    }
  }
}
