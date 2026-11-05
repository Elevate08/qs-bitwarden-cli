import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Single-line field with the shell TextField's chrome and call-site API
// (text, placeholderText, accepted, password, foreground, accent,
// horizontalPadding). The root is a focus scope, not a TextField.
//
// Qt 6.12's editable TextInput handles QClipboard::dataChanged by calling
// QMimeData::text(). On Wayland that reads the data-device selection in the
// GUI thread until EOF, with a one-second idle timeout per chunk and no total
// byte cap (QTBUG-149610). TextEdit's handler only asks which formats are
// offered, so a clipboard change cannot pull the payload in. The value is
// kept in a read-only TextInput, which returns before that read. Its password
// echo mode is what makes an accessibility query report bullets; TextArea has
// no echo mode, so the visible document holds bullets instead of the secret.
//
// Ctrl+V, the editing menu, and middle-click still call text() themselves.
// Those go through wl-paste, capped by head before any byte reaches this
// process and supervised by timeout for a bounded lifetime. A masked field
// never holds a TextEdit selection: QQuickTextControl would copy it to the
// primary selection (bullets, so the password's length, over the user's own
// selection), and TextInput's password mode does not. Ctrl+A is a flag
// (_maskedAll) with its own highlight, and the caret is drawn here because a
// read-only TextEdit does not blink one and keyboard selection would be the
// only way to enable it.
FocusScope {
  id: root

  signal accepted()
  signal textEdited()

  property color foreground: Color.foreground
  property color accent: Color.accent
  property color selectionTint: Style.selectionFillFor(foreground, accent)
  property bool password: false
  property real horizontalPadding: Style.spacing.controlPaddingX
  property real verticalPadding: Style.spacing.inputPaddingY
  property bool hasCursor: false
  property bool readOnly: false
  property int inputMethodHints: Qt.ImhNone
  // SecretField reserves the trailing eye here. The default matches the shell
  // field's own right inset.
  property real rightPadding: horizontalPadding + Border.right(_borderSpec)
  // Return also submits the form around the field: the nearest ancestor with
  // a submitForm() function. A form-level Shortcut cannot, because the
  // editable TextEdit claims Return and Enter in ShortcutOverride, so the
  // Shortcut never fires while a field has focus. A field whose own Return
  // does something else (onAccepted) turns this off.
  property bool submitsForm: true

  // Callers and the qml-kit tests read the TextInput echo values.
  readonly property int echoMode: password ? TextInput.Password : TextInput.Normal
  // The visible control draws at this inset. Tests and the caret math read it.
  readonly property real leftPadding: editor.leftPadding
  readonly property rect cursorRectangle: editor.cursorRectangle
  readonly property real contentWidth: editor.contentWidth

  // One clipboard read, stopped outside the shell. head closes the pipe.
  readonly property int pasteByteCap: 65536
  readonly property int pasteTimeoutSec: 3
  // Bumped when this field can no longer accept a paste that is still in flight.
  property int pasteEpoch: 0
  property var pasteProc: null
  // Parents connected while a paste runs. Hiding a form does not notify the
  // field itself, and the collector would otherwise keep reading.
  property var _pasteGuards: []
  // TextEdit paints at the padding origin and does not follow the caret the
  // way TextInput does. Shifting the padding scrolls the glyphs and the caret
  // together; clip hides what moved past the edge.
  property real hscroll: 0
  property bool _following: false
  property bool _syncing: false
  property bool _fromEditor: false
  property bool _pasting: false
  // Virtual select-all of a masked value. The editor selection stays empty.
  property bool _maskedAll: false
  property bool _blinkOn: true
  readonly property bool _maskedCaretWanted: password && editor.activeFocus && enabled && !readOnly

  readonly property bool _focused: editor.activeFocus
  readonly property bool _hot: editor.hovered || hasCursor
  readonly property var _borderSpec: Border.controlSpec(_focused ? "focus" : (_hot ? "hover-cursor" : "normal"), root.foreground, root.accent)

  // Binding-preserving value. insert and remove do not break `text:`.
  property alias text: store.text
  property alias placeholderText: editor.placeholderText
  property alias cursorPosition: editor.cursorPosition
  property alias selectedText: editor.selectedText
  property alias length: store.length

  activeFocusOnTab: false
  implicitWidth: editor.implicitWidth
  implicitHeight: editor.implicitHeight

  function pasteCommand(primary) {
    // --type text: without it wl-paste takes whatever is offered, and an
    // image-only clipboard would put 64 KiB of binary in the field.
    var mode = (primary ? "--primary " : "") + "--type text "
    // timeout owns the process group. SIGALRM requests its configured KILL
    // immediately on cancellation; TERM would leave a resistant grandchild
    // alive after bash exits. Do not use --foreground (it disables group kill).
    return ["timeout", "--signal=KILL", pasteTimeoutSec + "s", "bash", "-c",
      "wl-paste " + mode + "--no-newline 2>/dev/null | head -c " + pasteByteCap]
  }

  function editingOpen() {
    if (!enabled || readOnly) return false
    var item = root
    while (item) {
      if (!item.visible) return false
      item = item.parent
    }
    return true
  }

  function invalidatePaste() {
    pasteEpoch++
    var proc = pasteProc
    if (!proc) return
    // Stop the read. The exit handler finishes it, after the collector has
    // delivered whatever already arrived. A process that never started has
    // no exit left to wait for.
    if (proc.running) proc.signal(14) // Linux SIGALRM: timeout kills its group.
    else finishPaste(proc)
  }

  // Destroying a Quickshell Process SIGKILLs only its own pid (timeout). That
  // pid is also the group id, and bash, wl-paste and head would outlive it with
  // no deadline. The group kill goes out by its own process, so it does not
  // depend on timeout running a handler first.
  function killPasteGroup() {
    var proc = pasteProc
    if (!proc) return
    pasteEpoch++
    proc.payload = ""
    var pid = proc.running ? proc.processId : 0
    if (pid > 1) Quickshell.execDetached(["kill", "-KILL", "--", "-" + pid])
  }

  function armPasteGuards() {
    disarmPasteGuards()
    var item = root.parent
    while (item) {
      item.visibleChanged.connect(root.dropPasteIfClosed)
      _pasteGuards.push(item)
      item = item.parent
    }
  }

  function disarmPasteGuards() {
    for (var i = 0; i < _pasteGuards.length; ++i) {
      var item = _pasteGuards[i]
      if (item) item.visibleChanged.disconnect(root.dropPasteIfClosed)
    }
    _pasteGuards = []
  }

  function dropPasteIfClosed() {
    if (!editingOpen()) invalidatePaste()
  }

  function pasteFrom(primary) {
    if (!editingOpen() || pasteProc) return
    var proc = pasteComponent.createObject(keySink, {
      epoch: pasteEpoch,
      command: pasteCommand(primary)
    })
    if (!proc) return
    pasteProc = proc
    armPasteGuards()
    proc.exec(proc.command)
    // FailedToStart finishes inside exec, and destroy() drops that object.
    // A paste that is still running finishes in onRunningChanged.
    if (proc && pasteProc === proc && !proc.running) finishPaste(proc)
  }

  // StdioCollector keeps its last output until the process runs again, and it
  // has no clear(). Destroying the process is what drops a pasted secret.
  // A field that closed while wl-paste ran does not receive it.
  function finishPaste(proc) {
    if (!proc || proc.closed) return
    proc.closed = true
    disarmPasteGuards()
    var epoch = proc.epoch
    var payload = proc.payload
    proc.payload = ""
    if (pasteProc === proc) pasteProc = null
    if (proc.succeeded && epoch === pasteEpoch && editingOpen()) insertPlainPaste(payload)
    proc.destroy()
  }

  function acceptPaste(epoch, payload) {
    if (epoch !== pasteEpoch || !editingOpen()) return
    insertPlainPaste(payload)
  }

  function insertPlainPaste(raw) {
    if (!enabled || readOnly) return
    var clean = String(raw == null ? "" : raw).replace(/[\r\n\u2028\u2029]/g, "")
    if (!clean) return
    // An unmasked paste goes through the visible document so Ctrl+Z can undo
    // it. Assigning editor.text would drop that history.
    if (!password) {
      var before = store.text
      _pasting = true
      var from = Math.min(editor.selectionStart, editor.selectionEnd)
      var to = Math.max(editor.selectionStart, editor.selectionEnd)
      if (from !== to) editor.remove(from, to)
      editor.insert(editor.cursorPosition, clean)
      _pasting = false
      if (store.text !== before) textEdited()
      return
    }
    insertSecret(clean)
  }

  function shownText() {
    // The visible document is what TextArea exposes to accessibility. Bullets
    // here, never the secret. U+2022 matches the shell's password glyph.
    return password ? "\u2022".repeat(store.text.length) : store.text
  }

  // Keep the visible document equal to shownText without a write back into
  // the value. cursor is an index in that string.
  function refreshDisplay(cursor) {
    var shown = shownText()
    var pos = cursor === undefined ? editor.cursorPosition : cursor
    if (pos < 0) pos = 0
    if (pos > shown.length) pos = shown.length
    if (editor.text !== shown) {
      _syncing = true
      editor.text = shown
      _syncing = false
    }
    if (editor.cursorPosition !== pos) editor.cursorPosition = pos
    if (password && editor.selectedText) editor.deselect()
  }

  // A typed edit lands in the visible document first. Replay the changed
  // span into the value with insert/remove so a `text:` binding survives.
  function mirrorEditorToStore() {
    var want = editor.text
    var have = store.text
    if (want === have) return
    var start = 0
    while (start < want.length && start < have.length && want.charAt(start) === have.charAt(start))
      start++
    var endWant = want.length
    var endHave = have.length
    while (endWant > start && endHave > start && want.charAt(endWant - 1) === have.charAt(endHave - 1)) {
      endWant--
      endHave--
    }
    _fromEditor = true
    if (endHave > start) store.remove(start, endHave)
    if (endWant > start) store.insert(start, want.substring(start, endWant))
    _fromEditor = false
    if (!_pasting) textEdited()
  }

  function replaceStore(from, to, clean) {
    if (!enabled || readOnly) return
    var before = store.text
    var at = from
    // Any edit ends a virtual select-all, including a no-op one.
    _maskedAll = false
    _syncing = true
    if (to > from) store.remove(from, to)
    if (clean) store.insert(at, clean)
    _syncing = false
    refreshDisplay(at + (clean ? clean.length : 0))
    if (store.text !== before) textEdited()
  }

  // Bullets map 1:1 to UTF-16 units, so a range edge can fall inside a pair.
  function snapIndex(text, index, dir) {
    if (index <= 0 || index >= text.length) return index
    var low = text.charCodeAt(index)
    var high = text.charCodeAt(index - 1)
    if (low >= 0xDC00 && low <= 0xDFFF && high >= 0xD800 && high <= 0xDBFF)
      return index + (dir < 0 ? -1 : 1)
    return index
  }

  // The span an edit replaces: everything after a virtual select-all,
  // otherwise the editor selection, otherwise the caret.
  function editRange() {
    var text = store.text
    var from = 0
    var to = text.length
    if (!_maskedAll) {
      from = Math.min(editor.selectionStart, editor.selectionEnd)
      to = Math.max(editor.selectionStart, editor.selectionEnd)
      if (from === to) {
        // A bare caret inserts where it is; only a span is widened.
        return { from: editor.cursorPosition, to: editor.cursorPosition }
      }
    }
    return { from: snapIndex(text, from, -1), to: snapIndex(text, to, 1) }
  }

  function restartBlink() {
    _blinkOn = true
    if (blink.running) blink.restart()
  }

  function insertSecret(raw) {
    if (!enabled || readOnly) return
    var clean = String(raw == null ? "" : raw).replace(/[\r\n\u2028\u2029]/g, "")
    if (!clean) return
    var range = editRange()
    replaceStore(range.from, range.to, clean)
  }

  // UTF-16 indexes. A supplementary character is a surrogate pair, and a
  // one-unit step would leave half of it in the value.
  function stepIndex(text, index, dir) {
    if (dir < 0) {
      if (index <= 0) return 0
      var back = index - 1
      var unit = text.charCodeAt(back)
      if (unit >= 0xDC00 && unit <= 0xDFFF && back > 0) {
        var high = text.charCodeAt(back - 1)
        if (high >= 0xD800 && high <= 0xDBFF) return back - 1
      }
      return back
    }
    if (index >= text.length) return text.length
    var lead = text.charCodeAt(index)
    if (lead >= 0xD800 && lead <= 0xDBFF && index + 1 < text.length) {
      var low = text.charCodeAt(index + 1)
      if (low >= 0xDC00 && low <= 0xDFFF) return index + 2
    }
    return index + 1
  }

  function deleteSecret(dir) {
    if (!enabled || readOnly) return
    var range = editRange()
    if (_maskedAll || range.from !== range.to) {
      replaceStore(range.from, range.to, "")
      return
    }
    var pos = editor.cursorPosition
    var text = store.text
    if (dir < 0) replaceStore(stepIndex(text, pos, -1), pos, "")
    else replaceStore(pos, stepIndex(text, pos, 1), "")
  }

  function submit() {
    if (!enabled || readOnly) return
    accepted()
    if (!submitsForm) return
    for (var item = root.parent; item; item = item.parent) {
      if (typeof item.submitForm === "function") {
        item.submitForm()
        return
      }
    }
  }

  function select(start, end) {
    editor.select(start, end)
  }

  // TextEdit inserts Tab as a character. Walk to the next control that
  // actually takes tab focus and skip this field's own chrome.
  function focusFromTab(forward) {
    var item = editor
    for (var i = 0; i < 64; ++i) {
      item = item.nextItemInFocusChain(forward)
      if (!item || item === editor || item === root) return
      if (item.activeFocusOnTab && item.enabled && item.visible) {
        item.forceActiveFocus()
        return
      }
    }
  }

  function followCaret() {
    if (_following || width <= 0) return
    _following = true
    var padL = horizontalPadding + Border.left(_borderSpec)
    // rightPadding is the live inset, including a reveal button a caller reserved.
    var padR = editor.rightPadding
    var viewW = width - padL - padR
    var next = hscroll
    if (viewW > 0) {
      var glyph = editor.cursorRectangle.x - editor.leftPadding
      var shown = glyph - next
      if (shown < 0) next = glyph
      else if (shown > viewW) next = glyph - viewW
      var limit = Math.max(0, editor.contentWidth - viewW)
      if (next < 0) next = 0
      if (next > limit) next = limit
    } else {
      next = 0
    }
    if (Math.abs(next - hscroll) > 0.5) hscroll = next
    _following = false
  }

  function moveWithoutSelection(key) {
    var pos = editor.cursorPosition
    if (key === Qt.Key_Left) editor.cursorPosition = stepIndex(store.text, pos, -1)
    else if (key === Qt.Key_Right) editor.cursorPosition = stepIndex(store.text, pos, 1)
    else if (key === Qt.Key_Home || key === Qt.Key_Up) editor.cursorPosition = 0
    else if (key === Qt.Key_End || key === Qt.Key_Down) editor.cursorPosition = length
    else return false
    return true
  }

  onPasswordChanged: {
    _maskedAll = false
    refreshDisplay(editor.cursorPosition)
  }
  on_MaskedCaretWantedChanged: restartBlink()
  on_MaskedAllChanged: restartBlink()
  onActiveFocusChanged: if (activeFocus && !editor.activeFocus) editor.forceActiveFocus()
  // Keep cancellation independent of a caller's own visibility handler
  // (SecretField uses one to reset its reveal state).
  Connections {
    target: root
    function onVisibleChanged() { if (!root.visible) root.invalidatePaste() }
    function onEnabledChanged() {
      if (!root.enabled) {
        root._maskedAll = false
        root.invalidatePaste()
      }
    }
    function onReadOnlyChanged() {
      if (root.readOnly) {
        root._maskedAll = false
        root.invalidatePaste()
      }
    }
  }

  // Qt blinks at the platform flash time, on for half and off for half. Zero
  // or less means a solid caret.
  Timer {
    id: blink
    interval: Math.max(1, Qt.styleHints.cursorFlashTime / 2)
    repeat: true
    running: root._maskedCaretWanted && Qt.styleHints.cursorFlashTime > 0
    onTriggered: root._blinkOn = !root._blinkOn
  }
  Component.onCompleted: refreshDisplay(0)
  Component.onDestruction: killPasteGroup()

  // BeforeItem is the Keys default. The editor forwards here before it handles
  // the key, so a caller's own onReturnPressed replaces this handler and still
  // accepts the key before the document can insert a line.
  Keys.onReturnPressed: function(event) {
    event.accepted = true
    root.submit()
  }
  Keys.onEnterPressed: function(event) {
    event.accepted = true
    root.submit()
  }
  Keys.onTabPressed: function(event) {
    event.accepted = true
    root.focusFromTab(true)
  }
  Keys.onBacktabPressed: function(event) {
    event.accepted = true
    root.focusFromTab(false)
  }

  // Read-only on purpose. An editable TextInput would read the clipboard offer
  // on every change. Password echo mode is what the accessible text interface
  // returns as bullets; the QML text property stays the real value.
  TextInput {
    id: store
    readOnly: true
    visible: false
    width: 0
    height: 0
    activeFocusOnTab: false
    maximumLength: 10000000
    echoMode: root.password ? TextInput.Password : TextInput.Normal
    Accessible.ignored: true
    onTextChanged: {
      if (root._fromEditor || root._syncing) return
      root._maskedAll = false
      root.refreshDisplay()
    }
  }

  TextArea {
    id: editor
    focus: true
    width: root.width
    height: root.height

    readOnly: root.readOnly || root.password
    inputMethodHints: root.inputMethodHints | (root.password ? Qt.ImhHiddenText : 0)
    // Window.activeFocusItem is this editor. Callers and the kit tests
    // identify a masked field by the echo value on the focused item.
    readonly property int echoMode: root.echoMode

    // Plain text, one line. Return is accepted on the scope, so it does not
    // insert a break.
    textFormat: TextEdit.PlainText
    wrapMode: TextEdit.NoWrap
    verticalAlignment: TextEdit.AlignVCenter
    selectByMouse: !root.password
    clip: true
    implicitHeight: Math.ceil(font.pixelSize + topPadding + bottomPadding)

    font.family: Style.font.family
    font.pixelSize: Style.font.body
    color: root.foreground
    selectionColor: root.password ? "transparent" : root.selectionTint
    selectedTextColor: root.password ? "transparent" : root.foreground
    placeholderTextColor: Qt.darker(root.foreground, 1.6)

    leftPadding: root.horizontalPadding + Border.left(root._borderSpec) - root.hscroll
    rightPadding: root.rightPadding
    topPadding: root.verticalPadding + Border.top(root._borderSpec)
    bottomPadding: root.verticalPadding + Border.bottom(root._borderSpec)

    // The style menu pastes through the control, which reads the offer here.
    ContextMenu.menu: null
    // TextArea's accessible text is the document. Masked, that document is
    // bullets. The password state tells assistive tech not to spell them.
    Accessible.passwordEdit: root.password

    // Qt owns this item's visibility and geometry, so a masked field hides it
    // with opacity and draws maskedCaret instead.
    cursorDelegate: Rectangle {
      width: 1
      color: root.foreground
      opacity: root.password ? 0 : 1
    }

    // The field's own caret for a masked value: same look as the delegate.
    // x follows cursorRectangle (padding and hscroll included). y is centred
    // from the editor's own box: cursorRectangle.y can lag a size change
    // until the next edit, which drew the caret high on a field that was
    // just shown.
    Rectangle {
      id: maskedCaret
      objectName: "maskedCaret"
      parent: editor
      x: editor.cursorRectangle.x
      y: editor.topPadding + Math.max(0, (editor.height - editor.topPadding - editor.bottomPadding - height) / 2)
      width: 1
      height: editor.cursorRectangle.height > 0 ? editor.cursorRectangle.height : editor.font.pixelSize
      color: root.foreground
      visible: root._maskedCaretWanted && root._blinkOn
    }

    // Virtual select-all. Behind the bullets (above the background at -1).
    Rectangle {
      id: maskedHighlight
      objectName: "maskedHighlight"
      parent: editor
      z: -0.5
      x: editor.leftPadding
      y: editor.topPadding
      width: editor.contentWidth
      height: editor.height - editor.topPadding - editor.bottomPadding
      color: root.selectionTint
      visible: root.password && root._maskedAll
    }

    background: BorderSurface {
      color: Style.controlFill(root._focused, root._hot, root.foreground, root.accent)
      borderSpec: root._borderSpec
      radius: Style.cornerRadius
    }

    onSelectedTextChanged: if (root.password && selectedText) deselect()
    onCursorRectangleChanged: root.followCaret()
    onWidthChanged: root.followCaret()
    onTextChanged: {
      root.restartBlink()
      if (root._syncing) return
      if (root.password) root.refreshDisplay(cursorPosition)
      else root.mirrorEditorToStore()
    }
    onRightPaddingChanged: root.followCaret()
    onCursorPositionChanged: {
      root._maskedAll = false
      root.restartBlink()
    }
    onActiveFocusChanged: if (!activeFocus) root._maskedAll = false

    // Passive: it only observes the press, the click still reaches the editor.
    TapHandler {
      acceptedButtons: Qt.LeftButton | Qt.RightButton
      onPressedChanged: if (pressed) root._maskedAll = false
    }

    Keys.priority: Keys.BeforeItem
    Keys.forwardTo: [root, keySink]

    // Left clicks pass through. Middle click is the Selection paste, which
    // would otherwise read the offer inside this process.
    MouseArea {
      parent: editor
      anchors.fill: parent
      acceptedButtons: Qt.MiddleButton
      z: 1
      onPressed: function(mouse) {
        mouse.accepted = true
        root.pasteFrom(true)
      }
    }

    // Visible on purpose: Keys.forwardTo skips an item that is not visible.
    Item {
      id: keySink
      parent: editor
      width: 0
      height: 0

      Keys.onPressed: function(event) {
        // Accepted even when the field cannot edit, so the document does not
        // read the offer itself.
        if (event.matches(StandardKey.Paste)) {
          event.accepted = true
          root.pasteFrom(false)
          return
        }
        if (!root.password) return
        root.restartBlink()
        if (event.matches(StandardKey.SelectAll)) {
          event.accepted = true
          root._maskedAll = root.enabled && !root.readOnly && store.text.length > 0
          return
        }
        if (event.matches(StandardKey.Copy)
            || event.matches(StandardKey.Cut)
            || event.matches(StandardKey.Undo)
            || event.matches(StandardKey.Redo)) {
          event.accepted = true
          return
        }
        if (!root.enabled || root.readOnly) return
        if (root.moveWithoutSelection(event.key)) {
          root._maskedAll = false
          event.accepted = true
          return
        }
        if (event.key === Qt.Key_Backspace) {
          event.accepted = true
          root.deleteSecret(-1)
          return
        }
        if (event.key === Qt.Key_Delete) {
          event.accepted = true
          root.deleteSecret(1)
          return
        }
        // AltGr arrives as Ctrl+Alt and still carries a printable character.
        // A bare Ctrl, Alt, or Meta chord does not.
        if (event.text && event.text.charCodeAt(0) >= 32) {
          var mods = event.modifiers
          var altGr = (mods & Qt.ControlModifier) && (mods & Qt.AltModifier)
          var chord = mods & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)
          if (altGr || !chord) {
            event.accepted = true
            root.insertSecret(event.text)
          }
        }
      }

      Component {
        id: pasteComponent
        Process {
          id: proc
          property int epoch: 0
          property bool closed: false
          property bool succeeded: false
          property string payload: ""
          stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: proc.payload = text
          }
          // Quickshell emits exited after the collector and before runningChanged.
          onExited: function(exitCode, exitStatus) {
            succeeded = exitCode === 0 && exitStatus === 0
          }
          onRunningChanged: if (!running) root.finishPaste(proc)
        }
      }
    }
  }
}
