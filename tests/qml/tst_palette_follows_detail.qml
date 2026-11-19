// The action palette closes when the vault changes under it: a lock, another
// screen, or the open item replaced by another (a new item's saved copy, a
// browse). That is a Connections block in Panel.qml, and a handler that is
// right does nothing if the block listens to the wrong object. So the block
// itself is taken from Panel.qml and instantiated here, against a stand-in
// vault and palette under the ids it names, and the vault's properties are
// changed: the palette must hear it.
//
// Needs the QML sources readable from QML:
//
//   QML_XHR_ALLOW_FILE_READ=1 QT_QPA_PLATFORM=offscreen \
//     /usr/lib/qt6/bin/qmltestrunner -input tests/qml
//
import QtQuick
import QtTest

TestCase {
  id: tc
  name: "PaletteFollowsDetail"

  // Panel.qml's `root`, as far as the block reads it.
  QtObject {
    id: root
    property QtObject vault: QtObject {
      property var detailItem: null
      property string status: "unlocked"
      property string currentScreen: "detail"
    }
  }

  // The palette's state, and a count of its closes.
  QtObject {
    id: actionPalette
    property bool shown: false
    property string fromScreen: ""
    property string itemId: ""
    property int closes: 0
    function close() { closes += 1; shown = false }
  }

  property var connections: null

  function readFile(relativePath) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", Qt.resolvedUrl("../../" + relativePath), false)
    xhr.send()
    return xhr.responseText || ""
  }

  // The `Connections { ... }` block under the palette's comment, braces matched.
  function paletteConnections() {
    var source = readFile("Panel.qml")
    var at = source.indexOf("// Closed when the vault locks or the screen changes underneath it.")
    if (at < 0) return ""
    var start = source.indexOf("Connections {", at)
    if (start < 0 || start - at > 200) return ""
    var depth = 0
    for (var i = source.indexOf("{", start); i < source.length; i++) {
      if (source[i] === "{") depth++
      else if (source[i] === "}" && --depth === 0) return source.slice(start, i + 1)
    }
    return ""
  }

  function initTestCase() {
    var block = paletteConnections()
    verify(block.length > 0, "the palette's Connections block was not found in Panel.qml (is QML_XHR_ALLOW_FILE_READ=1 set?)")
    verify(block.indexOf("function onDetailItemChanged()") > 0, "the block no longer handles detailItemChanged")
    connections = Qt.createQmlObject("import QtQuick\n" + block, tc, "PanelPaletteConnections")
    verify(connections !== null, "the block did not instantiate")
  }

  function open(screen, itemId) {
    root.vault.status = "unlocked"
    root.vault.currentScreen = screen
    actionPalette.fromScreen = screen
    actionPalette.itemId = itemId
    actionPalette.shown = true
    actionPalette.closes = 0
  }

  function test_listens_to_the_vault() {
    compare(connections.target, root.vault, "the block must listen to root.vault")
  }

  function test_detail_replaced_closes_the_palette() {
    root.vault.detailItem = { id: "a" }
    open("detail", "a")
    // The provisional row's detail becomes the saved item's.
    root.vault.detailItem = { id: "b" }
    compare(actionPalette.closes, 1, "another item under the palette must close it")
    verify(!actionPalette.shown)
  }

  function test_detail_gone_closes_the_palette() {
    root.vault.detailItem = { id: "a" }
    open("detail", "a")
    root.vault.detailItem = null
    compare(actionPalette.closes, 1)
  }

  function test_same_item_reloaded_keeps_it_open() {
    root.vault.detailItem = { id: "a" }
    open("detail", "a")
    // The whole item loaded for an edit, or dropped again: the same id.
    root.vault.detailItem = { id: "a", secretsWithheld: true }
    compare(actionPalette.closes, 0, "a reload of the same item must not close the palette")
    verify(actionPalette.shown)
  }

  function test_list_palette_ignores_the_detail() {
    root.vault.detailItem = { id: "a" }
    open("main", "a")
    root.vault.detailItem = { id: "b" }
    compare(actionPalette.closes, 0, "a palette opened from the list does not follow the detail")
  }

  function test_lock_and_screen_change_close_it() {
    root.vault.detailItem = { id: "a" }
    open("detail", "a")
    root.vault.currentScreen = "main"
    compare(actionPalette.closes, 1, "leaving the screen closes the palette")
    open("main", "a")
    root.vault.status = "locked"
    compare(actionPalette.closes, 1, "a lock closes the palette")
  }
}
