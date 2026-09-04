// A row of buttons must fit the panel it is drawn in.
//
// QtQuick's Row is a positioner, not a layout: it cannot shrink a child and it
// cannot start a second line. Anything wider than the panel is simply laid out
// past the right edge, and the control that lands there is gone -- not clipped
// with a scrollbar, not wrapped, just off the panel with no way to reach it.
//
// That is how "Suggested here" cost the detail view its Delete button. The
// header holds four buttons only when the active window matched a login, and
// the pinned label is one character wider than the unpinned one -- so the row
// fit at 441px until the moment you clicked, and 454.5px after. Nothing in the
// panel said so; the button was just missing.
//
// So this measures. It reads the panel's own QML, finds every Row of buttons,
// rebuilds each label with the real font, and adds up what the kit will make
// of them. A Row that does not fit fails here instead of in a screenshot.
//
// Rows declared as Flow or RowLayout are reported but not failed: those two
// CAN wrap or shrink, which is the fix this test exists to push people toward.
//
// Needs the QML sources readable from QML, which Qt gates behind an env var:
//
//   QML_XHR_ALLOW_FILE_READ=1 QT_QPA_PLATFORM=offscreen \
//     /usr/lib/qt6/bin/qmltestrunner -input tests/qml
//
import QtQuick
import QtTest

TestCase {
  id: tc
  name: "RowWidths"
  when: windowShown
  width: 600; height: 200
  visible: true

  // ---------------------------------------------------------------- budgets
  //
  // Panel.qml draws into `fittedContentWidth(Style.space(450))`. Rows inside a
  // Flickable lose `scrollGutter` (Style.space(10)) on top of that, and rather
  // than track which rows are and are not inside one, every panel row is held
  // to the narrower 440. The SSH prompt is its own card: Style.space(460) less
  // panelPadding (18) and the card border (2) on each side.
  //
  // These are the sizes at the default [font] base-size of 12. A theme scales
  // fonts and spacing by the same factor -- Style.space() multiplies by
  // fontScale too -- so the ratio this test pins holds at any base size.
  readonly property int panelBudget: 440
  readonly property int popupBudget: 420

  // ------------------------------------------------------- the kit's Button
  //
  // qs.Ui.Button cannot be instantiated here: it imports qs.Commons, which
  // imports Quickshell, whose plugin only loads inside the quickshell runtime.
  // So its geometry is restated, from Ui/Button.qml:
  //
  //   implicitWidth: row.implicitWidth + horizontalPadding * 2
  //                  + _reservedBorderLeft + _reservedBorderRight
  //
  // where the inner row is `icon + Style.spacing.controlGap + label`, the
  // padding is Style.spacing.controlPaddingX, and the reserved border is the
  // widest any state can paint (1px a side at the default border width).
  // `verify_button_geometry_is_still_the_kits` below fails if that changes.
  readonly property int controlGap: 8
  readonly property int controlPaddingX: 10
  readonly property int reservedBorder: 2

  // Style.font tokens at base-size 12: caption .833, body-small .917, body 1.0,
  // and `icon` defaults to `title` (1.167).
  readonly property var fontPx: ({
    "Style.font.caption": 10,
    "Style.font.bodySmall": 11,
    "Style.font.body": 12
  })
  readonly property int iconPx: 14

  TextMetrics { id: labelMetrics; font.family: "monospace" }
  TextMetrics { id: iconMetrics; font.family: "monospace"; font.pixelSize: tc.iconPx }

  function labelWidth(text, px) {
    labelMetrics.font.pixelSize = px
    labelMetrics.text = text
    return labelMetrics.advanceWidth
  }

  // One monospace cell at the icon size, NOT the glyph itself.
  //
  // These icons are Nerd Font private-use codepoints, which exist on a desktop
  // running the shell and not on a CI runner -- and a missing glyph measures as
  // the fallback's notdef box, so measuring them directly would quietly change
  // every total the moment this runs somewhere without the font. In a patched
  // monospace font a Nerd glyph occupies exactly one cell, so an ordinary
  // character at the same pixel size is the same width and is everywhere.
  // (Locally both measure 8.390625.)
  function iconWidth(glyph) {
    if (!glyph) return 0
    iconMetrics.text = "M"
    return iconMetrics.advanceWidth
  }

  function buttonWidth(button) {
    var icon = iconWidth(button.icon)
    var label = button.label === "" ? 0 : labelWidth(button.label, button.fontSize)
    var gap = (icon > 0 && label > 0) ? tc.controlGap : 0
    return icon + gap + label + button.paddingX * 2 + tc.reservedBorder
  }

  // ------------------------------------------------------------ reading QML
  function readFile(relativePath) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", Qt.resolvedUrl("../../" + relativePath), false)
    xhr.send()
    return xhr.responseText || ""
  }

  // Every string literal in a binding, longest first. A label is often a
  // conditional -- `root.sendMode === "create" ? "Back to Sends" : "Back"` --
  // and the widest branch is the one that has to fit.
  function widestLiteral(binding) {
    var found = binding.match(/"((?:[^"\\]|\\.)*)"/g)
    if (!found) return null
    var widest = ""
    for (var i = 0; i < found.length; i++) {
      var value = found[i].slice(1, -1).replace(/\\"/g, "\"")
      if (value.length > widest.length) widest = value
    }
    return widest
  }

  function propertyIn(body, name) {
    var m = body.match(new RegExp("^\\s*" + name + ":\\s*(.*)$", "m"))
    return m ? m[1].trim() : null
  }

  // Direct children only. A nested Row -- the per-item action buttons inside a
  // list delegate, say -- is found and measured as a row in its own right, and
  // must not also be counted as part of its parent.
  function directChildren(body, type) {
    var out = []
    var open = new RegExp("(?:^|\\n)(\\s*)(?:" + type + ")\\s*\\{")
    var rest = body
    var depth = 0
    var lines = body.split("\n")
    var i
    for (i = 0; i < lines.length; i++) {
      var line = lines[i]
      var isChild = depth === 1 && new RegExp("^\\s*(?:" + type + ")\\s*\\{").test(line)
      if (isChild) {
        var childDepth = 0
        var collected = []
        for (var j = i; j < lines.length; j++) {
          collected.push(lines[j])
          childDepth += (lines[j].match(/\{/g) || []).length
          childDepth -= (lines[j].match(/\}/g) || []).length
          if (childDepth === 0 && j > i) break
        }
        out.push(collected.join("\n"))
      }
      depth += (line.match(/\{/g) || []).length
      depth -= (line.match(/\}/g) || []).length
    }
    return out
  }

  // Every Row / Flow / RowLayout in a file, with the buttons directly in it.
  function rowsIn(source, file) {
    var lines = source.split("\n")
    var rows = []
    for (var i = 0; i < lines.length; i++) {
      var opener = lines[i].match(/^(\s*)(Row|Flow|RowLayout)\s*\{\s*$/)
      if (!opener) continue
      var depth = 0
      var block = []
      for (var j = i; j < lines.length; j++) {
        block.push(lines[j])
        depth += (lines[j].match(/\{/g) || []).length
        depth -= (lines[j].match(/\}/g) || []).length
        if (depth === 0 && j > i) break
      }
      var body = block.join("\n")
      var buttons = []
      var declarations = directChildren(body, "Button|VaultFilterButton")
      for (var k = 0; k < declarations.length; k++) {
        var declaration = declarations[k]
        var textBinding = propertyIn(declaration, "text")
        var label = textBinding === null ? null : widestLiteral(textBinding)
        // A label with no literal in it is vault text or a computed string.
        // Its width is not ours to know, so it is reported, never measured.
        if (label === null) { buttons.push(null); continue }
        var sizeBinding = propertyIn(declaration, "fontSize")
        var iconBinding = propertyIn(declaration, "iconText")
        var padBinding = propertyIn(declaration, "horizontalPadding")
        buttons.push({
          label: label,
          icon: iconBinding === null ? "" : (widestLiteral(iconBinding) || ""),
          fontSize: (sizeBinding && tc.fontPx[sizeBinding] !== undefined)
            ? tc.fontPx[sizeBinding] : tc.fontPx["Style.font.body"],
          paddingX: padBinding === null ? tc.controlPaddingX : tc.controlPaddingX
        })
      }
      var spacingBinding = propertyIn(body, "spacing")
      var spacingMatch = spacingBinding ? spacingBinding.match(/Style\.space\((\d+)\)/) : null
      rows.push({
        file: file,
        line: i + 1,
        kind: opener[2],
        spacing: spacingMatch ? parseInt(spacingMatch[1], 10) : 0,
        buttons: buttons
      })
      i = j
    }
    return rows
  }

  function measure(row) {
    var total = 0
    for (var i = 0; i < row.buttons.length; i++) {
      if (row.buttons[i] === null) return -1
      total += buttonWidth(row.buttons[i])
    }
    return total + row.spacing * Math.max(0, row.buttons.length - 1)
  }

  // ------------------------------------------------------------------ tests
  readonly property var sources: [
    { file: "Panel.qml", budget: panelBudget },
    { file: "SshAgentSettings.qml", budget: panelBudget },
    { file: "SshApprovalScreen.qml", budget: popupBudget },
    { file: "SshUnlockScreen.qml", budget: popupBudget }
  ]

  // Every budget here is a pixel count, and pixel counts only mean anything
  // while the font puts every character in the same width of cell. If this
  // machine resolves `monospace` to something proportional, the numbers below
  // are measuring a different panel than the one that ships -- say so rather
  // than report a pass or a failure that was never about the layout.
  function test_the_font_is_monospaced() {
    var narrow = labelWidth("iiiiiiiiii", 11)
    var wide = labelWidth("MMMMMMMMMM", 11)
    verify(narrow > 0 && Math.abs(narrow - wide) < 0.01,
      "`monospace` resolved to a proportional font here (i=" + narrow
      + ", M=" + wide + "), so these width budgets do not describe the panel")
  }

  function test_the_sources_are_readable() {
    // Without QML_XHR_ALLOW_FILE_READ every parse silently finds nothing, and
    // a test that measures nothing passes. Fail loudly instead.
    for (var i = 0; i < sources.length; i++) {
      var body = readFile(sources[i].file)
      verify(body.length > 0,
        sources[i].file + " read back empty -- set QML_XHR_ALLOW_FILE_READ=1")
    }
  }

  function test_every_row_of_buttons_fits_its_panel() {
    var offenders = []
    var measured = 0
    for (var i = 0; i < sources.length; i++) {
      var rows = rowsIn(readFile(sources[i].file), sources[i].file)
      for (var j = 0; j < rows.length; j++) {
        var row = rows[j]
        if (row.buttons.length < 2) continue
        var total = measure(row)
        if (total < 0) continue
        measured++
        // Flow wraps and RowLayout shrinks; neither can push a button off the
        // panel, so neither is held to the single-line budget.
        if (row.kind !== "Row") continue
        if (total > sources[i].budget) {
          offenders.push(row.file + ":" + row.line + " (" + row.buttons.length
            + " buttons) needs " + total.toFixed(1)
            + "px, panel gives " + sources[i].budget + "px")
        }
      }
    }
    verify(measured >= 12, "only measured " + measured + " rows -- the parser stopped seeing them")
    // Every button is counted, including ones a `visible:` binding makes
    // mutually exclusive -- the parser cannot evaluate those, and a row whose
    // contents depend on runtime state is exactly the row that should wrap
    // rather than be trusted to a hand-checked worst case. The remedy either
    // way is one word: Flow.
    verify(offenders.length === 0,
      "these Rows lay a button out past the panel edge; make them a Flow, or "
      + "shorten the labels:\n    " + offenders.join("\n    "))
  }

  // The header that started this. Pinned and unpinned are measured separately
  // because only the pinned label overflowed, which is why it survived review.
  function test_the_detail_header_fits_with_the_suggestion_button_showing() {
    var header = { spacing: 8, buttons: [
      { label: "Back (Esc)", icon: "\u{f040d}", fontSize: 11, paddingX: 10 },
      { label: "Suggested here", icon: "\u{f043e}", fontSize: 11, paddingX: 10 },
      { label: "Edit", icon: "\u{f03eb}", fontSize: 11, paddingX: 10 },
      { label: "Delete", icon: "\u{f01b4}", fontSize: 11, paddingX: 10 }
    ] }
    var pinned = measure(header)
    header.buttons[1].label = "Suggest here"
    header.buttons[1].icon = "\u{f043d}"
    var unpinned = measure(header)
    verify(pinned <= panelBudget,
      "pinned header needs " + pinned.toFixed(1) + "px of " + panelBudget)
    verify(unpinned <= panelBudget,
      "unpinned header needs " + unpinned.toFixed(1) + "px of " + panelBudget)
  }

  // The filter row names each filter as well as showing its value, because
  // three chips reading "All" say nothing about which is which. That costs
  // width, and the row is allowed to wrap to pay for it -- so what has to hold
  // is not that every combination fits one line, but these two things.
  function filterChip(name, value, glyph) {
    // Model.clipLabel(value, 20), restated.
    var clipped = value.length <= 20 ? value : value.slice(0, 17) + "..."
    return { label: name + ": " + clipped, icon: glyph, fontSize: 10, paddingX: 10 }
  }

  // One: the state the panel actually opens in stays on a single line. If this
  // fails the row wraps by default, which is a worse row than a shorter label.
  function test_the_unfiltered_filter_row_is_one_line() {
    var row = { spacing: 6, buttons: [
      filterChip("Folders", "All", "\u{f024b}"),
      filterChip("Organizations", "All", "\u{f0991}"),
      filterChip("Types", "All", "\u{f003b}")
    ] }
    var total = measure(row)
    verify(total <= panelBudget,
      "the default filter row needs " + total.toFixed(1) + "px of " + panelBudget
      + " -- it would open already wrapped")
  }

  // Two: no single chip can be wider than the panel, whatever is in the vault.
  // A Flow can move a button to the next line but never make one narrower, so
  // this is the one thing wrapping cannot rescue -- it is what the clip is for.
  function test_no_filter_chip_can_outgrow_the_panel_on_its_own() {
    var monstrous = "Acme Corporation Holdings International Limited"
    var names = [["Folders", "\u{f024b}"], ["Organizations", "\u{f0991}"], ["Types", "\u{f003b}"]]
    for (var i = 0; i < names.length; i++) {
      var chip = filterChip(names[i][0], monstrous, names[i][1])
      var width = buttonWidth(chip)
      verify(width <= panelBudget,
        names[i][0] + " chip reaches " + width.toFixed(1) + "px of " + panelBudget
        + " with a long vault name -- the clip is not holding")
    }
  }

  // --------------------------------------------------- the wrapping is real
  //
  // Everything above is arithmetic. This part instantiates the two containers
  // the fix relies on and checks they behave, because both do something a Row
  // does not: the header wraps, and the filter row shrink-wraps so it can stay
  // centred while it fits and take the whole panel when it cannot.
  //
  // The chips stand in for qs.Ui.Button -- which will not load here -- using
  // the same implicitWidth this file already restates.
  Component {
    id: chip
    Item {
      // Named, because inside a Component `parent` is the Flow it is created
      // in, not this Item -- reaching the label through `parent` silently
      // measures an empty string and nothing ever wraps.
      id: chipRoot
      property string label: ""
      property int px: 11
      implicitWidth: chipMetrics.advanceWidth + tc.controlGap + tc.iconWidth("\u{f01b4}")
        + tc.controlPaddingX * 2 + tc.reservedBorder
      width: implicitWidth
      height: 26
      TextMetrics {
        id: chipMetrics
        font.family: "monospace"
        font.pixelSize: chipRoot.px
        text: chipRoot.label
      }
    }
  }

  Item {
    id: headerHost
    width: tc.panelBudget
    height: 100
    Flow {
      id: headerFlow
      width: parent.width
      spacing: 8
    }
  }

  Item {
    id: filterHost
    width: tc.panelBudget
    height: 100
    Flow {
      id: filterFlow
      anchors.horizontalCenter: parent.horizontalCenter
      spacing: 6
      // The binding under test, copied from Panel.qml: it reads the chips'
      // implicitWidth and never their width, so it cannot feed itself.
      readonly property real naturalWidth: {
        var total = 0
        for (var i = 0; i < children.length; i++) total += children[i].implicitWidth
        return total + spacing * Math.max(0, children.length - 1)
      }
      width: Math.min(parent.width, naturalWidth)
    }
  }

  function fill(flow, labels, px) {
    for (var i = flow.children.length - 1; i >= 0; i--) flow.children[i].destroy()
    wait(20) // destroy() is deferred; the children are still there until it runs
    for (var j = 0; j < labels.length; j++) {
      chip.createObject(flow, { label: labels[j], px: px })
    }
    wait(20)
    compare(flow.children.length, labels.length, "the stub chips did not all get created")
    for (var k = 0; k < flow.children.length; k++) {
      verify(flow.children[k].implicitWidth > 0,
        "a stub chip measured as zero-width -- it is not measuring its label")
    }
  }

  function overhang(flow, host) {
    var worst = 0
    for (var i = 0; i < flow.children.length; i++) {
      var child = flow.children[i]
      var edge = child.mapToItem(host, child.width, 0).x
      if (edge - host.width > worst) worst = edge - host.width
    }
    return worst
  }

  function test_the_header_wraps_instead_of_pushing_a_button_off_the_panel() {
    fill(headerFlow, ["Back (Esc)", "Suggested here", "Edit", "Delete"], 11)
    var oneLine = headerFlow.height
    compare(overhang(headerFlow, headerHost), 0, "a button hangs past the panel at full width")

    // The narrow panel a small screen actually produces.
    headerHost.width = 300
    wait(20)
    compare(overhang(headerFlow, headerHost), 0, "a button hangs past a 300px panel")
    verify(headerFlow.height > oneLine, "the header should have taken a second line")

    headerHost.width = tc.panelBudget
    wait(20)
    compare(headerFlow.height, oneLine, "and should return to one line")
  }

  function test_the_filter_row_stays_centred_while_it_fits_and_wraps_when_it_does_not() {
    fill(filterFlow, ["Unfiled", "Personal", "Favorites"], 10)
    verify(filterFlow.width < filterHost.width,
      "the row should shrink-wrap so it can be centred, got " + filterFlow.width)
    var left = filterFlow.x
    var right = filterHost.width - (filterFlow.x + filterFlow.width)
    verify(Math.abs(left - right) < 1.5, "not centred: left " + left + ", right " + right)

    filterHost.width = 200
    wait(20)
    compare(filterFlow.width, 200, "the row should take the whole panel once it must wrap")
    compare(overhang(filterFlow, filterHost), 0, "a filter chip hangs past the panel")

    filterHost.width = tc.panelBudget
    wait(20)
    verify(filterFlow.width < tc.panelBudget, "the row should shrink-wrap and re-centre")
  }

  // The restated geometry above is only right while the kit's is unchanged.
  function test_button_geometry_is_still_the_kits() {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", "file:///usr/share/omarchy/shell/Ui/Button.qml", false)
    xhr.send()
    var source = xhr.responseText || ""
    if (source.length === 0) return // kit not installed here; nothing to check
    verify(source.indexOf(
      "implicitWidth: row.implicitWidth + horizontalPadding * 2 "
      + "+ _reservedBorderLeft + _reservedBorderRight") >= 0,
      "Ui/Button.qml no longer sizes itself the way this test assumes")
    verify(/spacing:\s*Style\.spacing\.controlGap/.test(source),
      "Ui/Button.qml no longer gaps its icon and label by controlGap")
  }
}
