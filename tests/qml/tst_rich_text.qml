// A Text left on its default textFormat sniffs its own string and renders it
// as HTML the moment it looks like markup. That is a real hazard in a panel
// whose strings come out of a vault, and it is invisible in code review --
// nothing in the QML says "HTML". So it is pinned here against Qt itself
// rather than against our reading of the docs.
//
// Rendering is observed through contentWidth: markup that Qt parsed is markup
// Qt did not draw, so the parsed line is narrower than the literal one.
//
//   QT_QPA_PLATFORM=offscreen qmltestrunner -input tests/qml
//
import QtQuick
import QtTest
import "../../BitwardenModel.js" as Model

TestCase {
  id: tc
  name: "RichText"
  when: windowShown

  // A vault value crafted to be read as markup. The tags are what an attacker
  // controls; the visible text is what the user is entitled to see.
  readonly property string vaultName: "<b>Work</b> &amp; Home"

  // Default textFormat -- Text.AutoText -- exactly as the shared kit controls
  // render the labels we hand them.
  Text { id: sniffing; font.pixelSize: 14 }

  // What the plugin's own Text elements now declare.
  Text { id: literal; textFormat: Text.PlainText; font.pixelSize: 14 }

  function test_auto_text_swallows_markup_in_a_vault_value() {
    literal.text = tc.vaultName
    sniffing.text = tc.vaultName
    verify(sniffing.contentWidth > 0)
    verify(sniffing.contentWidth < literal.contentWidth - 1)
  }

  function test_plain_text_draws_the_value_the_vault_holds() {
    literal.text = tc.vaultName
    compare(literal.textFormat, Text.PlainText)
    verify(literal.contentWidth > 0)
  }

  function test_plainLabel_restores_the_literal_value_for_a_sniffing_control() {
    literal.text = tc.vaultName
    sniffing.text = Model.plainLabel(tc.vaultName)
    // Same glyphs, so the same width: nothing was parsed away and no entity
    // leaked through as "&amp;".
    fuzzyCompare(sniffing.contentWidth, literal.contentWidth, 2.0)
  }

  function test_plainLabel_leaves_an_ordinary_name_alone() {
    compare(Model.plainLabel("Work"), "Work")
  }
}
