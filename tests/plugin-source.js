// Source for the suites that read the plugin's QML as text.
//
// Those suites were written while the vault and its view were one file. Since
// issue #30 the vault is Service.qml, loaded once per shell, and Panel.qml is a
// per-monitor view of it that reaches vault members as `root.vault.<name>`; the
// SSH screens and the custom-field editor receive it as `vault` beside the
// `panel` that draws them.
//
// readPluginSource() gives a suite the text it was written against: for
// Panel.qml, the vault followed by the view -- the order the single file had --
// and in every file the vault qualifier folded back into the view's. The fold
// is exact rather than loose. tests/service-host.test.js fails if any view
// names a vault member other than through `root.vault` or `vault`, and if a
// vault member is still declared in a view, so after folding `root.status`
// can only mean the vault's status, as it always did.

const fs = require("fs")
const path = require("path")

const root = path.join(__dirname, "..")
const raw = file => fs.readFileSync(path.join(root, file), "utf8")

function readPluginSource(file) {
  if (file === "Panel.qml") {
    return raw("Service.qml") + "\n" + raw("Panel.qml").replace(/\broot\.vault\./g, "root.")
  }
  return raw(file).replace(/\bvault\./g, "panel.")
}

module.exports = { readPluginSource }
