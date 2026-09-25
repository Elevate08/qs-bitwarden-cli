#!/usr/bin/env node
// Smaller view fixes, pinned in the view's source:
// what a field shows once the state behind it is gone, which screen keys act
// on, and confirmations before destructive keys.
//
//   node tests/view-hardening.test.js

const { createSuite, readView, functionBody } = require("./harness")

const { check, done } = createSuite("view-hardening")

const view = readView()

// --- the login form's "Show password" ---------------------------------------

check("a cleared login password hides it again",
  /function syncLoginFields\(\)[\s\S]*?if \(!root\.vault\.loginPassword\) eyeBtnLogin\.revealed = false/.test(view),
  functionBody(view, "syncLoginFields"))
check("and closing the panel does too",
  /onOpenedChanged: if \(!root\.opened\) eyeBtnLogin\.revealed = false/.test(view),
  "a revealed master password would be shown in the clear at the next open")

// --- the item form's secrets ------------------------------------------------

for (const prop of ["formTotp", "formCardNumber", "formCardCode", "formIdSsn", "formIdPassport", "formIdLicense"]) {
  check(`the form's ${prop} field is masked`,
    new RegExp(`SecretField \\{\\s*width: parent\\.width\\s*placeholderText: [^\\n]*\\s*text: root\\.vault\\.${prop}\\s*onTextChanged: root\\.vault\\.${prop} = text`).test(view),
    `${prop} is a plain TextField, drawn in the clear and offered to input methods`)
}
check("a revealed password field is still kept from input methods",
  (view.match(/inputMethodHints: Qt\.ImhSensitiveData \| Qt\.ImhNoPredictiveText/g) || []).length >= 2,
  "the login and item-form password fields lose the hint when shown")

done()
