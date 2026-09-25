#!/usr/bin/env node
// Smaller view fixes from the fork's UI audit, pinned in the view's source:
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

done()
