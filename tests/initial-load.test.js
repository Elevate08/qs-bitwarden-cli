#!/usr/bin/env node
// The first post-authentication bw process is the item list. Organization and
// folder metadata must not compete with it; they begin only after items have
// reached the model and had an event-loop turn to paint.
//
//   node tests/initial-load.test.js

const fs = require("fs")
const path = require("path")

const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

const bodyOf = name => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}

const initial = bodyOf("beginInitialVaultLoad")
check("initial loading starts the item list", /loadItems\(/.test(initial), initial)
check("initial loading does not start organizations concurrently",
  !/loadOrganizations\(/.test(initial), initial)
check("initial loading does not start folders concurrently",
  !/loadFolders\(/.test(initial), initial)

for (const source of ["onUnlockSuccess", "onSessionHandoff"]) {
  const body = bodyOf(source)
  check(`${source} uses the items-first entry point`, /beginInitialVaultLoad\(/.test(body), body)
  check(`${source} does not launch organization metadata directly`, !/loadOrganizations\(/.test(body), body)
  check(`${source} does not launch folder metadata directly`, !/loadFolders\(/.test(body), body)
}

const listFinished = bodyOf("onListFinished")
check("metadata deferral begins only after the item result is accepted",
  /items\s*=\s*Model\.parseSanitizedItems/.test(listFinished)
    && !/items\s*=\s*Model\.parseItems/.test(listFinished)
    && /deferredMetadataTimer\.restart\(\)/.test(listFinished)
    && listFinished.indexOf("items = Model.parseSanitizedItems") < listFinished.indexOf("deferredMetadataTimer.restart()"),
  listFinished)

const listExited = bodyOf("onListProcessExited")
check("item output is accepted only after the process exit status is known",
  /exitCode\s*===\s*0/.test(listExited) && /onListFinished\(/.test(listExited), listExited)
check("a failed item refresh clears all loading and deferred-work state",
  /isLoading\s*=\s*false/.test(listExited)
    && /isSyncing\s*=\s*false/.test(listExited)
    && /metadataLoadPending\s*=\s*false/.test(listExited)
    && /syncReloadPending\s*=\s*false/.test(listExited),
  listExited)
check("a failed item refresh does not run the post-load status refresh",
  !/statusRefreshAfterItems[\s\S]{0,140}runStatusCheck\(/.test(listExited),
  listExited)

const timerStart = panelSrc.indexOf("id: deferredMetadataTimer")
const timer = timerStart === -1 ? "" : panelSrc.slice(timerStart, timerStart + 700)
check("deferred metadata loads both organizations and folders", /loadOrganizations\(/.test(timer) && /loadFolders\(/.test(timer), timer)
check("metadata waits long enough for an item-list frame",
  /interval:\s*(?:[2-9][0-9]|[1-9][0-9]{2,})/.test(timer), timer)
check("post-load status refresh is metadata-only",
  /runStatusCheck\(false\)/.test(timer)
    && /function runStatusCheck\(authoritative\)/.test(panelSrc)
    && /statusCheckAuthoritative\s*=\s*authoritative\s*!==\s*false/.test(panelSrc)
    && /if\s*\(!authoritative\)\s*\{[\s\S]{0,220}return/.test(bodyOf("onStatusFinished")),
  bodyOf("runStatusCheck") + "\n" + bodyOf("onStatusFinished") + "\n" + timer)

const sync = bodyOf("onSyncFinished")
check("a successful server sync also reloads items before metadata",
  /beginInitialVaultLoad\(/.test(sync) && !/loadOrganizations\(/.test(sync) && !/loadFolders\(/.test(sync), sync)

check("the empty list says when items are loading", panelSrc.includes('"Loading items..."'), "missing loading label")
const syncButton = panelSrc.slice(panelSrc.indexOf("// Sync Vault Button"), panelSrc.indexOf("// Send Button"))
check("the compact sync control reports progress using supported PanelActionButton properties",
  /tooltipText:\s*root\.isSyncing\s*\?\s*"Syncing\.\.\."/.test(syncButton)
    && /enabled:\s*!root\.isSyncing/.test(syncButton)
    && !/iconSpinning/.test(syncButton),
  syncButton)
check("the panel header reports sync progress in text",
  /if\s*\(root\.isSyncing\)\s*return\s*"Syncing\.\.\."/.test(panelSrc),
  "missing Syncing... header state")

const listProcessStart = panelSrc.indexOf("id: listProc")
const listProcess = listProcessStart === -1 ? "" : panelSrc.slice(listProcessStart, listProcessStart + 900)
check("the item process waits for onExited instead of racing its stdout and stderr handlers",
  /onExited:[\s\S]*onListProcessExited/.test(listProcess)
    && !/onStreamFinished:[\s\S]*onListFinished/.test(listProcess),
  listProcess)

const processBlock = id => {
  const idAt = panelSrc.indexOf(`id: ${id}`)
  if (idAt === -1) return ""
  const next = panelSrc.indexOf("\n  Process {", idAt)
  return panelSrc.slice(idAt, next === -1 ? panelSrc.length : next)
}
for (const id of ["statusProc", "sessionHandoffProc", "listOrgsProc", "listFoldersProc",
                  "orgCollectionsProc", "listSendsProc", "keyringLookupMasterProc",
                  "getItemProc", "getTotpProc"]) {
  const block = processBlock(id)
  check(`${id} accepts output only after its exit status is known`,
    /onExited:/.test(block) && !/onStreamFinished:/.test(block), block)
}

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
