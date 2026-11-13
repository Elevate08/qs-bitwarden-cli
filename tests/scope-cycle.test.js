#!/usr/bin/env node
// Alt+V / Ctrl+Alt+F: the next vault scope or folder, without a drawer.
//
//   node tests/scope-cycle.test.js

const { createSuite, loadModule, readPluginSource } = require("./harness")
const Model = loadModule()
const { check, done } = createSuite("scope-cycle")

// Rows in the shape Service.filterOptions() builds.
const rows = (ids, active) => ids.map(id => ({ id, label: id, active: id === active }))
const orgs = ["all", "personal", "orgA", "orgB"]
const folders = ["all", "none", "f1", "f2"]

check("vault scope steps all -> personal -> each org",
  Model.nextFilterOptionId(rows(orgs, "all"), 1) === "personal"
  && Model.nextFilterOptionId(rows(orgs, "personal"), 1) === "orgA"
  && Model.nextFilterOptionId(rows(orgs, "orgA"), 1) === "orgB", "forward")
check("vault scope wraps back to all", Model.nextFilterOptionId(rows(orgs, "orgB"), 1) === "all", "wrap fwd")
check("backwards wraps from all to the last org", Model.nextFilterOptionId(rows(orgs, "all"), -1) === "orgB", "wrap back")
check("backwards steps one", Model.nextFilterOptionId(rows(orgs, "orgA"), -1) === "personal", "back")
check("folders include No Folder, then every folder, then all",
  Model.nextFilterOptionId(rows(folders, "all"), 1) === "none"
  && Model.nextFilterOptionId(rows(folders, "none"), 1) === "f1"
  && Model.nextFilterOptionId(rows(folders, "f2"), 1) === "all", "folders")
check("no active row counts as the first", Model.nextFilterOptionId(rows(orgs, "gone"), 1) === "personal", "unmatched")
check("a single option stays put", Model.nextFilterOptionId(rows(["all"], "all"), 1) === "all", "single")
check("empty or missing list gives empty id",
  Model.nextFilterOptionId([], 1) === "" && Model.nextFilterOptionId(null, -1) === "", "empty")

// Wiring: Alt+F stays the Folders drawer, so folders take Ctrl+Alt+F.
const panelSrc = readPluginSource("Panel.qml")
check("Panel cycles vault on Alt+V and folders on Ctrl+Alt+F",
  /Key_V && !ctrl\) root\.cycleFilter\("organizations"/.test(panelSrc)
  && /Key_F && ctrl\) root\.cycleFilter\("folders"/.test(panelSrc), "bindings")
check("both the interceptor and the search box call it",
  (panelSrc.match(/root\.cycleFilterFromKey\(event\)/g) || []).length === 2, "call sites")

done()
