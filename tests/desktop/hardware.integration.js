#!/usr/bin/env node
// Hardware readiness of the loaded plugin. Physical authentication is covered
// by focus.integration.js --interactive, through that plugin's own UI.
const { spawnSync } = require('child_process')
const { createSuite } = require('../harness')
const { check, done } = createSuite('loaded-hardware')
const result = spawnSync('omarchy-shell', ['io.github.elevate08.qs-bitwarden-cli', 'desktopState'],
  { encoding: 'utf8', timeout: 5000 })
let skips = 0
try {
  if (result.status !== 0) throw new Error('IPC unavailable')
  const state = JSON.parse(result.stdout)
  for (const method of ['fingerprint', 'fido']) {
    const ready = state[method + 'Ready']
    check(method + ' readiness is reported', typeof ready === 'boolean', '')
    if (!ready) { skips++; console.log('SKIP loaded-hardware: ' + method + ' unavailable or not configured') }
  }
} catch (_) { skips++; console.log('SKIP loaded-hardware: loaded plugin diagnostics unavailable') }
if (process.argv.includes('--require') && skips) check('all hardware must be ready', false, '')
console.log('loaded-hardware: ' + skips + ' explicit skips')
done()
