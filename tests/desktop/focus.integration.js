#!/usr/bin/env node
// Drives only the plugin already loaded in the current Omarchy session.
// Credentials are entered by the owner; IPC contains state/booleans only.
const { spawnSync } = require('child_process')
const { createSuite } = require('../harness')
const suite = createSuite('loaded-desktop')
const done = suite.done
const check = (label, ok, detail) => {
  suite.check(label, ok, detail); console.log((ok ? 'PASS ' : 'FAIL ') + label)
}
const target = 'io.github.elevate08.qs-bitwarden-cli'
const cancelOnly = process.argv.includes('--cancel-only')
const requestedMethod = process.argv.find(arg => arg.startsWith('--method='))?.slice(9)
for (const arg of process.argv.slice(2)) {
  if (!['--interactive', '--require', '--cancel-only', '--unlock-only'].includes(arg)
      && !arg.startsWith('--method=')) throw new Error('Unknown test option: ' + arg)
}
if (requestedMethod && !['password', 'pin', 'fingerprint', 'fido'].includes(requestedMethod)) {
  throw new Error('Unknown unlock method')
}
const unlockOnly = process.argv.includes('--unlock-only') || !!requestedMethod
if (cancelOnly && unlockOnly) throw new Error('Choose cancellation or unlock testing')
const interactive = process.argv.includes('--interactive') || cancelOnly || unlockOnly
const required = process.argv.includes('--require')
const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
let skips = 0
const skip = message => { skips++; console.log('SKIP loaded-desktop: ' + message) }
function ipc(method) {
  const result = spawnSync('omarchy-shell', [target, method], { encoding: 'utf8', timeout: 5000 })
  if (result.status !== 0) throw new Error('Loaded plugin IPC failed: ' + method)
  return result.stdout.trim()
}
const state = () => JSON.parse(ipc('desktopState'))
function waitFor(predicate, timeout = 5000) {
  const deadline = Date.now() + timeout
  let value
  do { value = state(); if (predicate(value)) return value; sleep(75) } while (Date.now() < deadline)
  return null
}
const focused = s => s.views.some(v => v && v.opened && v.visible &&
  (s.status === 'unlocked' ? v.searchFocused : v.windowFocused))
function pinentryHasFocus() {
  // The helper reports asking before pinentry has mapped its native window.
  const deadline = Date.now() + 5000
  do {
    const active = spawnSync('hyprctl', ['-j', 'activewindow'], { encoding: 'utf8', timeout: 3000 })
    try {
      // Arch's pinentry wrapper can delegate to GNOME's GCR System Prompter.
      if (active.status === 0 && /pinentry|gcr-prompter/i.test(JSON.parse(active.stdout).class || '')) return true
    } catch (_) {}
    sleep(100)
  } while (Date.now() < deadline)
  return false
}
let initial
try { initial = state() } catch (_) {
  skip('loaded plugin diagnostics unavailable; install the candidate and rescanPlugins first')
  if (required) check('loaded plugin is required', false, '')
  done(); process.exit(0)
}
check('diagnostics come from the loaded plugin', Array.isArray(initial.views) && initial.views.length > 0, '')
if (initial.pinentryActive || initial.unlocking || initial.fingerprintScanning || initial.fidoScanning
    || !['main', 'locked'].includes(initial.screen)) {
  skip('an existing prompt or editing screen is active; leave it before running')
} else {
  try {
    // The rapid reopen runs while the real layer surface can still be fading.
    for (const delay of [0, 25, 200]) {
      ipc('close'); sleep(delay); ipc('open')
      check('real panel acquires focus after reopen (' + delay + 'ms)', !!waitFor(focused), '')
      ipc('close')
      check('closing releases logical panel ownership (' + delay + 'ms)', !!waitFor(s => !s.opened), '')
      check('closing releases the mapped surface (' + delay + 'ms)',
        !!waitFor(s => s.views.every(v => !v || !v.visible)), '')
    }
    if (!interactive) skip('live unlock/cancel requires --interactive and owner input')
    else {
      if (!unlockOnly) {
        ipc('lock'); ipc('open')
        console.log('ACTION: Select Password (or PIN) to open its prompt, then CANCEL it. Do not unlock yet.')
        const prompt = waitFor(s => s.pinentryActive, 120000)
        if (prompt) {
          check('real pinentry prompt starts', true, '')
          check('compositor focuses the real pinentry window', pinentryHasFocus(), '')
          const cancelled = waitFor(s => !s.pinentryActive && !s.unlocking && s.status === 'locked', 120000)
          check('cancel leaves the vault locked and idle', !!cancelled, '')
          check('cancel restores panel focus', !!cancelled && !!waitFor(focused), '')
        } else if (state().typedSecretEntry !== 'pinentry') skip('panel typing configured; no pinentry cancellation to test')
        else check('real pinentry prompt starts', false, 'No prompt observed within two minutes')
      }
      const ready = state()
      const methods = []
      if (!cancelOnly) {
        for (const method of requestedMethod ? [requestedMethod] : ['password', 'pin', 'fingerprint', 'fido']) {
          if (method === 'password' || ready[method + 'Ready']) methods.push(method)
          else skip(method + ' not ready in the loaded plugin')
        }
      }
      for (const method of methods) {
        ipc('close'); ipc('lock'); ipc('open')
        console.log('ACTION: Select ' + method.toUpperCase() + ' in the loaded plugin and complete its unlock prompt.')
        let observed = false
        let promptFocused = false
        const unlocked = waitFor(s => {
          // The panel intentionally hides while pinentry owns the keyboard.
          const selected = s.views.some(v => v && v.method === method)
          if (method === 'fingerprint') observed ||= selected && s.fingerprintScanning
          else if (method === 'fido') observed ||= selected && s.fidoScanning
          else observed ||= selected && (s.pinentryActive || s.unlocking || s.views.some(v => v &&
            (method === 'pin' ? v.pinFocused : v.passwordFocused)))
          if (selected && s.pinentryActive && !promptFocused) promptFocused = pinentryHasFocus()
          return s.status === 'unlocked'
        }, 180000)
        check(method + ' follows its real authentication path', observed, 'Requested path was not observed')
        if ((method === 'pin' || method === 'password') && ready.typedSecretEntry === 'pinentry') {
          check(method + ' prompt receives compositor focus', promptFocused, '')
        }
        check(method + ' unlocks the real vault', !!unlocked, 'Unlock did not finish within three minutes')
        check(method + ' clears authentication busy state', !!unlocked && !!waitFor(s => !s.pinentryActive
          && !s.unlocking && !s.fingerprintScanning && !s.fidoScanning), '')
        check(method + ' returns focus to the real panel', !!unlocked && !!waitFor(focused), '')
        if (!unlocked) break
      }
    }
  } finally {
    if (initial.opened) ipc('open'); else ipc('close')
  }
}
console.log('loaded-desktop: ' + skips + ' explicit skips')
if (required && skips) check('required coverage has no skips', false, skips + ' checks skipped')
done()
