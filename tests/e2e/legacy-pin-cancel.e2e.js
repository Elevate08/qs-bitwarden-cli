#!/usr/bin/env node
// Native Service/VaultProcess and shipped vault helper, disposable account.
// Cancel and resubmit in one IPC turn so the killed process cannot finish
// before the second action. Only bw/keyring and the UI are fixture boundaries.
const { createSuite, loadModule } = require('../harness')
const { createShell, sleep } = require('./shell')
const fs = require('fs')
const path = require('path')
const { spawn, spawnSync } = require('child_process')
const os = require('os')
const Model = loadModule()
const { check, done } = createSuite('e2e-legacy-pin-cancel')
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'qsbw-pin-cancel-'))
const gate = path.join(scratch, 'gate')
const shell = createShell('legacy-pin-cancel', check, { plugin: process.env.REVIEW_SOURCE_ROOT,
  env: { FAKE_LEGACY_PIN_GATE: gate } })
try {
  shell.start()
  shell.q('open')
  shell.expect('fixture starts signed out', s => s.status === 'unauthenticated')
  shell.q('login', 'legacy-fixture@x', 'pw-legacy-fixture@x')
  shell.expect('fixture signs in with the real helper', s => s.status === 'unlocked' && s.helper === 'active')
  shell.q('lock')
  shell.expect('fixture is locked', s => s.status === 'locked')
  for (const cleanup of ['once', 'twice', 'panel', 'late']) {
    if (cleanup === 'late') {
      // A real legacy encrypted blob, containing only the fixture password.
      const encrypted = spawnSync('openssl', ['enc', '-aes-256-cbc', '-pbkdf2',
        '-iter', String(Model.PIN_ITERATIONS), '-md', 'sha256', '-pass', 'env:QSBW_FIXTURE_PIN', '-base64', '-A'],
        { input: 'pw-legacy-fixture@x', env: { ...shell.env, QSBW_FIXTURE_PIN: '123456' }, encoding: 'utf8', timeout: 15000 })
      check('fixture legacy blob encrypts', encrypted.status === 0, '')
      if (encrypted.status !== 0) throw new Error('Could not create the legacy fixture')
      fs.writeFileSync(path.join(shell.env.FAKE_KEYRING,
        Model.keyringEntryName(Model.KEYRING_PIN, shell.state().slot)), encrypted.stdout, { mode: 0o600 })
      shell.q('beginLegacyPinForLateResult')
      const deadline = Date.now() + 5000
      while (!fs.existsSync(gate + '.started') && Date.now() < deadline) sleep(25)
      check('fixture legacy run reaches the gated keyring lookup', fs.existsSync(gate + '.started'), '')
      if (!fs.existsSync(gate + '.started')) throw new Error('Legacy helper run did not start')
      // Release from another process after the next IPC turn has blocked Qt.
      spawn('bash', ['-c', 'sleep 0.5; touch "$1.release"', '_', gate], { env: shell.env, stdio: 'ignore' })
    }
    const result = JSON.parse(shell.q('cancelLegacyPinAndRetry', cleanup))
    check(cleanup + ': native helper run started', result.started, '')
    check(cleanup + ': cancellation flips running before the exit', result.stopped && result.sameRun, '')
    check(cleanup + ': capture ownership survives the second submit', result.captureStable, '')
    check(cleanup + ': killed run stays busy without a replacement submission', result.busy && !result.submitted, '')
    const settled = shell.expect(cleanup + ': cancelled native run settles', s => !s.legacyPin.busy && !s.legacyPin.submitted)
    check(cleanup + ': cancellation charges no PIN attempts', settled.legacyPin.attempts === 0, '')
    check(cleanup + ': cancellation leaves the vault locked without a PIN error',
      settled.status === 'locked' && settled.pinUnlockError === '', '')
    if (cleanup === 'late') {
      check('late: the real helper finished and held its output before cancellation',
        settled.legacyPin.exitCode === 0 && settled.legacyPin.outputHeld, '')
      shell.q('checkHeld', result.heldName)
      const held = shell.expect('late: real helper answers the held-reference check', s => s.held === 'none' || s.held === 'held')
      check('late: abandoned held output is forgotten by the real helper', held.held === 'none', '')
    }
  }
  check('no native QML script errors', shell.scriptErrors().length === 0, shell.scriptErrors().join('\n'))
} catch (e) {
  check('ran to completion', false, String(e && e.stack || e))
} finally { shell.cleanup(); fs.rmSync(scratch, { recursive: true, force: true }) }
done()
