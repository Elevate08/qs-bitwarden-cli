#!/usr/bin/env node
// Real libsecret/GNOME Keyring, on a private bus with a throwaway HOME.
// Never connects to the caller's bus or reads their keyring. All values are fixtures.
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn, spawnSync } = require('child_process')
const { loadModule, createSuite, repoRoot } = require('../harness')
const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
const required = process.argv.includes('--require')
if (!process.argv.includes('--isolated')) {
  const missing = ['dbus-run-session', 'gnome-keyring-daemon', 'secret-tool', 'gdbus'].filter(name =>
    spawnSync('bash', ['-c', 'command -v -- "$1"', '_', name], { encoding: 'utf8' }).status !== 0)
  if (missing.length) {
    console.log('SKIP real-keyring: missing ' + missing.join(', ')); process.exit(required ? 1 : 0)
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qsbw-keyring-test-'))
  try {
    for (const dir of ['home', 'run', 'data', 'config']) fs.mkdirSync(path.join(root, dir), { mode: 0o700 })
    const env = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', HOME: root + '/home',
      XDG_RUNTIME_DIR: root + '/run', XDG_DATA_HOME: root + '/data', XDG_CONFIG_HOME: root + '/config',
      QSBW_ISOLATED_KEYRING: root }
    const result = spawnSync('dbus-run-session', ['--', process.execPath, __filename, '--isolated'],
      { env, stdio: 'inherit', timeout: 90000 })
    process.exitCode = result.status === null ? 1 : result.status
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
} else {
  const root = process.env.QSBW_ISOLATED_KEYRING
  if (!root || !path.basename(root).startsWith('qsbw-keyring-test-') || process.env.HOME !== root + '/home'
      || process.env.XDG_RUNTIME_DIR !== root + '/run' || !process.env.DBUS_SESSION_BUS_ADDRESS) {
    throw new Error('Refusing to test outside the isolated keyring environment')
  }
  const Model = loadModule()
  const { check, eq, done } = createSuite('real-keyring')
  const run = (command, extra = {}, inputValue) => spawnSync(command[0], command.slice(1),
    { env: { ...process.env, ...extra }, input: inputValue, encoding: 'utf8', timeout: 8000 })
  fs.writeFileSync(root + '/daemon-input', 'disposable-test-keyring\n', { mode: 0o600 })
  const input = fs.openSync(root + '/daemon-input', 'r')
  const daemon = spawn('gnome-keyring-daemon', ['--foreground', '--unlock', '--components=secrets',
    '--control-directory', root + '/control'], { stdio: [input, 'ignore', 'ignore'] })
  fs.closeSync(input)
  const store = (account, value) => run(['bash', '-c', Model.keyringStoreScript('Disposable test',
    account)], { [Model.keyringSecretEnvVar()]: value })
  const lookup = account => run(Model.keyringLookupEntryCommand(account))
  try {
    sleep(1000) // Let the daemon claim the bus before a client can auto-activate another.
    let ready = false
    for (let i = 0; i < 50; i++) {
      if (run(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets', '--object-path',
        '/org/freedesktop/secrets', '--method', 'org.freedesktop.DBus.Peer.Ping']).status === 0) { ready = true; break }
      sleep(100)
    }
    check('private Secret Service is ready', ready, '')
    if (!ready) done()
    const value = "synthetic value with 'quotes', $dollars and edge spaces "
    eq('store using the production command', store('fixture', value).status, 0)
    check('lookup preserves fixture bytes', lookup('fixture').stdout === value, '')
    eq('overwrite an existing item', store('fixture', 'replacement-fixture').status, 0)
    check('replacement is returned', lookup('fixture').stdout === 'replacement-fixture', '')
    eq('clear existing item', run(Model.keyringClearEntryCommand('fixture')).status, 0)
    check('missing lookup is empty', lookup('fixture').stdout === '', '')
    eq('native absent lookup exits 1', run(['secret-tool', 'lookup', 'service', Model.KEYRING_SERVICE,
      'account', 'fixture']).status, 1)
    eq('clear-all accepts an already empty slot', run(Model.keyringClearAllCommand('default')).status, 0)
    for (const account of Model.KEYRING_ALL_ACCOUNTS) {
      eq('seed logout entry ' + account, store(account, 'disposable-entry').status, 0)
    }
    const other = Model.keyringEntryName(Model.KEYRING_MASTER, '0123456789abcdef')
    eq('seed second account', store(other, 'other-account-fixture').status, 0)
    eq('seed unrelated application', run(['secret-tool', 'store', '--label=Unrelated fixture',
      'service', 'qsbw-unrelated-test', 'account', 'fixture'], {}, 'unrelated-fixture').status, 0)
    eq('production logout clears its whole slot', run(Model.keyringClearAllCommand('default')).status, 0)
    for (const account of Model.KEYRING_ALL_ACCOUNTS) check('logout removes ' + account, lookup(account).stdout === '', '')
    check('logout preserves another account', lookup(other).stdout === 'other-account-fixture', '')
    check('logout preserves an unrelated application', run(['secret-tool', 'lookup',
      'service', 'qsbw-unrelated-test', 'account', 'fixture']).stdout.trim() === 'unrelated-fixture', '')
    eq('logout is idempotent', run(Model.keyringClearAllCommand('default')).status, 0)
    const badBus = { DBUS_SESSION_BUS_ADDRESS: 'unix:path=' + root + '/not-a-bus' }
    check('lookup on an unavailable bus fails', run(Model.keyringLookupEntryCommand(other), badBus).status !== 0, '')
    check('logout on an unavailable bus fails', run(Model.keyringClearAllCommand('default'), badBus).status !== 0, '')
    const tool = path.join(repoRoot, 'bin/x86_64-linux/qs-bitwarden-unlock-key')
    eq('purge with no envelope succeeds', run(Model.quickUnlockPurgeCommand(tool, ['default'], 'pin')).status, 0)
    check('purge on an unavailable bus fails instead of reporting absence',
      run(Model.quickUnlockPurgeCommand(tool, ['default'], 'pin'), badBus).status !== 0, '')
    const alias = run(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets',
      '--object-path', '/org/freedesktop/secrets', '--method', 'org.freedesktop.Secret.Service.ReadAlias', 'default'])
    const collection = /objectpath '([^']+)'/.exec(alias.stdout)
    check('disposable collection can be located', alias.status === 0 && !!collection, '')
    if (collection) {
      const locked = run(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets',
        '--object-path', '/org/freedesktop/secrets', '--method', 'org.freedesktop.Secret.Service.Lock',
        "['" + collection[1] + "']"])
      eq('disposable collection can be locked', locked.status, 0)
      const result = lookup(other)
      check('a locked keyring never releases its stored credential', result.stdout === '', '')
      check('locked lookup reports failure', result.status !== null && result.status !== 0, '')
    }
  } finally { daemon.kill('SIGTERM') }
  done()
}
