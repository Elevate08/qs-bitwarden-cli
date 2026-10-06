const { read, functionBody, createSuite } = require('./harness')
const { check, eq, done } = createSuite('desktop-state')
function bind(file, name, scope) {
  const code = functionBody(read(file), name).replace(/\): string/, ')')
  if (!code) return null
  return new Function('scope', 'with(scope){' + code + ';return ' + name + '}')(scope)
}
const panel = { opened: true, sshKeysArmed: true }
const scope = { root: panel, panel: { visible: true, focusTarget: { activeFocus: true } },
  searchField: { activeFocus: false, text: 'secret-canary' },
  keyCatcher: { Window: { active: true } },
  unlockForm: { method: 'pin', passwordField: { activeFocus: false, text: 'secret-canary' },
    pinField: { activeFocus: true, text: 'secret-canary' } } }
const focus = bind('Panel.qml', 'focusState', scope)
check('panel offers safe focus diagnostics', !!focus, '')
if (focus) {
  const state = focus()
  eq('reports actual target focus', state.targetFocused, true)
  eq('reports native window focus', state.windowFocused, true)
  eq('reports PIN field focus', state.pinFocused, true)
  eq('reports password field focus', state.passwordFocused, false)
  scope.panel.focusTarget = null
  eq('missing target is unfocused', focus().targetFocused, false)
  check('never includes field contents', !JSON.stringify(state).includes('secret-canary'), '')
}
const root = { status: 'locked', currentScreen: 'locked', opened: true, pinentryActive: false,
  isUnlocking: false, pinReady: true, fingerprintReady: false, fidoReady: true,
  fingerprintScanning: false, fidoScanning: false, typedSecretEntry: 'pinentry',
  masterPassword: 'secret-canary', accountId: 'secret-canary',
  views: [{ focusState: () => ({ targetFocused: true }) }, {}] }
const state = bind('Service.qml', 'desktopState', { root })
check('service offers desktop diagnostics', !!state, '')
if (state) {
  const raw = state(); const result = JSON.parse(raw)
  eq('reports lock state', result.status, 'locked')
  eq('reports real hardware readiness', result.fidoReady, true)
  eq('reports each view', result.views.length, 2)
  eq('headless view is supported', result.views[1], null)
  check('never includes account or credentials', !raw.includes('secret-canary'), '')
}
done()
