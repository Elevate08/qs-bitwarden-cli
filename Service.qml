import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import Quickshell.Services.Pam
import qs.Commons
import "BitwardenModel.js" as Model
import "TotpModel.js" as Totp

// The vault, once per shell. The bar (and Panel.qml) exists once per monitor;
// the shell loads this `service` entry point once and hands it to every bar
// via `bar.shell.serviceFor()`, and each Panel.qml is a view of it. A view
// that cannot reach it creates a private one (Model.vaultHostDecision), so
// this must also work as a single view's own vault.
Item {
  id: root

  // Injected by the shell's service loader. A private host has neither.
  property var shell: null
  property var manifest: null

  // Created by a view for itself because the shared service was unavailable.
  property bool privateHost: false

  // -------------------------------------------------------------------------
  // Views
  // -------------------------------------------------------------------------
  //
  // Attached bar copies, in attach order. A view detaches when destroyed (an
  // unplugged monitor), leaving the vault running.
  property var views: []
  readonly property int viewCount: views.length

  function attachView(view) {
    if (!view || views.indexOf(view) !== -1) return
    // Settings first: the first attach starts the vault, with these settings.
    if (view.settings) updateSettings(view.settings)
    views = views.concat([view])
  }

  // The view that acts when the vault needs the screen; see
  // Model.presenterIndex().
  readonly property string focusedScreen: Hyprland.focusedMonitor
    ? String(Hyprland.focusedMonitor.name || "") : ""
  readonly property var presenter: {
    var summaries = []
    for (var i = 0; i < views.length; i++) {
      summaries.push({ opened: views[i].opened === true, screen: views[i].screenName })
    }
    var index = Model.presenterIndex(summaries, focusedScreen)
    return index >= 0 ? views[index] : nullPresenter
  }

  // Runs fn on every attached view.
  function eachView(fn) {
    var list = views.slice()
    for (var i = 0; i < list.length; i++) fn(list[i])
  }

  // Whether any view's popout is open.
  readonly property bool opened: {
    for (var i = 0; i < views.length; i++) {
      if (views[i].opened === true) return true
    }
    return false
  }

  // Live once a view is attached; see onLiveChanged.
  readonly property bool live: viewCount > 0
  property bool started: false

  // Presenter stand-in when no view is attached, so late callbacks are safe.
  QtObject {
    id: nullPresenter
    readonly property bool opened: false
    readonly property string screenName: ""
    function showPopout() {}
    function hidePopout() {}
    function focusField(name) {}
    function fieldHasFocus(name) { return false }
    function loginFieldHasFocus() { return false }
    function unlockFieldHasFocus() { return false }
    function syncLoginFields() {}
    function syncSensitiveFields() {}
    function revealListIndex(index) {}
    function updateSettingsSticky() {}
  }

  function detachView(view) {
    var index = views.indexOf(view)
    if (index === -1) return
    var next = views.slice()
    next.splice(index, 1)
    views = next
  }

  // -------------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------------
  //
  // The bar entry's inline object in shell.json. A service only gets a load-time
  // snapshot, so views (whose `settings` the bar keeps current) push them here;
  // every view carries the same entry.
  property var settings: ({})

  function updateSettings(next) {
    settings = next || ({})
  }

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }


  // Settings, validated on the way in (nothing validates shell.json); see
  // intSetting() in BitwardenModel.js.
  readonly property int autoLockMinutes: Model.intSetting("autoLockMinutes", setting("autoLockMinutes"))
  readonly property int clearClipboardSec: Model.intSetting("clearClipboardSec", setting("clearClipboardSec"))
  readonly property bool lockOnScreenLock: Model.boolSetting("lockOnScreenLock", setting("lockOnScreenLock", true))
  readonly property bool lockOnSuspend: Model.boolSetting("lockOnSuspend", setting("lockOnSuspend", true))
  readonly property bool rememberSession: Model.boolSetting("rememberSession", setting("rememberSession", true))
  readonly property int autoCopyTotpSec: Model.intSetting("autoCopyTotpSec", setting("autoCopyTotpSec"))
  readonly property bool closeOnCopy: Model.boolSetting("closeOnCopy", setting("closeOnCopy", true))
  readonly property bool colorizeIcon: Model.boolSetting("colorizeIcon", setting("colorizeIcon", false))
  readonly property bool suggestOnOpen: Model.boolSetting("suggestOnOpen", setting("suggestOnOpen", true))
  readonly property bool fingerprintUnlock: Model.boolSetting("fingerprintUnlock", setting("fingerprintUnlock", false))
  readonly property bool fidoUnlock: Model.boolSetting("fidoUnlock", setting("fidoUnlock", false))
  readonly property bool pinUnlock: Model.boolSetting("pinUnlock", setting("pinUnlock", false))
  // Opt-in: nothing starts, binds or opens a FIFO while false.
  readonly property bool sshAgentEnabled: Model.boolSetting("sshAgentEnabled", setting("sshAgentEnabled", false))
  readonly property bool sshAgentUnlockOnDemand: Model.boolSetting("sshAgentUnlockOnDemand", setting("sshAgentUnlockOnDemand", false))
  readonly property bool sshAgentApprovalPopup: Model.boolSetting("sshAgentApprovalPopup", setting("sshAgentApprovalPopup", true))
  readonly property int sshAgentApprovalWindowSec: Model.intSetting("sshAgentApprovalWindowSec", setting("sshAgentApprovalWindowSec"))

  // State
  // status: "checking" | "unauthenticated" | "locked" | "unlocked"
  property string status: "checking"
  property string userEmail: ""
  property string session: ""
  property string masterPassword: ""

  // Login form state
  property string loginMethod: "email" // "email" | "apikey"
  property string loginEmail: ""
  property string loginPassword: ""
  property string login2faCode: ""
  property string loginServerRegion: "us" // "us" | "eu" | "custom"
  property string loginServerUrl: ""
  property string loginClientId: ""
  property string loginClientSecret: ""
  property bool show2faField: false
  // Whether the running attempt carries --code; distinguishes a rejected code
  // from new-device verification (loginNeedsDeviceVerification()).
  property bool loginAttemptHadCode: false
  // Bitwarden asked for new-device verification.
  property bool loginDeviceVerification: false

  // The two-step method passed to bw, or -1 to let bw decide (right when the
  // account has one). See TWO_FACTOR_METHODS.
  property int login2faMethod: rememberedTwoFactorMethod
  // Picked in this login rather than remembered. A remembered method may be
  // stale, so an unconfirmed one is dropped and retried without.
  property bool login2faMethodConfirmed: false
  property bool show2faMethodPicker: false
  // New-device verification has its own code stage and login path; see
  // deviceVerificationLoginCommand().
  property string loginDeviceCode: ""
  property bool showDeviceCodeField: false
  // The one login with bw's prompts enabled is in flight.
  property bool deviceVerificationAttempt: false
  property bool deviceVerificationPending: false
  // When the login began waiting on a second factor (epoch ms, 0 if not). A
  // closed panel keeps it alive for SECOND_FACTOR_WINDOW_MS.
  property double secondFactorStartedAt: 0
  // This login's one automatic retry at delivering the password is spent.
  property bool loginPasswordRetryUsed: false
  // Email login stages: credentials, method picker, two-step code, device
  // verification. One at a time.
  readonly property bool loginCredentialsStage:
    !show2faField && !show2faMethodPicker && !showDeviceCodeField
  readonly property string login2faMethodLabel: Model.twoFactorMethodLabel(login2faMethod)
  // The method the last attempt sent.
  property int loginAttemptMethod: -1
  // Per login email; follows loginEmail as it is typed.
  readonly property var twoFactorMethodStore: setting("twoFactorMethods", null)
  readonly property int rememberedTwoFactorMethod:
    Model.rememberedTwoFactorMethodFor(twoFactorMethodStore, loginEmail)

  // When the panel last launched a terminal login (epoch ms, 0 if never); a
  // handoff is only read shortly after. See sessionHandoffReadCommand().
  property double terminalLoginStartedAt: 0

  // Navigation: "main" | "detail" | "edit" | "settings" | "setup" | "pin" |
  // "fingerprint" | "generator" | "sends" | "sshApproval" | "locked". Lock and
  // login screens follow `status`; "locked" only moves off the open screen.
  property string currentScreen: "main"
  property string screenBeforeSettings: "main"

  // Dependency / setup state
  property var dependencies: ({ items: [], hasOmarchy: true })
  property bool depsChecked: false
  property bool setupDismissed: false
  // The last dependency probe's output, and `bw -v` cached by the binary's
  // identity (dependencyBwId()) so opening the panel does not start Node.
  property string depsRaw: ""
  property bool bwVersionKnown: false
  property string bwVersionId: ""
  property string bwVersionValue: ""
  property string listReadMode: "sanitized"
  property var sshCapability: Model.defaultSshCapability()
  // Show setup instead of probing `bw`; see setupGateActive().
  readonly property bool setupGated: Model.setupGateActive(dependencies, depsChecked, setupDismissed)
  // The first `bw status` was started; on a fresh install it waits for setup.
  property bool statusProbeStarted: false
  // A required tool was seen missing; cleared after the post-install probe.
  property bool setupWasGated: false
  property string settingsFlash: ""
  property int settingsIndex: 0
  readonly property var settingsEntries: Model.visibleSettings(dependencies, depsChecked)

  // Vault data
  property var items: []
  // Reuse loaded data until stale (`bw list items` is slow); mutations always
  // reload.
  property double itemsLoadedAt: 0
  property double orgsLoadedAt: 0
  property double foldersLoadedAt: 0
  readonly property int itemsFreshMs: 60000
  // Organizations and folders outlive an item refresh many times over.
  readonly property int metaFreshMs: 600000
  property var filteredItems: []
  property var organizations: []
  property string selectedOrg: "all" // "all" | "personal" | orgId
  property var folders: []
  property string selectedFolder: "all" // "all" | "none" | folderId
  // The open filter group: "" | "folders" | "organizations" | "types".
  property string openFilterGroup: ""
  property int filterOptionIndex: 0

  readonly property int filterRowHeight: Style.space(30)
  readonly property int filterVisibleRows: 5
  readonly property var currentFilterOptions: openFilterGroup === "" ? [] : filterOptions(openFilterGroup)
  readonly property int currentFilterVisibleRows: openFilterGroup === "types" ? currentFilterOptions.length : filterVisibleRows
  // Added to the panel's height cap so the drawer opens downward.
  readonly property int filterDrawerHeight: openFilterGroup === ""
    ? 0
    : Style.space(30) + Math.min(currentFilterVisibleRows, currentFilterOptions.length) * filterRowHeight + Style.space(8)
  property string formFolderId: ""
  property string newFolderName: ""
  // The expanded item-form picker: folder, organization, "customAdd",
  // "customLabel:<row>" or "customLinked:<row>".
  property string formPicker: ""
  property var formCollections: []
  property var formCollectionIds: []
  property bool formCollectionsLoading: false
  property bool creatingFolder: false
  property string searchQuery: ""
  property string selectedCategory: "all"
  property int selectedIndex: 0

  // Selected item detail
  property var detailItem: null
  property string detailPassword: ""
  // Revealed sensitive fields of the open item, by key; each eye is separate.
  property var revealedFields: ({})

  function isFieldRevealed(key) { return Boolean(revealedFields[key]) }

  function toggleFieldReveal(key) {
    var next = {}
    for (var k in revealedFields) next[k] = revealedFields[k]
    if (next[key]) delete next[key]
    else next[key] = true
    revealedFields = next
  }

  // The field `v` reveals: card number or password. None for identities.
  readonly property string primaryRevealKey:
    detailIsCard ? "cardNumber" : (detailIsLoginLike ? "password" : "")

  // Which detail blocks the open item shows.
  readonly property int detailTypeCode: detailItem ? Number(detailItem.typeCode || 1) : 1
  readonly property bool detailIsLoginLike: detailTypeCode === 1 || detailTypeCode === 2
  readonly property bool detailIsCard: detailTypeCode === 3
  readonly property bool detailIsIdentity: detailTypeCode === 4

  readonly property var detailCard: detailItem ? (detailItem.card || null) : null
  readonly property var detailIdentity: detailItem ? (detailItem.identity || null) : null

  // "MM / YY", or whichever half is set.
  readonly property string detailCardExpiry: {
    if (!detailCard) return ""
    var m = String(detailCard.expMonth || "").trim()
    var y = String(detailCard.expYear || "").trim()
    if (m && y) return m + " / " + y
    return m || y
  }

  readonly property string detailIdentityName: detailIdentity ? Model.identityFullName(detailIdentity) : ""

  // Postal lines in envelope order, empty parts skipped.
  readonly property string detailIdentityAddress: {
    if (!detailIdentity) return ""
    var id = detailIdentity
    return Model.nonEmptyParts([id.address1, id.address2, id.address3,
      Model.nonEmptyParts([id.city, id.state, id.postalCode]).join(" "), id.country]).join("\n")
  }
  property string liveTotp: ""
  property int totpSecRemaining: 30
  property string totpRequestItemId: ""
  property string totpQueuedItemId: ""
  property int totpQueuedEpoch: -1
  property bool totpRestartPending: false
  property string totpCopyItemId: ""
  property string passwordCopyItemId: ""

  // Attachment downloads run one at a time from a queue. `attachmentSaved`
  // maps attachment id to saved path (for Open / Show in folder); cleared when
  // another item opens.
  property var attachmentQueue: []
  property string attachmentBusyId: ""
  property var attachmentSaved: ({})

  // Enter copies the password, then a second Enter copies the TOTP.
  property var totpFollowupItem: null
  property string totpFollowupCode: ""
  property bool totpFollowupActive: false

  // The save in flight, with the list and form before it, so a failure can
  // restore both.
  property var pendingSave: null
  // The delete in flight, with the removed row for restoring on refusal.
  property var pendingDelete: null

  // A refused save's form, kept so it can be reopened rather than retyped.
  property var failedSave: null

  // Item form
  property bool formIsEditing: false
  property string formItemId: ""
  property int formTypeCode: 1 // 1 login, 2 note, 3 card, 4 identity
  property string formName: ""
  property string formUsername: ""
  property string formPassword: ""
  property string formTotp: ""
  property string formUri: ""
  property string formNotes: ""
  property bool formFavorite: false
  property string formOrgId: ""
  property bool formPasswordRevealed: false
  property var formCustomFields: []
  property int formNewCustomFieldType: 0
  property string formNewCustomFieldName: ""
  property string formCustomFieldLabelDraft: ""
  property bool showDeleteConfirm: false

  // Card and identity fields, flat like the rest of the form; formTypeFields()
  // gathers them for the payload builders.
  property string formCardholderName: ""
  property string formCardBrand: ""
  property string formCardNumber: ""
  property string formCardExpMonth: ""
  property string formCardExpYear: ""
  property string formCardCode: ""

  property string formIdTitle: ""
  property string formIdFirstName: ""
  property string formIdMiddleName: ""
  property string formIdLastName: ""
  property string formIdUsername: ""
  property string formIdCompany: ""
  property string formIdEmail: ""
  property string formIdPhone: ""
  property string formIdSsn: ""
  property string formIdPassport: ""
  property string formIdLicense: ""
  property string formIdAddress1: ""
  property string formIdAddress2: ""
  property string formIdAddress3: ""
  property string formIdCity: ""
  property string formIdState: ""
  property string formIdPostalCode: ""
  property string formIdCountry: ""

  // When the auto-lock window started (wall clock, so suspend counts).
  property double autoLockArmedAt: 0

  // The vault generation: advances on lock, logout and unlock. Readers record
  // it so answers for a vault no longer open are dropped (vaultReadIsStale()).
  property int vaultEpoch: 0
  property var readEpochs: ({})

  // Processes whose collectors still need emptying after a lock; see
  // scrubSecretBuffers().
  property var scrubPending: []

  // Status & indicators
  property bool isLoading: false
  property bool isUnlocking: false
  property bool isSyncing: false
  property bool metadataLoadPending: false
  property bool metadataForceRefresh: false
  property bool statusRefreshAfterItems: false
  property bool statusCheckAuthoritative: true
  // This session already tried to repair an unsynced vault (onStatusFinished()).
  property bool initialSyncAttempted: false
  property bool syncReloadPending: false
  property string errorMessage: ""
  property string flashMessage: ""
  property bool cursorActive: false

  // Fingerprint unlock state.
  property bool fingerprintAvailable: false   // PAM stack + reader + enrolled finger
  property bool fingerprintStored: false      // a fingerprint way into the envelope, or the legacy entry
  property bool fingerprintScanning: false
  property bool fingerprintAuthorized: false // a live PAM success may consume one envelope open
  property string fingerprintMessage: ""
  // Why the last attempt failed; kept apart from fingerprintMessage (progress)
  // so it is still shown on the PIN or password screen.
  property string fingerprintError: ""
  // FIDO2 unlock lives in FidoUnlock.qml; these forward what the lock screen
  // and settings read.
  readonly property bool fidoReady: fidoUnlocker.ready
  readonly property bool fidoAvailable: fidoUnlocker.available
  readonly property bool fidoStored: fidoUnlocker.stored
  readonly property bool fidoScanning: fidoUnlocker.scanning
  // Between a verified touch and the unlock it starts.
  readonly property bool fidoAuthorized: fidoUnlocker.authorized
  readonly property string fidoMessage: fidoUnlocker.message
  // Edited by the setup screen; owned by FidoUnlock.qml.
  property alias fidoSetupMaster: fidoUnlocker.setupMaster
  // The setup form's error; fidoError is a failed touch.
  property alias fidoSetupError: fidoUnlocker.error
  property alias fidoBusy: fidoUnlocker.busy
  readonly property string fidoError: fidoUnlocker.failure
  property string pendingUnlockPassword: ""   // held only until the unlock lands
  // Auth processes start early and wait on a private FIFO; these tell that
  // waiting apart from an attempt whose password was delivered.
  property bool unlockSubmitted: false
  property bool loginSubmitted: false
  property bool loginSubmitAfterPrewarmStop: false
  property bool loginPrepareAfterPrewarmStop: false
  property string loginPrewarmSignature: ""
  property string authPasswordWriteTarget: ""
  property string authPasswordWriteValue: ""
  // Item JSON for create/edit, passed in the environment.
  property string itemPayloadJson: ""
  property bool fpSetupActive: false
  property string fpSetupMaster: ""
  property string fpError: ""
  property bool fpBusy: false
  // What drove the in-flight unlock, so a stale stored secret is discarded
  // rather than retried: "" | "fingerprint" | "fido" | "pin".
  property string pendingUnlockFrom: ""

  // Send state
  property var sends: []
  property bool sendsLoading: false
  property string sendMode: "list"      // "list" | "create"
  property string sendPayloadJson: ""
  property bool sendBusy: false
  property string sendError: ""
  property string sendFormName: ""
  property string sendFormText: ""
  property bool sendFormHidden: false
  property int sendFormDays: 7
  property int sendFormMaxAccess: 0
  property string sendFormPassword: ""
  property int sendIndex: 0

  // Generator state (session-scoped; the browser extension's options)
  property var genOpts: Model.generatorDefaults()
  property string genValue: ""
  property bool genBusy: false
  property bool genRegeneratePending: false
  property string genRequestSignature: ""
  // `bw serve`: ready once it answers; failed means the CLI is used instead,
  // usually because someone else holds the port (whose answers must not be
  // trusted).
  property bool generateServeReady: false
  property bool generateServeStarting: false
  property bool generateServeFailed: false
  // We are stopping it, so its exit is not a bind failure.
  property bool generateServeStopping: false
  property bool generateCliStopping: false
  property bool generateServeRequestStopping: false
  property bool generateServeRequestPending: false
  property var generateServeRequestPendingOptions: null
  property var generateServeRequestPendingCallback: null
  // Where Back/Esc go. Opened from the item form, the generator fills its
  // password field and returns there.
  property string generatorReturnScreen: "main"
  readonly property bool generatorFeedsForm: generatorReturnScreen === "edit"

  // PIN unlock state
  property bool pinConfigured: false        // a PIN way into the envelope, or the legacy blob
  property string pinEntry: ""              // locked-screen input
  property int pinAttempts: 0
  readonly property int pinMaxAttempts: 5
  // The PIN setup form's error.
  property string pinError: ""
  // Why a PIN unlock failed, shown on whatever screen the user moves to.
  property string pinUnlockError: ""
  property string pinSetupPin: ""
  property string pinSetupConfirm: ""
  property string pinSetupMaster: ""
  property bool pinBusy: false
  property bool pinUnlockSubmitted: false
  readonly property bool pinReady: pinUnlock && pinConfigured
  // Valid but weak: turns the setup field red (pinWeakWarning()).
  readonly property bool pinSetupWeak: Model.isPinWeak(pinSetupPin)
  readonly property string userName: Quickshell.env("USER") || Quickshell.env("LOGNAME") || ""
  // A closed lid puts the fingerprint reader out of reach (LidState.qml).
  readonly property bool lidClosed: lidState.closed
  // Cancel a scan when the lid closes; nothing else watches fingerprintReady.
  onLidClosedChanged: if (lidClosed && fingerprintScanning) cancelFingerprintUnlock()
  // Enrolled, stored and reachable. Everything that offers fingerprint unlock
  // reads this.
  readonly property bool fingerprintReady: fingerprintUnlock && fingerprintAvailable && fingerprintStored && !lidClosed

  // Contextual suggestions state
  property var activeWindowData: null
  property var detectedContext: null
  property var suggestedItems: []
  property bool suggestionsDismissed: false
  property var associations: Model.emptyAssociations()
  property var learnedIds: ({})
  property string pendingAssociationsJson: ""
  property bool associationsWritePending: false
  property bool associationsClearPending: false
  property int associationsEpoch: 0
  property int associationsReadEpoch: -1
  property bool sessionStorePending: false
  property bool sessionClearPending: false
  // Which account's session the running store writes, and the accounts
  // whose session clears wait behind a running one: a switch can land
  // between a request and its run.
  property string sessionStoreSlot: ""
  property var sessionClearSlots: []
  property bool pinClearPending: false
  property bool masterClearPending: false
  property bool allCredentialsClearPending: false
  property bool logoutPending: false
  property bool logoutCliDone: false
  property bool logoutCredentialsDone: false
  property int logoutExitCode: 0
  property int logoutCredentialsExitCode: 0
  readonly property bool logoutCleanupFailed: logoutPending && logoutCredentialsDone
    && logoutCredentialsExitCode !== 0

  // Start with the first view. Until then the vault is inert: no `bw`, SSH
  // agent or IPC target.
  onLiveChanged: {
    if (!root.live || root.started) return
    root.started = true
    // Dependencies first; the status probe follows in onDependenciesChecked,
    // so a fresh install opens on setup rather than a doomed login form.
    root.checkDependencies()
    // Which account is active; learned suggestions and the status probe wait
    // for it.
    root.loadAccountRegistry()
    // Also called explicitly: a binding already true at creation never fires
    // its change handler.
    root.syncSshAgentSupervision()
    // Only changes after this are user transitions.
    root.sshAgentSettingsReady = true
    if (root.sshAgentEnabled) root.inspectSshAgentHelper()
    root.inspectUnlockKey()
    root.inspectQuickUnlockPrereqs()
    root.inspectUwsmFragment()
  }

  readonly property var categories: [
    { id: "all", label: "All", icon: "󰞀" },
    { id: "login", label: "Logins", icon: "󰌋" },
    { id: "secureNote", label: "Notes", icon: "󰈙" },
    { id: "card", label: "Cards", icon: "󰿯" },
    { id: "identity", label: "Identities", icon: "" },
    { id: "sshKey", label: "SSH Keys", icon: "󰣀" },
    { id: "favorite", label: "Favorites", icon: "󰓒" }
  ]

  // No SSH type filter until the probe confirms an SSH-capable CLI.
  readonly property bool sshUiAvailable: Model.sshUiAvailable(dependencies, depsChecked)
  readonly property var visibleCategories: sshUiAvailable
    ? categories
    : categories.filter(function(category) { return category.id !== "sshKey" })

  // -------------------------------------------------------------------------
  // SSH companion supervision
  // -------------------------------------------------------------------------
  //
  // Decisions live in Model.sshAgentReduce(); this side owns the Process, clock
  // and timers. applySshAgentEvent() is the only place the state is replaced.
  // Nothing here is on the path of ordinary vault operations: a failing helper
  // only closes the signing gate.

  // From this file's URL, so the helper runs by absolute path, not from PATH.
  readonly property string sshAgentPluginDir: Model.pluginDirFromUrl(String(Qt.resolvedUrl(".")))
  readonly property string sshAgentRuntimeDir: Quickshell.env("XDG_RUNTIME_DIR") || ""
  // Inspected when enabled and whenever the plugin dir changes (an update can
  // replace the binary under a running shell).
  property var sshAgentHelper: Model.uninspectedHelper()

  readonly property bool sshAgentSupervisable: sshAgentEnabled
    && sshAgentPluginDir !== "" && sshAgentRuntimeDir !== ""
    // A helper that fails inspection disables this feature and nothing else:
    // no supervisor, so no socket, no FIFO, and no agent branch in the vault
    // read. The rest of the plugin never sees it.
    && Model.helperReady(sshAgentHelper)

  function inspectSshAgentHelper() {
    if (sshAgentHelperProc.running) return
    sshAgentHelperProc.command = Model.sshAgentHelperInspectCommand(root.sshAgentPluginDir)
    sshAgentHelperProc.running = true
  }

  function onSshAgentHelperInspected(raw) {
    root.sshAgentHelper = Model.parseSshAgentHelperInspection(raw)
  }

  // The quick-unlock tool, inspected at every start: the envelope is written
  // after each password login, before anyone opens settings. Failing disables
  // only PIN, fingerprint and FIDO2 unlock.
  property var unlockKeyHelper: Model.uninspectedHelper()
  readonly property bool unlockKeyReady: Model.helperReady(unlockKeyHelper)

  function inspectUnlockKey() {
    if (unlockKeyProc.running || sshAgentPluginDir === "") return
    unlockKeyProc.command = Model.unlockKeyInspectCommand(root.sshAgentPluginDir)
    unlockKeyProc.running = true
  }

  function onUnlockKeyInspected(raw) {
    root.unlockKeyHelper = Model.parseUnlockKeyInspection(raw)
    root.envelopeReadinessChanged()
  }

  // -------------------------------------------------------------------------
  // The quick-unlock envelope
  // -------------------------------------------------------------------------
  //
  // One keyring item holds the master password, written when `bw` first
  // accepts a typed password; each quick-unlock method adds a way into it. Jobs
  // run one at a time, since concurrent writers would lose updates.

  // Besides the tool: argon2 and systemd-creds --user.
  property var quickUnlockPrereqs: ({ argon2: false, creds: false, ready: false, message: "", checked: false })
  readonly property bool quickUnlockAvailable: unlockKeyReady && quickUnlockPrereqs.ready
  readonly property string quickUnlockUnavailableReason: !unlockKeyReady
    ? String(unlockKeyHelper.message || "")
    : String(quickUnlockPrereqs.message || "")

  // Which account an envelope belongs to, from `bw status`.
  property string accountId: ""
  property string accountServer: ""

  // The secret-free summary, or null if none (`envelopeChecked`: read yet).
  property var envelopeSummary: null
  property bool envelopeChecked: false

  property var envelopeJobs: []
  property var envelopeJob: null
  // The keyring repair runs once per start; see repairKeyring().
  property bool keyringRepairQueued: false

  // A quick-unlock password `bw` refused (changed elsewhere). Kept until the
  // next typed unlock re-seals the envelope with it, keeping every method.
  property string rotationOldPassword: ""
  // The legacy plaintext fingerprint entry, migrated at the first chance.
  property bool legacyFingerprintStored: false
  property bool legacyMigrationAttempted: false
  property bool fingerprintFromEnvelope: false
  // The legacy PIN blob, migrated at the next PIN unlock (when both PIN and
  // password are in hand).
  property bool legacyPinStored: false
  property bool pinFromEnvelope: false
  // Set by FidoUnlock when the password came from the envelope's FIDO wrap.
  property bool fidoFromEnvelope: false
  // The PIN that decrypted a legacy blob, held until that unlock settles.
  property string pendingPinForMigration: ""

  function inspectQuickUnlockPrereqs() {
    if (!quickUnlockPrereqProc.running) quickUnlockPrereqProc.running = true
  }

  function onQuickUnlockPrereqs(raw) {
    var parsed = Model.parseQuickUnlockPrereqs(raw)
    parsed.checked = true
    root.quickUnlockPrereqs = parsed
    root.envelopeReadinessChanged()
  }

  function envelopeTool() {
    return Model.unlockKeyPath(sshAgentPluginDir, unlockKeyHelper.source)
  }

  function envelopeAccount() {
    return { id: accountId, server: accountServer, slot: activeSlot }
  }

  function envelopeReadinessChanged() {
    // Which account's envelope is only known once the registry is read.
    if (!quickUnlockAvailable || !accountsLoaded) return
    if (!envelopeChecked) refreshEnvelope()
    maybeMigrateLegacyFingerprint()
  }

  // Queue one envelope process: { command, env, secretOutput, writes,
  // onDone(exitCode, stdout) }. `env` holds secrets and is dropped on start.
  function queueEnvelopeJob(job) {
    // Answers for an account no longer active are dropped (onEnvelopeJobExited()).
    job.slot = activeSlot
    var jobs = envelopeJobs.slice()
    jobs.push(job)
    envelopeJobs = jobs
    pumpEnvelopeJobs()
  }

  function pumpEnvelopeJobs() {
    if (envelopeProc.running || envelopeJob !== null || envelopeJobs.length === 0) return
    var jobs = envelopeJobs.slice()
    var job = jobs.shift()
    envelopeJobs = jobs
    envelopeJob = job
    envelopeProc.command = job.command
    envelopeProc.environment = job.env || {}
    job.env = null
    envelopeProc.running = true
  }

  function onEnvelopeJobExited(exitCode) {
    if (finishScrubRun(envelopeProc)) {
      pumpEnvelopeJobs()
      return
    }
    var job = envelopeJob
    var out = String(envelopeStdout.text || "")
    envelopeJob = null
    envelopeProc.environment = {}
    // The output was the master password: scrub the collector.
    if (job && job.secretOutput) clearProcessCollectorSoon(envelopeProc)
    if (job && job.onDone && !logoutPending && job.slot === activeSlot) job.onDone(exitCode, out)
    out = ""
    if (logoutPending && allCredentialsClearPending) Qt.callLater(requestAllCredentialClear)
    Qt.callLater(pumpEnvelopeJobs)
  }

  // Logout: nothing queued may run after the keyring is cleared.
  function dropEnvelopeState() {
    envelopeJobs = []
    // The next login may be another account.
    accountId = ""
    accountServer = ""
    envelopeSummary = null
    envelopeChecked = false
    rotationOldPassword = ""
    legacyFingerprintStored = false
    legacyMigrationAttempted = false
    fingerprintFromEnvelope = false
    legacyPinStored = false
    pinFromEnvelope = false
    pendingPinForMigration = ""
    fidoFromEnvelope = false
  }

  // First in the envelope queue at every start, so the first start after an
  // update repairs what an earlier build stored across several lines, before
  // anything reads or writes an envelope. The command is keyringRepairCommand().
  function repairKeyring() {
    if (keyringRepairQueued) return
    keyringRepairQueued = true
    var slots = (accountRegistry.accounts || []).map(function(a) { return a.slot })
    queueEnvelopeJob({
      command: Model.keyringRepairCommand(sshAgentPluginDir, slots),
      onDone: function(exitCode, out) { root.onKeyringRepaired(exitCode, out) }
    })
  }

  function onKeyringRepaired(exitCode, out) {
    var r = Model.parseKeyringRepair(out)
    if (r.rejoined > 0) {
      console.log("qs-bitwarden keyring: stored " + r.rejoined + " quick-unlock envelope(s) again on one line")
    }
    for (var i = 0; i < r.rejoinFailed.length; i++) {
      console.warn("qs-bitwarden keyring: " + r.rejoinFailed[i] + " is stored across several lines and did not"
        + " decrypt joined; turn quick unlock off and on again for that account")
    }
    if (r.file === "repaired") {
      console.log("qs-bitwarden keyring: repaired the default keyring file; the original is kept beside it")
      Quickshell.execDetached(Model.repairedKeyringNoticeCommand())
    } else if (r.file === "failed") {
      console.warn("qs-bitwarden keyring: the default keyring file needs repair and it failed (exit " + exitCode
        + "); run scripts/repair-keyring.sh in the plugin's directory")
    }
  }

  function refreshEnvelope() {
    if (!quickUnlockAvailable) return
    queueEnvelopeJob({
      command: Model.unlockEnvelopeInspectCommand(envelopeTool(), activeSlot),
      onDone: function(code, out) {
        if (code === 0) {
          try { root.envelopeSummary = JSON.parse(out) } catch (e) { root.envelopeSummary = null }
        } else if (code === Model.envelopeExitCodes().absent) {
          root.envelopeSummary = null
        }
        root.envelopeChecked = true
        root.recomputeFingerprintStored()
        root.recomputePinConfigured()
        // A switched-to account's methods are known only now.
        if (root.armAfterEnvelope) {
          root.armAfterEnvelope = false
          if (root.sshAuthSurfaceActive && root.status === "locked" && !root.isUnlocking
              && !root.fingerprintScanning && !root.fidoScanning) root.armPresenceUnlock()
        }
      }
    })
  }

  function recomputePinConfigured() {
    pinConfigured = Boolean(envelopeSummary && envelopeSummary.pin) || legacyPinStored
  }

  function recomputeFingerprintStored() {
    fingerprintStored = Boolean(envelopeSummary && envelopeSummary.fingerprint) || legacyFingerprintStored
  }

  // Runs `then()` once the account is known (asking `bw status` if needed),
  // else `otherwise()`.
  function withEnvelopeAccount(then, otherwise) {
    if (accountId) { then(); return }
    queueEnvelopeJob({
      command: Model.statusCommand(),
      env: bwEnv(),
      onDone: function(code, out) {
        var st = code === 0 ? Model.parseStatus(out) : null
        if (st && st.userId) {
          root.accountId = st.userId
          root.accountServer = st.serverUrl
          root.noteActiveAccount(st)
          then()
        } else if (otherwise) {
          otherwise()
        }
      }
    })
  }

  // The only writer of the stored password: called when `bw` just accepted a
  // typed password (login, unlock, or an enable form's check), never with one
  // a quick-unlock method produced. `done(ok)` is optional.
  function storeAcceptedMasterPassword(password, done) {
    var pw = String(password || "")
    var finish = function(ok) { if (done) done(ok) }
    if (!pw || !quickUnlockAvailable) { finish(false); return }
    var oldPassword = rotationOldPassword
    rotationOldPassword = ""
    withEnvelopeAccount(function() {
      var E = Model.envelopeExitCodes()
      var tool = root.envelopeTool()
      var account = root.envelopeAccount()
      var env = {}
      env[Model.keyringSecretEnvVar()] = pw
      root.queueEnvelopeJob({
        command: Model.unlockEnvelopeOpenCommand(tool, account, { kind: "master" }),
        env: env, secretOutput: true,
        onDone: function(code) {
          if (code === 0) { finish(true); return }
          if (code === E.absent || code === 6 || code === E.unseal) {
            root.writeEnvelope(Model.unlockEnvelopeCreateCommand(tool, account), env, finish)
            return
          }
          if (code === 3) {
            // `bw` accepts it but the envelope does not: changed elsewhere.
            // Re-seal through whatever still opens it, keeping every method.
            var rotate = {}
            rotate[Model.envelopeNewSecretEnvVar()] = pw
            if (oldPassword) {
              rotate[Model.keyringSecretEnvVar()] = oldPassword
              root.writeEnvelope(Model.unlockEnvelopeUpdateCommand(tool, account,
                { kind: "rotate", auth: { kind: "master" } }), rotate, finish)
            } else if (root.envelopeSummary && root.envelopeSummary.fingerprint) {
              root.writeEnvelope(Model.unlockEnvelopeUpdateCommand(tool, account,
                { kind: "rotate", auth: { kind: "fingerprint" } }), rotate, finish)
            } else if (!root.envelopeHasMethods()) {
              // No methods to keep: this password becomes the envelope.
              root.writeEnvelope(Model.unlockEnvelopeCreateCommand(tool, account), env, finish)
            } else {
              // Nothing reaches the data key yet; the next quick unlock will
              // produce the old password and come back here.
              root.writeEnvelope(Model.unlockEnvelopeUpdateCommand(tool, account, { kind: "mark-stale" }),
                {}, finish)
            }
            return
          }
          console.log("qs-bitwarden envelope: check failed with " + code)
          finish(false)
        }
      })
    }, function() { finish(false) })
  }

  // Whether any method has a way in. Unknown (no summary yet) counts as yes:
  // never drop methods on a guess.
  function envelopeHasMethods() {
    if (!envelopeSummary) return envelopeChecked ? false : true
    return Boolean(envelopeSummary.pin || envelopeSummary.fingerprint
      || (Array.isArray(envelopeSummary.fido) && envelopeSummary.fido.length > 0))
  }

  function writeEnvelope(command, env, done, quiet) {
    queueEnvelopeJob({
      command: command, env: env, writes: true,
      onDone: function(code) {
        if (code !== 0 && (!quiet || quiet.indexOf(code) === -1)) {
          console.log("qs-bitwarden envelope: write failed with " + code)
        }
        root.refreshEnvelope()
        if (done) done(code === 0, code)
      }
    })
  }

  // An enable form's password is checked against the stored one, never stored
  // anew; `op` (the add) is authorized by it opening the master wrap. With no
  // envelope, `bw` checks it, it is stored as an accepted password, then the
  // method is added.
  function addQuickUnlockMethod(password, op, extraEnv, done) {
    addQuickUnlockMethodWith(password, function(tool, account) {
      return Model.unlockEnvelopeUpdateCommand(tool, account, op)
    }, extraEnv, done)
  }

  // The same, for a method whose command is more than an update (FIDO2
  // touches the key first). `done(ok, why, exitCode)`.
  function addQuickUnlockMethodWith(password, makeCommand, extraEnv, done) {
    var pw = String(password || "")
    if (!quickUnlockAvailable) { done(false, "unavailable", 0); return }
    withEnvelopeAccount(function() {
      var env = {}
      env[Model.keyringSecretEnvVar()] = pw
      if (extraEnv) for (var k in extraEnv) env[k] = extraEnv[k]
      var command = makeCommand(root.envelopeTool(), root.envelopeAccount())
      root.queueEnvelopeJob({
        command: command, env: env, writes: true,
        onDone: function(code) {
          var E = Model.envelopeExitCodes()
          if (code === 0) { root.refreshEnvelope(); done(true, "", 0); return }
          if (code === 3) {
            // A stale envelope opens with nobody's current password.
            done(false, root.envelopeSummary && root.envelopeSummary.stale ? "stale" : "wrong-password", code)
            return
          }
          if (code !== E.absent && code !== 6 && code !== E.unseal) { done(false, "failed", code); return }
          root.verifyWithBw(pw, function(ok) {
            if (!ok) { done(false, "wrong-password", 3); return }
            root.storeAcceptedMasterPassword(pw, function(stored) {
              if (!stored) { done(false, "failed", 0); return }
              var again = {}
              again[Model.keyringSecretEnvVar()] = pw
              if (extraEnv) for (var k2 in extraEnv) again[k2] = extraEnv[k2]
              root.writeEnvelope(command, again, function(added, addCode) {
                done(added, added ? "" : "failed", added ? 0 : addCode)
              })
            })
          })
        }
      })
    }, function() { done(false, "failed", 0) })
  }

  // No envelope: `bw` checks the password. The session key it mints replaces
  // the current one and is adopted like an unlock's.
  function verifyWithBw(password, done) {
    var env = {}
    env[Model.keyringSecretEnvVar()] = String(password || "")
    beginEpochOperation("bwVerify")
    queueEnvelopeJob({
      command: Model.bwVerifyPasswordCommand(),
      env: bwEnv(env), secretOutput: true,
      onDone: function(code, out) {
        var s = code === 0 ? Model.extractSessionToken(out) : ""
        // Locked or logged out meanwhile: adopting the new session would
        // unlock behind the panel's back.
        if (root.epochOperationIsStale("bwVerify") || root.logoutPending || root.status !== "unlocked") {
          s = ""
          done(false)
          return
        }
        if (!s) { done(false); return }
        root.session = s
        root.storeCurrentSession()
        done(true)
      }
    })
  }

  function quickUnlockErrorText(why, fallback) {
    if (why === "wrong-password") return "That is not your master password."
    if (why === "stale") {
      return "Your master password was changed and the stored copy has not caught up yet. "
        + "Unlock once with a PIN, fingerprint or key you already have set up, then with your new password."
    }
    return fallback
  }

  // Not gated on envelopeSummary: a wrap from this same flow may not be in it
  // yet.
  function removeQuickUnlockMethod(op) {
    if (!quickUnlockAvailable || !accountId) return
    // No envelope, or no such method in it, is the state removal wanted.
    writeEnvelope(Model.unlockEnvelopeUpdateCommand(envelopeTool(), envelopeAccount(), op), {}, null,
      [Model.envelopeExitCodes().absent, 7])
  }

  // Migrates the legacy PIN blob at the PIN unlock that decrypted it; the blob
  // is deleted only once the new PIN wrap yields the same password.
  function migrateLegacyPin(password, pin) {
    if (!quickUnlockAvailable) return
    withEnvelopeAccount(function() {
      var env = {}
      env[Model.keyringSecretEnvVar()] = password
      env[Model.pinEnvVar()] = pin
      var codes = Model.legacyMigrationExitCodes()
      root.queueEnvelopeJob({
        command: Model.legacyPinMigrationCommand(root.envelopeTool(), root.envelopeAccount()),
        env: env, writes: true,
        onDone: function(code) {
          if (code === 0 || code === codes.none) root.legacyPinStored = false
          else console.log("qs-bitwarden envelope: PIN migration left the legacy blob (" + code + ")")
          root.refreshEnvelope()
        }
      })
    })
  }

  // Migrates the legacy fingerprint entry, once per session.
  function maybeMigrateLegacyFingerprint() {
    if (legacyMigrationAttempted || !legacyFingerprintStored || !quickUnlockAvailable || !accountId) return
    legacyMigrationAttempted = true
    var codes = Model.legacyMigrationExitCodes()
    queueEnvelopeJob({
      command: Model.legacyFingerprintMigrationCommand(envelopeTool(), envelopeAccount()),
      writes: true,
      onDone: function(code) {
        if (code === 0 || code === codes.none) root.legacyFingerprintStored = false
        if (code !== 0 && code !== codes.none) {
          console.log("qs-bitwarden envelope: fingerprint migration left the legacy entry (" + code + ")")
        }
        root.refreshEnvelope()
      }
    })
  }

  // -------------------------------------------------------------------------
  // Accounts
  // -------------------------------------------------------------------------
  //
  // Each signed-in account keeps its own bw data directory and keyring
  // entries (see "Accounts" in BitwardenModel.js), so switching never signs
  // one out or drops its quick-unlock methods. One account is active, and
  // only it can be unlocked: switching locks the one being left.

  property var accountRegistry: Model.emptyAccountRegistry()
  property bool accountsLoaded: false
  property string activeSlot: Model.defaultAccountSlot()
  readonly property var accountRows: Model.accountRows(accountRegistry, activeSlot)
  readonly property int accountCount: accountRegistry.accounts.length
  readonly property bool accountsFull: accountCount >= Model.maxAccounts()
  // The active slot's bw data directory; "" for bw's own.
  readonly property string accountAppDataDir: Model.accountAppDataDir(activeSlot,
    Quickshell.env("XDG_DATA_HOME") || "", Quickshell.env("HOME") || "")
  // An "Add account" sign-in not finished yet, and the account Cancel returns to.
  property bool addingAccount: false
  property string slotBeforeAdd: ""
  property string screenBeforeAccounts: "main"
  // Arm the lock screen's presence method once the new account's envelope
  // has been read (refreshEnvelope()).
  property bool armAfterEnvelope: false
  // A status probe stopped by a switch; its stale answer restarts the probe.
  property bool statusRefreshPending: false
  property bool statusCheckQueued: false
  property string pendingAccountsJson: ""
  property bool accountsWritePending: false
  // Slots to sign out of and delete, one process at a time.
  property var slotRemovalQueue: []

  // Never leave a non-default slot's `bw` in bw's own directory: without a
  // home to put it in, point it where nothing can be created.
  function accountAppDataEnv() {
    var env = {}
    if (activeSlot === Model.defaultAccountSlot()) return env
    env[Model.appDataEnvVar()] = accountAppDataDir || "/dev/null/qs-bitwarden-cli-no-home"
    return env
  }

  function accountsEnv() {
    var env = {}
    env[Model.accountsEnvVar()] = String(pendingAccountsJson || "")
    return env
  }

  function loadAccountRegistry() {
    if (!accountsReadProc.running) accountsReadProc.running = true
  }

  function onAccountRegistryLoaded(raw) {
    var registry = Model.parseAccountRegistry(raw)
    var slot = registry.active
    // A registry naming a slot it no longer lists: its most recent account.
    if (slot !== Model.defaultAccountSlot() && !Model.registryHasAccount(registry, slot)) {
      slot = Model.registryNextAccount(registry, "") || Model.defaultAccountSlot()
    }
    registry.active = slot
    accountRegistry = registry
    activeSlot = slot
    accountsLoaded = true
    repairKeyring()
    loadAssociations()
    refreshAccountCredentials()
    // The status probe waited for this (refreshStatus()).
    if (depsChecked && !setupGated && !statusProbeStarted) refreshStatus()
  }

  function saveAccountRegistry() {
    pendingAccountsJson = Model.serializeAccountRegistry(accountRegistry)
    if (accountsWriteProc.running) {
      accountsWritePending = true
      return
    }
    accountsWritePending = false
    accountsWriteProc.running = true
  }

  function onAccountRegistryWritten(exitCode) {
    if (exitCode !== 0) console.warn("qs-bitwarden-cli: could not save the account list (exit " + exitCode + ")")
    if (accountsWritePending) {
      accountsWritePending = false
      accountsWriteProc.running = true
      return
    }
    pendingAccountsJson = ""
  }

  // What `bw status` says the active slot holds.
  function noteActiveAccount(st) {
    if (!accountsLoaded || logoutPending || !st || !st.userId) return
    var known = Model.registryAccount(accountRegistry, activeSlot)
    if (known && known.userId === st.userId && known.server === st.serverUrl
        && (known.email === st.userEmail || !st.userEmail) && accountRegistry.active === activeSlot) {
      addingAccount = false
      return
    }
    var noted = Model.registryNoteAccount(accountRegistry, activeSlot,
      { userId: st.userId, email: st.userEmail, server: st.serverUrl }, Date.now())
    if (noted.full) {
      console.warn("qs-bitwarden-cli: account list full; this sign-in is not remembered")
      return
    }
    accountRegistry = noted.registry
    addingAccount = false
    slotBeforeAdd = ""
    saveAccountRegistry()
    for (var i = 0; i < noted.retired.length; i++) retireAccountSlot(noted.retired[i], true)
    if (noted.retired.length > 0) {
      flashNotification("This account was already added; its older sign-in was replaced")
    }
  }

  // Signs a slot out and deletes it. `clearKeyring` also removes its keyring
  // entries and learned suggestions (a logout has already cleared them).
  function retireAccountSlot(slot, clearKeyring) {
    if (!Model.isAccountSlot(slot) || slot === activeSlot) return
    slotRemovalQueue = slotRemovalQueue.concat([{ slot: slot, clearKeyring: clearKeyring === true }])
    pumpSlotRemovals()
  }

  function pumpSlotRemovals() {
    if (slotRemovalProc.running || slotRemovalQueue.length === 0) return
    var queue = slotRemovalQueue.slice()
    var next = queue.shift()
    slotRemovalQueue = queue
    slotRemovalProc.command = next.clearKeyring
      ? Model.accountSlotRetireCommand(next.slot)
      : Model.accountSlotRemoveCommand(next.slot)
    slotRemovalProc.running = true
  }

  // Everything held for the account being left, as a lock drops the vault
  // plus what a lock keeps: its email, envelope summary and method flags.
  // Nothing in the keyring or on disk is touched.
  function leaveActiveAccount() {
    closeFilterGroup()
    cancelAuthPrewarm()
    abandonAuthSecrets()
    abandonPinSetup()
    abandonFingerprintSetup()
    fidoUnlocker.abandonSetup()
    stopGeneratorServe()
    // The companion drops this account's keys and public projection.
    applySshAgentLifecycle("account-change")
    clearClipboard()
    if (session) {
      lockProc.command = Model.lockCommand()
      lockProc.running = true
    }
    requestSessionCredentialClear()
    // The status chain may still be answering for the account being left.
    // Checked before the lock's scrub borrows the same processes.
    if (sessionHandoffProc.running || keyringLookupProc.running || statusProc.running) {
      statusRefreshPending = true
      if (keyringLookupProc.running) keyringLookupProc.running = false
      if (statusProc.running) statusProc.running = false
    }
    dropVaultState()
    dropEnvelopeState()
    terminalLoginStartedAt = 0
    cancelFingerprintUnlock()
    fidoUnlocker.reset()
    legacyPinStored = false
    pinConfigured = false
    fingerprintStored = false
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
    pinUnlockError = ""
    fingerprintMessage = ""
    fingerprintError = ""
    errorMessage = ""
    userEmail = ""
    loginEmail = ""
    associationsEpoch += 1
    // A write still owed is the old account's; the running one finishes into
    // its own file.
    associationsWritePending = false
    associations = Model.emptyAssociations()
    suggestedItems = []
    detectedContext = null
    learnedIds = ({})
    syncLoginFieldsToState()
  }

  // The per-account checks a start runs, for the account now active.
  function refreshAccountCredentials() {
    if (!accountsLoaded) return
    if (pinUnlock) refreshPinConfigured()
    if (fingerprintAvailable && fingerprintUnlock) refreshLegacyFingerprint()
    envelopeReadinessChanged()
    if (fidoUnlock) fidoUnlocker.refresh()
  }

  function enterAccount(slot) {
    activeSlot = slot
    if (Model.registryHasAccount(accountRegistry, slot)) {
      accountRegistry = Model.registrySetActive(accountRegistry, slot, Date.now())
      saveAccountRegistry()
    }
    armAfterEnvelope = true
    loadAssociations()
    refreshAccountCredentials()
  }

  function canChangeAccount() {
    return accountsLoaded && !logoutPending && !isUnlocking && !loginSubmitted
  }

  function switchAccount(slot) {
    if (!canChangeAccount() || !Model.registryHasAccount(accountRegistry, slot)) return
    if (slot === activeSlot && !addingAccount) {
      closeAccounts()
      return
    }
    var abandoned = abandonedAddSlot()
    leaveActiveAccount()
    addingAccount = false
    slotBeforeAdd = ""
    enterAccount(slot)
    if (abandoned) retireAccountSlot(abandoned, true)
    status = "checking"
    currentScreen = "locked"
    refreshStatus()
    focusAppropriateField()
  }

  // An add given up before its sign-in finished leaves nothing behind. bw's
  // own directory is never cleaned up this way: nothing of ours is in it.
  function abandonedAddSlot() {
    if (!addingAccount || activeSlot === Model.defaultAccountSlot()) return ""
    return Model.registryHasAccount(accountRegistry, activeSlot) ? "" : activeSlot
  }

  // Signs another account in beside the ones already here.
  function beginAddAccount() {
    if (!canChangeAccount()) return
    if (accountsFull) {
      errorMessage = "The panel keeps up to " + Model.maxAccounts() + " accounts. Log out of one to add another."
      return
    }
    var slot = Model.slotForNewAccount(accountRegistry)
    if (!slot) return
    var before = addingAccount ? slotBeforeAdd : activeSlot
    var abandoned = abandonedAddSlot()
    if (abandoned === slot) abandoned = ""
    leaveActiveAccount()
    addingAccount = true
    slotBeforeAdd = Model.registryHasAccount(accountRegistry, before) ? before : ""
    enterAccount(slot)
    if (abandoned) retireAccountSlot(abandoned, true)
    if (slot === Model.defaultAccountSlot()) {
      // bw's own directory may already hold a sign-in the list lost.
      status = "checking"
      currentScreen = "locked"
      refreshStatus()
    } else {
      status = "unauthenticated"
      currentScreen = "login"
    }
    focusAppropriateField()
  }

  function cancelAddAccount() {
    if (!addingAccount || !slotBeforeAdd) return
    switchAccount(slotBeforeAdd)
  }

  // The account list, from any screen. Its rows are the accounts, then "Add
  // account"; the cursor starts on the active one.
  property int accountIndex: 0

  function openAccounts() {
    closeFilterGroup()
    if (currentScreen !== "accounts") screenBeforeAccounts = currentScreen
    accountIndex = 0
    for (var i = 0; i < accountRows.length; i++) if (accountRows[i].active) accountIndex = i
    currentScreen = "accounts"
    Qt.callLater(function() { presenter.focusField("keyCatcher") })
  }

  function moveAccountCursor(delta) {
    var n = accountRows.length + 1
    accountIndex = Math.max(0, Math.min(n - 1, accountIndex + delta))
  }

  function activateAccountRow() {
    if (accountIndex < accountRows.length) switchAccount(accountRows[accountIndex].slot)
    else beginAddAccount()
  }

  function closeAccounts() {
    if (currentScreen !== "accounts") return
    var back = screenBeforeAccounts
    if (back === "accounts" || back === "") back = "main"
    if (status !== "unlocked") back = status === "unauthenticated" ? "login" : "locked"
    currentScreen = back
  }

  // After a logout: the next most recent account, or a clean sign-in. The
  // logged-out slot's directory is deleted once it is no longer active.
  function moveOffRemovedAccount(removed) {
    accountRegistry = Model.registryRemoveAccount(accountRegistry, removed)
    var next = Model.registryNextAccount(accountRegistry, removed)
    loginEmail = ""
    syncLoginFieldsToState()
    if (next) {
      enterAccount(next)
    } else {
      var fresh = Model.slotForNewAccount(accountRegistry)
      accountRegistry = Model.registrySetActive(accountRegistry, fresh)
      saveAccountRegistry()
      activeSlot = fresh
      loadAssociations()
    }
    if (removed !== Model.defaultAccountSlot()) retireAccountSlot(removed, false)
    if (!next) return false
    status = "checking"
    currentScreen = "locked"
    refreshStatus()
    return true
  }

  property var sshAgentState: Model.sshAgentInitialState()
  // Mirrors of sshAgentState, since bindings (the timers) cannot follow a
  // plain JS object.
  property string sshAgentPhase: "disabled"
  property bool sshAgentGateOpen: false
  property string sshAgentSocketPath: ""
  property string sshAgentFifoPath: ""
  property string sshAgentVersion: ""
  property string sshAgentErrorCode: ""
  property string sshAgentErrorMessage: ""

  function applySshAgentEvent(event) {
    var step = Model.sshAgentReduce(root.sshAgentState, event)
    root.sshAgentState = step.state
    root.sshAgentPhase = step.state.phase
    root.sshAgentGateOpen = step.state.gateOpen
    root.sshAgentSocketPath = step.state.socketPath
    root.sshAgentFifoPath = step.state.fifoPath
    root.sshAgentVersion = step.state.agentVersion
    root.sshAgentErrorCode = step.state.errorCode
    root.sshAgentErrorMessage = step.state.errorMessage

    // State is committed first: stopping the Process can re-enter with the
    // exit before this returns, and must see the new phase.
    var action = step.action
    // Cancel before scheduling, so a stop never leaves a restart armed.
    if (action.cancelRestart) sshAgentRestartTimer.stop()
    if (action.stop) stopSshAgentHelper()
    if (action.writeHello && sshAgentProc.running) sshAgentProc.write(Model.sshAgentHelloLine())
    if (action.restartInMs >= 0) {
      sshAgentRestartTimer.interval = action.restartInMs
      sshAgentRestartTimer.restart()
    }
    if (action.start) startSshAgentHelper()
    if (action.message) root.onSshAgentMessage(action.message)
  }

  // An exit before `ready` may be a lost runtime lock (another shell), not a
  // crash; the helper exits 1 either way. The lock is probed before
  // reporting, and a held lock parks the supervisor without counting toward
  // CRASH_LOOP.
  property int sshAgentPendingExitCode: 0

  function onSshAgentHelperExited(exitCode) {
    var command = Model.sshAgentLockProbeCommand(root.sshAgentRuntimeDir)
    if ((root.sshAgentPhase !== "starting" && root.sshAgentPhase !== "handshaking")
        || !command || sshAgentLockProbeProc.running) {
      root.applySshAgentEvent({ kind: "exited", exitCode: exitCode, nowMs: Date.now() })
      return
    }
    root.sshAgentPendingExitCode = exitCode
    sshAgentLockProbeProc.command = command
    sshAgentLockProbeProc.running = true
  }

  Process {
    id: sshAgentLockProbeProc
    onExited: function(exitCode) {
      root.applySshAgentEvent({ kind: "exited", exitCode: root.sshAgentPendingExitCode,
        lockHeld: Model.sshAgentLockHeld(exitCode), nowMs: Date.now() })
    }
  }

  function startSshAgentHelper() {
    sshAgentTerminateTimer.stop()
    // Reopen stdin (the control channel) closed by a previous stop.
    sshAgentProc.stdinEnabled = true
    sshAgentProc.running = true
  }

  // Ask the helper to stop by closing its control channel, so it drops keys
  // and removes its socket and FIFO; SIGTERM only if it does not exit.
  // A helper killed with the shell objects (plugin disabled or removed)
  // leaves its socket, FIFO and lock behind; remove them once it is gone.
  Component.onDestruction: {
    if (root.sshAgentPhase === "disabled" && !sshAgentProc.running) return
    var cleanup = Model.sshAgentRuntimeCleanupCommand(root.sshAgentRuntimeDir)
    if (cleanup) Quickshell.execDetached(cleanup)
  }

  function stopSshAgentHelper() {
    if (!sshAgentProc.running) {
      sshAgentTerminateTimer.stop()
      return
    }
    if (sshAgentProc.stdinEnabled) {
      sshAgentProc.write(Model.sshAgentShutdownLine())
      sshAgentProc.stdinEnabled = false
    }
    sshAgentTerminateTimer.restart()
  }

  // -------------------------------------------------------------------------
  // Signing authorization
  // -------------------------------------------------------------------------
  //
  // One prompt at a time, never over a locked screen, claiming nothing the
  // companion did not check.

  // What is on screen. A live signing request outranks navigation, so flows
  // that reset currentScreen cannot hide a prompt a client is waiting on.
  readonly property string activeScreen: sshPrompt !== null && !sshAgentApprovalPopup ? "sshApproval" : currentScreen

  property var sshPrompt: null            // the approval_required being shown
  property var sshPromptQueue: []         // FIFO queue of approval_required messages waiting to be shown
  property var sshUnlockRequest: null     // the unlock_required being shown
  property var sshUnlockRaw: null         // its original message, to promote from
  property var sshUnlockQueue: []         // FIFO queue of unlock_required messages waiting
  readonly property int sshPendingCount: Model.sshAgentPendingCount(sshPrompt, sshPromptQueue)
  readonly property int sshUnlockPendingCount: Model.sshAgentPendingCount(sshUnlockRequest, sshUnlockQueue)
  readonly property int sshTotalPendingCount: sshPendingCount + sshUnlockPendingCount
  readonly property bool sshApprovalPopupOpen: sshAgentApprovalPopup
    && (sshPrompt !== null || sshUnlockRequest !== null)
  // Completion handlers treat the SSH popup as an auth surface even with the
  // panel closed.
  readonly property bool sshAuthSurfaceActive: opened || sshApprovalPopupOpen
  // The last announced grants, and a view re-derived each tick so countdowns
  // move and lapsed grants disappear.
  property var sshGrantsAnnounced: []
  property double sshGrantTick: 0
  readonly property var sshGrants: Model.sshAgentGrantsAt(sshGrantsAnnounced, sshGrantTick)
  property var sshCooldown: Model.sshAgentCooldownInitial()
  // The current cooldown was announced; reset when it lapses.
  property bool sshCooldownAnnounced: false
  readonly property var sshCooldownStatus: Model.sshAgentCooldownStatus(sshCooldown, sshCooldownTick)
  // One-second tick for the countdown (Date.now() does not re-evaluate).
  property double sshCooldownTick: 0
  property double sshPromptStartedMs: 0
  property int sshPromptRemainingSec: 0
  property string screenBeforeSshApproval: "main"
  // The request opened the panel, so answering closes it again.
  property bool sshPromptOpenedPanel: false

  function sshAgentWrite(line) {
    if (line === "") return
    if (sshAgentProc.running && sshAgentProc.stdinEnabled) sshAgentProc.write(line)
  }

  // Announce a cooldown that may have just started: it is the only
  // explanation for suddenly failing SSH commands.
  function noteSshCooldown() {
    root.sshCooldownTick = Date.now()
    var status = Model.sshAgentCooldownStatus(root.sshCooldown, Date.now())
    if (status.active && !root.sshCooldownAnnounced) {
      root.sshCooldownAnnounced = true
      flashNotification("SSH signing paused: too many unanswered prompts")
    } else if (!status.active) {
      root.sshCooldownAnnounced = false
    }
  }

  // The only way to end a cooldown early; the requester cannot, since no
  // prompts are shown during it.
  function resumeSshSigning() {
    root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "resumed", Date.now())
    noteSshCooldown()
  }

  function sshAgentMayPrompt() {
    // A stale lock reading (the poll is not running) counts as locked.
    var fresh = root.screenLockCheckedAt > 0
      && (Date.now() - root.screenLockCheckedAt) < (Model.screenLockPollMs() * 4)
    if (!Model.sshAgentShouldPrompt(fresh ? { screenLocked: root.screenIsLocked } : null)) return false
    return !Model.sshAgentCooldownActive(root.sshCooldown, Date.now())
  }

  // Starts a request's countdown; true when the popup (not the panel) shows it.
  function startSshPromptClock() {
    root.sshPromptStartedMs = Date.now()
    root.sshPromptRemainingSec = Math.ceil(Model.sshAgentRequestDeadlineMs() / 1000)
    if (!root.sshAgentApprovalPopup) return false
    root.sshPromptOpenedPanel = false
    return true
  }

  function showSshApproval(message) {
    root.sshPrompt = Model.sshAgentPromptView(message, root.sshAgentApprovalWindowSec)
    if (startSshPromptClock()) return
    if (root.currentScreen !== "sshApproval") root.screenBeforeSshApproval = root.currentScreen
    // Recorded before opening, because open() is what makes it true.
    if (!root.sshUnlockRaw) root.sshPromptOpenedPanel = !root.opened
    // Open first: opening sends an unlocked panel to the list, which would
    // undo claiming the screen.
    if (!root.opened) root.open()
    root.currentScreen = "sshApproval"
  }

  // The preference hot-reloads; move a pending request to the new surface.
  onSshAgentApprovalPopupChanged: {
    if (!(root.sshPrompt || root.sshUnlockRequest)) return
    if (root.sshAgentApprovalPopup) {
      var requestOpenedPanel = root.sshPromptOpenedPanel
      root.sshPromptOpenedPanel = false
      if (requestOpenedPanel && root.opened) root.close()
      return
    }

    root.sshPromptOpenedPanel = !root.opened
    if (!root.opened) root.open()
    if (root.sshPrompt) root.currentScreen = "sshApproval"
  }

  function dismissSshApproval() {
    var openedForThis = root.sshPromptOpenedPanel
    var popupWasUsed = root.sshApprovalPopupOpen
    root.sshPrompt = null
    root.sshPromptQueue = []
    root.sshPromotedOldId = null
    root.sshUnlockRequest = null
    root.sshUnlockRaw = null
    root.sshUnlockQueue = []
    root.sshPromptOpenedPanel = false
    if (root.currentScreen === "sshApproval") {
      root.currentScreen = root.screenBeforeSshApproval === "sshApproval"
        ? "main" : root.screenBeforeSshApproval
    }
    if (popupWasUsed) clearSshPopupUnlockState()
    // Close the panel if the request opened it; otherwise leave it as it was.
    if (openedForThis && root.opened) root.close()
  }

  function advanceSshPrompt() {
    var res = Model.sshAgentDequeuePrompt(root.sshPromptQueue)
    root.sshPromptQueue = res.remaining
    if (res.next) {
      showSshApproval(res.next)
      return
    }
    dismissSshApproval()
  }

  function advanceSshUnlock() {
    var res = Model.sshAgentDequeuePrompt(root.sshUnlockQueue)
    root.sshUnlockQueue = res.remaining
    if (res.next) {
      root.sshUnlockRaw = res.next
      root.sshUnlockRequest = Model.sshAgentPromptView(res.next, 0)
      root.sshPromptStartedMs = Date.now()
      root.sshPromptRemainingSec = Math.ceil(Model.sshAgentRequestDeadlineMs() / 1000)
      return
    }
    dismissSshApproval()
  }

  // Leave no password, PIN, PAM conversation or prewarmed CLI behind a
  // dismissed or expired popup.
  function clearSshPopupUnlockState() {
    cancelFingerprintUnlock()
    cancelFidoUnlock()
    cancelAuthPrewarm()
    if (pinUnlockProc.running) pinUnlockProc.running = false
    root.pinUnlockSubmitted = false
    root.pinBusy = false
    root.masterPassword = ""
    root.pendingUnlockPassword = ""
    root.pendingUnlockFrom = ""
    root.pinEntry = ""
    root.pinError = ""
    root.pinUnlockError = ""
    root.fingerprintMessage = ""
    root.fingerprintError = ""
    root.errorMessage = ""
    syncLoginFieldsToState()
  }

  function approveSshRequest(grantSeconds) {
    if (!sshPrompt) return
    sshAgentWrite(Model.sshAgentApproveLine(sshPrompt.requestId, grantSeconds))
    root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "approved", Date.now())
    noteSshCooldown()
    advanceSshPrompt()
  }

  function denySshRequest() {
    if (sshUnlockRequest) {
      sshAgentWrite(Model.sshAgentUnlockCancelledLine(sshUnlockRequest.requestId))
      root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "denied", Date.now())
      noteSshCooldown()
      advanceSshUnlock()
      return
    }
    if (sshPrompt) {
      sshAgentWrite(Model.sshAgentDenyLine(sshPrompt.requestId))
      root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "denied", Date.now())
      noteSshCooldown()
      advanceSshPrompt()
      return
    }
    dismissSshApproval()
  }

  function denyAllSshRequests() {
    if (sshPrompt) {
      sshAgentWrite(Model.sshAgentDenyLine(sshPrompt.requestId))
    }
    for (var i = 0; i < root.sshPromptQueue.length; i++) {
      if (root.sshPromptQueue[i] && root.sshPromptQueue[i].requestId) {
        sshAgentWrite(Model.sshAgentDenyLine(root.sshPromptQueue[i].requestId))
      }
    }
    if (sshUnlockRequest) {
      sshAgentWrite(Model.sshAgentUnlockCancelledLine(sshUnlockRequest.requestId))
    }
    for (var j = 0; j < root.sshUnlockQueue.length; j++) {
      if (root.sshUnlockQueue[j] && root.sshUnlockQueue[j].requestId) {
        sshAgentWrite(Model.sshAgentUnlockCancelledLine(root.sshUnlockQueue[j].requestId))
      }
    }
    root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "denied", Date.now())
    noteSshCooldown()
    dismissSshApproval()
  }

  // The companion expires the request; this just stops showing it.
  function expireSshRequest() {
    if (!sshPrompt && !sshUnlockRequest) return
    root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "timeout", Date.now())
    noteSshCooldown()
    dismissSshApproval()
  }

  // Git SSH signing needs key files: write the companion's validated public
  // keys (sshExportIdentities() refuses anything else).
  function exportSshPublicKeys() {
    var payload = Model.sshExportPayload(root.sshPendingPublicKeys)
    root.sshPendingPublicKeys = []
    if (sshExportProc.running) return
    sshExportProc.running = true
    sshExportProc.write(payload)
    sshExportProc.stdinEnabled = false
  }

  // Removed on logout, account change and disable; kept on lock, like the
  // public identities themselves.
  function clearSshPublicKeys() {
    root.sshPendingPublicKeys = []
    root.sshPendingPublicEpoch = -1
    if (sshExportClearProc.running) return
    sshExportClearProc.running = true
  }

  function onSshExportFinished(exitCode, stdout) {
    var result = Model.parseSshExportResult(exitCode, stdout)
    root.sshExportError = result.ok ? "" : result.message
  }

  property string sshExportError: ""

  function revokeSshGrant(grantId) {
    sshAgentWrite(Model.sshAgentRevokeGrantLine(grantId))
  }

  function revokeAllSshGrants() {
    sshAgentWrite(Model.sshAgentRevokeGrantsLine())
  }

  property var sshPromotedOldId: null

  function adoptSshPrompt(message) {
    if (root.sshPromotedOldId !== null && root.sshPrompt) {
      root.sshPrompt.requestId = message.requestId
      root.sshPromotedOldId = null
      return true
    }
    return false
  }

  function onSshAgentMessage(message) {
    if (message.type === "approval_required") {
      // Refuse now rather than let the client wait out the deadline.
      if (!sshAgentMayPrompt()) {
        sshAgentWrite(Model.sshAgentDenyLine(message.requestId))
        return
      }
      if (adoptSshPrompt(message)) return
      if (root.sshPrompt !== null) {
        root.sshPromptQueue = Model.sshAgentEnqueuePrompt(root.sshPromptQueue, message, 4)
        return
      }
      showSshApproval(message)
      return
    }
    if (message.type === "unlock_required") {
      if (!sshAgentMayPrompt()) {
        sshAgentWrite(Model.sshAgentUnlockCancelledLine(message.requestId))
        return
      }
      if (root.sshUnlockRequest !== null) {
        root.sshUnlockQueue = Model.sshAgentEnqueuePrompt(root.sshUnlockQueue, message, 4)
        return
      }
      root.sshUnlockRaw = message
      root.sshUnlockRequest = Model.sshAgentPromptView(message, 0)
      if (startSshPromptClock()) return
      root.sshPromptOpenedPanel = !root.opened
      if (!root.opened) root.open()
      return
    }
    if (message.type === "request_cancelled") {
      // The request was cancelled by the client, timed out, released on
      // unlock, or answered by a grant the user just approved ("granted").
      var live = root.sshPrompt || root.sshUnlockRequest
      if (live && live.requestId === message.requestId) {
        if (message.reason === "granted") {
          // Answered, not ignored: no cooldown.
        } else if (message.reason === "released") {
          // A released sign request comes back as an approval, so the popup
          // stays for it; a released identity listing is already answered, so
          // the prompt closes.
          var listingAnswered = root.sshUnlockRequest !== null
            && root.sshUnlockRaw !== null
            && root.sshUnlockRaw.reason === "list-identities"
          if (!listingAnswered) return
        } else {
          root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "timeout", Date.now())
          noteSshCooldown()
        }
        if (root.sshPrompt && root.sshPromptQueue.length > 0) advanceSshPrompt()
        else if (root.sshUnlockRequest && root.sshUnlockQueue.length > 0) advanceSshUnlock()
        else dismissSshApproval()
        return
      }
      if (root.sshPromptQueue.length > 0) {
        root.sshPromptQueue = Model.sshAgentRemovePrompt(root.sshPromptQueue, message.requestId)
      }
      if (root.sshUnlockQueue.length > 0) {
        root.sshUnlockQueue = Model.sshAgentRemovePrompt(root.sshUnlockQueue, message.requestId)
      }
      return
    }
    if (message.type === "grants_changed") {
      root.sshGrantsAnnounced = Model.sshAgentGrantViews(message.grants, Date.now())
      root.sshGrantTick = Date.now()
      return
    }
    if (message.type === "public_key") {
      // A new epoch starts a new set rather than adding to the last one.
      if (root.sshPendingPublicEpoch !== message.epoch) {
        root.sshPendingPublicEpoch = message.epoch
        root.sshPendingPublicKeys = []
      }
      root.sshPendingPublicKeys = root.sshPendingPublicKeys.concat([message])
      return
    }
    if (message.type === "keys_loaded") {
      root.sshAgentKeyCount = Math.max(0, Math.floor(Number(message.keyCount)) || 0)
      root.sshAgentKeysLoadedAt = Date.now()
      root.sshAgentLoadFailStreak = 0
      // Every public_key for this epoch arrived before this message.
      if (root.sshPendingPublicEpoch === message.epoch) exportSshPublicKeys()
      return
    }
    if (message.type === "load_failed") {
      // The helper dropped its private keys but keeps serving (unlike
      // `locked`, the vault_locked ack). Ignore failures of older loads.
      if (message.epoch !== root.sshAgentEpoch) return
      root.sshAgentLoadFailStreak += 1
      root.sshAgentLoadedForVaultEpoch = -1
      if (root.sshAgentLoadFailStreak === 1) maybeStartupLoad()
      return
    }
    if (message.type === "locked") {
      // The lock ack: signing denied, grants and private keys dropped.
      sshAgentLockAckTimer.stop()
      return
    }
    if (message.type === "state_changed") {
      root.sshAgentKeyCount = Math.max(0, Math.floor(Number(message.keyCount)) || 0)
      return
    }
    // An unknown *type* is a protocol failure and never reaches this.
  }

  // -------------------------------------------------------------------------
  // Key loading (the agent branch of the shared vault read)
  // -------------------------------------------------------------------------
  //
  // The companion requires a strictly increasing epoch per load, so this only
  // goes up; a restarted companion starts from 0, below any value sent.
  property int sshAgentEpoch: 0
  property string sshAgentLoadId: ""
  property bool sshAgentLoadActive: false
  // The running read carries the agent branch / was already retried without
  // it (so the agent can never cost the user the item list).
  property bool listAgentBranchActive: false
  property bool listRetriedWithoutAgent: false
  // The running item read started before `bw status` confirmed the session
  // (onKeyringLookupFinished()); its failure means nothing yet.
  property bool listReadEarly: false

  // The nonce is primed ahead of time so the item list never waits on it; a
  // load without one runs without the branch and primes one for next time.
  property string sshAgentNextLoadId: ""
  // Keys the companion reported serving (a count only); tells whether a locked
  // companion still has a public cache.
  property int sshAgentKeyCount: 0
  // Public identities reported for the loading epoch, one message per key
  // (all at once would exceed the line limit).
  property var sshPendingPublicKeys: []
  property int sshPendingPublicEpoch: -1
  property double sshAgentKeysLoadedAt: 0
  // The vault epoch a key load was started for, so a startup load runs once.
  property int sshAgentLoadedForVaultEpoch: -1
  // Auto-retries of a failed FIFO load (one), so a bad payload cannot loop.
  property int sshAgentLoadFailStreak: 0

  function primeSshAgentLoadId() {
    if (loadIdProc.running || sshAgentNextLoadId !== "") return
    loadIdProc.running = true
  }

  function onSshAgentLoadIdRead(raw) {
    var candidate = String(raw || "").trim()
    root.sshAgentNextLoadId = Model.isValidLoadId(candidate) ? candidate : ""
    // A load that was owed while no nonce was ready waited for this one.
    if (root.sshAgentNextLoadId !== "") maybeStartupLoad()
  }

  // Close the load window on success, failure or a cancelling lock. The
  // companion publishes nothing until then and discards on failure, so every
  // window must be closed.
  function endSshAgentLoad(ok) {
    if (!sshAgentLoadActive) return
    sshAgentLoadActive = false
    sshAgentLoadId = ""
    if (sshAgentProc.running && sshAgentProc.stdinEnabled) {
      sshAgentProc.write(Model.sshAgentLoadEndLine(sshAgentEpoch, ok))
    }
    primeSshAgentLoadId()
  }

  // Abandon the loadId and stop the read; its process group takes bw, tee and
  // jq with it.
  function cancelSshAgentLoad() {
    if (listProc.running) listProc.running = false
    endSshAgentLoad(false)
    listAgentBranchActive = false
    listRetriedWithoutAgent = false
  }

  // The vault as the companion's state table sees it.
  function sshAgentVaultContext() {
    return {
      enabled: root.sshAgentEnabled,
      helperReady: root.sshAgentGateOpen,
      loggedIn: root.status !== "unauthenticated",
      unlocked: root.status === "unlocked",
      loading: root.sshAgentLoadActive,
      hasPublicCache: root.sshAgentKeyCount > 0,
      epoch: root.sshAgentEpoch
    }
  }

  // Every vault transition reaches the companion here: deny first, cancel work
  // in flight, then lock. Never waits on the helper.
  function applySshAgentLifecycle(event) {
    var action = Model.sshAgentLifecycleTransition(event, sshAgentVaultContext())

    if (action.cancelLoad) cancelSshAgentLoad()
    for (var i = 0; i < action.controlLines.length; i++) {
      if (sshAgentProc.running && sshAgentProc.stdinEnabled) sshAgentProc.write(action.controlLines[i])
    }
    if (action.clearPublic) {
      root.sshAgentKeyCount = 0
      root.sshAgentKeysLoadedAt = 0
      clearSshPublicKeys()
    }
    // The ack is not a precondition: a companion that cannot confirm the lock
    // within the timeout is killed.
    if (action.awaitLockAck) sshAgentLockAckTimer.restart()
    if (action.stopHelper) stopSshAgentHelper()
    if (action.startLoad && !listProc.running) loadItems(false)
  }

  function syncSshAgentSupervision() {
    applySshAgentEvent({ kind: "enabled", value: root.sshAgentSupervisable, nowMs: Date.now() })
  }

  onSshAgentSupervisableChanged: syncSshAgentSupervision()

  function sendSshAgentOptions() {
    sshAgentWrite(Model.sshAgentOptionsLine(root.sshAgentUnlockOnDemand))
  }

  onSshAgentUnlockOnDemandChanged: sendSshAgentOptions()

  onSshAgentGateOpenChanged: {
    if (sshAgentGateOpen) sendSshAgentOptions()
    if (!sshAgentGateOpen) {
      endSshAgentLoad(false)
      // Its keys went with the process.
      root.sshAgentKeyCount = 0
      return
    }
    // A new helper is empty even if the vault epoch did not move; allow a load.
    root.sshAgentLoadedForVaultEpoch = -1
    root.sshAgentLoadFailStreak = 0
    primeSshAgentLoadId()
    // A remembered session may already be unlocked. Deferred a beat so the
    // just-primed nonce is ready.
    sshAgentStartupLoadTimer.restart()
  }

  Timer {
    id: sshAgentStartupLoadTimer
    interval: 250
    repeat: false
    onTriggered: root.maybeStartupLoad()
  }

  // A startup load needs a serving helper and an unlocked vault, which can
  // arrive in either order; both edges call this and the epoch keeps it to one.
  function maybeStartupLoad() {
    if (!sshAgentGateOpen || root.status !== "unlocked") return
    // The first item read usually starts before the handshake; onListFinished()
    // calls back when it lands.
    if (sshAgentLoadActive || listProc.running) return
    if (sshAgentLoadedForVaultEpoch === root.vaultEpoch) return
    // No nonce yet: onSshAgentLoadIdRead() calls back when it is ready.
    if (!Model.isValidLoadId(sshAgentNextLoadId)) {
      primeSshAgentLoadId()
      return
    }
    // Marked before the attempt, so a failure cannot relaunch itself.
    sshAgentLoadedForVaultEpoch = root.vaultEpoch
    applySshAgentLifecycle("startup")
  }

  onStatusChanged: {
    promoteUnlockToApproval()
    maybeStartupLoad()
  }

  // Unlocked but keys still loading: ask for approval now. The companion
  // applies it once the keys land, re-checking the key is present.
  function promoteUnlockToApproval() {
    if (root.status !== "unlocked" || !root.sshUnlockRaw || root.sshPrompt) return
    // A listing is answered by the load itself; nothing to approve.
    if (root.sshUnlockRaw.reason === "list-identities") return
    var raw = root.sshUnlockRaw
    root.sshPromotedOldId = raw.requestId
    root.sshUnlockRequest = null
    root.sshUnlockRaw = null
    root.sshUnlockQueue = []
    showSshApproval(raw)
  }

  // Kills a helper that does not confirm the lock in time.
  Timer {
    id: sshAgentLockAckTimer
    interval: Model.sshAgentLockAckTimeoutMs()
    repeat: false
    onTriggered: if (sshAgentProc.running) sshAgentProc.running = false
  }

  // Disabled / enabled / error, derived from the supervisor.
  readonly property var sshAgentSetup: Model.sshAgentSetupState({
    enabled: sshAgentEnabled,
    supervisable: sshAgentSupervisable,
    phase: sshAgentPhase,
    errorCode: sshAgentErrorCode
  })

  // -------------------------------------------------------------------------
  // Client routing (advisory)
  // -------------------------------------------------------------------------
  //
  // Whether clients will find the companion's socket. Only the graphical
  // session's SSH_AUTH_SOCK is visible here, so this is phrased as a hint with
  // a command to check in the user's own terminal.
  readonly property string sshAuthSock: Quickshell.env("SSH_AUTH_SOCK") || ""
  readonly property var sshRouting: Model.sshAuthSockDiagnostic(sshAuthSock, sshAgentRuntimeDir)

  property var uwsmFragment: ({ state: "unknown", removable: false, message: "" })
  readonly property var sshRoutingNotice: Model.sshAgentRoutingNotice(uwsmFragment, sshRouting)
  property bool uwsmBusy: false
  property string uwsmFlash: ""
  // Set when the session points at another agent; replacing it needs a
  // confirmation.
  property bool uwsmConfirmPending: false

  function inspectUwsmFragment() {
    if (uwsmInspectProc.running) return
    uwsmInspectProc.running = true
  }

  function beginUwsmSetup() {
    if (uwsmBusy) return
    if (sshRouting.state === "elsewhere" && !uwsmConfirmPending) {
      uwsmConfirmPending = true
      return
    }
    uwsmConfirmPending = false
    uwsmBusy = true
    uwsmFlash = ""
    uwsmWriteProc.running = true
  }

  // Removing all stored data is confirmed first; it cannot be undone.
  property bool pluginDataConfirmPending: false
  property bool pluginDataBusy: false
  property string pluginDataFlash: ""

  function beginPluginDataRemoval() {
    if (pluginDataBusy) return
    if (!pluginDataConfirmPending) {
      pluginDataConfirmPending = true
      return
    }
    pluginDataConfirmPending = false
    pluginDataBusy = true
    pluginDataFlash = ""
    pluginDataRemoveProc.running = true
  }

  function cancelPluginDataRemoval() {
    pluginDataConfirmPending = false
  }

  function onPluginDataRemoved(exitCode, stdout) {
    var result = Model.parsePluginDataRemoval(exitCode, stdout)
    root.pluginDataBusy = false
    root.pluginDataFlash = result.message
    if (!result.ok) return
    // The stored master password went with it.
    root.fingerprintStored = false
    // So did the other accounts' sign-ins and the list of them; bw's own
    // (default) sign-in is the one left.
    var wasElsewhere = root.activeSlot !== Model.defaultAccountSlot()
    if (wasElsewhere) root.leaveActiveAccount()
    root.accountRegistry = Model.emptyAccountRegistry()
    root.addingAccount = false
    root.slotBeforeAdd = ""
    if (wasElsewhere) {
      root.enterAccount(Model.defaultAccountSlot())
      root.status = "checking"
      root.currentScreen = "locked"
      root.refreshStatus()
    }
  }

  function cancelUwsmSetup() {
    uwsmConfirmPending = false
  }

  // Safe unconditionally: only our exact file is removed, never a symlink.
  function removeUwsmFragment() {
    if (uwsmBusy) return
    uwsmConfirmPending = false
    uwsmBusy = true
    uwsmFlash = ""
    uwsmRemoveProc.running = true
  }

  function onUwsmActionFinished(exitCode, stdout) {
    var result = Model.parseUwsmActionResult(exitCode, stdout)
    root.uwsmBusy = false
    root.uwsmFlash = result.message
    root.inspectUwsmFragment()
  }

  // Disabling the agent removes our routing file (never a user's). Only on a
  // real transition after startup, not the binding's initial evaluation.
  property bool sshAgentSettingsReady: false

  onSshAgentEnabledChanged: {
    if (sshAgentEnabled) inspectSshAgentHelper()
    inspectUwsmFragment()
    if (!sshAgentSettingsReady) return
    if (!sshAgentEnabled) {
      // The supervisor does not know about the public key files.
      applySshAgentLifecycle("disable")
      removeUwsmFragment()
      return
    }
    // Re-enabling restores the file, or the next login would silently lose
    // routing. Waits for the inspection's answer.
    uwsmRestorePending = true
  }

  // Set only by re-enabling; restores what disabling removed, never more.
  property bool uwsmRestorePending: false

  function applyUwsmRestore() {
    if (!uwsmRestorePending) return
    uwsmRestorePending = false
    if (!sshAgentEnabled || uwsmBusy) return
    // Only "absent": never touch a foreign file or symlink, and replacing
    // another agent is the user's call at the button.
    if (uwsmFragment.state !== "absent" || sshRouting.state === "elsewhere") return
    beginUwsmSetup()
  }

  // -------------------------------------------------------------------------
  // Open and close
  // -------------------------------------------------------------------------

  function open(view) {
    errorMessage = ""
    flashMessage = ""
    revealedFields = ({})
    cursorActive = true
    showDeleteConfirm = false
    totpFollowupActive = false
    isUnlocking = false
    suggestionsDismissed = false
    fingerprintMessage = ""
    fingerprintError = ""

    // show() flips `opened`, which runs onPanelOpened; call it directly only
    // if the panel was already open (else the startup work runs twice).
    var wasOpen = opened
    var target = view || presenter
    target.showPopout()
    if (wasOpen) onPanelOpened()
  }

  function close() {
    errorMessage = ""
    revealedFields = ({})
    showDeleteConfirm = false
    totpFollowupActive = false
    isUnlocking = false
    cancelAuthPrewarm()
    if (pendingSecondFactorLogin()) suspendPendingLogin()
    else abandonAuthSecrets()
    // Closing a setup form cancels it; a write already running is discarded.
    abandonPinSetup()
    abandonFingerprintSetup()
    cancelFingerprintUnlock()
    // Released, not cancelled: the key's request stays adoptable.
    releaseFidoUnlock()
    cancelAttachmentDownloads()
    stopGeneratorServe()
    eachView(function(view) { view.hidePopout() })
  }

  function toggle(view) {
    if (opened) close()
    else open(view)
  }

  function detectActiveWindowContext() {
    if (!suggestOnOpen) return
    activeWindowProc.command = Model.activeWindowCommand()
    activeWindowProc.running = true
  }

  // A read requested while the process is busy (another account's read, or
  // a lock's scrub) is asked again by busyRetryTimer.
  property bool associationsReloadPending: false

  function loadAssociations() {
    if (associationsReadProc.running) {
      associationsReloadPending = true
      return
    }
    associationsReloadPending = false
    associationsReadEpoch = associationsEpoch
    associationsReadProc.command = Model.associationsReadCommand(activeSlot)
    associationsReadProc.running = true
  }

  function onAssociationsLoaded(raw) {
    if (associationsReadEpoch !== associationsEpoch) return
    associations = Model.parseAssociations(raw)
    if (activeWindowData) handleActiveWindowDetected(activeWindowData)
  }

  function saveAssociations(next) {
    associations = next
    pendingAssociationsJson = Model.serializeAssociations(next)
    if (associationsWriteProc.running) {
      associationsWritePending = true
      return
    }
    associationsWritePending = false
    associationsWriteProc.running = true
  }

  // Learn silently from any pick made while a window context is active.
  function learnFromPick(item) {
    if (!suggestOnOpen || !item || !item.id || !detectedContext || !Model.isLoginItem(item)) return
    if (Model.isAssociated(associations, detectedContext, item.id)) return
    saveAssociations(Model.recordAssociation(associations, detectedContext, item.id, new Date().toISOString()))
  }

  // Explicit pin/unpin from the detail view.
  function toggleAssociation(item) {
    if (!item || !item.id || !detectedContext || !Model.isLoginItem(item)) return
    if (Model.isAssociated(associations, detectedContext, item.id)) {
      saveAssociations(Model.forgetAssociation(associations, detectedContext, item.id))
      flashNotification("No longer suggested for " + detectedContext.displayName)
    } else {
      saveAssociations(Model.recordAssociation(associations, detectedContext, item.id, new Date().toISOString()))
      flashNotification("Always suggested for " + detectedContext.displayName)
    }
    if (activeWindowData) handleActiveWindowDetected(activeWindowData)
  }

  function handleActiveWindowDetected(data) {
    activeWindowData = data
    if (!suggestOnOpen) {
      suggestedItems = []
      detectedContext = null
      rebuildFilter()
      return
    }
    if (items.length === 0) {
      return
    }
    var res = Model.findContextualMatches(items, data, associations)
    detectedContext = res.context
    suggestedItems = res.matches
    learnedIds = res.learnedIds || ({})
    rebuildFilter()
  }

  // Focus the right field when a screen appears, but never move focus off a
  // field on the same screen: a logout's confirming `bw status` arriving
  // mid-typing once moved the cursor from the password to the email field.
  function focusAppropriateField() {
    if (sshApprovalPopupOpen) return
    Qt.callLater(function() {
      // Setup and the account list have no field.
      if (currentScreen === "setup" || currentScreen === "accounts") return
      if (status === "unlocked" && currentScreen === "main") {
        if (!presenter.fieldHasFocus("search")) presenter.focusField("search")
      } else if (status === "locked" || status === "checking") {
        if (presenter.unlockFieldHasFocus()) return
        if (pinReady) presenter.focusField("pin")
        else presenter.focusField("pass")
      } else if (status === "unauthenticated") {
        if (presenter.loginFieldHasFocus()) return
        // A resumed login focuses the waiting challenge field.
        if (showDeviceCodeField) presenter.focusField("deviceCode")
        else if (show2faField) presenter.focusField("code2fa")
        else if (!show2faMethodPicker) presenter.focusField("email")
      }
    })
  }

  onOpenedChanged: {
    if (opened) onPanelOpened()
    else {
      cancelFingerprintUnlock()
      // Not a cancel; see releaseSurface() in FidoUnlock.qml.
      fidoUnlocker.releaseSurface()
      cancelAuthPrewarm()
      if (pendingSecondFactorLogin()) suspendPendingLogin()
      else abandonAuthSecrets()
      // A closed panel must not keep a field focused, or the next open would
      // count as "already typing here" and skip the field the screen opens on.
      presenter.focusField("keyCatcher")
    }
  }

  function onPanelOpened() {
    // A pending login that outlived its window is gone, not resumed.
    if (secondFactorStartedAt > 0
        && !Model.secondFactorWindowOpen(secondFactorStartedAt, Date.now())) {
      abandonAuthSecrets()
    }
    focusAppropriateField()
    detectActiveWindowContext()
    refreshFingerprintAvailability()

    // A signing request, which a client is blocked on, outranks the list.
    if (sshPrompt) {
      currentScreen = "sshApproval"
      return
    }
    if (status === "unlocked") {
      currentScreen = "main"
      ensureItemsFresh()
    } else if (status === "locked") {
      // A terminal login leaves the panel locked, so check for a handoff.
      refreshStatus()
      prepareUnlock()
      armPresenceUnlock()
    } else {
      refreshStatus()
    }
  }

  // -------------------------------------------------------------------------
  // Status and keyring
  // -------------------------------------------------------------------------

  function refreshStatus() {
    errorMessage = ""
    if (logoutPending) return
    // Wait for the dependency probe, which owns the first status transition.
    if (!depsChecked) {
      checkDependencies()
      return
    }
    // Never walk past setup into a login form with no CLI behind it.
    if (setupGated) {
      currentScreen = "setup"
      return
    }
    // Which account to ask about; onAccountRegistryLoaded() calls back.
    if (!accountsLoaded) {
      loadAccountRegistry()
      return
    }
    // Recorded here so a panel opened before the dependency probe reports does
    // not start a second slow `bw status`.
    statusProbeStarted = true
    // A terminal login may have left a session: check first (it leaves the
    // panel locked). Only read within the window after we launched one;
    // otherwise the file is just removed.
    if (sessionHandoffProc.running) {
      // One started for an earlier vault, or a lock's scrub of it, restarts
      // this when it exits.
      if (epochOperationIsStale("sessionHandoff") || Model.isScrubCommand(sessionHandoffProc.command)) {
        statusRefreshPending = true
      }
      return
    }
    var expecting = Model.handoffWindowOpen(terminalLoginStartedAt, Date.now())
    if (!expecting) terminalLoginStartedAt = 0
    beginEpochOperation("sessionHandoff")
    sessionHandoffProc.command = Model.sessionHandoffReadCommand(expecting)
    sessionHandoffProc.running = true
  }

  // A probe stopped by an account switch answered for the old account; ask
  // again for the new one.
  function restartStaleStatusProbe() {
    if (!statusRefreshPending) return
    statusRefreshPending = false
    statusCheckQueued = false
    Qt.callLater(refreshStatus)
  }

  // A lock scrubs the status chain's processes (scrubSecretBuffers()); a
  // probe that found one busy waits for this.
  function onStatusProbeProcessFreed() {
    if (statusRefreshPending) {
      restartStaleStatusProbe()
    } else if (statusCheckQueued) {
      statusCheckQueued = false
      Qt.callLater(runStatusCheck)
    }
  }

  function onSessionHandoff(raw) {
    if (epochOperationIsStale("sessionHandoff")) {
      restartStaleStatusProbe()
      return
    }
    var handed = Model.extractSessionToken(String(raw || "").trim())
    if (handed) {
      cancelAuthPrewarm()
      abandonAuthSecrets()
      // Consumed: close the window.
      terminalLoginStartedAt = 0
      session = handed
      vaultEpoch += 1
      storeCurrentSession()

      // bw just minted this key: trust it and load now; `bw status` runs
      // alongside, only for the account email.
      status = "unlocked"
      currentScreen = "main"
      itemsLoadedAt = 0
      statusRefreshAfterItems = true
      beginInitialVaultLoad(true, false)
      resetAutoLockTimer()
      focusAppropriateField()
      flashNotification("Signed in from the terminal")
      return
    }

    if (status === "locked" && !session) return

    if (session) {
      runStatusCheck()
    } else if (rememberSession && status !== "locked") {
      if (keyringLookupProc.running) {
        statusRefreshPending = true
        return
      }
      beginEpochOperation("keyringLookup")
      keyringLookupProc.command = Model.keyringLookupCommand(activeSlot)
      keyringLookupProc.running = true
    } else {
      runStatusCheck()
    }
  }

  function onKeyringLookupFinished(rawToken) {
    if (epochOperationIsStale("keyringLookup")) {
      restartStaleStatusProbe()
      return
    }
    var token = String(rawToken || "").trim()
    if (token) {
      session = token
      vaultEpoch += 1
    }
    runStatusCheck()
    // A remembered session is usually still good, so read the list alongside
    // `bw status` rather than after it: two bw starts overlap instead of
    // queueing (~3 s each). Nothing shows, and the SSH agent does not load,
    // until the status confirms; a locked answer drops the read's epoch.
    if (token) beginInitialVaultLoad(false, false)
  }

  function runStatusCheck(authoritative) {
    if (statusProc.running) {
      // A probe for another account (or a locked vault), or a lock's scrub,
      // is still exiting: run once it has.
      if (epochOperationIsStale("status") || Model.isScrubCommand(statusProc.command)) statusCheckQueued = true
      return
    }
    statusCheckAuthoritative = authoritative !== false
    beginEpochOperation("status")
    statusProc.command = Model.statusCommand()
    statusProc.running = true
  }

  // An authentication the user has actually submitted, still running.
  function authAttemptInFlight() {
    return loginSubmitted || unlockSubmitted
  }

  function onStatusFinished(rawJson) {
    if (epochOperationIsStale("status")) {
      restartStaleStatusProbe()
      return
    }
    // A slow `bw status` landing mid-login reports "unauthenticated" as of when
    // it started; acting on it would cancel the submitted login. The attempt
    // will set the state itself.
    if (authAttemptInFlight()) {
      return
    }
    isLoading = false
    var authoritative = statusCheckAuthoritative
    statusCheckAuthoritative = true
    var st = Model.parseStatus(rawJson)
    if (st && st.userId) {
      accountId = st.userId
      accountServer = st.serverUrl
      noteActiveAccount(st)
      Qt.callLater(maybeMigrateLegacyFingerprint)
    }
    if (!authoritative) {
      if (st && st.userEmail) {
        userEmail = st.userEmail
        if (!loginEmail) loginEmail = st.userEmail
      }
      return
    }
    if (!st) {
      cancelAuthPrewarm()
      if (vaultStatePresent()) {
        if (session) requestSessionCredentialClear()
        dropVaultState()
      }
      status = "unauthenticated"
      currentScreen = "login"
      focusAppropriateField()
      return
    }

    userEmail = st.userEmail
    if (st.userEmail && !loginEmail) {
      loginEmail = st.userEmail
    }

    if (st.unlocked) {
      cancelAuthPrewarm()
      // Unlocked elsewhere: stop waiting on a finger or key touch.
      cancelFingerprintUnlock()
      cancelFidoUnlock()
      abandonAuthSecrets()
      status = "unlocked"
      currentScreen = "main"
      ensureItemsFresh()
      // Held back while an early list read ran on an unconfirmed session.
      loadPendingMetadata()
      resetAutoLockTimer()
      focusAppropriateField()
      // No lastSync means an empty local vault: `bw login` swallows a failed
      // sync and still prints a session. Repair it once and reload.
      if (!st.lastSync && session && !initialSyncAttempted && !isSyncing) {
        initialSyncAttempted = true
        syncVault()
      }
    } else if (st.locked) {
      if (vaultStatePresent()) {
        if (session) requestSessionCredentialClear()
        dropVaultState()
      }
      status = "locked"
      currentScreen = "locked"
      focusAppropriateField()
      if (sshAuthSurfaceActive) prepareUnlock()
      if (sshAuthSurfaceActive) armPresenceUnlock()
    } else {
      cancelAuthPrewarm()
      if (vaultStatePresent()) {
        if (session) requestSessionCredentialClear()
        dropVaultState()
      }
      status = "unauthenticated"
      currentScreen = "login"
      focusAppropriateField()
    }
  }

  // -------------------------------------------------------------------------
  // Login and authentication
  // -------------------------------------------------------------------------

  function emailLoginSignature() {
    return String(loginEmail || "").trim() + "\n"
      + resolvedLoginServerUrl() + "\n"
      + (String(login2faCode || "").trim() ? "2fa" : "plain") + "\n"
      + String(login2faMethod)
  }

  function resolvedLoginServerUrl() {
    return Model.loginServerUrlFor(loginServerRegion, loginServerUrl)
  }

  function selectLoginServerRegion(region) {
    if (loginServerRegion === region) return
    loginServerRegion = region
    errorMessage = ""
    resetEmailLoginSecondFactor()
    invalidateEmailLoginPrewarm()
  }

  function invalidateEmailLoginPrewarm() {
    if (loginSubmitted) return
    if (loginSubmitAfterPrewarmStop) isLoading = false
    loginSubmitAfterPrewarmStop = false
    loginPrepareAfterPrewarmStop = false
    loginPrewarmSignature = ""
    if (loginProc.running) loginProc.running = false
  }

  function resetEmailLoginSecondFactor() {
    show2faField = false
    login2faCode = ""
    loginDeviceVerification = false
    show2faMethodPicker = false
    login2faMethodConfirmed = false
    showDeviceCodeField = false
    loginDeviceCode = ""
    // Back to the remembered method.
    login2faMethod = rememberedTwoFactorMethod
    syncLoginFieldsToState()
  }

  // The user's answer to bw's method question. Sent first without a code, so
  // bw mails one (Email), proceeds (Authenticator, YubiKey), or refuses; a
  // wrong pick costs nothing typed.
  function chooseTwoFactorMethod(method) {
    if (!Model.isTwoFactorMethod(method)) return
    errorMessage = ""
    login2faMethod = method
    login2faMethodConfirmed = true
    show2faMethodPicker = false
    show2faField = false
    login2faCode = ""
    submitLogin()
  }

  // Answers bw's new-device prompt (no flag can): the code goes in the env,
  // the password down the FIFO, and bw runs with prompts on for this call.
  function submitDeviceVerification() {
    if (loginSubmitted) return
    var code = String(loginDeviceCode || "").trim()
    if (!code) {
      errorMessage = "Enter the code Bitwarden emailed you."
      Qt.callLater(function() { presenter.focusField("deviceCode") })
      return
    }
    if (!String(loginPassword || "")) {
      errorMessage = "Your master password is needed again for this step."
      resetEmailLoginSecondFactor()
      Qt.callLater(function() { presenter.focusField("loginPass") })
      return
    }
    errorMessage = ""
    isLoading = true
    // A prewarmed ordinary login cannot answer this; restart when it exits.
    if (loginProc.running) {
      deviceVerificationPending = true
      loginSubmitAfterPrewarmStop = false
      loginPrepareAfterPrewarmStop = false
      loginProc.running = false
      return
    }
    startDeviceVerificationLogin()
  }

  function startDeviceVerificationLogin() {
    deviceVerificationPending = false
    loginPrewarmSignature = ""
    loginAttemptHadCode = false
    loginAttemptMethod = login2faMethod
    // Before starting: the env binding and exit handler read it.
    deviceVerificationAttempt = true
    loginProc.command = Model.deviceVerificationLoginCommand(
      String(loginEmail || "").trim(), resolvedLoginServerUrl(), login2faMethod)
    loginProc.running = true
    loginSubmitted = true
    writeAuthPassword("login", loginPassword)
  }

  // A login waiting on an emailed challenge survives a close, within its
  // window and while the password is still held.
  function pendingSecondFactorLogin() {
    if (status !== "unauthenticated" || loginMethod !== "email") return false
    if (!show2faField && !showDeviceCodeField && !show2faMethodPicker) return false
    if (!String(loginPassword || "")) return false
    return Model.secondFactorWindowOpen(secondFactorStartedAt, Date.now())
  }

  // Re-point every view's login fields at the state (see syncLoginFields()).
  function syncLoginFieldsToState() {
    eachView(function(view) { view.syncSensitiveFields() })
  }

  // Closing on a challenge keeps the stage and password but drops the
  // half-typed code.
  function suspendPendingLogin() {
    login2faCode = ""
    loginDeviceCode = ""
    loginSubmitted = false
    isLoading = false
    syncLoginFieldsToState()
  }

  // What a stopped login owes its stopper. `mayScrub` is false when the run
  // that ended was itself a scrub.
  function resumeDeferredLogin(mayScrub) {
    if (deviceVerificationPending) {
      deviceVerificationPending = false
      Qt.callLater(startDeviceVerificationLogin)
    } else if (loginSubmitAfterPrewarmStop) {
      loginSubmitAfterPrewarmStop = false
      Qt.callLater(submitLogin)
    } else if (loginPrepareAfterPrewarmStop) {
      loginPrepareAfterPrewarmStop = false
      Qt.callLater(prepareEmailLogin)
    } else if (mayScrub) {
      clearProcessCollectorSoon(loginProc)
    }
  }

  function markSecondFactorStage() {
    secondFactorStartedAt = Date.now()
  }

  function reopenTwoFactorMethodPicker() {
    errorMessage = ""
    show2faField = false
    login2faCode = ""
    show2faMethodPicker = true
    markSecondFactorStage()
  }

  function emailLoginButtonText() {
    if (logoutCleanupFailed) return "Retry Logout Cleanup"
    if (logoutPending) return "Finishing logout..."
    if (isLoading) return show2faField ? "Verifying..." : "Logging in..."
    return show2faField ? "Verify & Unlock" : "Log In & Unlock"
  }

  function prepareEmailLogin() {
    if (logoutPending || !opened || status !== "unauthenticated" || loginMethod !== "email" || isLoading) return
    var email = String(loginEmail || "").trim()
    var serverUrl = resolvedLoginServerUrl()
    if (!email || Model.validateServerUrl(serverUrl)) return
    // `bw config server` changes bw's global state: only on explicit submit,
    // never on field focus.
    if (serverUrl) return

    var signature = emailLoginSignature()
    if (loginProc.running) {
      if (loginPrewarmSignature === signature) return
      loginPrepareAfterPrewarmStop = true
      loginProc.running = false
      return
    }

    loginPrepareAfterPrewarmStop = false
    loginPrewarmSignature = signature
    loginSubmitted = false
    deviceVerificationAttempt = false
    loginAttemptHadCode = String(login2faCode || "").trim().length > 0
    loginAttemptMethod = login2faMethod
    loginProc.command = Model.emailLoginPrewarmCommand(
      email, loginAttemptHadCode, serverUrl, login2faMethod)
    loginProc.running = true
  }

  function prepareUnlock() {
    if (!sshAuthSurfaceActive || status !== "locked" || unlockProc.running) return
    unlockSubmitted = false
    unlockProc.command = Model.unlockPrewarmCommand()
    unlockProc.running = true
  }

  function cancelAuthPrewarm() {
    authPasswordWriteTarget = ""
    authPasswordWriteValue = ""
    unlockSubmitted = false
    loginSubmitted = false
    loginSubmitAfterPrewarmStop = false
    loginPrepareAfterPrewarmStop = false
    loginPrewarmSignature = ""
    if (authPasswordWriterProc.running) authPasswordWriterProc.running = false
    if (unlockProc.running) unlockProc.running = false
    if (loginProc.running) loginProc.running = false
  }

  // Login credentials and challenge state, back to the first stage.
  function clearLoginAttempt() {
    loginPassword = ""
    loginClientId = ""
    loginClientSecret = ""
    login2faCode = ""
    show2faField = false
    loginDeviceVerification = false
    loginAttemptHadCode = false
    show2faMethodPicker = false
    login2faMethodConfirmed = false
    login2faMethod = rememberedTwoFactorMethod
    loginAttemptMethod = -1
    showDeviceCodeField = false
    loginDeviceCode = ""
    deviceVerificationAttempt = false
    deviceVerificationPending = false
    secondFactorStartedAt = 0
    loginPasswordRetryUsed = false
  }

  function abandonAuthSecrets() {
    masterPassword = ""
    clearLoginAttempt()
    pendingUnlockPassword = ""
    pendingUnlockFrom = ""
    authPasswordWriteValue = ""
    pinEntry = ""
    pinUnlockSubmitted = false
    fingerprintAuthorized = false
    syncLoginFieldsToState()
  }

  function writeAuthPassword(channel, password) {
    authPasswordWriteTarget = channel
    authPasswordWriteValue = String(password === undefined || password === null ? "" : password)
    authPasswordWriterProc.command = Model.authPasswordWriteCommand(channel)
    authPasswordWriterProc.running = true
  }

  function onAuthPasswordWriterExited(exitCode) {
    var target = authPasswordWriteTarget
    authPasswordWriteTarget = ""
    authPasswordWriteValue = ""
    if (exitCode === 0) {
      loginPasswordRetryUsed = false
      return
    }
    if (!target) return

    if (target === "unlock") {
      unlockSubmitted = false
      isUnlocking = false
      pendingUnlockPassword = ""
      if (unlockProc.running) unlockProc.running = false
      errorMessage = "Could not deliver the password to Bitwarden. Please try again."
      Qt.callLater(prepareUnlock)
    } else if (target === "login") {
      loginSubmitted = false
      isLoading = false
      if (loginProc.running) loginProc.running = false
      // The writer gives up if bw has not opened the FIFO in time, which a cold
      // start can outrun. Retry once, like unlock does.
      if (!loginPasswordRetryUsed) {
        loginPasswordRetryUsed = true
        var retryDevice = deviceVerificationAttempt
        deviceVerificationAttempt = false
        Qt.callLater(retryDevice ? submitDeviceVerification : submitLogin)
        return
      }
      errorMessage = "Could not deliver the password to Bitwarden. Please try again."
    }
  }

  function submitLogin() {
    if (loginSubmitted) return
    errorMessage = ""
    if (logoutPending) {
      errorMessage = "Finishing logout. Please wait a moment."
      return
    }

    // Validated first: both branches send the master password here.
    var serverUrl = resolvedLoginServerUrl()
    var serverProblem = Model.validateServerUrl(serverUrl)
    if (serverProblem) {
      errorMessage = serverProblem
      return
    }

    if (loginMethod === "email") {
      var email = String(loginEmail || "").trim()
      var pass = String(loginPassword === undefined || loginPassword === null ? "" : loginPassword)
      if (!email) {
        errorMessage = "Email address is required"
        return
      }
      if (!pass) {
        errorMessage = "Master password is required"
        return
      }
      if (show2faMethodPicker) {
        errorMessage = "Choose a two-step method to continue."
        return
      }
      if (show2faField && !String(login2faCode || "").trim()) {
        errorMessage = "Two-step verification code is required"
        Qt.callLater(function() { presenter.focusField("code2fa") })
        return
      }

      isLoading = true
      deviceVerificationAttempt = false
      var signature = emailLoginSignature()
      if (loginProc.running && loginPrewarmSignature !== signature) {
        loginPrepareAfterPrewarmStop = false
        loginSubmitAfterPrewarmStop = true
        loginProc.running = false
        return
      }
      if (!loginProc.running) {
        loginPrewarmSignature = signature
        loginAttemptHadCode = login2faCode.trim().length > 0
        loginAttemptMethod = login2faMethod
        loginProc.command = Model.emailLoginPrewarmCommand(
          email, loginAttemptHadCode, serverUrl, login2faMethod)
        loginProc.running = true
      }
      loginSubmitted = true
      writeAuthPassword("login", pass)
    } else {
      var id = String(loginClientId || "").trim()
      var secret = String(loginClientSecret || "").trim()
      var pass2 = String(loginPassword === undefined || loginPassword === null ? "" : loginPassword)

      if (!id) {
        errorMessage = "API Client ID is required"
        return
      }
      if (!secret) {
        errorMessage = "API Client Secret is required"
        return
      }
      if (!pass2) {
        errorMessage = "Master password is required to unlock vault"
        return
      }

      isLoading = true
      if (loginProc.running) {
        loginPrepareAfterPrewarmStop = false
        loginSubmitAfterPrewarmStop = true
        loginProc.running = false
        return
      }
      // Client ID, client secret and password all travel in the environment.
      loginSubmitted = true
      loginPrewarmSignature = ""
      loginAttemptHadCode = false
      loginAttemptMethod = -1
      loginProc.command = Model.apiKeyLoginCommand(serverUrl)
      loginProc.running = true
    }
  }

  // Logs which branch each login exit took (`quickshell log -f | grep qs-bitwarden`).
  function logLogin(branch, out, err, exitCode) {
    console.log("qs-bitwarden login " + Model.loginDiagnostic(out, err, exitCode, branch))
  }

  function onLoginOutput(stdoutText, stderrText, exitCode) {
    isLoading = false
    loginPrewarmSignature = ""
    var out = String(stdoutText || "").trim()
    var err = String(stderrText || "").trim()
    var wasDeviceAttempt = deviceVerificationAttempt
    deviceVerificationAttempt = false

    // An interactive login's output is a prompt session; the detectors below
    // must not read it.
    if (wasDeviceAttempt && !(exitCode === 0 && out.length > 10)) {
      var detail = Model.sanitizeInteractiveStderr(err, loginDeviceCode)
      loginDeviceCode = ""
      loginDeviceVerification = true
      // A timeout (124) or inquirer out of input: bw wanted something only a
      // terminal can give.
      if (exitCode === 124 || Model.loginPromptRanOutOfInput(out, err)) {
        showDeviceCodeField = false
        logLogin("device-unanswerable", out, err, exitCode)
        errorMessage = "This login asked for something the panel could not answer. "
          + "Finish it in a terminal instead."
        return
      }
      logLogin("device-code-rejected", out, err, exitCode)
      showDeviceCodeField = true
      markSecondFactorStage()
      errorMessage = detail
        ? "Device verification failed: " + detail
        : "That verification code was not accepted. Use the newest email and try again."
      Qt.callLater(function() { presenter.focusField("deviceCode") })
      return
    }

    // Before the second-factor check, which matches the same sentence: a code
    // was sent and still "required" means new-device verification, which only
    // the terminal login can answer.
    if (Model.loginNeedsDeviceVerification(out, err, loginAttemptHadCode)) {
      resetEmailLoginSecondFactor()
      loginDeviceVerification = true
      showDeviceCodeField = true
      markSecondFactorStage()
      errorMessage = "Bitwarden needs to verify this device. Enter the code it emailed you."
      logLogin("device-verification", out, err, exitCode)
      Qt.callLater(function() { presenter.focusField("deviceCode") })
      return
    }

    // The account's two-step methods are all ones the CLI cannot do.
    if (Model.loginHasNoUsableProvider(out, err)) {
      resetEmailLoginSecondFactor()
      logLogin("no-usable-provider", out, err, exitCode)
      errorMessage = "This account's two-step method is one the Bitwarden CLI cannot use, "
        + "such as a passkey or Duo. Log in with an API key instead."
      return
    }

    // bw asks which two-step method to use; ask the user rather than guess.
    if (Model.loginNeedsMethodChoice(out, err)) {
      // A remembered (unconfirmed) method is the likeliest culprit: drop it
      // and retry untargeted. Only ever set -> unset, so no loop.
      if (Model.isTwoFactorMethod(loginAttemptMethod) && !login2faMethodConfirmed) {
        forgetTwoFactorMethod()
        login2faMethod = -1
        loginAttemptMethod = -1
        logLogin("method-stale-retry", out, err, exitCode)
        Qt.callLater(submitLogin)
        return
      }
      var rejectedMethod = login2faMethodConfirmed
        ? Model.twoFactorMethodLabel(loginAttemptMethod) : ""
      show2faField = false
      login2faCode = ""
      login2faMethod = -1
      login2faMethodConfirmed = false
      show2faMethodPicker = true
      markSecondFactorStage()
      errorMessage = rejectedMethod
        ? "Bitwarden does not have " + rejectedMethod + " set up for this account. "
          + "Choose another method."
        : "This account has more than one two-step method. Choose the one you use."
        logLogin("method-choice", out, err, exitCode)
      return
    }

    if (Model.loginNeedsSecondFactor(out, err)) {
      // Never send a code without its --method: without one bw sends a bare
      // password grant, and for Email the server issues a new code that
      // invalidates the typed one (seen with bw 2026.2.0). So ask for the
      // method once per account before collecting a code.
      if (!Model.isTwoFactorMethod(login2faMethod)) {
        show2faField = false
        login2faCode = ""
        show2faMethodPicker = true
        markSecondFactorStage()
        syncLoginFieldsToState()
        errorMessage = "Two-step verification is required. Choose the method this account uses."
        logLogin("second-factor-needs-method", out, err, exitCode)
        return
      }
      var secondFactorWasVisible = show2faField
      show2faMethodPicker = false
      show2faField = true
      markSecondFactorStage()
      logLogin("second-factor", out, err, exitCode)
      errorMessage = secondFactorWasVisible
        ? "That two-step verification code was not accepted. Please try again."
        : "Two-step verification is required. Enter your code to continue."
      Qt.callLater(function() { presenter.focusField("code2fa") })
      return
    }

    if (exitCode === 0 && out.length > 10) {
      rememberTwoFactorMethod(login2faMethod)
      // Typed and accepted by `bw`: the stored password for a fresh login
      // (storeAcceptedMasterPassword()).
      pendingUnlockPassword = String(loginPassword || "")
      pendingUnlockFrom = ""
      loginPassword = ""
      login2faCode = ""
      logLogin("success", out, err, exitCode)
      onUnlockSuccess(out)
      return
    }

    if (err) {
      logLogin("bw-error", out, err, exitCode)
      errorMessage = Model.sanitizeInteractiveStderr(err, "") || "Login failed. Please check your credentials."
    } else if (exitCode !== 0) {
      logLogin("failed-no-stderr", out, err, exitCode)
      errorMessage = "Login failed. Please check your credentials."
    } else {
      // A clean exit with no output: say so rather than fail silently later.
      logLogin("clean-exit-no-session", out, err, exitCode)
      errorMessage = "Bitwarden reported no error but returned no session. "
        + "Please try again, or use the terminal login."
    }
  }

  function launchTerminalLogin() {
    if (logoutPending) {
      errorMessage = "Finishing logout. Please wait a moment."
      return
    }
    // The panel knows login vs unlock, sparing the terminal a `bw status`.
    var mode = (status === "locked") ? "unlock" : "login"
    var serverUrl = mode === "login" ? resolvedLoginServerUrl() : ""
    var serverProblem = Model.validateServerUrl(serverUrl)
    if (serverProblem) {
      errorMessage = serverProblem
      return
    }
    close()
    // Opens the window in which a handed-over session key is accepted. See
    // refreshStatus().
    terminalLoginStartedAt = Date.now()
    Quickshell.execDetached(Model.terminalLoginCommand(mode, serverUrl, activeSlot))
  }

  // Signs the active account out and forgets it; other accounts keep their
  // sign-ins and quick-unlock methods.
  function logoutAccount() {
    if (logoutPending) return
    addingAccount = false
    slotBeforeAdd = ""
    logoutPending = true
    logoutCliDone = false
    logoutCredentialsDone = false
    logoutExitCode = 0
    logoutCredentialsExitCode = 0
    terminalLoginStartedAt = 0
    lockVault()
    // Logout also drops the public projection, so a new account inherits none.
    applySshAgentLifecycle("logout")
    forgetStoredCredentials()
    pendingUnlockPassword = ""
    logoutProc.command = Model.logoutCommand()
    logoutProc.running = true
    status = "unauthenticated"
    currentScreen = "login"
    userEmail = ""
  }

  function onLogoutCliFinished(exitCode) {
    if (!logoutPending) return
    logoutExitCode = exitCode
    logoutCliDone = true
    finishLogoutIfReady()
  }

  function onLogoutCredentialsFinished(exitCode) {
    if (!logoutPending) return
    logoutCredentialsExitCode = exitCode
    logoutCredentialsDone = true
    finishLogoutIfReady()
  }

  function finishLogoutIfReady() {
    if (!logoutPending || !logoutCliDone || !logoutCredentialsDone) return
    if (logoutCredentialsExitCode !== 0) {
      errorMessage = "Could not clear stored credentials. Retry logout cleanup before signing in."
      return
    }
    logoutPending = false
    status = "unauthenticated"
    currentScreen = "login"
    var email = String(Model.registryAccount(accountRegistry, activeSlot)
      ? Model.registryAccount(accountRegistry, activeSlot).email : "")
    var movedOn = moveOffRemovedAccount(activeSlot)
    if (logoutExitCode === 0) flashNotification(movedOn && email ? "Logged out of " + email : "Logged out")
    else errorMessage = "Bitwarden logout did not complete cleanly. Please try again."
    focusAppropriateField()
  }

  function retryLogoutCleanup() {
    if (!logoutCleanupFailed) return
    errorMessage = ""
    logoutCredentialsDone = false
    logoutCredentialsExitCode = 0
    requestAllCredentialClear()
  }

  function storeCurrentSession() {
    if (logoutPending) {
      sessionStorePending = false
      return
    }
    if (!rememberSession || !session) {
      sessionStorePending = false
      return
    }
    if (keyringStoreProc.running || keyringClearProc.running) {
      sessionStorePending = true
      return
    }
    sessionStorePending = false
    beginEpochOperation("sessionStore")
    sessionStoreSlot = activeSlot
    keyringStoreProc.command = Model.keyringStoreCommand(activeSlot)
    keyringStoreProc.running = true
  }

  function onSessionStored(exitCode) {
    if (epochOperationIsStale("sessionStore") || status !== "unlocked" || !session) {
      sessionStorePending = rememberSession && status === "unlocked" && !!session
      // The account it was written for, which may no longer be active.
      requestSessionCredentialClear(sessionStoreSlot)
      return
    }
    sessionStorePending = false
    if (exitCode !== 0) {
      console.warn("qs-bitwarden-cli: could not store session in keyring (exit " + exitCode + ")")
    }
  }

  // Runs the next clear or store that waited behind the keyring processes.
  function pumpSessionKeyring() {
    if (keyringClearProc.running || keyringStoreProc.running) return
    if (sessionClearSlots.length > 0) {
      var waiting = sessionClearSlots.slice()
      var next = waiting.shift()
      sessionClearSlots = waiting
      requestSessionCredentialClear(next)
      return
    }
    if (sessionStorePending) storeCurrentSession()
  }

  // `slot` defaults to the active account's.
  function requestSessionCredentialClear(slot) {
    var target = Model.isAccountSlot(slot) ? slot : activeSlot
    if (keyringClearProc.running) {
      if (sessionClearSlots.indexOf(target) === -1) sessionClearSlots = sessionClearSlots.concat([target])
      sessionClearPending = true
      return
    }
    sessionClearPending = false
    keyringClearProc.command = Model.keyringClearCommand(target)
    keyringClearProc.running = true
  }

  function requestPinCredentialClear() {
    if (keyringClearPinProc.running) {
      pinClearPending = true
      return
    }
    pinClearPending = false
    keyringClearPinProc.running = true
  }

  function requestMasterCredentialClear() {
    if (keyringClearMasterProc.running) {
      masterClearPending = true
      return
    }
    masterClearPending = false
    keyringClearMasterProc.running = true
  }

  function credentialStoresRunning() {
    return keyringStoreProc.running || envelopeProc.running
  }

  function requestAllCredentialClear() {
    if (keyringClearAllProc.running) {
      allCredentialsClearPending = true
      return
    }
    // A store still running could recreate the credential after this clear;
    // logout waits for every writer, then sweeps. A writer's exit handler
    // asks again, but the Process can still read as running then, so a
    // timer keeps asking until it does not.
    if (credentialStoresRunning()) {
      allCredentialsClearPending = true
      credentialClearRetry.restart()
      return
    }
    allCredentialsClearPending = false
    keyringClearAllProc.running = true
  }

  // Logout clears every keyring entry the plugin writes, unconditionally:
  // flags like fingerprintStored reflect settings, not the keyring (see
  // keyringClearAllCommand()).
  function forgetStoredCredentials() {
    dropEnvelopeState()
    requestAllCredentialClear()
    // Learned suggestions are this account's data too (a plain file).
    associationsEpoch += 1
    pendingAssociationsJson = ""
    associationsWritePending = false
    if (associationsWriteProc.running) {
      associationsClearPending = true
      associationsWriteProc.running = false
    } else {
      associationsClearPending = false
      associationsClearProc.running = true
    }
    associations = Model.emptyAssociations()
    suggestedItems = []
    detectedContext = null
    activeWindowData = null
    cancelFingerprintUnlock()
    fingerprintStored = false
    fingerprintMessage = ""
    fingerprintError = ""
    fidoUnlocker.reset()
    pinConfigured = false
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
    pinUnlockError = ""
    if (pinUnlock && !otherAccountsExist()) writeSetting("pinUnlock", false, "bool")
  }

  // The quick-unlock settings are shared by every account; each account's own
  // envelope says which it has. Only a sole account turns a setting off.
  function otherAccountsExist() {
    for (var i = 0; i < accountRegistry.accounts.length; i++) {
      if (accountRegistry.accounts[i].slot !== activeSlot) return true
    }
    return false
  }

  // Process environments
  // -------------------------------------------------------------------------

  // Secrets reach processes in the environment, never argv
  // (keyringStoreScript()).
  function associationsEnv() {
    var env = {}
    env[Model.associationsEnvVar()] = String(pendingAssociationsJson || "")
    return env
  }

  // BW_SESSION rather than --session keeps the token out of argv. Every `bw`
  // runs in the active account's data directory (accountAppDataEnv()).
  // Read once: the shell's own NODE_OPTIONS plus the early-exit preload.
  readonly property string bwNodeOptions: Model.bwNodeOptions(sshAgentPluginDir, Quickshell.env("NODE_OPTIONS"))

  function bwEnv(extra) {
    var env = accountAppDataEnv()
    if (session) env[Model.sessionEnvVar()] = String(session)
    if (bwNodeOptions) env.NODE_OPTIONS = bwNodeOptions
    if (extra) for (var k in extra) env[k] = extra[k]
    return env
  }

  // Credentials in the environment, never argv: BW_PASSWORD (read from the
  // FIFO by password flows), BW_CLIENTID and BW_CLIENTSECRET for API login.
  // Read as a binding by loginProc and unlockProc.
  function authEnv(password, clientId, clientSecret, code) {
    var env = bwEnv()
    env[Model.noInteractionEnvVar()] = "true"
    if (password) env[Model.passwordEnvVar()] = String(password)
    if (clientId) env[Model.clientIdEnvVar()] = String(clientId)
    if (clientSecret) env[Model.clientSecretEnvVar()] = String(clientSecret)
    // No env option exists for this; see TWOFACTOR_CODE_ENV.
    if (code) env[Model.twoFactorCodeEnvVar()] = String(code)
    return env
  }

  function loginProcessEnv() {
    if (loginMethod === "apikey") {
      // A live Process binding: only carry the API fields once a login starts.
      if (!loginSubmitted) return authEnv("", "", "", "")
      return authEnv(loginPassword,
                     String(loginClientId || "").trim(),
                     String(loginClientSecret || "").trim(),
                     String(login2faCode || "").trim())
    }
    // The one login allowed to prompt: BW_NOINTERACTION omitted (so not
    // authEnv()), and the code set for the command's printf.
    if (deviceVerificationAttempt) {
      var deviceEnv = bwEnv()
      deviceEnv[Model.deviceCodeEnvVar()] = String(loginDeviceCode || "").trim()
      return deviceEnv
    }
    // The password arrives via the FIFO writer, not this long-lived process.
    return authEnv("", "", "", String(login2faCode || "").trim())
  }

  function itemEnv() {
    var e = {}
    e[Model.itemEnvVar()] = String(itemPayloadJson || "")
    return bwEnv(e)
  }

  function folderEnv() {
    var e = {}
    e[Model.folderEnvVar()] = Model.folderPayload(newFolderName)
    return bwEnv(e)
  }

  function sendEnv(json) {
    var e = {}
    e[Model.sendEnvVar()] = String(json || "")
    return bwEnv(e)
  }

  function pinEnv(pin) {
    var env = {}
    env[Model.pinEnvVar()] = String(pin || "")
    return env
  }

  function secretEnv(value) {
    var env = {}
    env[Model.keyringSecretEnvVar()] = String(value || "")
    return env
  }

  // -------------------------------------------------------------------------
  // Bitwarden Send
  // -------------------------------------------------------------------------

  function openSends() {
    closeFilterGroup()
    sendMode = "list"
    sendError = ""
    sendIndex = 0
    currentScreen = "sends"
    loadSends()
  }

  function loadSends() {
    if (!session) return
    sendsLoading = true
    beginVaultRead("sends")
    listSendsProc.command = Model.listSendsCommand()
    listSendsProc.running = true
  }

  function onSendsLoaded(raw) {
    sendsLoading = false
    if (vaultReadIsStale("sends")) return
    sends = Model.parseSends(raw)
    if (sendIndex >= sends.length) sendIndex = Math.max(0, sends.length - 1)
  }

  function beginCreateSend() {
    sendFormName = ""
    sendFormText = ""
    sendFormHidden = false
    sendFormDays = 7
    sendFormMaxAccess = 0
    sendFormPassword = ""
    sendError = ""
    sendMode = "create"
    Qt.callLater(function() { presenter.focusField("sendName") })
  }

  function submitCreateSend() {
    if (!String(sendFormText || "").trim()) {
      sendError = "Nothing to send -- enter some text"
      return
    }
    sendError = ""
    sendBusy = true
    sendPayloadJson = JSON.stringify(Model.buildSendPayload(
      sendFormName, sendFormText, sendFormHidden,
      sendFormDays, sendFormMaxAccess, sendFormPassword, ""))
    beginVaultRead("sendCreate")
    createSendProc.command = Model.createSendCommand()
    createSendProc.running = true
  }

  function onSendCreated(exitCode, stdoutText, stderrText) {
    sendBusy = false
    sendPayloadJson = ""
    if (vaultReadIsStale("sendCreate")) return
    if (exitCode !== 0) {
      sendError = String(stderrText || "").trim() || "Could not create the Send"
      return
    }
    // Copy the new Send's link straight away.
    var created = null
    try { created = JSON.parse(stdoutText) } catch (e) { created = null }
    var url = created && created.accessUrl ? String(created.accessUrl) : String(stdoutText || "").trim()
    if (url) {
      copyToClipboard(url, "Send link")
    } else {
      flashNotification("Send created")
    }
    sendFormText = ""
    sendFormPassword = ""
    sendMode = "list"
    loadSends()
  }

  function copySendLink(send) {
    if (!send || !send.accessUrl) return
    copyToClipboard(send.accessUrl, "Send link")
  }

  function deleteSend(send) {
    if (!send || !send.id) return
    sendBusy = true
    beginVaultRead("sendDelete")
    deleteSendProc.command = Model.deleteSendCommand(send.id)
    deleteSendProc.running = true
  }

  function onSendDeleted(exitCode) {
    sendBusy = false
    if (vaultReadIsStale("sendDelete")) return
    if (exitCode !== 0) {
      sendError = "Could not delete the Send"
      return
    }
    flashNotification("Send deleted")
    loadSends()
  }

  function moveSendCursor(delta) {
    if (sends.length === 0) return
    sendIndex = Math.max(0, Math.min(sends.length - 1, sendIndex + delta))
  }

  // -------------------------------------------------------------------------
  // Generator
  // -------------------------------------------------------------------------

  // From the header on any screen, or from the item form's Generate button
  // (which wants the value back).
  function openGenerator() {
    closeFilterGroup()
    generatorReturnScreen = (currentScreen === "edit") ? "edit" : "main"
    screenBeforeSettings = "main"
    currentScreen = "generator"
    // The form wants a fresh value; a standalone visit keeps the last one.
    if (generatorFeedsForm || !genValue) regenerate()
  }

  function closeGenerator() {
    var toForm = generatorFeedsForm
    currentScreen = generatorReturnScreen
    generatorReturnScreen = "main"
    // Land back on the field the trip was about, filled in or not.
    if (toForm) Qt.callLater(function() { presenter.focusField("formPass") })
  }

  // Put the value in the caller's field and return to it.
  function useGeneratedPassword() {
    if (!generatorFeedsForm || genBusy || !genValue) return
    formPassword = genValue
    // Shown, since it goes into a form still being filled in.
    formPasswordRevealed = true
    closeGenerator()
    flashNotification("Generated password filled in")
  }

  // `bw serve` (~2 ms per request) is started on first use; `bw generate`
  // (~2.9 s) is the fallback.
  function generatorOptionsSignature() {
    return JSON.stringify(Model.normalizeGeneratorOptions(genOpts))
  }

  function regenerate() {
    if (generateCliStopping) {
      genBusy = true
      genRegeneratePending = true
      return
    }
    if (genBusy) {
      genRegeneratePending = true
      return
    }
    genBusy = true
    genRegeneratePending = false
    genRequestSignature = generatorOptionsSignature()
    beginVaultRead("generator")
    if (generateServeReady) {
      requestGeneratedValue()
      return
    }
    startGeneratorServe()
    // A starting server will drive the request itself.
    if (!generateServeStarting) regenerateViaCli()
  }

  function regenerateViaCli() {
    genBusy = true
    genRegeneratePending = false
    genRequestSignature = generatorOptionsSignature()
    generateProc.command = Model.generateCommand(genOpts)
    generateProc.running = true
  }

  // No session in its environment, so it can only generate.
  function generatorServeEnv() {
    var env = accountAppDataEnv()
    env[Model.sessionEnvVar()] = null
    env[Model.noInteractionEnvVar()] = "true"
    return env
  }

  // A 200 does not prove the answer is ours: another account could bind the
  // port first and serve known passwords. So the port must be silent before
  // our server takes it; otherwise the CLI is used.
  function startGeneratorServe() {
    if (generateServeReady || generateServeStarting || generateServeFailed) return
    generateServeStarting = true
    probeGeneratorPort()
  }

  // Generator requests go through a capped curl child, not XMLHttpRequest
  // (which buffers unbounded responses in the shell). `done(exitCode, stdout,
  // stderr)`.
  property var generateServeRequestCallback: null

  function generatorRequest(opts, done) {
    if (generateServeRequestStopping || generateServeRequestProc.running) {
      generateServeRequestPending = true
      generateServeRequestPendingOptions = opts
      generateServeRequestPendingCallback = done
      return
    }
    generateServeRequestCallback = done
    generateServeRequestProc.command = Model.generateServeRequestCommand(opts)
    generateServeRequestProc.running = true
  }

  function resumePendingGeneratorRequest() {
    if (!generateServeRequestPending) return false
    var pendingOptions = generateServeRequestPendingOptions
    var pendingCallback = generateServeRequestPendingCallback
    generateServeRequestPending = false
    generateServeRequestPendingOptions = null
    generateServeRequestPendingCallback = null
    Qt.callLater(function() {
      if (root.opened && root.currentScreen === "generator")
        root.generatorRequest(pendingOptions, pendingCallback)
    })
    return true
  }

  function probeGeneratorPort() {
    generatorRequest(null, function(exitCode, stdout, stderr) {
      if (Model.generatorProbeIsForeign(exitCode, stdout)) {
        root.generateServeStarting = false
        root.generateServeFailed = true
        if (root.genBusy) root.regenerateViaCli()
        return
      }
      // Screen closed mid-probe: do not start a server nobody is looking at.
      if (root.currentScreen !== "generator") {
        root.generateServeStarting = false
        return
      }
      generateServeProc.running = true
      generateServePoll.attempts = 0
      generateServePoll.restart()
    })
  }

  function stopGeneratorServe() {
    var cancelCliGeneration = genBusy && generateProc.running
    generateServePoll.stop()
    generateServeStarting = false
    generateServeReady = false
    // A deliberate shutdown: the next visit may start one again.
    generateServeFailed = false
    genBusy = false
    genRegeneratePending = false
    genRequestSignature = ""
    generateServeRequestPending = false
    generateServeRequestPendingOptions = null
    generateServeRequestPendingCallback = null
    if (generateServeRequestProc.running
        && !Model.isScrubCommand(generateServeRequestProc.command)) {
      generateServeRequestCallback = null
      generateServeRequestStopping = true
      generateServeRequestProc.running = false
    }
    if (cancelCliGeneration) {
      generateCliStopping = true
      generateProc.running = false
    }
    if (generateServeProc.running) {
      generateServeStopping = true
      generateServeProc.running = false
    }
  }

  // Poll until the server answers (binding takes a couple of seconds).
  function pollGeneratorServe() {
    if (generateServeRequestProc.running) return
    generatorRequest(root.genOpts, function(exitCode, stdout, stderr) {
      if (exitCode !== 0) return
      var value = Model.parseServeGenerated(stdout)
      if (!value) return
      root.generateServeStarting = false
      root.generateServeReady = true
      generateServePoll.stop()
      root.onGenerated(value, 0)
    })
  }

  function requestGeneratedValue() {
    generatorRequest(root.genOpts, function(exitCode, stdout, stderr) {
      var value = exitCode === 0 ? Model.parseServeGenerated(stdout) : ""
      if (value) {
        root.onGenerated(value, 0)
        return
      }
      // Gone or misbehaving: fall back and stop trusting it.
      root.generateServeReady = false
      root.regenerateViaCli()
    })
  }

  function onGenerated(text, exitCode) {
    if (vaultReadIsStale("generator")) {
      genBusy = false
      genRegeneratePending = false
      return
    }
    if (genRegeneratePending || genRequestSignature !== generatorOptionsSignature()) {
      genBusy = false
      genRegeneratePending = false
      regenerate()
      return
    }
    genBusy = false
    var v = String(text || "").trim()
    if (exitCode !== 0 || !v) {
      errorMessage = "Could not generate with these options"
      return
    }
    genValue = v
  }

  // Every control changes options here: normalise and regenerate.
  function setGenOpt(key, value) {
    var next = {}
    for (var k in genOpts) next[k] = genOpts[k]
    next[key] = value
    genOpts = Model.normalizeGeneratorOptions(next)
    regenerate()
  }

  function copyGenerated() {
    if (genBusy || !genValue) return
    copyToClipboard(genValue, genOpts.type === "passphrase" ? "Passphrase" : "Password")
  }

  // -------------------------------------------------------------------------
  // PIN unlock
  // -------------------------------------------------------------------------

  // The legacy checks record which account they ask about; an answer for an
  // account no longer active is dropped and asked again.
  property string pinCheckSlot: ""
  property string masterCheckSlot: ""
  // A check asked for while its process was busy; busyRetryTimer asks again.
  property bool pinRecheck: false
  property bool masterRecheck: false

  function refreshPinConfigured() {
    if (keyringHasPinProc.running) {
      pinRecheck = true
      return
    }
    pinRecheck = false
    pinCheckSlot = activeSlot
    keyringHasPinProc.running = true
  }

  function onPinConfiguredChecked(raw) {
    if (pinCheckSlot !== activeSlot) {
      if (pinUnlock) pinRecheck = true
      return
    }
    legacyPinStored = String(raw || "").trim() === "yes"
    recomputePinConfigured()
  }

  function refreshLegacyFingerprint() {
    if (keyringHasMasterProc.running) {
      masterRecheck = true
      return
    }
    masterRecheck = false
    masterCheckSlot = activeSlot
    keyringHasMasterProc.running = true
  }

  function beginPinSetup() {
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    pinError = ""
    pinUnlockError = ""
    screenBeforeSettings = "main"
    currentScreen = "pin"
    Qt.callLater(function() { presenter.focusField("pinSetupPin") })
  }

  function abandonPinSetup() {
    // A wrap still being written is removed when it lands (submitPinSetup()).
    if (pinBusy) invalidateEpochOperation("pinAdd")
    pinBusy = false
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
  }

  // The typed master password must open the envelope; a PIN wrap (Argon2id of
  // the PIN) is added. Nothing typed is stored.
  function submitPinSetup() {
    if (pinBusy) return
    var err = Model.validatePin(pinSetupPin, pinSetupConfirm)
    if (err) { pinError = err; return }
    if (!quickUnlockAvailable) { pinError = quickUnlockUnavailableReason; return }
    if (!pinSetupMaster) { pinError = "Confirm your master password to set a PIN"; return }

    pinError = ""
    pinUnlockError = ""
    pinBusy = true
    var typed = pinSetupMaster
    var pin = {}
    pin[Model.pinEnvVar()] = pinSetupPin
    pinSetupMaster = ""
    beginEpochOperation("pinAdd")
    addQuickUnlockMethod(typed, { kind: "add-pin" }, pin, function(ok, why) {
      typed = ""
      pin = null
      root.pinBusy = false
      // Stale by the time it landed: remove the unwanted wrap.
      if (root.epochOperationIsStale("pinAdd") || root.currentScreen !== "pin") {
        if (ok) root.removeQuickUnlockMethod({ kind: "remove", method: "pin" })
        return
      }
      if (!ok) {
        root.pinError = root.quickUnlockErrorText(why, "Could not save the PIN. Is the OS keyring available?")
        return
      }
      // The older PIN blob, if any, is superseded.
      root.legacyPinStored = false
      root.requestPinCredentialClear()
      root.pinSetupPin = ""
      root.pinSetupConfirm = ""
      root.pinAttempts = 0
      root.recomputePinConfigured()
      root.writeSetting("pinUnlock", true, "bool")
      root.flashNotification("PIN unlock enabled")
      root.currentScreen = "settings"
    })
  }

  function submitPinUnlock() {
    if (!sshAuthSurfaceActive || !pinReady || isUnlocking || pinBusy) return
    // As for the password: the PIN's result is discarded unless locked.
    if (status !== "locked") {
      pinUnlockError = "Still checking the vault. Try again in a moment."
      return
    }
    if (String(pinEntry || "").length < Model.pinMinLength()) {
      pinUnlockError = "PIN must be at least " + Model.pinMinLength() + " digits"
      return
    }
    pinUnlockError = ""
    pinBusy = true
    pinUnlockSubmitted = true
    if (quickUnlockAvailable && accountId && envelopeSummary && envelopeSummary.pin) {
      var env = {}
      env[Model.pinEnvVar()] = String(pinEntry || "")
      queueEnvelopeJob({
        command: Model.unlockEnvelopeOpenCommand(envelopeTool(), envelopeAccount(), { kind: "pin" }),
        env: env, secretOutput: true,
        onDone: function(code, out) { root.onEnvelopePinResult(code, out) }
      })
      return
    }
    pinUnlockProc.command = Model.pinUnlockCommand(activeSlot)
    pinUnlockProc.running = true
  }

  // The envelope's answer to a PIN; exit 3 is a wrong PIN.
  function onEnvelopePinResult(code, out) {
    var accepting = pinUnlockSubmitted && sshAuthSurfaceActive && status === "locked"
    pinUnlockSubmitted = false
    pinBusy = false
    if (!accepting) return
    if (code === 0 && out) {
      pinAttempts = 0
      pinFromEnvelope = true
      pendingUnlockFrom = "pin"
      unlockVaultWithPassword(out)
      return
    }
    if (code === 3) {
      countWrongPin()
      return
    }
    pinEntry = ""
    pinUnlockError = "Could not read the stored password. Unlock with your master password."
    refreshEnvelope()
  }

  function countWrongPin() {
    pinAttempts += 1
    pinEntry = ""
    if (pinAttempts >= pinMaxAttempts) {
      // Stop taking guesses and remove the PIN's way in (a UI limit; Argon2
      // is the real cost).
      clearPin()
      pinUnlockError = "Too many incorrect PINs. PIN unlock has been removed -- use your master password."
    } else {
      pinUnlockError = "Incorrect PIN (" + pinAttempts + " of " + pinMaxAttempts + ")"
    }
  }

  function onPinUnlockResult(exitCode, password) {
    var accepting = pinUnlockSubmitted && sshAuthSurfaceActive && status === "locked"
    pinUnlockSubmitted = false
    pinBusy = false
    if (!accepting) {
      clearProcessCollectorSoon(pinUnlockProc)
      return
    }
    var pw = String(password || "")

    if (exitCode !== 0 || !pw) {
      countWrongPin()
      return
    }

    // A legacy blob: keep the PIN until this unlock settles, to migrate it.
    pinAttempts = 0
    pendingPinForMigration = String(pinEntry || "")
    pendingUnlockFrom = "pin"
    unlockVaultWithPassword(pw)
  }

  function clearPin() {
    requestPinCredentialClear()
    legacyPinStored = false
    if (envelopeSummary && envelopeSummary.pin) {
      removeQuickUnlockMethod({ kind: "remove", method: "pin" })
    }
    pinConfigured = false
    pinEntry = ""
    pinAttempts = 0
    if (pinUnlock && !otherAccountsExist()) writeSetting("pinUnlock", false, "bool")
  }

  function disablePinUnlock() {
    clearPin()
    pinError = ""
    pinUnlockError = ""
    flashNotification("PIN unlock removed")
  }

  onPinUnlockChanged: {
    if (pinUnlock) refreshPinConfigured()
    else if (pinConfigured) clearPin()
  }

  // -------------------------------------------------------------------------
  // Setup and settings
  // -------------------------------------------------------------------------

  function checkDependencies() {
    if (!depsCheckProc.running) depsCheckProc.running = true
  }

  function onDependenciesChecked(raw) {
    depsRaw = String(raw || "")
    var bwId = Model.dependencyBwId(depsRaw)
    var cached = bwVersionKnown && bwId !== "" && bwId === bwVersionId
    dependencies = Model.parseDependencies(depsRaw, cached ? bwVersionValue : null)
    // Off the status probe's path: only SSH support waits for the version.
    if (!cached && Model.dependencyInstalled(dependencies, "bw")) probeBwVersion(bwId)
    depsChecked = true
    // The legacy entries checked here are the active account's.
    if (pinUnlock && accountsLoaded) refreshPinConfigured()

    // Fingerprint availability comes from the same probe, so keep them in step.
    for (var i = 0; i < dependencies.items.length; i++) {
      if (dependencies.items[i].key === "fprintd") fingerprintAvailable = dependencies.items[i].ready
    }
    if (fingerprintAvailable && fingerprintUnlock) {
      if (accountsLoaded) refreshLegacyFingerprint()
    } else {
      fingerprintStored = false
    }

    // A missing required tool is not something to discover mid-task.
    if (Model.missingRequired(dependencies).length > 0) setupWasGated = true

    var next = Model.dependencyProbeOutcome(dependencies, setupDismissed, statusProbeStarted, setupWasGated)
    if (next === "setup") {
      currentScreen = "setup"
    } else if (next === "probe") {
      // Either the first look at the vault this session, or the one that
      // follows an install landing. onStatusFinished puts up whichever screen
      // the answer calls for, so setup gets left behind without being told to.
      setupWasGated = false
      refreshStatus()
    }
  }

  function probeBwVersion(bwId) {
    if (bwVersionProc.running) return
    bwVersionProc.probeId = bwId
    bwVersionProc.running = true
  }

  function onBwVersionProbed(raw, probedId) {
    bwVersionId = probedId
    bwVersionValue = Model.parseBwVersionProbe(raw)
    bwVersionKnown = true
    // bw changed while `bw -v` ran: that answer is for the old binary.
    var latestId = Model.dependencyBwId(depsRaw)
    if (latestId !== probedId) {
      if (Model.dependencyInstalled(dependencies, "bw")) probeBwVersion(latestId)
      return
    }
    dependencies = Model.parseDependencies(depsRaw, bwVersionValue)
  }

  readonly property var missingRequired: Model.missingRequired(dependencies)
  readonly property var installablePackages: Model.missingPackages(dependencies)
  // Whether anything on the setup screen is still waiting on the user. Covers
  // the setup rows too, so a fingerprint enrolment running in its own terminal
  // is watched for the same way an install is.
  readonly property bool setupActionsPending: {
    var rows = Model.applicableDependencies(dependencies)
    for (var i = 0; i < rows.length; i++) {
      if (!rows[i].ready) return true
    }
    return false
  }

  function installMissing() {
    var pkgs = Model.missingPackages(dependencies)
    var cmd = Model.installPackagesCommand(pkgs,
      pkgs.length === 1 ? "Bitwarden CLI" : "Bitwarden plugin dependencies")
    if (!cmd) return
    Quickshell.execDetached(cmd)
    flashNotification("Installing -- this screen updates itself")
  }

  function installOne(dep) {
    if (!dep) return
    // Rows Omarchy sets up itself are not a package install.
    if (dep.setup) {
      runFingerprintSetup()
      return
    }
    var cmd = Model.installPackagesCommand([dep.pkg], dep.label)
    if (!cmd) return
    Quickshell.execDetached(cmd)
    flashNotification("Installing " + dep.pkg + " -- this screen updates itself")
  }

  // Skip setup, releasing the status probe it was holding back.
  function dismissSetup() {
    setupDismissed = true
    currentScreen = status === "unlocked" ? "main"
      : (status === "locked" ? "locked" : "login")
    if (!statusProbeStarted) refreshStatus()
  }

  function runFingerprintSetup() {
    Quickshell.execDetached(Model.fingerprintSetupCommand())
    flashNotification("Fingerprint setup opened -- this screen updates itself")
  }

  // A setting whose dependency is missing does nothing if changed.
  function settingBlocked(entry) {
    return settingDependencyMissing(entry) || quickUnlockToolMissing(entry)
  }

  function settingDependencyMissing(entry) {
    if (!entry || !entry.requires) return false
    for (var i = 0; i < dependencies.items.length; i++) {
      if (dependencies.items[i].key === entry.requires) return !dependencies.items[i].ready
    }
    return false
  }

  // Quick-unlock options need the tool to switch on, never to switch off.
  // "unknown" (before the first inspection) is not a verdict.
  function quickUnlockToolMissing(entry) {
    if (!entry || !Model.isQuickUnlockSetting(entry.key)) return false
    if (unlockKeyHelper.state === "unknown" || !quickUnlockPrereqs.checked) return false
    if (quickUnlockAvailable) return false
    return !settingValue(entry)
  }

  // The stored password is only as protected as the weakest way in; with
  // fingerprint on (no secret involved) a PIN or key adds nothing, and those
  // rows say so.
  function settingNote(entry) {
    if (!entry || (entry.key !== "pinUnlock" && entry.key !== "fidoUnlock")) return ""
    if (!settingValue(entry) || !fingerprintUnlock || !fingerprintStored) return ""
    return "Fingerprint unlock is also on, so the stored password is only as protected as "
      + "fingerprint unlock: a program running as you can open it without the "
      + (entry.key === "pinUnlock" ? "PIN." : "key.")
  }

  // Shown instead of the description, so an inert control says why.
  function settingBlockedReason(entry) {
    if (settingDependencyMissing(entry)) return "Needs fingerprint setup -- see Dependencies below."
    if (quickUnlockToolMissing(entry)) {
      return quickUnlockUnavailableReason + " Your master password still unlocks the vault."
    }
    return ""
  }

  // The cursor steps over group headings.
  function moveSettingsCursor(delta) {
    var n = settingsEntries.length
    if (n === 0) return
    var step = delta < 0 ? -1 : 1
    var i = settingsIndex + delta
    while (i >= 0 && i < n && settingsEntries[i] && settingsEntries[i].kind === "group") i += step
    // Only a heading beyond: stay put.
    if (i < 0 || i >= n) return
    settingsIndex = i
  }

  function firstSettingIndex() {
    for (var i = 0; i < settingsEntries.length; i++) {
      if (settingsEntries[i] && settingsEntries[i].kind === "setting") return i
    }
    return 0
  }

  // Left/right nudge a value: numbers by their step, switches off and on.
  function adjustSetting(direction) {
    var e = settingsEntries[settingsIndex]
    if (!e || settingBlocked(e)) return

    if (e.type === "int") {
      var cur = Number(settingValue(e))
      var step = e.step || 1
      var next = Math.max(e.min || 0, Math.min(e.max || 100, cur + direction * step))
      if (next !== cur) writeSetting(e.key, next, "int")
      return
    }

    if (e.type === "bool") {
      var want = direction > 0
      if (Boolean(settingValue(e)) !== want) activateSettingRow()
    }
  }

  function activateSettingRow() {
    var e = settingsEntries[settingsIndex]
    if (!e || settingBlocked(e)) return

    // These two open a form rather than flipping a value.
    if (e.action === "pin") {
      if (pinConfigured) disablePinUnlock()
      else beginPinSetup()
      return
    }
    if (e.action === "fingerprint") {
      if (fingerprintStored) forgetFingerprintUnlock()
      else beginFingerprintSetup()
      return
    }
    if (e.action === "fido") {
      if (fidoStored) forgetFidoUnlock()
      else beginFidoSetup()
      return
    }
    if (e.type === "bool") writeSetting(e.key, !settingValue(e), "bool")
  }

  function openSettings() {
    closeFilterGroup()
    if (currentScreen !== "settings") screenBeforeSettings = currentScreen
    settingsFlash = ""
    settingsIndex = firstSettingIndex()
    uwsmFlash = ""
    uwsmConfirmPending = false
    checkDependencies()
    inspectUwsmFragment()
    currentScreen = "settings"
    Qt.callLater(function() { eachView(function(view) { view.updateSettingsSticky() }) })
  }

  function closeSettings() {
    currentScreen = (screenBeforeSettings === "settings" ? "main" : screenBeforeSettings)
  }

  // Via `omarchy bar set`; the shell reloads, so setting() sees the change.
  function writeSetting(key, value, type) {
    settingWriteProc.command = Model.settingWriteCommand(key, value, type)
    settingWriteProc.running = true
    settingsFlash = "Saved"
    settingsFlashTimer.restart()
  }

  // For internal notes like the remembered two-step method: no "Saved" flash.
  function writeSettingQuietly(key, value, type) {
    settingWriteProc.command = Model.settingWriteCommand(key, value, type)
    settingWriteProc.running = true
  }

  function rememberTwoFactorMethod(method) {
    if (!Model.isTwoFactorMethod(method)) return
    if (method === rememberedTwoFactorMethod) return
    var next = Model.rememberTwoFactorMethodIn(twoFactorMethodStore, loginEmail, method)
    if (next) writeSettingQuietly("twoFactorMethods", next, "json")
  }

  function forgetTwoFactorMethod() {
    if (rememberedTwoFactorMethod < 0) return
    var next = Model.forgetTwoFactorMethodIn(twoFactorMethodStore, loginEmail)
    if (next) writeSettingQuietly("twoFactorMethods", next, "json")
  }

  // Read through the properties actually in effect (setting() alone would
  // miss manifest defaults).
  function settingValue(entry) {
    if (!entry) return 0
    switch (entry.key) {
      case "autoLockMinutes": return autoLockMinutes
      case "clearClipboardSec": return clearClipboardSec
      case "lockOnScreenLock": return lockOnScreenLock
      case "lockOnSuspend": return lockOnSuspend
      case "autoCopyTotpSec": return autoCopyTotpSec
      case "closeOnCopy": return closeOnCopy
      case "suggestOnOpen": return suggestOnOpen
      case "rememberSession": return rememberSession
      case "fingerprintUnlock": return fingerprintUnlock && fingerprintStored
      case "fidoUnlock": return fidoUnlock && fidoStored
      // The toggle reflects a PIN actually being set, not just the flag.
      case "pinUnlock": return pinUnlock && pinConfigured
      case "sshAgentEnabled": return sshAgentEnabled
      case "sshAgentUnlockOnDemand": return sshAgentUnlockOnDemand
      case "sshAgentApprovalPopup": return sshAgentApprovalPopup
      case "sshAgentApprovalWindowSec": return sshAgentApprovalWindowSec
    }
    return entry.type === "bool" ? Model.boolSetting(entry.key, setting(entry.key, entry.defaultValue)) : Number(setting(entry.key, 0))
  }

  function refreshFingerprintAvailability() {
    checkDependencies()
    // Probe now so the setup form opens on the right branch.
    fidoUnlocker.refresh()
  }

  function onFingerprintStoredChecked(raw) {
    if (masterCheckSlot !== activeSlot) {
      if (fingerprintUnlock) masterRecheck = true
      return
    }
    legacyFingerprintStored = String(raw || "").trim() === "yes"
    recomputeFingerprintStored()
    maybeMigrateLegacyFingerprint()
    if (sshAuthSurfaceActive && status === "locked") armPresenceUnlock()
  }

  function startFingerprintUnlock() {
    if (!fingerprintReady || status !== "locked" || isUnlocking) return
    if (fingerprintScanning || fingerprintPam.active) return
    // Release, not cancel: a return to the key can adopt its request.
    fidoUnlocker.releaseSurface()
    if (!userName) {
      fingerprintError = "Cannot determine current user for fingerprint verification"
      return
    }

    errorMessage = ""
    fingerprintError = ""
    fingerprintAuthorized = false
    fingerprintScanning = true
    fingerprintMessage = "󰈷  Touch the fingerprint reader..."
    if (!fingerprintPam.start()) {
      fingerprintScanning = false
      fingerprintMessage = ""
      fingerprintError = "Could not start fingerprint verification"
    }
  }

  function cancelFingerprintUnlock() {
    fingerprintScanning = false
    fingerprintAuthorized = false
    if (fingerprintPam.active) fingerprintPam.abort()
  }

  function onFingerprintResult(result) {
    var accepting = fingerprintScanning && sshAuthSurfaceActive && status === "locked"
    fingerprintScanning = false
    if (!accepting) return

    if (result === PamResult.Success) {
      fingerprintAuthorized = true
      // The button under this says "Unlocking..." on its own now.
      fingerprintMessage = "󰈷  Fingerprint verified"
      if (quickUnlockAvailable && accountId && envelopeSummary && envelopeSummary.fingerprint) {
        openEnvelopeForFingerprint()
        return
      }
      if (!keyringLookupMasterProc.running) {
        keyringLookupMasterProc.command = Model.keyringLookupMasterPasswordCommand(activeSlot)
        keyringLookupMasterProc.running = true
      }
    } else if (result === PamResult.MaxTries) {
      fingerprintMessage = ""
      fingerprintError = "Too many fingerprint attempts. Use your master password."
    } else {
      fingerprintMessage = ""
      fingerprintError = "Fingerprint not recognised. Try again or use your master password."
    }
  }

  // After PAM success, via the envelope's fingerprint wrap, falling back to
  // the legacy entry until it is migrated.
  function openEnvelopeForFingerprint() {
    queueEnvelopeJob({
      command: Model.unlockEnvelopeOpenCommand(envelopeTool(), envelopeAccount(), { kind: "fingerprint" }),
      secretOutput: true,
      onDone: function(code, out) {
        if (code === 0 && out) {
          root.fingerprintFromEnvelope = true
          root.onFingerprintPasswordRetrieved(out)
          return
        }
        var E = Model.envelopeExitCodes()
        if ((code === 7 || code === E.absent) && root.legacyFingerprintStored
            && !keyringLookupMasterProc.running) {
          keyringLookupMasterProc.command = Model.keyringLookupMasterPasswordCommand(root.activeSlot)
          keyringLookupMasterProc.running = true
          return
        }
        root.fingerprintAuthorized = false
        root.fingerprintMessage = ""
        root.fingerprintError = "Could not read the stored password. Unlock with your master password."
        root.refreshEnvelope()
      }
    })
  }

  // Only ever called after PamResult.Success.
  function onFingerprintPasswordRetrieved(raw) {
    if (!fingerprintAuthorized || !sshAuthSurfaceActive || status !== "locked") {
      fingerprintAuthorized = false
      clearProcessCollectorSoon(keyringLookupMasterProc)
      return
    }
    fingerprintAuthorized = false
    // Not trimmed: edge spaces can be part of the password.
    var pw = String(raw || "")
    if (!pw) {
      fingerprintStored = false
      fingerprintMessage = ""
      fingerprintError = "No stored master password. Unlock with your password once to enable this."
      return
    }
    pendingUnlockFrom = "fingerprint"
    unlockVaultWithPassword(pw)
  }

  // Enrolling asks for the master password up front, like PIN setup.
  function beginFingerprintSetup() {
    fpSetupMaster = ""
    fpError = ""
    currentScreen = "fingerprint"
    Qt.callLater(function() { presenter.focusField("fpMaster") })
  }

  function abandonFingerprintSetup() {
    // A wrap still being written is removed when it lands.
    if (fpBusy) invalidateEpochOperation("fingerprintAdd")
    fpSetupActive = false
    fpBusy = false
    fpSetupMaster = ""
  }

  // The typed master password must open the envelope; a fingerprint wrap is
  // added. Nothing typed is stored.
  function submitFingerprintSetup() {
    if (fpBusy) return
    if (!quickUnlockAvailable) {
      fpError = quickUnlockUnavailableReason
      return
    }
    if (!fpSetupMaster) {
      fpError = "Confirm your master password to enable fingerprint unlock"
      return
    }
    fpError = ""
    fpBusy = true
    fpSetupActive = true
    var typed = fpSetupMaster
    fpSetupMaster = ""
    beginEpochOperation("fingerprintAdd")
    addQuickUnlockMethod(typed, { kind: "add-fingerprint" }, null, function(ok, why) {
      typed = ""
      root.fpBusy = false
      // Stale by the time it landed: remove the unwanted wrap.
      if (root.epochOperationIsStale("fingerprintAdd") || !root.fpSetupActive) {
        root.fpSetupActive = false
        if (ok) root.removeQuickUnlockMethod({ kind: "remove", method: "fingerprint" })
        return
      }
      root.fpSetupActive = false
      if (!ok) {
        root.fpError = root.quickUnlockErrorText(why, "Could not enable fingerprint unlock. Is the OS keyring available?")
        return
      }
      // The plaintext entry, if an older version left one, is superseded.
      root.legacyFingerprintStored = false
      root.requestMasterCredentialClear()
      root.recomputeFingerprintStored()
      root.writeSetting("fingerprintUnlock", true, "bool")
      root.flashNotification("Fingerprint unlock enabled")
      root.currentScreen = "settings"
    })
  }

  function forgetFingerprintUnlock() {
    requestMasterCredentialClear()
    legacyFingerprintStored = false
    if (envelopeSummary && envelopeSummary.fingerprint) {
      removeQuickUnlockMethod({ kind: "remove", method: "fingerprint" })
    }
    fingerprintStored = false
    cancelFingerprintUnlock()
    fingerprintMessage = ""
    fingerprintError = ""
    flashNotification("Fingerprint unlock forgotten")
  }

  onFingerprintUnlockChanged: {
    if (!fingerprintUnlock) {
      cancelFingerprintUnlock()
      fingerprintMessage = ""
      fingerprintError = ""
      // Unconditional: fingerprintStored also goes false when the reader or
      // fprintd is missing, and a way in may still be stored.
      forgetFingerprintUnlock()
    } else {
      refreshFingerprintAvailability()
    }
  }

  // -------------------------------------------------------------------------
  // FIDO2 unlock
  // -------------------------------------------------------------------------
  //
  // FidoUnlock.qml owns the probe, the key request and the setup form; these
  // names parallel the fingerprint's for the lock screen and settings.

  // One presence method at a time: a second would wait for a touch that goes
  // nowhere.
  function startFidoUnlock() {
    cancelFingerprintUnlock()
    fidoUnlocker.startUnlock()
  }
  function cancelFidoUnlock() { fidoUnlocker.cancelUnlock() }
  // Step back from the key without abandoning the request it is holding.
  function releaseFidoUnlock() { fidoUnlocker.releaseSurface() }
  function beginFidoSetup() { fidoUnlocker.beginSetup() }
  function submitFidoSetup() { fidoUnlocker.submitSetup() }
  function runFidoSetup() { fidoUnlocker.runOmarchySetup() }
  function forgetFidoUnlock() { fidoUnlocker.forget("") }

  // Arm the FIDO2 key if one is ready, else the reader; both stay offered.
  function armPresenceUnlock() {
    if (fidoReady) {
      startFidoUnlock()
      return
    }
    // Re-probe: a key plugged in since the last probe arms itself when the
    // answer lands.
    if (fidoUnlock) fidoUnlocker.refresh()
    startFingerprintUnlock()
  }

  // -------------------------------------------------------------------------
  // Unlock and lock
  // -------------------------------------------------------------------------

  function unlockVault() {
    // No `bw unlock` is waiting until status says locked (it is "checking"
    // for a few seconds after a start); the typed text is kept.
    if (status !== "locked") {
      errorMessage = "Still checking the vault. Try again in a moment."
      return
    }
    pendingUnlockFrom = ""
    unlockVaultWithPassword(masterPassword)
  }

  function unlockVaultWithPassword(pass) {
    var p = String(pass === undefined || pass === null ? "" : pass)
    if (!p) {
      errorMessage = "Master password required"
      return
    }
    cancelFingerprintUnlock()
    cancelFidoUnlock()
    errorMessage = ""
    isUnlocking = true
    // Held until the result; the FIFO writer reads it as BW_PASSWORD (the
    // prewarmed unlockProc never sees it).
    pendingUnlockPassword = p
    prepareUnlock()
    unlockSubmitted = true
    writeAuthPassword("unlock", p)
  }

  function onUnlockOutput(stdoutText, stderrText, exitCode) {
    isUnlocking = false
    var out = String(stdoutText || "").trim()
    var err = String(stderrText || "").trim()

    if (exitCode === 0 && out) {
      fingerprintFromEnvelope = false
      onUnlockSuccess(out)
    } else {
      var fromEnvelope = (pendingUnlockFrom === "fingerprint" && fingerprintFromEnvelope)
        || (pendingUnlockFrom === "pin" && pinFromEnvelope)
        || (pendingUnlockFrom === "fido" && fidoFromEnvelope)
      if (!fromEnvelope) pendingUnlockPassword = ""
      pendingPinForMigration = ""
      // A stored secret the vault rejects: say which method went stale.
      if (pendingUnlockFrom === "fingerprint" && fingerprintFromEnvelope) {
        // Changed elsewhere: keep the method and remember the old password so
        // the next typed unlock re-seals the envelope.
        pendingUnlockFrom = ""
        fingerprintFromEnvelope = false
        rotationOldPassword = pendingUnlockPassword
        pendingUnlockPassword = ""
        fingerprintMessage = "Your master password was changed. Unlock with the new one once; fingerprint unlock will follow it."
        errorMessage = ""
        focusAppropriateField()
        Qt.callLater(prepareUnlock)
        return
      }
      if (pendingUnlockFrom === "fingerprint") {
        pendingUnlockFrom = ""
        requestMasterCredentialClear()
        fingerprintStored = false
        fingerprintMessage = "Stored password no longer valid. Unlock with your master password to re-enable fingerprint unlock."
        errorMessage = ""
        focusAppropriateField()
        Qt.callLater(prepareUnlock)
        return
      }
      if (pendingUnlockFrom === "fido" && fidoFromEnvelope) {
        // Changed elsewhere, as for fingerprint.
        pendingUnlockFrom = ""
        fidoFromEnvelope = false
        rotationOldPassword = pendingUnlockPassword
        pendingUnlockPassword = ""
        fidoUnlocker.failure = "Your master password was changed. Unlock with the new one once; FIDO2 unlock will follow it."
        errorMessage = ""
        focusAppropriateField()
        Qt.callLater(prepareUnlock)
        return
      }
      if (pendingUnlockFrom === "fido") {
        pendingUnlockFrom = ""
        fidoUnlocker.forget("Stored password no longer valid. Unlock with your master password to re-enable FIDO2 unlock.", false)
        errorMessage = ""
        focusAppropriateField()
        Qt.callLater(prepareUnlock)
        return
      }
      if (pendingUnlockFrom === "pin" && pinFromEnvelope) {
        // Changed elsewhere, as for fingerprint.
        pendingUnlockFrom = ""
        pinFromEnvelope = false
        rotationOldPassword = pendingUnlockPassword
        pendingUnlockPassword = ""
        pinUnlockError = "Your master password was changed. Unlock with the new one once; PIN unlock will follow it."
        errorMessage = ""
        focusAppropriateField()
        Qt.callLater(prepareUnlock)
        return
      }
      if (pendingUnlockFrom === "pin") {
        pendingUnlockFrom = ""
        clearPin()
        pinUnlockError = "Your master password changed, so the PIN no longer works. Unlock with your password and set a new PIN."
        errorMessage = ""
        focusAppropriateField()
        Qt.callLater(prepareUnlock)
        return
      }
      if (err.indexOf("not logged in") !== -1) {
        status = "unauthenticated"
        currentScreen = "login"
        errorMessage = "You are not logged in. Please log in below."
      } else {
        errorMessage = err || "Unlock failed: invalid master password"
        Qt.callLater(prepareUnlock)
      }
    }
  }

  function onUnlockSuccess(rawSession) {
    var s = Model.extractSessionToken(rawSession)
    masterPassword = ""
    clearLoginAttempt()
    initialSyncAttempted = false
    syncLoginFieldsToState()
    isUnlocking = false
    unlockSubmitted = false
    if (!s) {
      errorMessage = "Unlock did not return a session key"
      return
    }

    session = s
    vaultEpoch += 1
    status = "unlocked"
    currentScreen = "main"
    flashNotification("Vault unlocked successfully!")
    // A sign-in the account list does not know yet: `bw status` names it
    // once the list has painted (noteActiveAccount()).
    if (!accountId || !Model.registryHasAccount(accountRegistry, activeSlot)) statusRefreshAfterItems = true

    storeCurrentSession()

    // A typed password `bw` accepted is the only source of the stored one;
    // this also re-seals after a change made elsewhere.
    if (pendingUnlockPassword && pendingUnlockFrom === "") {
      storeAcceptedMasterPassword(pendingUnlockPassword)
    } else {
      rotationOldPassword = ""
    }
    if (pendingUnlockFrom === "pin" && !pinFromEnvelope && pendingPinForMigration && pendingUnlockPassword) {
      migrateLegacyPin(pendingUnlockPassword, pendingPinForMigration)
    }
    pendingPinForMigration = ""
    pinFromEnvelope = false
    fidoFromEnvelope = false
    pendingUnlockPassword = ""
    pendingUnlockFrom = ""
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
    pinUnlockError = ""
    fingerprintMessage = ""
    fingerprintError = ""

    beginInitialVaultLoad(true, false)
    resetAutoLockTimer()
    focusAppropriateField()
  }

  function lockVault() {
    closeFilterGroup()
    cancelAuthPrewarm()
    clearClipboard()
    // Before `bw lock`, so the companion denies first; never waited on.
    applySshAgentLifecycle("lock")
    if (session) {
      lockProc.command = Model.lockCommand()
      lockProc.running = true
    }
    // Unconditional: the setting may have been turned off after a session
    // was stored. Clearing nothing is harmless.
    requestSessionCredentialClear()

    dropVaultState()
    status = "locked"
    currentScreen = "locked"
    fingerprintMessage = ""
    fingerprintError = ""
    flashNotification("Vault locked")
    focusAppropriateField()
    // Arm whichever method the lock screen offers.
    if (sshAuthSurfaceActive) armPresenceUnlock()
  }

  function vaultStatePresent() {
    return !!session || status === "unlocked" || items.length > 0
      || organizations.length > 0 || folders.length > 0 || detailItem !== null
      || sends.length > 0 || itemPayloadJson !== "" || sendPayloadJson !== ""
  }

  // The local purge for every way an open vault becomes unusable, separate
  // from `bw lock` and the keyring so a failed status can fail closed.
  function dropVaultState() {
    initialSyncAttempted = false
    pinUnlockSubmitted = false
    cancelFingerprintUnlock()
    cancelFidoUnlock()
    cancelAttachmentDownloads()
    session = ""
    vaultEpoch += 1
    sshAgentLoadFailStreak = 0
    readEpochs = ({})
    masterPassword = ""
    itemsLoadedAt = 0
    orgsLoadedAt = 0
    foldersLoadedAt = 0
    items = []
    filteredItems = []
    organizations = []
    folders = []
    selectedOrg = "all"
    selectedFolder = "all"
    openFilterGroup = ""
    searchQuery = ""
    selectedCategory = "all"
    selectedIndex = 0
    detailItem = null
    revealedFields = ({})
    attachmentSaved = ({})
    resetItemForm()
    totpFollowupActive = false
    isLoading = false
    isUnlocking = false
    isSyncing = false
    metadataLoadPending = false
    metadataForceRefresh = false
    statusRefreshAfterItems = false
    syncReloadPending = false
    sendsLoading = false
    sendBusy = false
    genBusy = false
    pendingUnlockPassword = ""
    sessionStorePending = false
    dropVaultSecrets()
  }

  // A locked vault holds nothing from the vault and nothing that would reopen
  // it: generated values, half-typed forms, payload JSON, setup passwords. The
  // shell lives all session, so anything surviving a lock survives everything.
  function dropVaultSecrets() {
    detailPassword = ""
    liveTotp = ""
    totpRequestItemId = ""
    totpQueuedItemId = ""
    totpQueuedEpoch = -1
    totpRestartPending = false
    totpCopyItemId = ""
    passwordCopyItemId = ""
    totpFollowupItem = null
    totpFollowupCode = ""
    genValue = ""
    formPassword = ""
    formTotp = ""
    formCustomFields = []
    formNewCustomFieldName = ""
    formCustomFieldLabelDraft = ""
    itemPayloadJson = ""
    sends = []
    sendPayloadJson = ""
    sendFormText = ""
    sendFormPassword = ""
    clearLoginAttempt()
    syncLoginFieldsToState()
    pinEntry = ""
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    fpSetupMaster = ""
    pendingAssociationsJson = ""
    fidoUnlocker.dropSecrets()
    scrubSecretBuffers()
  }

  // The collectors those values came from still hold them; they are scrubbed
  // too (see "Collector scrubbing" in BitwardenModel.js). Built on demand:
  // these ids are declared further down.
  function secretProcesses() {
    return [
      statusProc, sessionHandoffProc, keyringLookupProc, pinUnlockProc, keyringLookupMasterProc,
      loginProc, unlockProc, listProc, listOrgsProc, listFoldersProc, orgCollectionsProc,
      getItemProc, getTotpProc, generateProc, listSendsProc, createSendProc,
      copyPasswordProc,
      createItemProc, editItemProc, deleteItemProc, createFolderProc, attachmentProc,
      associationsReadProc, generateServeRequestProc
    ].concat(fidoUnlocker.secretProcesses())
  }

  function scrubSecretBuffers() {
    scrubPending = secretProcesses()
    scrubStep()
    if (scrubPending.length) scrubRetry.restart()
  }

  // Running processes are skipped (their read is still wanted) and retried.
  function scrubStep() {
    var pass = Model.scrubPass(scrubPending)
    for (var i = 0; i < pass.start.length; i++) {
      pass.start[i].command = Model.scrubCommand()
      pass.start[i].running = true
    }
    scrubPending = pass.waiting
  }

  // Must be asked first by every handler: a scrub's empty, zero-exit result
  // would otherwise read as a success.
  function finishScrubRun(proc) {
    if (!Model.isScrubCommand(proc.command)) return false
    scrubPending = Model.finishScrub(scrubPending, proc)
    if (!scrubPending.length) scrubRetry.stop()
    return true
  }

  function clearProcessCollectorSoon(proc) {
    Qt.callLater(function() {
      if (proc.running) return
      // A submit can land between scheduling and running; do not take its
      // process for the scrub.
      if (proc === loginProc
          && (loginSubmitAfterPrewarmStop || loginPrepareAfterPrewarmStop
              || deviceVerificationPending || loginSubmitted)) return
      proc.command = Model.scrubCommand()
      proc.running = true
    })
  }

  // -------------------------------------------------------------------------
  // Vault data
  // -------------------------------------------------------------------------

  // Stamped when a reader starts and checked when its answer arrives: a `bw`
  // in flight at lock time cannot be recalled, only refused (see "Vault
  // generation" in BitwardenModel.js).
  function beginEpochOperation(name) {
    readEpochs[name] = vaultEpoch
  }

  function epochOperationIsStale(name) {
    return Number(readEpochs[name]) !== Number(vaultEpoch)
  }

  function invalidateEpochOperation(name) {
    readEpochs[name] = vaultEpoch - 1
  }

  function beginVaultRead(name) {
    beginEpochOperation(name)
  }

  function vaultReadIsStale(name) {
    return epochOperationIsStale(name) || !session
  }

  // Items, organizations and folders together: each is its own bw start, and
  // bw spends most of one waiting, so queueing them only added ~3 s. On a
  // session `bw status` has not confirmed yet, the metadata waits for it.
  function beginInitialVaultLoad(showSpinner, forceMetadata) {
    metadataLoadPending = true
    metadataForceRefresh = forceMetadata === true
    loadItems(showSpinner)
    loadPendingMetadata()
  }

  function loadPendingMetadata() {
    if (status !== "unlocked" || !metadataLoadPending) return
    var force = metadataForceRefresh
    metadataLoadPending = false
    metadataForceRefresh = false
    loadOrganizations(force)
    loadFolders(force)
  }

  // Stale-while-revalidate: show what is in memory at once and refresh behind
  // it; the spinner is only for when there is nothing to show.
  function ensureItemsFresh() {
    var haveItems = items.length > 0
    var stale = (Date.now() - itemsLoadedAt) >= itemsFreshMs

    if (haveItems) {
      if (activeWindowData) handleActiveWindowDetected(activeWindowData)
      else rebuildFilter()
      if (!stale) return
    }

    beginInitialVaultLoad(!haveItems, false)
  }

  // `showSpinner` defaults to true; background refreshes pass false.
  function loadItems(showSpinner) {
    if (!session) return
    if (showSpinner !== false) isLoading = true
    // The early read for this vault is still running: it serves this request.
    if (listProc.running && listReadEarly && !vaultReadIsStale("items")) return
    beginVaultRead("items")
    listReadMode = Model.vaultListMode(dependencies)
    if (listReadMode === "blocked") {
      isLoading = false
      if (!vaultReadIsStale("items")) errorMessage = Model.vaultListBlockedMessage(dependencies)
      return
    }
    startVaultListRead(false)
  }

  // The only launcher of the item read, with or without the agent branch.
  // `retrying` (after a failed fan-out) never carries the branch.
  function startVaultListRead(retrying) {
    // Keys go to the agent only from a read of a confirmed session;
    // maybeStartupLoad() loads them once the status has confirmed it.
    listReadEarly = status !== "unlocked"
    var useAgent = !retrying && !listReadEarly && sshAgentGateOpen && Model.isValidLoadId(sshAgentNextLoadId)
    if (useAgent) {
      sshAgentEpoch += 1
      sshAgentLoadId = sshAgentNextLoadId
      sshAgentNextLoadId = ""
      sshAgentLoadActive = true
      sshAgentLoadedForVaultEpoch = root.vaultEpoch
      if (sshAgentProc.stdinEnabled) {
        sshAgentProc.write(Model.sshAgentLoadBeginLine(sshAgentEpoch, sshAgentLoadId))
      }
    }
    listAgentBranchActive = useAgent
    listProc.environment = root.vaultListEnv(useAgent ? sshAgentLoadId : "")
    listProc.command = Model.sanitizedListCommand({ agentBranch: useAgent })
    listProc.running = true
  }

  // The nonce goes to jq in the environment, not argv.
  function vaultListEnv(loadId) {
    var env = root.bwEnv()
    env[Model.loadIdEnvVar()] = loadId !== "" ? loadId : null
    return env
  }

  function onListFinished(rawJson) {
    isLoading = false
    if (vaultReadIsStale("items")) return
    sshCapability = Model.inspectSanitizedVault(rawJson)
    items = Model.parseSanitizedItems(rawJson)
    itemsLoadedAt = Date.now()
    refreshDerivedFromItems()
    if (syncReloadPending) {
      syncReloadPending = false
      isSyncing = false
      flashNotification("Vault synced with Bitwarden")
    }
    if (metadataLoadPending || statusRefreshAfterItems) deferredMetadataTimer.restart()
    // The first read usually beat the handshake; see whether a load is owed.
    maybeStartupLoad()
  }

  function onListProcessExited(exitCode, rawJson, stderrText) {
    if (finishScrubRun(listProc)) return
    var hadAgentBranch = listAgentBranchActive
    var wasEarly = listReadEarly
    listAgentBranchActive = false
    listReadEarly = false
    endSshAgentLoad(exitCode === 0)

    if (exitCode === 0) {
      listRetriedWithoutAgent = false
      onListFinished(rawJson)
      return
    }

    // The agent must never cost the item list: retry once without it.
    if (hadAgentBranch && !listRetriedWithoutAgent && !vaultReadIsStale("items")) {
      listRetriedWithoutAgent = true
      beginVaultRead("items")
      startVaultListRead(true)
      return
    }
    listRetriedWithoutAgent = false

    // An early read that failed after the status confirmed the session is
    // asked again, now as an ordinary read that reports its own failure.
    if (wasEarly && status === "unlocked" && !vaultReadIsStale("items")) {
      beginVaultRead("items")
      startVaultListRead(false)
      return
    }

    isLoading = false
    isSyncing = false
    syncReloadPending = false
    metadataLoadPending = false
    metadataForceRefresh = false
    if (statusRefreshAfterItems) {
      statusRefreshAfterItems = false
    }
    // Before the status answers, a failure is most likely a stale session,
    // which the status will report as locked.
    if (!vaultReadIsStale("items") && !wasEarly) {
      errorMessage = Model.vaultListFailureMessage(stderrText, dependencies, listReadMode)
    }
  }

  // Rarely change; this panel's own changes pass `force`.
  function loadOrganizations(force) {
    if (!session) return
    if (!force && organizations.length > 0 && (Date.now() - orgsLoadedAt) < metaFreshMs) return
    beginVaultRead("organizations")
    listOrgsProc.command = Model.listOrganizationsCommand()
    listOrgsProc.running = true
  }

  function onListOrgsFinished(rawJson) {
    if (vaultReadIsStale("organizations")) return
    organizations = Model.parseOrganizations(rawJson)
    orgsLoadedAt = Date.now()
  }

  function loadFolders(force) {
    if (!session) return
    if (!force && folders.length > 0 && (Date.now() - foldersLoadedAt) < metaFreshMs) return
    beginVaultRead("folders")
    listFoldersProc.command = Model.listFoldersCommand()
    listFoldersProc.running = true
  }

  function onListFoldersFinished(rawJson) {
    if (vaultReadIsStale("folders")) return
    folders = Model.parseFolders(rawJson)
    foldersLoadedAt = Date.now()
  }

  function selectFolder(folderId) {
    selectedFolder = folderId
    selectedIndex = 0
    openFilterGroup = ""
    rebuildFilter()
  }

  function toggleFilterGroup(group) {
    if (openFilterGroup === group) {
      openFilterGroup = ""
      return
    }
    openFilterGroup = group
    // Start on the active option, so Enter changes nothing.
    var opts = filterOptions(group)
    filterOptionIndex = 0
    for (var i = 0; i < opts.length; i++) {
      if (opts[i].active) { filterOptionIndex = i; break }
    }
  }

  // Any other action closes the drawer.
  function closeFilterGroup() {
    if (openFilterGroup !== "") openFilterGroup = ""
  }

  function moveFilterCursor(delta) {
    var n = currentFilterOptions.length
    if (n === 0) return
    filterOptionIndex = Math.max(0, Math.min(n - 1, filterOptionIndex + delta))
  }

  function activateFilterOption() {
    var opts = currentFilterOptions
    if (filterOptionIndex < 0 || filterOptionIndex >= opts.length) return
    applyFilterOption(openFilterGroup, opts[filterOptionIndex].id)
  }

  // Labels for the collapsed filter buttons.
  function folderFilterLabel() {
    if (selectedFolder === "all") return "All"
    if (selectedFolder === "none") return "Unfiled"
    return Model.folderName(folders, selectedFolder) || "Folder"
  }

  function organizationFilterLabel() {
    if (selectedOrg === "all") return "All"
    if (selectedOrg === "personal") return "Personal"
    for (var i = 0; i < organizations.length; i++) {
      if (organizations[i].id === selectedOrg) return organizations[i].name
    }
    return "Vault"
  }

  function typeFilterLabel() {
    for (var i = 0; i < categories.length; i++) {
      if (categories[i].id === selectedCategory) return categories[i].label
    }
    return "All"
  }

  // Option rows for the open group, in one shape for all three lists.
  function filterOptions(group) {
    var out = []
    var i
    if (group === "folders") {
      out.push({ id: "all", label: "All Folders", icon: "󰉋", active: selectedFolder === "all" })
      out.push({ id: "none", label: "No Folder", icon: "󰉖", active: selectedFolder === "none" })
      for (i = 0; i < folders.length; i++) {
        out.push({ id: folders[i].id, label: folders[i].name, icon: "󰉋", active: selectedFolder === folders[i].id })
      }
    } else if (group === "organizations") {
      out.push({ id: "all", label: "All Organizations", icon: "󰦑", active: selectedOrg === "all" })
      out.push({ id: "personal", label: "My Vault", icon: "", active: selectedOrg === "personal" })
      for (i = 0; i < organizations.length; i++) {
        out.push({ id: organizations[i].id, label: organizations[i].name, icon: "󰓹", active: selectedOrg === organizations[i].id })
      }
    } else if (group === "types") {
      for (i = 0; i < visibleCategories.length; i++) {
        out.push({ id: visibleCategories[i].id, label: visibleCategories[i].label, icon: visibleCategories[i].icon, active: selectedCategory === visibleCategories[i].id })
      }
    }
    return out
  }

  function applyFilterOption(group, id) {
    if (group === "folders") selectFolder(id)
    else if (group === "organizations") { selectOrganization(id); openFilterGroup = "" }
    else if (group === "types") { selectCategory(id); openFilterGroup = "" }
  }

  function toggleFormPicker(which) {
    formPicker = (formPicker === which) ? "" : which
  }

  // Escape, from the key catcher and the shortcut interceptor alike (the
  // catcher is blocked on screens with a text field). Innermost first: a
  // drawer or picker, then the screen, then the panel.
  function handleEscape() {
    // A signing request first: dismissing it means "no".
    if (currentScreen === "sshApproval" || sshUnlockRequest) {
      denySshRequest()
      return
    }
    if (openFilterGroup !== "") {
      closeFilterGroup()
      return
    }
    if (currentScreen === "edit" && formPicker !== "") {
      formPicker = ""
      return
    }
    if (currentScreen === "sends") {
      if (sendMode === "create") {
        sendError = ""
        sendMode = "list"
        // The screen does not change, so re-home focus from the hidden field.
        restoreScreenFocus()
      } else {
        currentScreen = "main"
      }
    } else if (currentScreen === "generator") {
      // Back to the item form if opened from it.
      closeGenerator()
    } else if (currentScreen === "fingerprint") {
      fpError = ""
      currentScreen = "settings"
    } else if (currentScreen === "fido") {
      fidoUnlocker.error = ""
      currentScreen = "settings"
    } else if (currentScreen === "pin") {
      pinError = ""
      pinUnlockError = ""
      currentScreen = "settings"
    } else if (currentScreen === "settings") {
      closeSettings()
    } else if (currentScreen === "accounts") {
      closeAccounts()
    } else if (currentScreen === "setup") {
      dismissSetup()
    } else if (currentScreen === "edit") {
      // Escape discards the form, like its Cancel button.
      currentScreen = formIsEditing ? "detail" : "main"
    } else if (currentScreen === "detail") {
      currentScreen = "main"
    } else {
      close()
    }
  }

  // Qt keeps focus on hidden items, so a field on the screen just left would
  // keep the keyboard. Re-home focus on every screen change.
  onCurrentScreenChanged: {
    // Only while its screen is up: the port is open to every local account,
    // and `bw serve` reports the account email even when locked.
    if (currentScreen !== "generator") stopGeneratorServe()
    // Leaving a setup form drops its typed master password.
    if (currentScreen !== "pin") abandonPinSetup()
    if (currentScreen !== "fingerprint") abandonFingerprintSetup()
    if (currentScreen !== "fido") fidoUnlocker.abandonSetup()
    restoreScreenFocus()
  }

  function restoreScreenFocus() {
    Qt.callLater(function() {
      if (status !== "unlocked") { focusAppropriateField(); return }
      switch (currentScreen) {
        case "main": presenter.focusField("search"); return
        case "edit": presenter.focusField("formName"); return
        // These open through a function that focuses their own first field.
        case "pin": case "fingerprint": case "fido": return
        case "sends": if (sendMode === "create") return; break
      }
      // Everything else is keyboard-navigated rather than typed into.
      presenter.focusField("keyCatcher")
    })
  }

  function setFormFolder(id) {
    formFolderId = id
    formPicker = ""
  }

  // Collections belong to one organization; changing owner resets them.
  function setFormOrganization(id) {
    formOrgId = id
    formPicker = ""
    formCollectionIds = []
    formCollections = []
    if (id && id !== "personal" && id !== "all") loadOrgCollections(id)
  }

  function loadOrgCollections(orgId) {
    if (!session || !orgId) return
    formCollectionsLoading = true
    beginVaultRead("collections")
    orgCollectionsProc.command = Model.listOrgCollectionsCommand(orgId)
    orgCollectionsProc.running = true
  }

  function onOrgCollectionsLoaded(raw) {
    formCollectionsLoading = false
    if (vaultReadIsStale("collections")) return
    formCollections = Model.parseCollections(raw)
    // A single collection is not a choice; pre-select it.
    if (formCollections.length === 1 && formCollectionIds.length === 0) {
      formCollectionIds = [formCollections[0].id]
    }
  }

  function toggleFormCollection(id) {
    var next = []
    var found = false
    for (var i = 0; i < formCollectionIds.length; i++) {
      if (formCollectionIds[i] === id) found = true
      else next.push(formCollectionIds[i])
    }
    if (!found) next.push(id)
    formCollectionIds = next
  }

  function isFormCollectionSelected(id) {
    for (var i = 0; i < formCollectionIds.length; i++) {
      if (formCollectionIds[i] === id) return true
    }
    return false
  }

  function formFolderLabel() {
    if (!formFolderId) return "No Folder"
    return Model.folderName(folders, formFolderId) || "No Folder"
  }

  function formOrgLabel() {
    if (!formOrgId || formOrgId === "personal") return "My Vault"
    for (var i = 0; i < organizations.length; i++) {
      if (organizations[i].id === formOrgId) return organizations[i].name
    }
    return "My Vault"
  }

  function submitNewFolder() {
    var name = String(newFolderName || "").trim()
    if (!name) return
    creatingFolder = true
    beginVaultRead("folderCreate")
    createFolderProc.command = Model.createFolderCommand()
    createFolderProc.running = true
  }

  function onFolderCreated(exitCode, stdoutText) {
    creatingFolder = false
    if (vaultReadIsStale("folderCreate")) return
    if (exitCode !== 0) {
      errorMessage = "Could not create folder"
      return
    }
    var created = null
    try { created = JSON.parse(stdoutText) } catch (e) { created = null }
    newFolderName = ""
    // Created from the item form, so file the item in it.
    if (created && created.id) formFolderId = String(created.id)
    flashNotification("Folder created")
    loadFolders(true)
  }

  function syncVault() {
    closeFilterGroup()
    if (!session) return
    isSyncing = true
    beginVaultRead("sync")
    syncProc.command = Model.syncCommand()
    syncProc.running = true
  }

  function onSyncFinished(exitCode) {
    if (vaultReadIsStale("sync")) return
    if (exitCode === 0) {
      itemsLoadedAt = 0
      syncReloadPending = true
      beginInitialVaultLoad(true, true)
    } else {
      isSyncing = false
      syncReloadPending = false
      errorMessage = "Sync failed"
    }
  }

  function openDetail(item) {
    closeFilterGroup()
    if (!item || !item.id) return
    learnFromPick(item)
    isLoading = true
    errorMessage = ""
    revealedFields = ({})
    showDeleteConfirm = false
    detailItem = null
    detailPassword = ""
    liveTotp = ""
    // Another item's downloads say nothing about this one's.
    attachmentQueue = []
    attachmentSaved = ({})
    currentScreen = "detail"

    // Render from the list's raw object; `bw get item` only as a fallback.
    var detail = item.rawObject ? Model.itemDetailFromObject(item.rawObject) : null
    if (detail) {
      isLoading = false
      detailItem = detail
      detailPassword = detail.password
    } else {
      beginVaultRead("detail")
      if (item.typeCode === 5) {
        isLoading = false
        errorMessage = "SSH keys are read-only public records"
        currentScreen = "main"
        return
      }
      getItemProc.command = Model.getItemCommand(item.id, item.typeCode)
      getItemProc.running = true
    }

    // The TOTP is time-based, so it is fetched alongside.
    if (item.hasTotp) {
      fetchTotp(item.id)
    }
  }

  function onDetailFinished(rawJson) {
    isLoading = false
    if (vaultReadIsStale("detail")) return
    var parsed = Model.parseItemDetail(rawJson)
    if (parsed) {
      detailItem = parsed
      detailPassword = parsed.password
    } else {
      errorMessage = "Could not load item details"
    }
  }

  // -------------------------------------------------------------------------
  // Attachments
  // -------------------------------------------------------------------------

  function cancelAttachmentDownloads() {
    attachmentQueue = []
    attachmentBusyId = ""
    invalidateEpochOperation("attachment")
    // Its process group cleans up its staging dir and commits nothing after
    // a lock or close.
    if (attachmentProc.running) attachmentProc.running = false
  }

  function queueAttachment(att) {
    if (!detailItem || !att || !att.id) return
    if (attachmentBusyId === att.id) return
    for (var i = 0; i < attachmentQueue.length; i++) {
      if (attachmentQueue[i].id === att.id) return
    }
    resetAutoLockTimer()
    errorMessage = ""
    var next = attachmentQueue.slice()
    // The declared size lets the saver refuse early and check free space.
    next.push({ id: att.id, fileName: att.fileName, itemId: detailItem.id, size: att.size })
    attachmentQueue = next
    pumpAttachmentQueue()
  }

  function saveAllAttachments() {
    if (!detailItem || !detailItem.attachments) return
    for (var i = 0; i < detailItem.attachments.length; i++) {
      queueAttachment(detailItem.attachments[i])
    }
  }

  function pumpAttachmentQueue() {
    if (attachmentBusyId !== "" || attachmentQueue.length === 0) return
    if (!session) {
      attachmentQueue = []
      errorMessage = "Vault is locked or session expired. Please unlock your vault."
      return
    }
    var next = attachmentQueue.slice()
    var job = next.shift()
    attachmentQueue = next
    attachmentBusyId = job.id
    beginVaultRead("attachment")
    attachmentProc.command = Model.attachmentDownloadCommand(job.id, job.itemId, job.fileName, job.size)
    attachmentProc.running = true
  }

  function onAttachmentDownloaded(exitCode, savedPath, stderrText) {
    var id = attachmentBusyId
    attachmentBusyId = ""
    if (vaultReadIsStale("attachment")) return
    var path = String(savedPath || "").trim()

    if (exitCode !== 0 || !path) {
      // bw's own message is the useful one ("Not found.", permissions).
      var err = String(stderrText || "").trim().split("\n")[0]
      errorMessage = err ? ("Could not save the attachment: " + err)
                         : "Could not save the attachment"
      attachmentQueue = []
      return
    }

    var saved = {}
    for (var k in attachmentSaved) saved[k] = attachmentSaved[k]
    saved[id] = path
    attachmentSaved = saved
    flashNotification("Saved " + Model.baseName(path))
    pumpAttachmentQueue()
  }

  function attachmentSavedPath(id) {
    return (attachmentSaved && attachmentSaved[id]) ? String(attachmentSaved[id]) : ""
  }

  function isAttachmentQueued(id) {
    for (var i = 0; i < attachmentQueue.length; i++) {
      if (attachmentQueue[i].id === id) return true
    }
    return false
  }

  function openSavedAttachment(id) {
    var path = attachmentSaved[id]
    if (!path) return
    resetAutoLockTimer()
    Quickshell.execDetached(["xdg-open", path])
  }

  function revealSavedAttachment(id) {
    var path = attachmentSaved[id]
    if (!path) return
    var dir = Model.parentDirectory(path)
    if (!dir) return
    resetAutoLockTimer()
    Quickshell.execDetached(["xdg-open", dir])
  }

  function fetchTotp(itemId, copyWhenReady) {
    if (!session || !itemId) return
    // The list already holds the key: compute the code here rather than start
    // bw for it. Keys TotpModel.js does not mirror exactly still ask bw.
    var local = localTotp(String(itemId))
    if (local) {
      if (copyWhenReady) totpCopyItemId = String(itemId)
      applyTotpCode(String(itemId), local)
      return
    }
    if (copyWhenReady) totpCopyItemId = String(itemId)
    if (getTotpProc.running || totpRestartPending) {
      if (totpRequestItemId !== String(itemId)) {
        totpQueuedItemId = String(itemId)
        totpQueuedEpoch = vaultEpoch
      }
      return
    }
    startTotpFetch(String(itemId))
  }

  function startTotpFetch(itemId) {
    if (!session || !itemId) return
    totpRequestItemId = itemId
    beginVaultRead("totp")
    getTotpProc.command = Model.getTotpCommand(itemId)
    getTotpProc.running = true
  }

  function onTotpProcessExited(exitCode, code) {
    var itemId = totpRequestItemId
    totpRequestItemId = ""
    if (exitCode === 0) onTotpFinished(itemId, code)
    else if (totpCopyItemId === itemId) {
      totpCopyItemId = ""
      errorMessage = "Could not read this TOTP code"
    }

    continueTotpQueue(false)
  }

  function continueTotpQueue(collectorIsClean) {
    var queued = totpQueuedItemId
    var queuedEpoch = totpQueuedEpoch
    totpQueuedItemId = ""
    totpQueuedEpoch = -1
    if (queued) {
      // Reserve the Process before the deferred restart, so a newer request
      // cannot slip in and be overwritten.
      totpRestartPending = true
      totpRequestItemId = queued
      Qt.callLater(function() {
        root.totpRestartPending = false
        if (queuedEpoch === root.vaultEpoch && root.session) root.startTotpFetch(queued)
        else {
          if (root.totpRequestItemId === queued) root.totpRequestItemId = ""
          if (!collectorIsClean) root.clearProcessCollectorSoon(getTotpProc)
        }
      })
    }
    else if (!collectorIsClean) clearProcessCollectorSoon(getTotpProc)
  }

  // The code for `itemId` from its key in the list, or "" if bw must answer.
  function localTotp(itemId) {
    var key = ""
    if (detailItem && detailItem.id === itemId) key = detailItem.totpKey || ""
    if (!key) {
      for (var i = 0; i < items.length; i++) {
        if (items[i].id === itemId) {
          key = items[i].totpKey || ""
          break
        }
      }
    }
    if (!key) return ""
    var result = Totp.generate(key, Date.now())
    return result ? result.code : ""
  }

  function onTotpFinished(itemId, code) {
    if (vaultReadIsStale("totp")) return
    applyTotpCode(itemId, code)
  }

  function applyTotpCode(itemId, code) {
    var c = String(code || "").trim()
    if (detailItem && detailItem.id === itemId) liveTotp = c
    if (totpFollowupActive && totpFollowupItem && totpFollowupItem.id === itemId) {
      totpFollowupCode = c
    }
    if (totpCopyItemId === itemId) {
      totpCopyItemId = ""
      if (c) copyToClipboard(c, "TOTP code")
      else errorMessage = "Could not read this TOTP code"
    }
  }

  // -------------------------------------------------------------------------
  // Create, edit, delete
  // -------------------------------------------------------------------------

  function customFieldTypeLabel(type) {
    switch (Number(type)) {
      case 1: return "Hidden"
      case 2: return "Boolean"
      case 3: return "Linked"
      default: return "Text"
    }
  }

  function customFieldBooleanValue(value) {
    return value === true || String(value).toLowerCase() === "true"
  }

  // Bitwarden LinkedIdType values. Notes have none, as in the browser
  // extension.
  function customFieldLinkedOptions(typeCode) {
    if (Number(typeCode) === 1) return [
      { id: 100, label: "Username" }, { id: 101, label: "Password" }
    ]
    if (Number(typeCode) === 3) return [
      { id: 300, label: "Cardholder name" }, { id: 304, label: "Brand" },
      { id: 305, label: "Number" }, { id: 301, label: "Expiry month" },
      { id: 302, label: "Expiry year" }, { id: 303, label: "Security code" }
    ]
    if (Number(typeCode) === 4) return [
      { id: 400, label: "Title" }, { id: 416, label: "First name" },
      { id: 401, label: "Middle name" }, { id: 417, label: "Last name" },
      { id: 418, label: "Full name" }, { id: 413, label: "Username" },
      { id: 409, label: "Company" }, { id: 410, label: "Email" },
      { id: 411, label: "Phone" }, { id: 412, label: "Social security number" },
      { id: 414, label: "Passport number" }, { id: 415, label: "Licence number" },
      { id: 402, label: "Address line 1" }, { id: 403, label: "Address line 2" },
      { id: 404, label: "Address line 3" }, { id: 405, label: "City / town" },
      { id: 406, label: "State / county" }, { id: 407, label: "Postal code" },
      { id: 408, label: "Country" }
    ]
    return []
  }

  function customFieldLinkedLabel(linkedId) {
    var options = customFieldLinkedOptions(formTypeCode)
    for (var i = 0; i < options.length; i++) {
      if (Number(options[i].id) === Number(linkedId)) return options[i].label
    }
    return "Choose a field"
  }

  function copyCustomFieldsForForm(fields) {
    var source = fields || []
    var out = []
    for (var i = 0; i < source.length; i++) {
      var field = source[i]
      if (!field) continue
      out.push({
        name: String(field.name || ""),
        value: Number(field.type) === 2
          ? customFieldBooleanValue(field.value)
          : (field.value === undefined || field.value === null ? "" : String(field.value)),
        type: Number(field.type || 0),
        linkedId: field.linkedId === undefined || field.linkedId === null
          ? null : Number(field.linkedId),
        revealed: false
      })
    }
    return out
  }

  function beginCustomFieldLabelEdit(index) {
    if (index < 0 || index >= formCustomFields.length) return
    formCustomFieldLabelDraft = String(formCustomFields[index].name || "")
    formPicker = "customLabel:" + index
  }

  function saveCustomFieldLabel(index) {
    var label = String(formCustomFieldLabelDraft || "").trim()
    if (!label || index < 0 || index >= formCustomFields.length) return
    var next = formCustomFields.slice()
    var old = next[index]
    next[index] = {
      name: label, value: old.value, type: old.type,
      linkedId: old.linkedId, revealed: old.revealed
    }
    formCustomFields = next
    formCustomFieldLabelDraft = ""
    formPicker = ""
  }

  function cancelCustomFieldLabelEdit() {
    formCustomFieldLabelDraft = ""
    formPicker = ""
  }

  // Write through the form's own array: a Repeater's modelData may be a
  // delegate-local copy that saveItemForm never sees. No reassignment, so
  // focus stays put while typing.
  function setFormCustomFieldValue(index, value) {
    if (index < 0 || index >= formCustomFields.length) return
    formCustomFields[index].value = value
  }

  function setFormCustomFieldLinkedId(index, linkedId) {
    if (index < 0 || index >= formCustomFields.length) return
    formCustomFields[index].linkedId = Number(linkedId)
  }

  function removeFormCustomField(index) {
    if (index < 0 || index >= formCustomFields.length) return
    var next = formCustomFields.slice()
    next.splice(index, 1)
    formCustomFields = next
    formCustomFieldLabelDraft = ""
    if (formPicker.indexOf("custom") === 0) formPicker = ""
  }

  function addFormCustomField() {
    var label = String(formNewCustomFieldName || "").trim()
    if (!label) return
    var type = Number(formNewCustomFieldType)
    var options = customFieldLinkedOptions(formTypeCode)
    if (type === 3 && options.length === 0) type = 0
    var next = formCustomFields.slice()
    next.push({
      name: label,
      value: type === 2 ? false : "",
      type: type,
      linkedId: type === 3 ? options[0].id : null,
      revealed: false
    })
    formCustomFields = next
    formNewCustomFieldName = ""
    formCustomFieldLabelDraft = ""
    formNewCustomFieldType = 0
    formPicker = ""
  }

  function changeFormType(typeCode) {
    var nextType = Number(typeCode)
    if (nextType === formTypeCode) return
    formTypeCode = nextType
    formPicker = ""
    // On a type change, reset a linked field to a valid target, or to plain
    // text for a note (which has none).
    var options = customFieldLinkedOptions(nextType)
    if (formNewCustomFieldType === 3 && options.length === 0) formNewCustomFieldType = 0
    var next = copyCustomFieldsForForm(formCustomFields)
    for (var i = 0; i < next.length; i++) {
      if (next[i].type !== 3) continue
      if (options.length === 0) {
        next[i].type = 0
        next[i].linkedId = null
        next[i].value = ""
      } else {
        next[i].linkedId = options[0].id
      }
    }
    formCustomFields = next
  }

  // Card or identity fields for the payload builders; null for logins and
  // notes, which tells buildEditPayload to leave the sub-object alone.
  function formTypeFields() {
    if (formTypeCode === 3) {
      return {
        cardholderName: formCardholderName, brand: formCardBrand,
        number: formCardNumber, expMonth: formCardExpMonth,
        expYear: formCardExpYear, code: formCardCode
      }
    }
    if (formTypeCode === 4) {
      return {
        title: formIdTitle, firstName: formIdFirstName,
        middleName: formIdMiddleName, lastName: formIdLastName,
        username: formIdUsername, company: formIdCompany,
        email: formIdEmail, phone: formIdPhone, ssn: formIdSsn,
        passportNumber: formIdPassport, licenseNumber: formIdLicense,
        address1: formIdAddress1, address2: formIdAddress2,
        address3: formIdAddress3, city: formIdCity, state: formIdState,
        postalCode: formIdPostalCode, country: formIdCountry
      }
    }
    return null
  }

  // An empty item form (a new login).
  function resetItemForm() {
    formIsEditing = false
    formItemId = ""
    formTypeCode = 1
    clearTypeFields()
    formName = ""
    formUsername = ""
    formPassword = ""
    formTotp = ""
    formUri = ""
    formNotes = ""
    formCustomFields = []
    formNewCustomFieldType = 0
    formNewCustomFieldName = ""
    formCustomFieldLabelDraft = ""
    formFavorite = false
    formOrgId = ""
    formFolderId = ""
    formPicker = ""
    formCollections = []
    formCollectionIds = []
    formCollectionsLoading = false
    newFolderName = ""
    creatingFolder = false
    formPasswordRevealed = false
  }

  // Empty every card and identity field on form reset.
  function clearTypeFields() {
    formCardholderName = ""; formCardBrand = ""; formCardNumber = ""
    formCardExpMonth = ""; formCardExpYear = ""; formCardCode = ""
    formIdTitle = ""; formIdFirstName = ""; formIdMiddleName = ""
    formIdLastName = ""; formIdUsername = ""; formIdCompany = ""
    formIdEmail = ""; formIdPhone = ""; formIdSsn = ""
    formIdPassport = ""; formIdLicense = ""; formIdAddress1 = ""
    formIdAddress2 = ""; formIdAddress3 = ""; formIdCity = ""
    formIdState = ""; formIdPostalCode = ""; formIdCountry = ""
  }

  function loadTypeFields(item) {
    clearTypeFields()
    if (!item) return
    var c = item.card || null
    if (c) {
      formCardholderName = String(c.cardholderName || "")
      formCardBrand = String(c.brand || "")
      formCardNumber = String(c.number || "")
      formCardExpMonth = String(c.expMonth || "")
      formCardExpYear = String(c.expYear || "")
      formCardCode = String(c.code || "")
    }
    var d = item.identity || null
    if (d) {
      formIdTitle = String(d.title || "")
      formIdFirstName = String(d.firstName || "")
      formIdMiddleName = String(d.middleName || "")
      formIdLastName = String(d.lastName || "")
      formIdUsername = String(d.username || "")
      formIdCompany = String(d.company || "")
      formIdEmail = String(d.email || "")
      formIdPhone = String(d.phone || "")
      formIdSsn = String(d.ssn || "")
      formIdPassport = String(d.passportNumber || "")
      formIdLicense = String(d.licenseNumber || "")
      formIdAddress1 = String(d.address1 || "")
      formIdAddress2 = String(d.address2 || "")
      formIdAddress3 = String(d.address3 || "")
      formIdCity = String(d.city || "")
      formIdState = String(d.state || "")
      formIdPostalCode = String(d.postalCode || "")
      formIdCountry = String(d.country || "")
    }
  }

  function startAddNewItem() {
    closeFilterGroup()
    resetItemForm()
    formOrgId = selectedOrg !== "all" ? selectedOrg : ""
    formFolderId = (selectedFolder !== "all" && selectedFolder !== "none") ? selectedFolder : ""
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
    errorMessage = ""
    currentScreen = "edit"
  }

  // The whole form, so a failed save can be reopened exactly.
  function captureItemForm() {
    return {
      isEditing: formIsEditing, itemId: formItemId, typeCode: formTypeCode,
      name: formName, username: formUsername, password: formPassword,
      totp: formTotp, uri: formUri, notes: formNotes, favorite: formFavorite,
      orgId: formOrgId, folderId: formFolderId,
      collectionIds: (formCollectionIds || []).slice(),
      typeFields: formTypeFields(),
      customFields: copyCustomFieldsForForm(formCustomFields)
    }
  }

  function restoreItemForm(f) {
    if (!f) return
    formIsEditing = f.isEditing
    formItemId = f.itemId
    formTypeCode = f.typeCode
    formName = f.name
    formUsername = f.username
    formPassword = f.password
    formTotp = f.totp
    formUri = f.uri
    formNotes = f.notes
    formFavorite = f.favorite
    formOrgId = f.orgId
    formFolderId = f.folderId
    formCollectionIds = (f.collectionIds || []).slice()
    formCustomFields = copyCustomFieldsForForm(f.customFields)
    formNewCustomFieldType = 0
    formNewCustomFieldName = ""
    formCustomFieldLabelDraft = ""
    loadTypeFields({ card: f.typeCode === 3 ? f.typeFields : null,
                     identity: f.typeCode === 4 ? f.typeFields : null })
    formPicker = ""
    formPasswordRevealed = false
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
    currentScreen = "edit"
  }

  // Reopens the form a refused save was made from.
  function reopenFailedSave() {
    if (!failedSave) return
    var f = failedSave.form
    failedSave = null
    errorMessage = ""
    restoreItemForm(f)
  }

  function startEditItem(item) {
    if (!item || item.typeCode === 5) {
      if (item && item.typeCode === 5) errorMessage = "SSH keys are read-only public records"
      return
    }
    // Not saved yet (a create has no id): editing would race the save.
    if (item.pending) {
      errorMessage = "Still saving this item -- one moment"
      return
    }
    formIsEditing = true
    formItemId = item.id
    formTypeCode = item.typeCode || 1
    formName = item.name || ""
    formUsername = item.username || ""
    formPassword = detailPassword || (item.rawObject && item.rawObject.login ? item.rawObject.login.password : "") || ""
    formTotp = item.totpKey || (item.rawObject && item.rawObject.login ? item.rawObject.login.totp : "") || ""
    formUri = item.uris && item.uris.length > 0 ? item.uris[0] : ""
    formNotes = item.notes || ""
    formFavorite = Boolean(item.favorite)
    formOrgId = item.organizationId || ""
    formFolderId = item.folderId || ""
    newFolderName = ""
    formPicker = ""
    formCollections = []
    // Editing keeps whatever collections the item already has until changed.
    formCollectionIds = (item.rawObject && item.rawObject.collectionIds)
      ? item.rawObject.collectionIds.slice() : []
    formCustomFields = copyCustomFieldsForForm(
      item.rawObject && item.rawObject.fields ? item.rawObject.fields : item.fields)
    formNewCustomFieldType = 0
    formNewCustomFieldName = ""
    formCustomFieldLabelDraft = ""
    // Open with the real card/identity values, not blanks saved over them.
    loadTypeFields(item)
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
    formPasswordRevealed = false
    errorMessage = ""
    currentScreen = "edit"
  }

  // The form closes as soon as the save starts; the list shows the item marked
  // as saving until the vault's answer replaces it. One save at a time (one
  // process); another is refused with a reason.
  function saveItemForm() {
    if (pendingSave) {
      errorMessage = "Still saving " + pendingSave.name + " -- one moment"
      return
    }

    // Catch what the CLI would refuse before the form is gone.
    var problem = Model.validateItemForm(formName, formOrgId, formCollectionIds, formCustomFields)
    if (problem) {
      errorMessage = problem
      return
    }

    var editing = formIsEditing
    var payload = editing
      ? Model.buildEditPayload(detailItem, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId, formFolderId, formCollectionIds, formTypeFields(), formCustomFields)
      : Model.buildCreatePayload(formTypeCode, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId, formFolderId, formCollectionIds, formTypeFields(), formCustomFields)
    if (!payload) {
      errorMessage = editing ? "This item is read-only" : "This item type is read-only"
      return
    }

    errorMessage = ""
    beginVaultRead("itemSave")

    // A create gets a provisional id until the server assigns one.
    var rowId = editing ? formItemId : Model.pendingItemId(Date.now())
    var optimistic = Model.optimisticItem(payload, rowId)

    pendingSave = {
      id: rowId,
      isCreate: !editing,
      name: String(formName || "Untitled").trim(),
      // The list's row before, restored if the save fails.
      previous: editing ? Model.findItemById(items, rowId) : null,
      // The form, reopenable if the save fails.
      form: captureItemForm()
    }

    itemPayloadJson = JSON.stringify(payload)
    if (editing) {
      editItemProc.command = Model.editItemCommand(formItemId, formTypeCode)
      editItemProc.running = true
    } else {
      createItemProc.command = Model.createItemCommand(payload)
      createItemProc.running = true
    }

    if (optimistic) {
      items = Model.replaceItemById(items, rowId, optimistic)
      itemsLoadedAt = Date.now()
      refreshDerivedFromItems()
    }
    currentScreen = "main"
  }

  function onSaveItemFinished(exitCode, stdoutText, stderrText) {
    isLoading = false
    // Holds the password in clear; dropped once its process exits.
    itemPayloadJson = ""

    var save = pendingSave
    pendingSave = null
    if (vaultReadIsStale("itemSave")) return

    if (exitCode !== 0) {
      // Refused: restore the previous row (or remove a created one) and keep
      // the form for reopening.
      if (save) {
        items = Model.replaceItemById(items, save.id, save.previous)
        itemsLoadedAt = Date.now()
        refreshDerivedFromItems()
        failedSave = { name: save.name, form: save.form }
        errorMessage = "Could not save " + save.name + ". " + (stderrText || "")
      } else {
        errorMessage = stderrText || "Failed to save item"
      }
      return
    }

    flashNotification(save && save.isCreate ? "Item created successfully!" : "Item updated successfully!")

    // Update the list from the saved item the command printed. If it was not
    // sanitized (marker) or not recognised (null), reload the full list.
    var spliced = String(stdoutText).indexOf(Model.savedUnsanitizedMarker()) === 0
      ? null : Model.spliceSavedItem(items, stdoutText, save ? save.id : "")
    if (!spliced) {
      // A provisional row must never survive a reload it is not part of.
      if (save && save.isCreate) items = Model.replaceItemById(items, save.id, null)
      loadItems()
      return
    }
    items = spliced
    itemsLoadedAt = Date.now()
    refreshDerivedFromItems()
  }

  // The row disappears at once; if the vault refuses, it comes back.
  function deleteCurrentItem() {
    if (!detailItem || !detailItem.id || detailItem.typeCode === 5) return
    if (detailItem.pending || Model.isPendingItemId(detailItem.id)) {
      errorMessage = "Still saving this item -- one moment"
      return
    }
    if (pendingDelete) {
      errorMessage = "Still deleting " + pendingDelete.name + " -- one moment"
      return
    }

    var id = detailItem.id
    pendingDelete = {
      id: id,
      name: String(detailItem.name || "this item"),
      // The row as the list holds it, so a refusal can put it back exactly.
      previous: Model.findItemById(items, id)
    }

    beginVaultRead("itemDelete")
    deleteItemProc.command = Model.deleteItemCommand(id, detailItem.typeCode)
    deleteItemProc.running = true

    showDeleteConfirm = false
    items = Model.replaceItemById(items, id, null)
    itemsLoadedAt = Date.now()
    refreshDerivedFromItems()
    currentScreen = "main"
  }

  function onDeleteItemFinished(exitCode, stdoutText, stderrText) {
    isLoading = false
    showDeleteConfirm = false

    var removal = pendingDelete
    pendingDelete = null
    if (vaultReadIsStale("itemDelete")) return

    if (exitCode === 0) {
      // Nothing else changed; no reload needed.
      flashNotification("Item deleted")
      return
    }

    // Still in the vault: put the row back.
    if (removal && removal.previous) {
      items = Model.replaceItemById(items, removal.id, removal.previous)
      itemsLoadedAt = Date.now()
      refreshDerivedFromItems()
      errorMessage = "Could not delete " + removal.name + ". " + (stderrText || "")
    } else {
      errorMessage = stderrText || "Failed to delete item"
    }
  }

  // -------------------------------------------------------------------------
  // Filtering and selection
  // -------------------------------------------------------------------------

  // Everything derived from `items` (filter and suggestions); every change to
  // the list comes through here.
  function refreshDerivedFromItems() {
    if (activeWindowData) {
      handleActiveWindowDetected(activeWindowData)
    } else {
      rebuildFilter()
    }
  }

  // Called per keystroke; the rebuild waits for typing to pause.
  function scheduleFilterRebuild() {
    searchDebounceTimer.restart()
  }

  function rebuildFilter() {
    var baseList = Model.filterItems(items, searchQuery, selectedCategory, selectedOrg, selectedFolder)
    if (searchQuery.trim() === "" && selectedCategory === "all" && selectedOrg === "all" && selectedFolder === "all" && !suggestionsDismissed && suggestedItems.length > 0) {
      var suggestedIds = {}
      var topMatches = []
      for (var s = 0; s < suggestedItems.length; s++) {
        var sItem = Object.assign({}, suggestedItems[s], { isSuggested: true })
        topMatches.push(sItem)
        suggestedIds[sItem.id] = true
      }
      var otherItems = []
      for (var o = 0; o < baseList.length; o++) {
        if (!suggestedIds[baseList[o].id]) {
          otherItems.push(baseList[o])
        }
      }
      filteredItems = topMatches.concat(otherItems)
    } else {
      filteredItems = baseList
    }

    if (selectedIndex >= filteredItems.length) {
      selectedIndex = Math.max(0, filteredItems.length - 1)
    }
    if (selectedIndex < 0 && filteredItems.length > 0) {
      selectedIndex = 0
    }
  }

  // Empty-list text. For SSH, "no keys" and "server support unconfirmed"
  // differ.
  function emptyListMessage() {
    if (selectedCategory === "sshKey" && filteredItems.length === 0 && sshCapability
        && sshCapability.state === "unconfirmed") {
      return sshCapability.message
    }
    if (items.length === 0) return "Vault is empty"
    return "No items match '" + searchQuery + "'"
  }

  function selectCategory(catId) {
    selectedCategory = catId === "sshKey" && !sshUiAvailable ? "all" : catId
    selectedIndex = 0
    rebuildFilter()
  }

  function selectOrganization(orgId) {
    selectedOrg = orgId
    selectedIndex = 0
    rebuildFilter()
  }

  function cycleCategory(delta) {
    var currentIndex = 0
    for (var i = 0; i < visibleCategories.length; i++) {
      if (visibleCategories[i].id === selectedCategory) {
        currentIndex = i
        break
      }
    }
    var nextIndex = (currentIndex + delta + visibleCategories.length) % visibleCategories.length
    selectCategory(visibleCategories[nextIndex].id)
  }

  // Alt+letter, from inside the search box (bare letters are search text).
  // Same table as the bare letters, except Alt+s is Sends and Alt+, Settings.
  function runAltShortcut(lower) {
    if (lower === "s") { openSends(); return true }
    if (lower === "a") { openAccounts(); return true }
    if (lower === ",") { openSettings(); return true }
    return runShortcut(lower)
  }

  function runShortcut(lower) {
    var item = getSelectedItem()
    switch (lower) {
      case "y": case "p": if (item) copyPassword(item); return true
      case "u": case "c": if (item) copyUsername(item); return true
      case "m": if (item && item.hasTotp) copyTotpCode(item); return true
      case "w": if (item && item.uris && item.uris.length > 0) openUrl(item.uris[0]); return true
      case "e": if (item) openDetail(item); return true
      case "n": startAddNewItem(); return true
      case "l": lockVault(); return true
      case "r": syncVault(); return true
      case "f": toggleFilterGroup("folders"); return true
      case "o": toggleFilterGroup("organizations"); return true
      case "t": toggleFilterGroup("types"); return true
      case "g": openGenerator(); return true
      case "s": openSettings(); return true
    }
    return false
  }

  function moveCursor(delta) {
    if (filteredItems.length === 0) return
    // Done filtering: close the drawer off the results.
    openFilterGroup = ""
    selectedIndex = Math.max(0, Math.min(filteredItems.length - 1, selectedIndex + delta))
    presenter.revealListIndex(selectedIndex)
  }

  function getSelectedItem() {
    if (filteredItems.length === 0 || selectedIndex < 0 || selectedIndex >= filteredItems.length) {
      return null
    }
    return filteredItems[selectedIndex]
  }

  // -------------------------------------------------------------------------
  // Clipboard, and the password -> TOTP follow-up
  // -------------------------------------------------------------------------

  function copyToClipboard(text, label) {
    if (!text) return
    resetAutoLockTimer()
    // Via the environment, not argv; unset before starting wl-copy, whose
    // clipboard owner outlives this shell.
    Quickshell.execDetached({
      command: ["bash", "-c", "printf '%s' \"$QSBW_CLIP\" | env -u QSBW_CLIP wl-copy --sensitive"],
      environment: { "QSBW_CLIP": String(text) }
    })
    flashNotification(label + " copied!")

    if (clearClipboardSec > 0) {
      clipboardClearTimer.restart()
    }
  }

  function clearClipboard() {
    clipboardClearTimer.stop()
    Quickshell.execDetached(["wl-copy", "--clear"])
  }

  function requestPasswordCopy(itemId, typeCode) {
    if (!session || !itemId) return
    if (copyPasswordProc.running) {
      errorMessage = "Another password copy is still loading"
      return
    }
    passwordCopyItemId = String(itemId)
    beginVaultRead("passwordCopy")
    copyPasswordProc.command = Model.getPasswordCommand(itemId, typeCode)
    copyPasswordProc.running = true
  }

  function onPasswordCopyFinished(exitCode, text) {
    var requested = passwordCopyItemId
    passwordCopyItemId = ""
    // Drop the collector's plaintext copy once wl-copy has it.
    clearProcessCollectorSoon(copyPasswordProc)
    if (vaultReadIsStale("passwordCopy")) return
    var password = String(text || "")
    if (exitCode === 0 && requested && password) {
      copyToClipboard(password, "Password")
      return
    }
    errorMessage = "Could not read this password"
  }

  // Enter on a row: copy a login's password (then arm the TOTP follow-up);
  // for anything without a default secret, open the item.
  function handleSmartEnter(item) {
    openFilterGroup = ""
    if (!item) return

    var copyable = Model.isLoginItem(item)
      && (item.hasPassword !== undefined ? item.hasPassword : Boolean(item.password))
    if (!copyable) {
      openDetail(item)
      return
    }

    // If already in active TOTP follow-up mode for this item, copy TOTP now!
    if (totpFollowupActive && totpFollowupItem && totpFollowupItem.id === item.id) {
      copyTotpCode(item)
      totpFollowupActive = false
      if (closeOnCopy) close()
      return
    }

    // Step 1: Copy password
    copyPassword(item)

    // Step 2: If item has TOTP, arm follow-up and schedule auto-copy!
    if (item.hasTotp) {
      totpFollowupItem = item
      totpFollowupActive = true
      fetchTotp(item.id)
      totpFollowupTimer.restart()

      if (autoCopyTotpSec > 0) {
        autoTotpTimer.interval = autoCopyTotpSec * 1000
        autoTotpTimer.restart()
      }
    }

    if (closeOnCopy) {
      close()
    }
  }

  function copyPassword(item) {
    closeFilterGroup()
    if (!item || !Model.isLoginItem(item)) return
    learnFromPick(item)
    var pass = (detailItem && detailItem.id === item.id && detailPassword) ? detailPassword : (item.password || "")
    if (pass) {
      copyToClipboard(pass, "Password")
      return
    }
    if (session) {
      requestPasswordCopy(item.id, item.typeCode)
    } else {
      errorMessage = "Vault is locked or session expired. Please unlock your vault."
    }
  }

  function copyUsername(item) {
    closeFilterGroup()
    if (!item || !item.username) return
    copyToClipboard(item.username, "Username")
  }

  function copyTotpCode(item) {
    closeFilterGroup()
    if (!item || !Model.isLoginItem(item)) return
    if (liveTotp && item.id === (detailItem ? detailItem.id : "")) {
      copyToClipboard(liveTotp, "TOTP code")
      return
    }
    if (totpFollowupActive && totpFollowupItem && totpFollowupItem.id === item.id && totpFollowupCode) {
      copyToClipboard(totpFollowupCode, "TOTP code")
      return
    }
    fetchTotp(item.id, true)
  }

  function openUrl(url) {
    if (!url) return
    // Only http and https are handed to xdg-open; see normalizeOpenableUrl().
    var resolved = Model.normalizeOpenableUrl(url)
    if (!resolved.ok) {
      errorMessage = resolved.reason === "ambiguous"
        ? "Refusing to open an ambiguous link containing a backslash"
        : resolved.scheme
        ? ("Refusing to open a " + resolved.scheme + ": link -- only http and https are opened")
        : "That item has no link to open"
      return
    }
    Quickshell.execDetached(["xdg-open", resolved.url])
    flashNotification("Opening " + resolved.url)
  }

  function flashNotification(msg) {
    flashMessage = msg
    flashTimer.restart()
  }

  function resetAutoLockTimer() {
    // Recorded even with auto-lock off, so enabling it counts from now.
    autoLockArmedAt = Date.now()
    if (autoLockMinutes > 0) {
      autoLockTimer.interval = autoLockMinutes * 60 * 1000
      autoLockTimer.restart()
    }
  }

  // -------------------------------------------------------------------------
  // Timers
  // -------------------------------------------------------------------------

  Timer {
    id: searchDebounceTimer
    interval: 50
    repeat: false
    onTriggered: root.rebuildFilter()
  }

  Timer {
    id: deferredMetadataTimer
    // Metadata not already started with the list, and the account-naming
    // `bw status`, wait for the parsed list to render.
    interval: 50
    repeat: false
    onTriggered: {
      if (root.status !== "unlocked") return
      root.loadPendingMetadata()
      if (root.statusRefreshAfterItems) {
        root.statusRefreshAfterItems = false
        root.runStatusCheck(false)
      }
    }
  }

  Timer {
    id: flashTimer
    interval: 2500
    onTriggered: root.flashMessage = ""
  }

  Timer {
    id: totpFollowupTimer
    interval: 8000
    onTriggered: root.totpFollowupActive = false
  }

  Timer {
    id: autoTotpTimer
    repeat: false
    onTriggered: {
      if (root.totpFollowupItem && root.totpFollowupItem.hasTotp) {
        root.copyTotpCode(root.totpFollowupItem)
        // The code stays out of the notification (history, lock screen).
        Quickshell.execDetached(["omarchy-notification-send", "-g", "󰥔", "--app-name", "Bitwarden", "-t", "4000", "TOTP Code Copied", "2FA verification code ready to paste"])
        root.totpFollowupActive = false
      }
    }
  }

  Timer {
    id: clipboardClearTimer
    interval: root.clearClipboardSec * 1000
    onTriggered: root.clearClipboard()
  }

  Timer {
    id: autoLockTimer
    interval: root.autoLockMinutes * 60 * 1000
    running: root.status === "unlocked" && root.autoLockMinutes > 0
    onTriggered: {
      if (root.status === "unlocked") {
        root.lockVault()
      }
    }
  }

  // The wall-clock half of the auto-lock: the Timer above stops during suspend
  // (see "Auto-lock" in BitwardenModel.js).
  Timer {
    id: autoLockWatchdog
    interval: Model.autoLockPollMs(root.autoLockMinutes)
    repeat: true
    running: root.status === "unlocked" && root.autoLockMinutes > 0
    onTriggered: {
      if (root.status !== "unlocked") return
      // An unlock that somehow reached us without arming the window starts it
      // here rather than reading a deadline of "1970 plus fifteen minutes".
      if (root.autoLockArmedAt <= 0) {
        root.autoLockArmedAt = Date.now()
        return
      }
      if (Model.autoLockExpired(root.autoLockArmedAt, root.autoLockMinutes, Date.now())) {
        root.lockVault()
      }
    }
  }

  // -------------------------------------------------------------------------
  // Locking on screen lock and on suspend
  // -------------------------------------------------------------------------
  //
  // Evidence the vault is unattended, alongside (not instead of) the auto-lock.

  // The last screen-lock reading and when it was taken. The agent needs it
  // even with lockOnScreenLock off: no prompt may appear over a locked screen.
  property bool screenIsLocked: false
  property double screenLockCheckedAt: 0

  function onScreenLockState(raw) {
    root.screenIsLocked = Model.screenIsLocked(raw)
    root.screenLockCheckedAt = Date.now()
    if (!lockOnScreenLock || status !== "unlocked") return
    if (root.screenIsLocked) lockVault()
  }

  function onSleepSignal(line) {
    var token = String(line || "").trim()
    if (token === Model.wakeSignalToken()) {
      // The watchdog handles an expired countdown; just refresh stale state.
      if (opened) refreshStatus()
      return
    }
    if (token !== Model.sleepSignalToken()) return
    if (!lockOnSuspend || status !== "unlocked") return
    // The keyring clear it spawns is what the inhibitor's held second is for.
    lockVault()
  }

  Timer {
    id: screenLockPoll
    interval: Model.screenLockPollMs()
    repeat: true
    // Only when it could matter: the setting is on and the vault unlocked, or
    // the agent is serving (it needs a current reading for prompts).
    running: (root.lockOnScreenLock && root.status === "unlocked") || root.sshAgentGateOpen
    onTriggered: {
      if (!screenLockStateProc.running) screenLockStateProc.running = true
    }
  }

  // Retries processes that were mid-read at lock time; stops when the queue
  // empties.
  Timer {
    id: scrubRetry
    interval: Model.scrubRetryMs()
    repeat: true
    onTriggered: {
      root.scrubStep()
      if (!root.scrubPending.length) stop()
    }
  }

  Process {
    id: screenLockStateProc
    command: Model.screenLockStateCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onScreenLockState(text)
    }
  }

  Process {
    id: sshAgentHelperProc
    stdout: StdioCollector {
      id: sshAgentHelperStdout
      waitForEnd: true
      onStreamFinished: root.onSshAgentHelperInspected(text)
    }
  }

  Process {
    id: unlockKeyProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onUnlockKeyInspected(text)
    }
  }

  Process {
    id: quickUnlockPrereqProc
    command: Model.quickUnlockPrereqCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onQuickUnlockPrereqs(text)
    }
  }

  // Every envelope operation, one at a time; see queueEnvelopeJob().
  Process {
    id: envelopeProc
    stdout: StdioCollector {
      id: envelopeStdout
      waitForEnd: true
    }
    onExited: function(exitCode) { root.onEnvelopeJobExited(exitCode) }
  }

  Process {
    id: sshExportProc
    command: Model.sshExportCommand()
    stdinEnabled: true
    stdout: StdioCollector { id: sshExportStdout; waitForEnd: true }
    onExited: function(exitCode) {
      sshExportProc.stdinEnabled = true
      root.onSshExportFinished(exitCode, sshExportStdout.text)
    }
  }

  Process {
    id: sshExportClearProc
    command: Model.sshExportClearCommand()
    stdout: StdioCollector { id: sshExportClearStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onSshExportFinished(exitCode, sshExportClearStdout.text) }
  }

  Process {
    id: loadIdProc
    command: Model.loadIdCommand()
    stdout: StdioCollector {
      id: loadIdStdout
      waitForEnd: true
      onStreamFinished: root.onSshAgentLoadIdRead(text)
    }
  }

  Process {
    id: uwsmInspectProc
    command: Model.uwsmInspectCommand()
    stdout: StdioCollector {
      id: uwsmInspectStdout
      waitForEnd: true
      onStreamFinished: {
        root.uwsmFragment = Model.parseUwsmInspection(text)
        root.applyUwsmRestore()
      }
    }
  }

  Process {
    id: pluginDataRemoveProc
    command: Model.pluginDataRemoveCommand()
    stdout: StdioCollector { id: pluginDataRemoveStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onPluginDataRemoved(exitCode, pluginDataRemoveStdout.text) }
  }

  Process {
    id: uwsmWriteProc
    command: Model.uwsmWriteCommand()
    stdout: StdioCollector { id: uwsmWriteStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onUwsmActionFinished(exitCode, uwsmWriteStdout.text) }
  }

  Process {
    id: uwsmRemoveProc
    command: Model.uwsmRemoveCommand()
    stdout: StdioCollector { id: uwsmRemoveStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onUwsmActionFinished(exitCode, uwsmRemoveStdout.text) }
  }

  // The SSH companion: tracked, non-detached, so it dies with the shell and
  // owns the child (stdin EOF tells it to drop its keys and exit). Its
  // environment is cleared to just XDG_RUNTIME_DIR; it runs no `bw`.
  Process {
    id: sshAgentProc
    // The candidate the inspection accepted.
    command: Model.sshAgentHelperCommand(root.sshAgentPluginDir, root.sshAgentHelper.source)
    clearEnvironment: true
    environment: Model.sshAgentHelperEnv(root.sshAgentRuntimeDir) || ({})
    stdinEnabled: true
    // Attached from the start, so `ready` cannot be missed.
    stdout: SplitParser {
      onRead: function(line) { root.applySshAgentEvent({ kind: "line", line: line, nowMs: Date.now() }) }
    }
    onStarted: root.applySshAgentEvent({ kind: "started", nowMs: Date.now() })
    onExited: function(exitCode) {
      sshAgentTerminateTimer.stop()
      root.onSshAgentHelperExited(exitCode)
    }
  }

  // Handshake bound: a helper without `ready` in time is stopped and retried.
  Timer {
    id: sshAgentHandshakeTimer
    interval: Model.sshAgentHandshakeTimeoutMs()
    repeat: false
    running: root.sshAgentPhase === "starting" || root.sshAgentPhase === "handshaking"
    onTriggered: root.applySshAgentEvent({ kind: "handshakeTimeout", nowMs: Date.now() })
  }

  // Only while a grant is counting down (at most 15 minutes).
  Timer {
    id: sshGrantCountdown
    interval: 1000
    repeat: true
    running: root.sshGrantsAnnounced.length > 0
    onTriggered: root.sshGrantTick = Date.now()
  }

  Timer {
    id: sshCooldownCountdown
    interval: 1000
    repeat: true
    running: root.sshCooldownStatus.active
    onTriggered: root.noteSshCooldown()
  }

  Timer {
    id: sshPromptCountdown
    interval: 1000
    repeat: true
    running: root.sshPrompt !== null || root.sshUnlockRequest !== null
    onTriggered: {
      var elapsed = Date.now() - root.sshPromptStartedMs
      var remaining = Math.ceil((Model.sshAgentRequestDeadlineMs() - elapsed) / 1000)
      root.sshPromptRemainingSec = Math.max(0, remaining)
      if (remaining <= 0) root.expireSshRequest()
    }
  }

  // Grace between asking the helper to stop and killing it.
  Timer {
    id: sshAgentTerminateTimer
    interval: 2000
    repeat: false
    onTriggered: if (sshAgentProc.running) sshAgentProc.running = false
  }

  // Restart backoff; the reducer sets the interval.
  Timer {
    id: sshAgentRestartTimer
    repeat: false
    onTriggered: root.applySshAgentEvent({ kind: "restartTimer", nowMs: Date.now() })
  }

  // Holds the sleep inhibitor, so it runs whenever the setting is on, not only
  // while unlocked (it must already be listening when suspend is announced).
  Process {
    id: sleepMonitorProc
    running: root.live && root.lockOnSuspend
    // Closing this pipe tears down the monitor's entire process group.
    stdinEnabled: true
    command: Model.sleepMonitorCommand()
    stdout: SplitParser {
      onRead: function(line) { root.onSleepSignal(line) }
    }
  }

  Timer {
    id: totpCountdownTimer
    interval: 1000
    running: root.opened && (root.currentScreen === "detail" || root.totpFollowupActive)
    repeat: true
    onTriggered: {
      var sec = 30 - (Math.floor(Date.now() / 1000) % 30)
      root.totpSecRemaining = sec
      if (sec === 30) {
        if (root.currentScreen === "detail" && root.detailItem && root.detailItem.hasTotp) {
          root.fetchTotp(root.detailItem.id)
        } else if (root.totpFollowupActive && root.totpFollowupItem) {
          root.fetchTotp(root.totpFollowupItem.id)
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Processes
  // -------------------------------------------------------------------------

  Process {
    id: statusProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: statusStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(statusProc)) {
        root.onStatusProbeProcessFreed()
        return
      }
      root.onStatusFinished(exitCode === 0 ? statusStdout.text : "")
      if (root.statusCheckQueued) {
        root.statusCheckQueued = false
        Qt.callLater(root.runStatusCheck)
      }
    }
  }

  Process {
    id: sessionHandoffProc
    // Set by refreshStatus(). Defaults to the discard form, so a run not
    // started there can never adopt a key.
    command: Model.sessionHandoffReadCommand(false)
    stdout: StdioCollector {
      id: sessionHandoffStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(sessionHandoffProc)) {
        root.onStatusProbeProcessFreed()
        return
      }
      root.onSessionHandoff(exitCode === 0 ? sessionHandoffStdout.text : "")
    }
  }

  Process {
    id: keyringLookupProc
    command: Model.keyringLookupCommand(root.activeSlot)
    stdout: StdioCollector {
      id: keyringLookupStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(keyringLookupProc)) {
        root.onStatusProbeProcessFreed()
        return
      }
      root.onKeyringLookupFinished(exitCode === 0 ? keyringLookupStdout.text : "")
    }
  }

  Process {
    id: keyringStoreProc
    command: Model.keyringStoreCommand(root.activeSlot)
    environment: root.secretEnv(root.session)
    onExited: function(exitCode) {
      root.onSessionStored(exitCode)
      if (root.logoutPending && root.allCredentialsClearPending)
        Qt.callLater(root.requestAllCredentialClear)
    }
  }

  Process {
    id: keyringClearProc
    command: Model.keyringClearCommand(root.activeSlot)
    // What waits behind this clear is run by busyRetryTimer.
    onExited: function(exitCode) {}
  }

  // ---- Fingerprint unlock ----

  Process {
    id: listFoldersProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: listFoldersStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(listFoldersProc)) return
      if (exitCode === 0) root.onListFoldersFinished(listFoldersStdout.text)
    }
  }

  Process {
    id: orgCollectionsProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: orgCollectionsStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(orgCollectionsProc)) return
      if (exitCode === 0) root.onOrgCollectionsLoaded(orgCollectionsStdout.text)
      else root.formCollectionsLoading = false
    }
  }

  Process {
    id: createFolderProc
    environment: root.folderEnv()
    stdout: StdioCollector { id: createFolderStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(createFolderProc)) return
      root.onFolderCreated(exitCode, createFolderStdout.text)
    }
  }

  Process {
    id: attachmentProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: attachmentStdout; waitForEnd: true }
    stderr: StdioCollector { id: attachmentStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(attachmentProc)) return
      root.onAttachmentDownloaded(exitCode, attachmentStdout.text, attachmentStderr.text)
    }
  }

  Process {
    id: listSendsProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: listSendsStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(listSendsProc)) return
      if (exitCode === 0) root.onSendsLoaded(listSendsStdout.text)
      else root.sendsLoading = false
    }
  }

  Process {
    id: createSendProc
    environment: root.sendEnv(root.sendPayloadJson)
    stdout: StdioCollector { id: createSendStdout; waitForEnd: true }
    stderr: StdioCollector { id: createSendStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(createSendProc)) return
      root.onSendCreated(exitCode, createSendStdout.text, createSendStderr.text)
    }
  }

  Process {
    id: deleteSendProc
    environment: root.bwEnv()
    onExited: function(exitCode) { root.onSendDeleted(exitCode) }
  }

  Process {
    id: generateProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: generateStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(generateProc)) return
      if (root.generateCliStopping) {
        root.generateCliStopping = false
        var restart = root.currentScreen === "generator" && root.genRegeneratePending
        root.genBusy = false
        root.genRegeneratePending = false
        if (restart) Qt.callLater(root.regenerate)
        return
      }
      root.onGenerated(generateStdout.text, exitCode)
    }
  }

  // The generator server: managed, so it exits with the shell.
  Process {
    id: generateServeProc
    command: Model.generateServeCommand()
    environment: root.generatorServeEnv()
    onExited: function(exitCode) {
      generateServePoll.stop()
      var act = Model.generatorServeExitAction({
        stopping: root.generateServeStopping,
        wasReady: root.generateServeReady,
        busy: root.genBusy,
        onGeneratorScreen: root.currentScreen === "generator"
      })
      root.generateServeStarting = false
      root.generateServeReady = false
      root.generateServeStopping = false
      if (act.giveUp) root.generateServeFailed = true
      if (act.dropValue) root.genValue = ""
      if (act.useCli) root.regenerateViaCli()
    }
  }

  Process {
    id: generateServeRequestProc
    stdout: StdioCollector { id: generateServeRequestStdout; waitForEnd: true }
    stderr: StdioCollector { id: generateServeRequestStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(generateServeRequestProc)) {
        root.resumePendingGeneratorRequest()
        return
      }
      var stopped = root.generateServeRequestStopping
      root.generateServeRequestStopping = false
      var cb = root.generateServeRequestCallback
      root.generateServeRequestCallback = null
      if (root.resumePendingGeneratorRequest()) return
      if (stopped) return
      if (cb) cb(exitCode, generateServeRequestStdout.text, generateServeRequestStderr.text)
    }
  }

  Timer {
    id: generateServePoll
    property int attempts: 0
    interval: 250
    repeat: true
    onTriggered: {
      attempts++
      if (attempts > 40) {   // 10s, well past bw's usual couple of seconds
        stop()
        root.generateServeStarting = false
        root.generateServeFailed = true
        if (root.genBusy) root.regenerateViaCli()
        return
      }
      root.pollGeneratorServe()
    }
  }

  // ---- Legacy PIN blob ----
  //
  // Decrypted in one process with the PIN from the environment, so only the
  // result reaches QML.

  Process {
    id: pinUnlockProc
    command: Model.pinUnlockCommand(root.activeSlot)
    environment: root.pinEnv(root.pinEntry)
    stdout: StdioCollector { id: pinUnlockStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(pinUnlockProc)) return
      root.onPinUnlockResult(exitCode, pinUnlockStdout.text)
    }
  }

  Process {
    id: keyringHasPinProc
    command: Model.keyringHasPinCommand(root.activeSlot)
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onPinConfiguredChecked(text)
    }
  }

  Process {
    id: keyringClearPinProc
    command: Model.keyringClearPinCommand(root.activeSlot)
    onExited: function(exitCode) {
      if (root.pinClearPending) Qt.callLater(root.requestPinCredentialClear)
    }
  }

  Process {
    id: depsCheckProc
    command: Model.dependencyCheckCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onDependenciesChecked(text)
    }
  }

  Process {
    id: bwVersionProc
    property string probeId: ""
    command: Model.bwVersionCommand()
    stdout: StdioCollector {
      id: bwVersionStdout
      waitForEnd: true
    }
    onExited: function(exitCode) { root.onBwVersionProbed(bwVersionStdout.text, bwVersionProc.probeId) }
  }

  // An install runs in a terminal we do not own, so re-probe while the setup
  // screen is open; the moment `bw` appears the panel moves on.
  Timer {
    id: setupPollTimer
    interval: 2500
    running: root.opened && root.currentScreen === "setup" && root.setupActionsPending
    repeat: true
    onTriggered: root.checkDependencies()
  }

  // If the dependency probe never reports (broken PATH), probe status anyway
  // after a few seconds rather than sit on "checking".
  Timer {
    id: statusProbeFallbackTimer
    interval: 4000
    running: root.live && !root.statusProbeStarted
    repeat: false
    onTriggered: {
      if (root.statusProbeStarted || root.setupGated) return
      // Treat the silent probe as checked so refreshStatus() can proceed.
      root.depsChecked = true
      root.refreshStatus()
    }
  }

  Process {
    id: settingWriteProc
    stderr: StdioCollector {
      id: settingWriteStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.settingsFlash = ""
        root.errorMessage = (settingWriteStderr.text || "").trim() || "Could not save setting to shell.json"
      }
    }
  }

  Timer {
    id: settingsFlashTimer
    interval: 1600
    onTriggered: root.settingsFlash = ""
  }

  Process {
    id: keyringHasMasterProc
    command: Model.keyringHasMasterPasswordCommand(root.activeSlot)
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onFingerprintStoredChecked(text)
    }
  }

  Process {
    id: keyringLookupMasterProc
    command: Model.keyringLookupMasterPasswordCommand(root.activeSlot)
    stdout: StdioCollector {
      id: keyringLookupMasterStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(keyringLookupMasterProc)) return
      if (exitCode === 0) {
        root.onFingerprintPasswordRetrieved(keyringLookupMasterStdout.text)
      } else {
        root.fingerprintAuthorized = false
        root.fingerprintStored = false
        root.fingerprintMessage = "Stored master password unavailable. Use your password."
      }
    }
  }

  Process {
    id: keyringClearMasterProc
    command: Model.keyringClearMasterPasswordCommand(root.activeSlot)
    onExited: function(exitCode) {
      if (root.masterClearPending) Qt.callLater(root.requestMasterCredentialClear)
    }
  }

  // Asks again for a sweep deferred behind a writer; see
  // requestAllCredentialClear().
  Timer {
    id: credentialClearRetry
    interval: 100
    repeat: false
    onTriggered: if (root.logoutPending && root.allCredentialsClearPending) root.requestAllCredentialClear()
  }

  // Logout's clean sweep; see forgetStoredCredentials().
  Process {
    id: keyringClearAllProc
    command: Model.keyringClearAllCommand(root.activeSlot)
    onExited: function(exitCode) {
      if (root.allCredentialsClearPending) {
        Qt.callLater(root.requestAllCredentialClear)
        return
      }
      root.onLogoutCredentialsFinished(exitCode)
    }
  }

  // Asks again for the reads above that found their process busy. A Process
  // can still read as running inside its own exit handler, so waiting on the
  // exit is not enough.
  Timer {
    id: busyRetryTimer
    interval: 150
    repeat: true
    running: root.live && (root.pinRecheck || root.masterRecheck || root.associationsReloadPending
      || root.sessionClearSlots.length > 0 || root.sessionStorePending)
    onTriggered: {
      root.pumpSessionKeyring()
      if (root.pinRecheck) root.refreshPinConfigured()
      if (root.masterRecheck) root.refreshLegacyFingerprint()
      if (root.associationsReloadPending) root.loadAssociations()
    }
  }

  // ---- Accounts ----

  Process {
    id: accountsReadProc
    command: Model.accountRegistryReadCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onAccountRegistryLoaded(text)
    }
  }

  Process {
    id: accountsWriteProc
    command: Model.accountRegistryWriteCommand()
    environment: root.accountsEnv()
    onExited: function(exitCode) { root.onAccountRegistryWritten(exitCode) }
  }

  Process {
    id: slotRemovalProc
    onExited: function(exitCode) {
      if (exitCode !== 0) console.warn("qs-bitwarden-cli: could not remove a signed-out account (exit " + exitCode + ")")
      Qt.callLater(root.pumpSlotRemovals)
    }
  }

  // ---- Learned associations ----

  Process {
    id: associationsReadProc
    command: Model.associationsReadCommand(root.activeSlot)
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (root.finishScrubRun(associationsReadProc)) return
        root.onAssociationsLoaded(text)
      }
    }
  }

  Process {
    id: associationsWriteProc
    command: Model.associationsWriteCommand(root.activeSlot)
    environment: root.associationsEnv()
    onExited: function(exitCode) {
      if (root.associationsClearPending) {
        root.associationsClearPending = false
        root.associationsWritePending = false
        root.pendingAssociationsJson = ""
        associationsClearProc.running = true
        return
      }
      if (exitCode !== 0) {
        console.warn("qs-bitwarden-cli: could not save learned suggestions (exit " + exitCode + ")")
      }
      // Never re-run with nothing to write: a lock empties the payload, and
      // an empty write would replace the file with nothing.
      if (root.associationsWritePending && root.pendingAssociationsJson !== "") {
        root.associationsWritePending = false
        associationsWriteProc.running = true
        return
      }
      root.associationsWritePending = false
      root.pendingAssociationsJson = ""
    }
  }

  Process {
    id: associationsClearProc
    command: Model.associationsClearCommand(root.activeSlot)
  }

  PamContext {
    id: fingerprintPam
    config: "omarchy-lock-fingerprint"
    user: root.userName

    onCompleted: function(result) {
      root.onFingerprintResult(result)
    }

    onError: function(error) {
      root.fingerprintScanning = false
      root.fingerprintAuthorized = false
      root.fingerprintMessage = "Fingerprint verification unavailable"
    }
  }

  // Lid state, for the fingerprint reader's reachability.
  LidState {
    id: lidState
    vault: root
  }

  // FIDO2 unlock: given the vault and setting, returns a password after a
  // verified touch.
  FidoUnlock {
    id: fidoUnlocker
    vault: root
    armed: root.fidoUnlock

    onUnlocked: function(password) {
      root.pendingUnlockFrom = "fido"
      root.unlockVaultWithPassword(password)
    }
  }

  // Polled on the wall clock, like the auto-lock, so a login pending across a
  // suspend expires on real time.
  Timer {
    id: pendingLoginTimer
    interval: 1000
    repeat: true
    running: root.secondFactorStartedAt > 0
    onTriggered: {
      if (!Model.secondFactorWindowOpen(root.secondFactorStartedAt, Date.now())) {
        root.abandonAuthSecrets()
      }
    }
  }

  Process {
    id: loginProc
    environment: root.loginProcessEnv()
    stdout: StdioCollector {
      id: loginStdout
      waitForEnd: true
    }
    stderr: StdioCollector {
      id: loginStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      // A scrub started here briefly holds the process; a submit arriving then
      // is dispatched when the scrub exits (else it would need a second click).
      if (root.finishScrubRun(loginProc)) {
        if (!root.loginSubmitted) root.resumeDeferredLogin(false)
        return
      }
      if (!root.loginSubmitted) {
        root.resumeDeferredLogin(true)
        return
      }
      root.loginSubmitted = false
      root.onLoginOutput(loginStdout.text, loginStderr.text, exitCode)
    }
  }

  Process {
    id: authPasswordWriterProc
    environment: root.authEnv(root.authPasswordWriteValue, "", "", "")
    onExited: function(exitCode) { root.onAuthPasswordWriterExited(exitCode) }
  }

  Process {
    id: unlockProc
    command: Model.unlockPrewarmCommand()
    environment: root.authEnv("", "", "", "")
    stdout: StdioCollector {
      id: unlockStdout
      waitForEnd: true
    }
    stderr: StdioCollector {
      id: unlockStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(unlockProc)) {
        if (root.sshAuthSurfaceActive && root.status === "locked") Qt.callLater(root.prepareUnlock)
        return
      }
      if (!root.unlockSubmitted) {
        root.clearProcessCollectorSoon(unlockProc)
        return
      }
      root.unlockSubmitted = false
      root.onUnlockOutput(unlockStdout.text, unlockStderr.text, exitCode)
    }
  }

  Process {
    id: logoutProc
    environment: root.bwEnv()
    onExited: function(exitCode) { root.onLogoutCliFinished(exitCode) }
  }

  Process {
    id: listProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: listStdout
      waitForEnd: true
    }
    stderr: StdioCollector {
      id: listStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      root.onListProcessExited(exitCode, listStdout.text, listStderr.text)
    }
  }

  Process {
    id: listOrgsProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: listOrgsStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(listOrgsProc)) return
      if (exitCode === 0) root.onListOrgsFinished(listOrgsStdout.text)
    }
  }

  Process {
    id: getItemProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: getItemStdout
      waitForEnd: true
    }
    stderr: StdioCollector {
      id: getItemStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(getItemProc)) return
      if (exitCode === 0) {
        root.onDetailFinished(getItemStdout.text)
      } else {
        root.isLoading = false
        if (!root.vaultReadIsStale("detail")) {
          root.errorMessage = String(getItemStderr.text || "").trim() || "Could not load item details"
        }
      }
    }
  }

  Process {
    id: getTotpProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: getTotpStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(getTotpProc)) {
        root.continueTotpQueue(true)
        return
      }
      root.onTotpProcessExited(exitCode, getTotpStdout.text)
    }
  }

  Process {
    id: copyPasswordProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: copyPasswordStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(copyPasswordProc)) return
      root.onPasswordCopyFinished(exitCode, copyPasswordStdout.text)
    }
  }

  Process {
    id: activeWindowProc
    command: Model.activeWindowCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (text && text.trim()) {
          try {
            var data = JSON.parse(text)
            root.handleActiveWindowDetected(data)
          } catch (e) {
            root.suggestedItems = []
            root.detectedContext = null
          }
        }
      }
    }
  }

  Process {
    id: createItemProc
    environment: root.itemEnv()
    stdout: StdioCollector { id: createItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: createItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(createItemProc)) return
      root.itemPayloadJson = ""
      root.onSaveItemFinished(exitCode, createItemStdout.text, createItemStderr.text)
    }
  }

  Process {
    id: editItemProc
    environment: root.itemEnv()
    stdout: StdioCollector { id: editItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: editItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(editItemProc)) return
      root.itemPayloadJson = ""
      root.onSaveItemFinished(exitCode, editItemStdout.text, editItemStderr.text)
    }
  }

  Process {
    id: deleteItemProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: deleteItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: deleteItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(deleteItemProc)) return
      root.onDeleteItemFinished(exitCode, deleteItemStdout.text, deleteItemStderr.text)
    }
  }

  Process {
    id: syncProc
    environment: root.bwEnv()
    onExited: function(exitCode) {
      root.onSyncFinished(exitCode)
    }
  }

  Process {
    id: lockProc
    environment: root.bwEnv()
  }

  // -------------------------------------------------------------------------
  // IPC
  // -------------------------------------------------------------------------

  IpcHandler {
    target: "io.github.elevate08.qs-bitwarden-cli"
    enabled: root.live
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function lock(): string { root.lockVault(); return "locked" }
    function settings(): string { root.open(); root.openSettings(); return "settings" }
    function setup(): string {
      root.open()
      root.setupDismissed = false
      root.checkDependencies()
      root.currentScreen = "setup"
      return "setup"
    }
    function sync(): string { root.syncVault(); return "syncing" }
    function status(): string { return root.status }
    // The accounts the panel holds (emails and servers only) and which is
    // active.
    function accounts(): string {
      var rows = root.accountRows
      var out = []
      for (var i = 0; i < rows.length; i++) {
        out.push({ email: rows[i].email, server: rows[i].server, active: rows[i].active })
      }
      return JSON.stringify({ adding: root.addingAccount, accounts: out })
    }
    // Switches to the account with this email (case-insensitive); locks the
    // one active now.
    function switchAccount(email: string): string {
      var want = String(email || "").trim().toLowerCase()
      var rows = root.accountRows
      for (var i = 0; i < rows.length; i++) {
        if (rows[i].email.toLowerCase() === want) {
          if (!root.canChangeAccount()) return "busy"
          root.switchAccount(rows[i].slot)
          return "switching"
        }
      }
      return "unknown"
    }
    // Which vault this view shows and how many views share it (non-secret).
    function vaultHost(): string {
      var screens = []
      for (var i = 0; i < root.views.length; i++) {
        screens.push({ screen: root.views[i].screenName, opened: root.views[i].opened === true })
      }
      return JSON.stringify({
        host: root.privateHost ? "private" : "shared",
        views: root.viewCount,
        privateHost: root.privateHost,
        opened: root.opened,
        presenter: root.presenter.screenName,
        focusedScreen: root.focusedScreen,
        screens: screens
      })
    }
    // Non-secret SSH agent diagnostics: no keys, fingerprints or paths.
    function sshAgentStatus(): string {
      return JSON.stringify({
        enabled: root.sshAgentEnabled,
        phase: root.sshAgentPhase,
        // The handshaked control channel, not "signing allowed" (see vaultState).
        helperChannelOpen: root.sshAgentGateOpen,
        vaultState: Model.sshAgentVaultState(root.sshAgentVaultContext()),
        setupState: root.sshAgentSetup.state,
        // Which binary runs and whether its digest was checked.
        helperSource: root.sshAgentHelper.source,
        helperChecksum: root.sshAgentHelper.checksum,
        // Why inspection rejected it (errorCode covers only the running helper).
        helperState: root.sshAgentHelper.state,
        // Routing as the settings screen sees it.
        routingFragment: root.uwsmFragment.state,
        routingNotice: root.sshRoutingNotice.text !== "",
        errorCode: root.sshAgentErrorCode,
        keyCount: root.sshAgentKeyCount,
        loadActive: root.sshAgentLoadActive,
        epoch: root.sshAgentEpoch,
        promptShowing: root.sshPrompt !== null,
        unlockShowing: root.sshUnlockRequest !== null,
        grants: root.sshGrants.length,
        screenLocked: root.screenIsLocked,
        screenLockAgeMs: root.screenLockCheckedAt > 0 ? Math.round(Date.now() - root.screenLockCheckedAt) : -1,
        mayPrompt: root.sshAgentMayPrompt(),
        cooldownRefusals: root.sshCooldown ? root.sshCooldown.refusals : 0,
        cooldownActive: Model.sshAgentCooldownActive(root.sshCooldown, Date.now())
      })
    }
  }
}
