import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import Quickshell.Services.Pam
import qs.Commons
import "BitwardenModel.js" as Model

// The vault, once per shell.
//
// Omarchy builds its bar once per monitor, so Panel.qml -- the bar widget -- is
// instantiated once per monitor as well. Everything that must exist exactly
// once no matter how many monitors are attached lives here instead: the shell
// loads a plugin's `service` entry point a single time and hands the same
// object to every bar copy through `bar.shell.serviceFor()`. Each Panel.qml is
// a view of this object (issue #30).
//
// Where the shared service cannot be reached, a view creates a private one
// (Model.vaultHostDecision), so this file must also work as one view's own
// vault. A private host is marked so that nothing here assumes it is alone.
Item {
  id: root

  // Injected by the shell's service loader. A private host has neither.
  property var shell: null
  property var manifest: null

  // True when a view created this instance for itself because the shared
  // service was unavailable.
  property bool privateHost: false

  // -------------------------------------------------------------------------
  // Views
  // -------------------------------------------------------------------------
  //
  // Every live bar copy attached to this vault, in attach order. A view
  // attaches once it has resolved its host and detaches when it is destroyed --
  // a monitor unplugged takes its view with it and leaves the vault running.
  property var views: []
  readonly property int viewCount: views.length

  function attachView(view) {
    if (!view || views.indexOf(view) !== -1) return
    // Settings first: attaching the first view is what starts the vault, and it
    // must start with the user's settings rather than the defaults.
    if (view.settings) updateSettings(view.settings)
    views = views.concat([view])
  }

  // The view that acts when the vault needs the screen -- see
  // Model.presenterIndex(). Re-evaluated whenever a view attaches or detaches,
  // opens or closes its popout, or Hyprland moves focus to another monitor.
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

  // Every attached view, for what each copy of a control must agree on.
  function eachView(fn) {
    var list = views.slice()
    for (var i = 0; i < list.length; i++) fn(list[i])
  }

  // Whether any view's popout is open. The logic's `opened` -- it used to be
  // the widget's own.
  readonly property bool opened: {
    for (var i = 0; i < views.length; i++) {
      if (views[i].opened === true) return true
    }
    return false
  }

  // Live once a view is attached. See onLiveChanged below.
  readonly property bool live: viewCount > 0
  property bool started: false

  // Stands in for a presenter when no view is attached, so a command finishing
  // after the last monitor's bar went away has nothing to throw on.
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
  // The plugin's settings are its bar entry's inline object in shell.json. A
  // service is handed only a snapshot of the shell config at load, which would
  // go stale on the first edit, so the views -- whose `settings` the bar keeps
  // current -- push them here instead. `allowMultiple` is false, so every view
  // carries the same entry and whichever pushed last is authoritative.
  property var settings: ({})

  function updateSettings(next) {
    settings = next || ({})
  }

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }


  // Configuration settings from shell.json. The numbers go through the schema
  // on the way in as well as on the way out -- nothing validates shell.json,
  // and a bad minute count does not fail loudly, it just stops the vault ever
  // locking itself. See intSetting() in BitwardenModel.js.
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
  // The SSH agent is opt-in. Nothing starts a helper, creates a socket, or
  // touches a FIFO while this is false.
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
  // Whether the login attempt now running carries --code. It is the only way
  // to tell a rejected two-step code from a new-device-verification challenge;
  // see loginNeedsDeviceVerification() in BitwardenModel.js.
  property bool loginAttemptHadCode: false
  // Set once Bitwarden has asked to verify this device with an emailed OTP.
  // bw can only answer that interactively, so the panel stops asking for a
  // code it cannot use and points at the terminal login instead.
  property bool loginDeviceVerification: false

  // Which two-step method this login tells bw to use, or -1 for "let bw
  // decide", which is right whenever the account has exactly one. See
  // TWO_FACTOR_METHODS in BitwardenModel.js.
  property int login2faMethod: rememberedTwoFactorMethod
  // Whether that method came from the user picking it in this login rather
  // than from the remembered setting. A remembered method can be stale -- it
  // is remembered per email -- so an unconfirmed one is dropped and
  // retried without, where a confirmed one is reported as not configured.
  property bool login2faMethodConfirmed: false
  property bool show2faMethodPicker: false
  // New-device verification collects its code in its own stage, because it is
  // answered on a different path from a two-step code and must not be mistaken
  // for one. See deviceVerificationLoginCommand() in BitwardenModel.js.
  property string loginDeviceCode: ""
  property bool showDeviceCodeField: false
  // Set while the one login that runs with bw's prompts enabled is in flight,
  // so both its environment and its result are read differently.
  property bool deviceVerificationAttempt: false
  property bool deviceVerificationPending: false
  // When the login reached a stage that is waiting on a second factor, as
  // epoch ms, or 0 if it is not. A closed panel keeps that login alive for
  // SECOND_FACTOR_WINDOW_MS, because an emailed code cannot be read without
  // leaving the panel. See secondFactorWindowOpen() in BitwardenModel.js.
  property double secondFactorStartedAt: 0
  // Whether this login has already spent its one automatic retry at handing
  // the password to bw. See onAuthPasswordWriterExited().
  property bool loginPasswordRetryUsed: false
  // The email login is four stages deep now: credentials, the method question
  // when bw asks it, the two-step code, and new-device verification. Only one
  // is ever on screen.
  readonly property bool loginCredentialsStage:
    !show2faField && !show2faMethodPicker && !showDeviceCodeField
  readonly property string login2faMethodLabel: Model.twoFactorMethodLabel(login2faMethod)
  // The method the last attempt actually sent, so its answer can be read
  // against it.
  property int loginAttemptMethod: -1
  // Keyed by login address, so two vaults on one machine each keep their own
  // answer. Tracks loginEmail as it is typed, which is what makes the method
  // apply the moment the address is complete.
  readonly property var twoFactorMethodStore: setting("twoFactorMethods", null)
  readonly property int rememberedTwoFactorMethod:
    Model.rememberedTwoFactorMethodFor(twoFactorMethodStore, loginEmail)

  // When the panel last launched a terminal login, as epoch ms, or 0 if it
  // never did. A session key left in the runtime directory is only adopted in
  // the minutes after this; see sessionHandoffReadCommand().
  property double terminalLoginStartedAt: 0

  // Navigation: "main" | "detail" | "edit" | "settings" | "setup" | "pin" |
  // "fingerprint" | "generator" | "sends" | "sshApproval" | "locked". Lock and
  // login visibility follow `status`; "locked" is set on a lock but nothing
  // reads it, so it only moves the panel off whatever screen was open.
  property string currentScreen: "main"
  property string screenBeforeSettings: "main"

  // Dependency / setup state
  property var dependencies: ({ items: [], hasOmarchy: true })
  property bool depsChecked: false
  property bool setupDismissed: false
  property string listReadMode: "sanitized"
  property var sshCapability: Model.defaultSshCapability()
  // True while the panel should be showing setup rather than probing `bw`.
  // See setupGateActive() in BitwardenModel.js for why the gate exists.
  readonly property bool setupGated: Model.setupGateActive(dependencies, depsChecked, setupDismissed)
  // Whether the first `bw status` has been started. The probe waits behind the
  // dependency check on a fresh install, so something has to remember that it
  // still owes the vault a look once the tools arrive.
  property bool statusProbeStarted: false
  // Set the moment a required tool is seen missing, cleared once the probe
  // that follows the install has run. It is what turns "the install finished
  // in a terminal we do not own" into a panel that moves on by itself.
  property bool setupWasGated: false
  property string settingsFlash: ""
  property int settingsIndex: 0
  readonly property var settingsEntries: Model.visibleSettings(dependencies, depsChecked)

  // Vault data
  property var items: []
  // `bw list items` costs seconds on a large vault, so a reopen reuses what is
  // already in memory until it goes stale. Any mutation reloads unconditionally.
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
  // Which bottom filter group is open: "" | "folders" | "organizations" | "types".
  // Only one at a time, so the panel grows by one list at most.
  property string openFilterGroup: ""
  property int filterOptionIndex: 0

  readonly property int filterRowHeight: Style.space(30)
  readonly property int filterVisibleRows: 5
  readonly property var currentFilterOptions: openFilterGroup === "" ? [] : filterOptions(openFilterGroup)
  readonly property int currentFilterVisibleRows: openFilterGroup === "types" ? currentFilterOptions.length : filterVisibleRows
  // The drawer's own height. The panel adds this to its cap so the window
  // opens downward like a drawer instead of squeezing the item list.
  readonly property int filterDrawerHeight: openFilterGroup === ""
    ? 0
    : Style.space(30) + Math.min(currentFilterVisibleRows, currentFilterOptions.length) * filterRowHeight + Style.space(8)
  property string formFolderId: ""
  property string newFolderName: ""
  // Which picker in the item form is expanded. Custom-field controls use
  // "customAdd", "customLabel:<row>" or "customLinked:<row>" alongside
  // folder/organization.
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
  // Which sensitive fields on the open item are currently shown, by field key.
  //
  // One flag used to serve all of them, which was invisible while a login had
  // exactly one secret to hide. A card has two and an identity three, and
  // revealing a card number also uncovered its security code -- and, on an
  // identity, the social security, passport and licence numbers at once. The
  // eye on each field now speaks only for that field.
  property var revealedFields: ({})

  function isFieldRevealed(key) { return Boolean(revealedFields[key]) }

  function toggleFieldReveal(key) {
    var next = {}
    for (var k in revealedFields) next[k] = revealedFields[k]
    if (next[key]) delete next[key]
    else next[key] = true
    revealedFields = next
  }

  // What `v` reaches: the one secret the open item is mostly about. A card has
  // a number, a login has a password. An identity has three identifiers and no
  // principal one, so `v` leaves it alone rather than picking arbitrarily --
  // each field carries its own eye.
  readonly property string primaryRevealKey:
    detailIsCard ? "cardNumber" : (detailIsLoginLike ? "password" : "")

  // Which detail blocks the open item is entitled to. The login fields --
  // username, password, TOTP, website -- used to be gated on "not an SSH
  // key", which was the same question while logins and notes were the only
  // other types. A card answers "not an SSH key" too, and would have drawn
  // an empty password row under its number.
  readonly property int detailTypeCode: detailItem ? Number(detailItem.typeCode || 1) : 1
  readonly property bool detailIsLoginLike: detailTypeCode === 1 || detailTypeCode === 2
  readonly property bool detailIsCard: detailTypeCode === 3
  readonly property bool detailIsIdentity: detailTypeCode === 4

  readonly property var detailCard: detailItem ? (detailItem.card || null) : null
  readonly property var detailIdentity: detailItem ? (detailItem.identity || null) : null

  // Expiry reads as one value, so it is composed once here rather than in the
  // binding that draws it. A card with only one half filled in shows that
  // half rather than a stray slash.
  readonly property string detailCardExpiry: {
    if (!detailCard) return ""
    var m = String(detailCard.expMonth || "").trim()
    var y = String(detailCard.expYear || "").trim()
    if (m && y) return m + " / " + y
    return m || y
  }

  readonly property string detailIdentityName: detailIdentity ? Model.identityFullName(detailIdentity) : ""

  // The postal parts, in the order an envelope wants them, with the empty
  // lines left out instead of drawn as blanks.
  readonly property string detailIdentityAddress: {
    if (!detailIdentity) return ""
    var street = [detailIdentity.address1, detailIdentity.address2, detailIdentity.address3]
      .map(function(part) { return String(part || "").trim() })
      .filter(function(part) { return part !== "" })
    var locality = [detailIdentity.city, detailIdentity.state, detailIdentity.postalCode]
      .map(function(part) { return String(part || "").trim() })
      .filter(function(part) { return part !== "" })
      .join(" ")
    var country = String(detailIdentity.country || "").trim()
    return street.concat(locality ? [locality] : []).concat(country ? [country] : []).join("\n")
  }
  property string liveTotp: ""
  property int totpSecRemaining: 30
  property string totpRequestItemId: ""
  property string totpQueuedItemId: ""
  property int totpQueuedEpoch: -1
  property bool totpRestartPending: false
  property string totpCopyItemId: ""
  property string passwordCopyItemId: ""

  // Attachment downloads. One `bw get attachment` runs at a time and the rest
  // wait in the queue, so "Save all" on an item with six files does not fire
  // six CLI bootstraps at once. `attachmentSaved` maps an attachment id to the
  // path it landed on, which is what turns the row's Download button into Open
  // and Show in folder; it is cleared whenever a different item is opened.
  property var attachmentQueue: []
  property string attachmentBusyId: ""
  property var attachmentSaved: ({})

  // Follow-up TOTP sequential copy state (Enter -> Password -> Enter -> TOTP)
  property var totpFollowupItem: null
  property string totpFollowupCode: ""
  property bool totpFollowupActive: false

  // The save currently in flight, or null. Holds what the list showed before
  // it, and the form that produced it, so a failure can put both back.
  property var pendingSave: null
  // The delete currently in flight, or null. Holds the row it removed so a
  // refusal can put it back.
  property var pendingDelete: null

  // A save that came back refused. The list has been restored to what the
  // vault actually holds; this is what the user typed, kept so it can be
  // reopened rather than retyped.
  property var failedSave: null

  // Add / Edit Form State
  property bool formIsEditing: false
  property string formItemId: ""
  property int formTypeCode: 1 // 1: Login, 2: Secure Note
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

  // Card and identity boxes. Flat strings rather than one object per type,
  // because that is what every other field on this form is and what the
  // TextField two-way binding above expects; formTypeFields() gathers them
  // back into the shape the payload builders want.
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

  // When the current auto-lock window started, in wall-clock terms, so a
  // suspend cannot hide from the countdown. See the autoLockWatchdog Timer.
  property double autoLockArmedAt: 0

  // The vault generation. Moves on whenever the vault changes hands -- locked,
  // logged out of, unlocked again -- and every `bw` reader records the one it
  // started under, so an answer from a vault that is no longer open can be
  // recognised as such when it arrives. See vaultReadIsStale().
  property int vaultEpoch: 0
  property var readEpochs: ({})

  // Processes whose collectors still have to be emptied after a lock. Anything
  // that was running at the time stays here until it finishes. See
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
  // Whether this unlocked session has already tried to repair an unsynced
  // vault. See the lastSync check in onStatusFinished().
  property bool initialSyncAttempted: false
  property bool syncReloadPending: false
  property string errorMessage: ""
  property string flashMessage: ""
  property bool cursorActive: false

  // Fingerprint unlock state.
  // PAM only proves presence, so a verified finger is used as the gate on
  // reading the master password back out of the login keyring.
  property bool fingerprintAvailable: false   // PAM stack + reader + enrolled finger
  property bool fingerprintStored: false      // master password present in keyring
  property bool fingerprintScanning: false
  property bool fingerprintAuthorized: false // a live PAM success may consume one keyring lookup
  property string fingerprintMessage: ""
  // Why the last fingerprint attempt failed. Separate from fingerprintMessage,
  // which is the progress of an attempt in front of the reader: the reason a
  // scan failed still has to be readable on the PIN or password screen the
  // user moves to, where there is no reader and no attempt.
  property string fingerprintError: ""
  // FIDO2 unlock state. The gate itself lives in FidoUnlock.qml, which reaches
  // the vault only for the setting it runs on and for the password a verified
  // touch releases; these forward what the locked screen and the settings row
  // read, the same way the fingerprint's own state is read. Its stored entry is
  // its own (account=fido_password), so this never borrows the fingerprint's.
  readonly property bool fidoReady: fidoUnlocker.ready
  readonly property bool fidoAvailable: fidoUnlocker.available
  readonly property bool fidoStored: fidoUnlocker.stored
  readonly property bool fidoScanning: fidoUnlocker.scanning
  // True between a verified touch and the unlock it starts, so the button can
  // say "Unlocking..." rather than re-inviting a touch already given.
  readonly property bool fidoAuthorized: fidoUnlocker.authorized
  readonly property string fidoMessage: fidoUnlocker.message
  // Writable through to the setup form in FidoUnlock.qml: the screen edits the
  // field, and the controller owns what the value means.
  property alias fidoSetupMaster: fidoUnlocker.setupMaster
  // The setup form's error, not a failed touch: fidoError below is the
  // fingerprint's counterpart, read by the unlock form on every method.
  property alias fidoSetupError: fidoUnlocker.error
  property alias fidoBusy: fidoUnlocker.busy
  readonly property string fidoError: fidoUnlocker.failure
  property string pendingUnlockPassword: ""   // held only until the unlock lands
  // Authentication processes are started before submission and wait on a
  // private FIFO. These flags distinguish that harmless waiting state from an
  // attempt whose password has actually been delivered.
  property bool unlockSubmitted: false
  property bool loginSubmitted: false
  property bool loginSubmitAfterPrewarmStop: false
  property bool loginPrepareAfterPrewarmStop: false
  property string loginPrewarmSignature: ""
  property string authPasswordWriteTarget: ""
  property string authPasswordWriteValue: ""
  // The value the keyring store process reads. Set from whichever path is
  // storing: the explicit setup form, or the automatic refresh after unlock.
  // Item JSON on its way to `bw encode`. Held here so the create/edit processes
  // can pass it in the environment instead of on the command line.
  property string itemPayloadJson: ""
  property bool fpSetupActive: false
  property string fpSetupMaster: ""
  property string fpError: ""
  property bool fpBusy: false
  // Which credential source drove the in-flight unlock, so a stale stored
  // secret can be discarded rather than retried forever. "" | "fingerprint" | "fido" | "pin"
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

  // Generator state (session-scoped, mirroring the browser extension's options)
  property var genOpts: Model.generatorDefaults()
  property string genValue: ""
  property bool genBusy: false
  property bool genRegeneratePending: false
  property string genRequestSignature: ""
  // `bw serve` state. Ready means the loopback generator answered; failed
  // means we stopped trying and the CLI carries the feature instead -- most
  // likely because something else already holds the port, in which case we
  // must not talk to it: a "generated password" from a stranger's server is
  // a password they know.
  property bool generateServeReady: false
  property bool generateServeStarting: false
  property bool generateServeFailed: false
  // Set while we are the ones shutting the server down, so its exit is not
  // mistaken for the bind failure that gives up on the port.
  property bool generateServeStopping: false
  property bool generateCliStopping: false
  property bool generateServeRequestStopping: false
  property bool generateServeRequestPending: false
  property var generateServeRequestPendingOptions: null
  property var generateServeRequestPendingCallback: null
  // Where Back and Esc go, and whether the generator can hand its value
  // somewhere. Opened from the item form it fills the password field in and
  // returns; opened on its own it is just the generator. One screen either
  // way, so the item form offers Bitwarden's own generator rather than a
  // second, weaker one of its own.
  property string generatorReturnScreen: "main"
  readonly property bool generatorFeedsForm: generatorReturnScreen === "edit"

  // PIN unlock state
  property bool pinConfigured: false        // ciphertext present in the keyring
  property string pinEntry: ""              // locked-screen input
  property int pinAttempts: 0
  readonly property int pinMaxAttempts: 5
  // The PIN setup form's own error: a PIN that is too short to save, a missing
  // master password, a keyring that refused the write.
  property string pinError: ""
  // Why an unlock with the PIN failed, which is a different thing from the
  // above and is read on whatever screen the user moves to next. Keeping the
  // two apart is what stops a half-finished setup putting "PIN must be at
  // least N digits" on a screen with no PIN on it.
  property string pinUnlockError: ""
  property string pinSetupPin: ""
  property string pinSetupConfirm: ""
  property string pinSetupMaster: ""
  property bool pinBusy: false
  property bool pinUnlockSubmitted: false
  readonly property bool pinReady: pinUnlock && pinConfigured
  // Long enough to save, short enough to be a bad idea. Drives the red state
  // on the PIN field during setup; see pinWeakWarning() in BitwardenModel.js.
  readonly property bool pinSetupWeak: Model.isPinWeak(pinSetupPin)
  readonly property string userName: Quickshell.env("USER") || Quickshell.env("LOGNAME") || ""
  // The fingerprint reader is on the laptop body, so a closed lid puts it out
  // of reach and the option must not be offered. Omarchy's detector decides;
  // see LidState.qml. The FIDO2 key on a cable is unaffected either way.
  readonly property bool lidClosed: lidState.closed
  // A lid shut during a scan takes the reader out of reach, and the first
  // reading can land after the auto-arm has already started one. Nothing else
  // watches fingerprintReady falling, so the conversation would sit in PAM with
  // no button on screen behind it.
  onLidClosedChanged: if (lidClosed && fingerprintScanning) cancelFingerprintUnlock()
  // Whether the vault can be unlocked with a finger *right now*: enrolled,
  // stored, and with the reader within reach. Everything that offers the option
  // -- the locked screen's button, the SSH prompt's, and the auto-arm -- reads
  // this, so gating it here is what hides them all.
  readonly property bool fingerprintReady: fingerprintUnlock && fingerprintAvailable && fingerprintStored && !lidClosed

  // Contextual suggestions state
  property var activeWindowData: null
  property var detectedContext: null
  property var suggestedItems: []
  property bool suggestionsDismissed: false
  property var associations: ({ version: 1, keys: {} })
  property var learnedIds: ({})
  property string pendingAssociationsJson: ""
  property bool associationsWritePending: false
  property bool associationsClearPending: false
  property int associationsEpoch: 0
  property int associationsReadEpoch: -1
  property bool sessionStorePending: false
  property bool sessionClearPending: false
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

  // Startup waits for the first view. A vault with no view attached is inert:
  // it is either the shared service before any monitor's bar has found it, or a
  // bar's own standby vault that the shared one made unnecessary. Neither may
  // probe `bw`, start the SSH agent or claim the IPC target.
  onLiveChanged: {
    if (!root.live || root.started) return
    root.started = true
    // The dependency probe goes first, and the status probe follows from it in
    // onDependenciesChecked. On a machine that already has `bw` the two are a
    // few milliseconds apart; on a fresh install the order is the difference
    // between opening on the setup screen and opening on a login form that
    // cannot succeed.
    root.checkDependencies()
    root.loadAssociations()
    // Explicit as well as bound: onSshAgentSupervisableChanged carries every
    // later change, but a shell that starts with the feature already enabled
    // evaluates that binding to true once, at creation, with nothing yet
    // listening.
    root.syncSshAgentSupervision()
    // Everything above is the startup value, not a user action. Only changes
    // after this point are transitions worth reacting to.
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

  // SSH keys need a CLI that can decrypt them. Until the probe confirms one,
  // the type filter that can only ever come back empty is not offered.
  readonly property bool sshUiAvailable: Model.sshUiAvailable(dependencies, depsChecked)
  readonly property var visibleCategories: sshUiAvailable
    ? categories
    : categories.filter(function(category) { return category.id !== "sshKey" })

  // -------------------------------------------------------------------------
  // SSH companion supervision
  // -------------------------------------------------------------------------
  //
  // The decisions live in Model.sshAgentReduce(); this side owns the Process,
  // the clock and the timers. Every event goes through applySshAgentEvent(),
  // which is the only place the state object is replaced, so the mirrored
  // properties below and the real state can never drift apart.
  //
  // Nothing here is on the path of an ordinary vault operation. A helper that
  // will not start, will not handshake, or crashes repeatedly leaves login,
  // unlock, list, copy, sync, edit, Send and the generator exactly as they
  // are; it only closes the signing gate and parks in an error state.

  // Resolved from Panel.qml's own URL, so the helper is launched by an
  // absolute path inside the plugin directory rather than off PATH.
  readonly property string sshAgentPluginDir: Model.pluginDirFromUrl(String(Qt.resolvedUrl(".")))
  readonly property string sshAgentRuntimeDir: Quickshell.env("XDG_RUNTIME_DIR") || ""
  // What the shipped helper turned out to be. Checked once when the feature
  // is enabled, and again whenever the plugin directory changes, because a
  // plugin update can replace the binary under a running shell.
  property var sshAgentHelper: ({ state: "unknown", source: "", version: "",
    protocol: 0, checksum: "unchecked", selfTest: "", message: "" })

  readonly property bool sshAgentSupervisable: sshAgentEnabled
    && sshAgentPluginDir !== "" && sshAgentRuntimeDir !== ""
    // A helper that fails inspection disables this feature and nothing else:
    // no supervisor, so no socket, no FIFO, and no agent branch in the vault
    // read. The rest of the plugin never sees it.
    && Model.sshAgentHelperReady(sshAgentHelper)

  function inspectSshAgentHelper() {
    if (sshAgentHelperProc.running) return
    sshAgentHelperProc.command = Model.sshAgentHelperInspectCommand(root.sshAgentPluginDir)
    sshAgentHelperProc.running = true
  }

  function onSshAgentHelperInspected(raw) {
    root.sshAgentHelper = Model.parseSshAgentHelperInspection(raw)
  }

  // The quick-unlock tool, checked the way the SSH helper is. Inspected at
  // every start, not only while a quick-unlock option is on: the encrypted
  // master password is written after each password login, so the panel has to
  // know whether it can do that before anyone opens settings. Failing this
  // disables PIN, fingerprint and FIDO2 unlock and nothing else.
  property var unlockKeyHelper: ({ state: "unknown", source: "", version: "",
    protocol: 0, checksum: "unchecked", selfTest: "", message: "" })
  readonly property bool unlockKeyReady: Model.unlockKeyReady(unlockKeyHelper)

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
  // One keyring item holds the master password, encrypted once, written the
  // first time `bw` accepts a typed password; each quick-unlock method only
  // adds a way into it. Everything here goes through BitwardenModel's
  // envelope builders, one process at a time: two writers racing on one
  // keyring item would lose whichever stored first.

  // Besides the tool: argon2 and systemd-creds --user.
  property var quickUnlockPrereqs: ({ argon2: false, creds: false, ready: false, message: "", checked: false })
  readonly property bool quickUnlockAvailable: unlockKeyReady && quickUnlockPrereqs.ready
  readonly property string quickUnlockUnavailableReason: !unlockKeyReady
    ? String(unlockKeyHelper.message || "")
    : String(quickUnlockPrereqs.message || "")

  // Which account an envelope belongs to, from `bw status`.
  property string accountId: ""
  property string accountServer: ""

  // The envelope's secret-free summary, or null when there is none (or none
  // has been read yet -- `envelopeChecked` says which).
  property var envelopeSummary: null
  property bool envelopeChecked: false

  property var envelopeJobs: []
  property var envelopeJob: null

  // The password a quick unlock just produced and `bw` refused: the master
  // password changed elsewhere. Held only until the next typed unlock, which
  // uses it to open the envelope and re-seal it for the new password -- so no
  // method has to be set up again. Cleared on lock-out paths and logout.
  property string rotationOldPassword: ""
  // Fingerprint unlock's plaintext entry from before the envelope. Migrated
  // at the first start that can, then deleted.
  property bool legacyFingerprintStored: false
  property bool legacyMigrationAttempted: false
  property bool fingerprintFromEnvelope: false

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
    return { id: accountId, server: accountServer }
  }

  function envelopeReadinessChanged() {
    if (!quickUnlockAvailable) return
    if (!envelopeChecked) refreshEnvelope()
    maybeMigrateLegacyFingerprint()
  }

  // Queue one envelope process. `job` is { command, env, secretOutput,
  // writes, onDone(exitCode, stdout) }. `env` carries the secrets and is
  // dropped the moment the process starts.
  function queueEnvelopeJob(job) {
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
    // What an open printed was the master password. Take it, then scrub the
    // collector so it does not sit in the Process until the next run.
    if (job && job.secretOutput) clearProcessCollectorSoon(envelopeProc)
    if (job && job.onDone && !logoutPending) job.onDone(exitCode, out)
    out = ""
    if (logoutPending && allCredentialsClearPending) Qt.callLater(requestAllCredentialClear)
    Qt.callLater(pumpEnvelopeJobs)
  }

  // Logout: nothing queued may run after the keyring is cleared.
  function dropEnvelopeState() {
    envelopeJobs = []
    envelopeSummary = null
    envelopeChecked = false
    rotationOldPassword = ""
    legacyFingerprintStored = false
    legacyMigrationAttempted = false
    fingerprintFromEnvelope = false
  }

  function refreshEnvelope() {
    if (!quickUnlockAvailable) return
    queueEnvelopeJob({
      command: Model.unlockEnvelopeInspectCommand(envelopeTool()),
      onDone: function(code, out) {
        if (code === 0) {
          try { root.envelopeSummary = JSON.parse(out) } catch (e) { root.envelopeSummary = null }
        } else if (code === Model.envelopeExitCodes().absent) {
          root.envelopeSummary = null
        }
        root.envelopeChecked = true
        root.recomputeFingerprintStored()
      }
    })
  }

  function recomputeFingerprintStored() {
    fingerprintStored = Boolean(envelopeSummary && envelopeSummary.fingerprint) || legacyFingerprintStored
  }

  // Runs `then()` once the account is known, asking `bw status` if a fresh
  // login has not reported it yet.
  function withEnvelopeAccount(then) {
    if (accountId) { then(); return }
    queueEnvelopeJob({
      command: Model.statusCommand(),
      env: bwEnv(),
      onDone: function(code, out) {
        var st = code === 0 ? Model.parseStatus(out) : null
        if (st && st.userId) {
          root.accountId = st.userId
          root.accountServer = st.serverUrl
          then()
        }
      }
    })
  }

  // THE writer of the stored password. Called whenever `bw` has just accepted
  // a password somebody typed -- email login, API-key login, master-password
  // unlock, or an enable form's check -- and never with one a quick-unlock
  // method produced. `done(ok)` is optional.
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
            // `bw` took this password and the envelope does not: it was
            // changed elsewhere. Re-seal through whatever still opens the
            // envelope, keeping every method.
            var rotate = {}
            rotate[Model.envelopeNewSecretEnvVar()] = pw
            if (oldPassword) {
              rotate[Model.keyringSecretEnvVar()] = oldPassword
              root.writeEnvelope(Model.unlockEnvelopeUpdateCommand(tool, account,
                { kind: "rotate", auth: { kind: "master" } }), rotate, finish)
            } else if (root.envelopeSummary && root.envelopeSummary.fingerprint) {
              root.writeEnvelope(Model.unlockEnvelopeUpdateCommand(tool, account,
                { kind: "rotate", auth: { kind: "fingerprint" } }), rotate, finish)
            } else {
              // Nothing here reaches the data key yet. The next quick unlock
              // will produce the old password, fail, and bring it back here.
              root.writeEnvelope(Model.unlockEnvelopeUpdateCommand(tool, account, { kind: "mark-stale" }),
                {}, finish)
            }
            return
          }
          console.log("qs-bitwarden envelope: check failed with " + code)
          finish(false)
        }
      })
    })
  }

  function writeEnvelope(command, env, done) {
    queueEnvelopeJob({
      command: command, env: env, writes: true,
      onDone: function(code) {
        if (code !== 0) console.log("qs-bitwarden envelope: write failed with " + code)
        root.refreshEnvelope()
        if (done) done(code === 0, code)
      }
    })
  }

  // An enable form's master password: a check against the stored password,
  // never a new copy of it. `op` is the update that adds the method; it is
  // itself authorized by the password opening the master wrap. With no
  // envelope at all, `bw` checks the password instead and it is stored the
  // way any accepted password is, then the method is added.
  function addQuickUnlockMethod(password, op, extraEnv, done) {
    var pw = String(password || "")
    if (!quickUnlockAvailable) { done(false, "unavailable"); return }
    withEnvelopeAccount(function() {
      var env = {}
      env[Model.keyringSecretEnvVar()] = pw
      if (extraEnv) for (var k in extraEnv) env[k] = extraEnv[k]
      var command = Model.unlockEnvelopeUpdateCommand(root.envelopeTool(), root.envelopeAccount(), op)
      root.queueEnvelopeJob({
        command: command, env: env, writes: true,
        onDone: function(code) {
          var E = Model.envelopeExitCodes()
          if (code === 0) { root.refreshEnvelope(); done(true, ""); return }
          if (code === 3) { done(false, "wrong-password"); return }
          if (code !== E.absent && code !== 6 && code !== E.unseal) { done(false, "failed"); return }
          root.verifyWithBw(pw, function(ok) {
            if (!ok) { done(false, "wrong-password"); return }
            root.storeAcceptedMasterPassword(pw, function(stored) {
              if (!stored) { done(false, "failed"); return }
              var again = {}
              again[Model.keyringSecretEnvVar()] = pw
              if (extraEnv) for (var k2 in extraEnv) again[k2] = extraEnv[k2]
              root.writeEnvelope(command, again, function(added) { done(added, added ? "" : "failed") })
            })
          })
        }
      })
    })
  }

  // No envelope to check against: ask `bw`. A successful `bw unlock` mints a
  // new session key that replaces the one in use, so it is adopted and
  // remembered exactly as an unlock's would be.
  function verifyWithBw(password, done) {
    var env = {}
    env[Model.keyringSecretEnvVar()] = String(password || "")
    queueEnvelopeJob({
      command: Model.bwVerifyPasswordCommand(),
      env: bwEnv(env), secretOutput: true,
      onDone: function(code, out) {
        var s = code === 0 ? Model.extractSessionToken(out) : ""
        if (!s) { done(false); return }
        root.session = s
        root.storeCurrentSession()
        done(true)
      }
    })
  }

  function removeQuickUnlockMethod(op) {
    if (!quickUnlockAvailable || !accountId) return
    if (!envelopeSummary) return
    writeEnvelope(Model.unlockEnvelopeUpdateCommand(envelopeTool(), envelopeAccount(), op), {}, null)
  }

  // The plaintext fingerprint entry, moved into the envelope in one shell.
  // Once per session: a failure leaves the entry for the next start.
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

  property var sshAgentState: Model.sshAgentInitialState()
  // Mirrors of sshAgentState. QML cannot bind through a plain JS object, and
  // the handshake timeout and backoff timers have to be driven by bindings
  // rather than by anything that waits.
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

    // The state above is committed before any of this runs, because stopping
    // the Process can re-enter this function with the child's exit before the
    // outer call returns. That order is what makes the re-entry safe: the
    // inner reduction sees the phase it should, and no action set here is one
    // the inner call also sets.
    var action = step.action
    // Cancel before scheduling: a stop that arrives while a restart is armed
    // must not leave the timer running against a helper nobody asked for.
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

  // A helper that exits before its handshake may have found the runtime lock
  // already held -- by another shell, say -- rather than failed. It exits 1
  // either way, so the lock is asked directly before the exit is reported, and
  // a held lock parks the supervisor instead of counting toward CRASH_LOOP.
  // An exit after `ready`, or while stopping, is reported at once.
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
    // A previous stop closed this. The control channel is the helper's only
    // input, so it has to be open again before the handshake is written.
    sshAgentProc.stdinEnabled = true
    sshAgentProc.running = true
  }

  // Stopping the helper is a request, not a signal. Its designed shutdown is
  // the control channel closing: it drops its keys, unlinks its socket and
  // FIFO, and exits. SIGTERM -- which is all `running = false` does -- skips
  // every one of those, leaving a socket and FIFO behind for the next start
  // to clean up. So ask, then terminate only if it does not go.
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
  // One prompt at a time, never over a locked screen, and never claiming more
  // about the requesting process than the companion actually checked.

  // What is actually on screen. A live signing request outranks navigation:
  // the panel's own flows reset currentScreen freely -- opening the panel,
  // finishing an unlock -- and each of those would otherwise drop a prompt
  // that a blocked client is waiting on. Screen visibility binds to this
  // rather than to currentScreen, so no later assignment can hide a prompt.
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
  // Password, PIN, and fingerprint completion handlers must accept the
  // transient overlay as a real authentication surface even while the
  // anchored panel stays closed.
  readonly property bool sshAuthSurfaceActive: opened || sshApprovalPopupOpen
  // What the companion last announced, and the live view of it. The
  // announcement is a snapshot; the view is that snapshot re-derived against
  // a ticking clock, so a grant counts down on screen and disappears when it
  // lapses instead of waiting for the next thing to happen.
  property var sshGrantsAnnounced: []
  property double sshGrantTick: 0
  readonly property var sshGrants: Model.sshAgentGrantsAt(sshGrantsAnnounced, sshGrantTick)
  property var sshCooldown: Model.sshAgentCooldownInitial()
  // Whether the current cooldown has already been announced. Reset when it
  // lapses, so a later one is announced again but the same one is not
  // repeated on every refused request.
  property bool sshCooldownAnnounced: false
  readonly property var sshCooldownStatus: Model.sshAgentCooldownStatus(sshCooldown, sshCooldownTick)
  // A one-second tick so the remaining time in the status actually counts
  // down; bindings on Date.now() would never re-evaluate on their own.
  property double sshCooldownTick: 0
  property double sshPromptStartedMs: 0
  property int sshPromptRemainingSec: 0
  property string screenBeforeSshApproval: "main"
  // Whether the signing request is what put the panel on screen. If it was,
  // answering hands the desktop back; if the user already had the panel open,
  // it is theirs and they are returned to what they were doing.
  property bool sshPromptOpenedPanel: false

  function sshAgentWrite(line) {
    if (line === "") return
    if (sshAgentProc.running && sshAgentProc.stdinEnabled) sshAgentProc.write(line)
  }

  // Whether a request may raise UI at all. A locked screen never does, and a
  // process that has had two refusals in a row is put on a cooldown so it
  // cannot keep reopening the panel.
  // Called wherever the cooldown may have just started. The announcement is
  // the only thing that tells a user why their SSH command suddenly fails.
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

  // The only way out of a running cooldown other than waiting it out. It has
  // to be explicit: the cooldown suppresses the prompts an approval would
  // answer, so nothing the requesting process does can end it, and nothing it
  // does should. A person pressing this is the signal that the requests are
  // wanted after all.
  function resumeSshSigning() {
    root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "resumed", Date.now())
    noteSshCooldown()
  }

  function sshAgentMayPrompt() {
    // An unknown screen state counts as locked. The poll runs every few
    // seconds while the agent is serving, so a reading older than this means
    // the poll is not running and the panel cannot tell -- and the cost of
    // guessing wrong is a credential prompt on a locked desktop.
    var fresh = root.screenLockCheckedAt > 0
      && (Date.now() - root.screenLockCheckedAt) < (Model.screenLockPollMs() * 4)
    if (!Model.sshAgentShouldPrompt(fresh ? { screenLocked: root.screenIsLocked } : null)) return false
    return !Model.sshAgentCooldownActive(root.sshCooldown, Date.now())
  }

  function showSshApproval(message) {
    root.sshPrompt = Model.sshAgentPromptView(message, root.sshAgentApprovalWindowSec)
    root.sshPromptStartedMs = Date.now()
    root.sshPromptRemainingSec = Math.ceil(Model.sshAgentRequestDeadlineMs() / 1000)
    if (root.sshAgentApprovalPopup) {
      root.sshPromptOpenedPanel = false
      return
    }
    if (root.currentScreen !== "sshApproval") root.screenBeforeSshApproval = root.currentScreen
    // Recorded before opening, because open() is what makes it true.
    if (!root.sshUnlockRaw) root.sshPromptOpenedPanel = !root.opened
    // Open first. Opening runs onPanelOpened(), which sends an unlocked panel
    // to the item list, so claiming the screen before that would simply be
    // undone -- the prompt would be live with nothing on screen.
    if (!root.opened) root.open()
    root.currentScreen = "sshApproval"
  }

  // shell.json hot-reloads. If the preference changes while a client is
  // blocked, move the same request to the newly selected surface rather than
  // making it invisible until its deadline expires.
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
    // Answered -- approved or denied alike -- so give the desktop back if the
    // request is what took it. A panel the user opened themselves stays open
    // on whatever screen they were using.
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

  // The popup is deliberately short lived. Do not let a dismissed or expired
  // request leave a password, PIN, PAM conversation, or prewarmed CLI behind.
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

  // The companion expires the request; this only stops the panel showing a
  // question whose answer would now be rejected anyway.
  function expireSshRequest() {
    if (!sshPrompt && !sshUnlockRequest) return
    root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "timeout", Date.now())
    noteSshCooldown()
    dismissSshApproval()
  }

  // Git SSH signing needs paths, so the validated public set is projected to
  // files. Only what the companion vouched for is written, and only its
  // public form -- sshExportIdentities() refuses anything that is not an
  // OpenSSH public line.
  function exportSshPublicKeys() {
    var payload = Model.sshExportPayload(root.sshPendingPublicKeys)
    root.sshPendingPublicKeys = []
    if (sshExportProc.running) return
    sshExportProc.running = true
    sshExportProc.write(payload)
    sshExportProc.stdinEnabled = false
  }

  // Logout, account change and disabling remove the projection. A lock does
  // not: public identities stay advertised while locked, so their files stay
  // with them.
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
      // A request that cannot raise UI is refused rather than left hanging:
      // the client gets its answer now instead of waiting out the deadline.
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
      root.sshPromptStartedMs = Date.now()
      root.sshPromptRemainingSec = Math.ceil(Model.sshAgentRequestDeadlineMs() / 1000)
      if (root.sshAgentApprovalPopup) {
        root.sshPromptOpenedPanel = false
        return
      }
      root.sshPromptOpenedPanel = !root.opened
      if (!root.opened) root.open()
      return
    }
    if (message.type === "request_cancelled") {
      // The request was cancelled by the client, timed out, or released on unlock.
      var live = root.sshPrompt || root.sshUnlockRequest
      if (live && live.requestId === message.requestId) {
        if (message.reason === "released") {
          // A released sign request returns immediately as an approval, so the
          // popup stays up and becomes that. A released identity listing has
          // just been answered from the freshly loaded keys -- nothing follows
          // it, and leaving the prompt up strands it on screen with the client
          // already served.
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
      // The set is complete: every public_key for this epoch arrived ahead of
      // this message.
      if (root.sshPendingPublicEpoch === message.epoch) exportSshPublicKeys()
      return
    }
    if (message.type === "load_failed") {
      // The helper dropped its private set and kept serving. Distinct from
      // `locked`, which is the ack for vault_locked and must not start a load.
      // A failure for an older load is stale: a newer one has already begun
      // and marked its epoch, and clearing that would read the vault again.
      if (message.epoch !== root.sshAgentEpoch) return
      root.sshAgentLoadFailStreak += 1
      root.sshAgentLoadedForVaultEpoch = -1
      if (root.sshAgentLoadFailStreak === 1) maybeStartupLoad()
      return
    }
    if (message.type === "locked") {
      // The companion has denied signing, dropped its grants and private keys,
      // and kept only the public projection. That is what the kill timer was
      // waiting for.
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
  // The companion's keystore requires a strictly increasing epoch per load, so
  // this counter only ever goes up. It survives helper restarts harmlessly: a
  // restarted companion begins again at 0, and every value the panel sends is
  // still greater than that.
  property int sshAgentEpoch: 0
  property string sshAgentLoadId: ""
  property bool sshAgentLoadActive: false
  // Whether the read now running carries the agent branch, and whether it has
  // already been retried without it. The retry exists so an optional feature
  // can never cost the user their item list.
  property bool listAgentBranchActive: false
  property bool listRetriedWithoutAgent: false

  // A nonce is generated ahead of the load that will use it. Reading
  // /dev/urandom is fast, but it is still a process, and the ordinary item
  // list must never wait on the agent feature -- so a load that finds no
  // nonce ready simply runs without the branch and primes one for next time.
  property string sshAgentNextLoadId: ""
  // What the companion last reported it was serving. Public metadata only --
  // a count, not the keys -- and it is what tells the panel whether a locked
  // companion still has a public cache to answer identity listings from.
  property int sshAgentKeyCount: 0
  // The validated public identities the companion reported for the epoch
  // currently loading. Accumulated per key, because a single message carrying
  // all of them would exceed the control-line ceiling at the key limit.
  property var sshPendingPublicKeys: []
  property int sshPendingPublicEpoch: -1
  property double sshAgentKeysLoadedAt: 0
  // The vault epoch a key load has already been started for. dropVaultState()
  // advances vaultEpoch on every lock and logout, so this is what tells a
  // startup load apart from one that has already happened for this session.
  property int sshAgentLoadedForVaultEpoch: -1
  // Auto-retries of a failed FIFO load. One extra attempt; a persistently
  // bad payload must not relaunch the item list forever.
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

  // Close an open load window. Called on success, on failure, and on a lock
  // that cancels the read underneath it. The companion holds every candidate
  // unpublished until this arrives, and discards it on a failed status, so a
  // window that is never closed is the one outcome to avoid.
  function endSshAgentLoad(ok) {
    if (!sshAgentLoadActive) return
    sshAgentLoadActive = false
    sshAgentLoadId = ""
    if (sshAgentProc.running && sshAgentProc.stdinEnabled) {
      sshAgentProc.write(Model.sshAgentLoadEndLine(sshAgentEpoch, ok))
    }
    primeSshAgentLoadId()
  }

  // A lock abandons the current loadId and stops the whole read. The pipeline
  // runs as its own process group, so terminating the wrapper reaps `bw`, the
  // caps, `tee` and both `jq` stages with it.
  function cancelSshAgentLoad() {
    if (listProc.running) listProc.running = false
    endSshAgentLoad(false)
    listAgentBranchActive = false
    listRetriedWithoutAgent = false
  }

  // Every vault transition reaches the companion through here, so the ordering
  // rules live in one place: deny first, cancel work in flight, then let the
  // panel get on with its own lock. Nothing below ever waits on the helper.
  function applySshAgentLifecycle(event) {
    var action = Model.sshAgentLifecycleTransition(event, {
      enabled: root.sshAgentEnabled,
      helperReady: root.sshAgentGateOpen,
      loggedIn: root.status !== "unauthenticated",
      unlocked: root.status === "unlocked",
      loading: root.sshAgentLoadActive,
      hasPublicCache: root.sshAgentKeyCount > 0,
      epoch: root.sshAgentEpoch
    })

    if (action.cancelLoad) cancelSshAgentLoad()
    for (var i = 0; i < action.controlLines.length; i++) {
      if (sshAgentProc.running && sshAgentProc.stdinEnabled) sshAgentProc.write(action.controlLines[i])
    }
    if (action.clearPublic) {
      root.sshAgentKeyCount = 0
      root.sshAgentKeysLoadedAt = 0
      clearSshPublicKeys()
    }
    // The acknowledgment is a courtesy the panel gives the companion two
    // seconds to return. It is not a precondition for locking: `bw lock` has
    // already been launched by the caller, and a companion that cannot
    // confirm a lock is one that must not keep running.
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
      // The keystore lives in the helper's memory. Whatever it held went with
      // it, so the panel must stop claiming those keys are still served.
      root.sshAgentKeyCount = 0
      return
    }
    // A new helper is empty even when the vault epoch has not moved -- the
    // epoch tracks the vault, not the process. Clearing this is what makes a
    // restarted or re-enabled helper eligible for a load, instead of leaving
    // it keyless until something unrelated happens to bump the epoch.
    root.sshAgentLoadedForVaultEpoch = -1
    root.sshAgentLoadFailStreak = 0
    primeSshAgentLoadId()
    // Startup is not evidence that the vault is locked: rememberSession can
    // restore a session key, so the panel can already be unlocked when the
    // companion finishes its handshake with an empty keystore. Deferred by a
    // beat so the nonce that was just primed is actually ready.
    sshAgentStartupLoadTimer.restart()
  }

  Timer {
    id: sshAgentStartupLoadTimer
    interval: 250
    repeat: false
    onTriggered: root.maybeStartupLoad()
  }

  // Two things have to be true before a startup load makes sense -- the helper
  // is serving, and the vault is actually unlocked -- and on a shell restart
  // they arrive in either order: the handshake can easily beat the first
  // `bw status`. So both edges call this, and the vault epoch keeps it to one
  // load rather than one per edge.
  function maybeStartupLoad() {
    if (!sshAgentGateOpen || root.status !== "unlocked") return
    // A read already running is the common case at startup: the panel's first
    // item read is launched before the helper has finished handshaking, so it
    // carries no agent branch. onListFinished() calls back here once it lands.
    if (sshAgentLoadActive || listProc.running) return
    if (sshAgentLoadedForVaultEpoch === root.vaultEpoch) return
    // Without a nonce the read would run with no agent branch, load nothing,
    // and still spend the attempt. The nonce is re-primed as each load closes,
    // so a retry right after a failure usually lands here first;
    // onSshAgentLoadIdRead() calls back once it is ready.
    if (!Model.isValidLoadId(sshAgentNextLoadId)) {
      primeSshAgentLoadId()
      return
    }
    // Marked before the attempt, not after it, so one failed attempt cannot
    // turn into a read that relaunches itself.
    sshAgentLoadedForVaultEpoch = root.vaultEpoch
    applySshAgentLifecycle("startup")
  }

  onStatusChanged: {
    promoteUnlockToApproval()
    maybeStartupLoad()
  }

  // The vault is unlocked but its keys are still being read. Ask now rather
  // than after: approving needs the key's identity and the requesting
  // program, and both are already known. The companion records the approval
  // and applies it the moment the keys land, re-checking that the approved
  // key is actually present before it signs.
  function promoteUnlockToApproval() {
    if (root.status !== "unlocked" || !root.sshUnlockRaw || root.sshPrompt) return
    // A listing is satisfied by the load itself; there is no signature to
    // authorise, so it stays a wait rather than becoming an approval.
    if (root.sshUnlockRaw.reason === "list-identities") return
    var raw = root.sshUnlockRaw
    root.sshPromotedOldId = raw.requestId
    root.sshUnlockRequest = null
    root.sshUnlockRaw = null
    root.sshUnlockQueue = []
    showSshApproval(raw)
  }

  // The bound on the companion's lock acknowledgment. A helper that cannot
  // confirm it has dropped its keys is a helper that must not keep running.
  Timer {
    id: sshAgentLockAckTimer
    interval: Model.sshAgentLockAckTimeoutMs()
    repeat: false
    onTriggered: if (sshAgentProc.running) sshAgentProc.running = false
  }

  // Disabled / enabled / error, as the design's table defines them. Derived,
  // never stored: it can only ever say what the supervisor is actually doing.
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
  // Where SSH_AUTH_SOCK points decides nothing above. The companion binds a
  // deterministic path and never reads it; this is only about whether the
  // user's *clients* will find that socket. The panel sees the graphical
  // session's environment and nothing else, so everything here is phrased as
  // a hint with a check the user can run in the terminal they actually use.
  readonly property string sshAuthSock: Quickshell.env("SSH_AUTH_SOCK") || ""
  readonly property var sshRouting: Model.sshAuthSockDiagnostic(sshAuthSock, sshAgentRuntimeDir)

  property var uwsmFragment: ({ state: "unknown", removable: false, message: "" })
  readonly property var sshRoutingNotice: Model.sshAgentRoutingNotice(uwsmFragment, sshRouting)
  property bool uwsmBusy: false
  property string uwsmFlash: ""
  // Set when the session already points at another agent. Writing the fragment
  // would make Bitwarden the primary agent at the next login, which is not
  // something to do silently on one click.
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

  // Clearing everything the plugin stored outside its own folder. Confirmed
  // rather than absorbed by the first click: it drops a stored master
  // password and every learned suggestion, and none of it comes back.
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
    // The keyring entry is part of what was just deleted, so what the panel
    // believes about a stored master password must not be kept.
    if (result.ok) root.fingerprintStored = false
  }

  function cancelUwsmSetup() {
    uwsmConfirmPending = false
  }

  // Safe to call unconditionally: the script removes the file only when it is
  // byte-for-byte the one this plugin writes, and refuses a symlink outright.
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

  // Turning the agent off takes the routing file with it, but only if it is
  // the exact file this plugin wrote. Anything the user manages by hand is
  // left alone with instructions rather than deleted on a toggle.
  //
  // Gated on startup having finished, because this must fire on a real
  // transition and not on the initial evaluation of the binding. Without the
  // guard, every shell start with the feature off would delete a routing file
  // the user never touched -- a filesystem change nobody asked for.
  property bool sshAgentSettingsReady: false

  onSshAgentEnabledChanged: {
    if (sshAgentEnabled) inspectSshAgentHelper()
    inspectUwsmFragment()
    if (!sshAgentSettingsReady) return
    if (!sshAgentEnabled) {
      // Stopping the helper goes through the supervisor, which knows nothing
      // about the public projection. Without this, the files of a feature
      // that is no longer running are left behind on disk.
      applySshAgentLifecycle("disable")
      removeUwsmFragment()
      return
    }
    // And turning it back on puts the file back, because taking it away on
    // one toggle and not restoring it on the other is a trap: SSH_AUTH_SOCK
    // is fixed at login, so the session that flips the setting keeps working
    // either way and the damage only appears at the next boot, long past the
    // point where anyone would connect the two. The inspection above is
    // asynchronous, so the decision waits for its answer.
    uwsmRestorePending = true
  }

  // Only ever set by re-enabling the agent, and cleared by the first
  // inspection that follows. It restores what disabling removed; it never
  // routes a session that was not already routed, and it never overrules a
  // file this plugin did not write.
  property bool uwsmRestorePending: false

  function applyUwsmRestore() {
    if (!uwsmRestorePending) return
    uwsmRestorePending = false
    if (!sshAgentEnabled || uwsmBusy) return
    // "absent" only: a foreign file, a symlink, an unreadable one or no HOME
    // are all cases the plugin refuses to touch, and it must keep refusing
    // here. An agent already owning SSH_AUTH_SOCK is a decision the user
    // makes at the button, with the conflict named.
    if (uwsmFragment.state !== "absent" || sshRouting.state === "elsewhere") return
    beginUwsmSetup()
  }

  // -------------------------------------------------------------------------
  // Lifecycle & Open / Close
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

    // controller.show() flips `opened`, which runs onPanelOpened via
    // onOpenedChanged. Only drive it directly when the panel was already open
    // and that signal will not fire -- otherwise every open did its startup
    // work twice, including two `bw status` calls at ~3s each.
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
    // Closing a setup form is cancellation even if its keyring writer has
    // already started; its completion handler will clear a stale write.
    abandonPinSetup()
    abandonFingerprintSetup()
    cancelFingerprintUnlock()
    // Released, not cancelled: closing the panel must leave the key's request
    // adoptable, or reopening asks a busy authenticator for a second one.
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

  function loadAssociations() {
    if (associationsReadProc.running) return
    associationsReadEpoch = associationsEpoch
    associationsReadProc.command = Model.associationsReadCommand()
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

  // Called whenever the user acts on an item while a window context is active.
  // Silent by design: teaching happens as a side effect of normal use.
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

  // Put the cursor somewhere sensible when a screen appears -- not hold it
  // there. Those are the same thing right up until something announces a
  // screen the user is already typing on, and something does: a logout sets
  // the status itself and then runs `bw status` to confirm it, which takes a
  // few seconds and arrives to say "unauthenticated" in the middle of the
  // master password being typed. Re-focusing on that news moved the cursor
  // from the password field to the email field mid-word, so the rest of the
  // password went into an unmasked field that was about to be submitted as an
  // email address.
  //
  // So a screen that already holds the cursor keeps it. Moving between screens
  // still focuses, because the field holding focus then belongs to the screen
  // being left rather than the one arriving.
  function focusAppropriateField() {
    if (sshApprovalPopupOpen) return
    Qt.callLater(function() {
      // Setup has no field to type into, and the ones this would reach for are
      // on screens that are not showing.
      if (currentScreen === "setup") return
      if (status === "unlocked" && currentScreen === "main") {
        if (!presenter.fieldHasFocus("search")) presenter.focusField("search")
      } else if (status === "locked" || status === "checking") {
        if (presenter.unlockFieldHasFocus()) return
        if (pinReady) presenter.focusField("pin")
        else presenter.focusField("pass")
      } else if (status === "unauthenticated") {
        if (presenter.loginFieldHasFocus()) return
        // A login resumed on a challenge opens on the field that is waiting,
        // not back at the top of the form.
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
      // Not a cancel: see releaseSurface() in FidoUnlock.qml. The key keeps the
      // request either way, so the conversation is kept to consume the touch.
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

    // A signing request outranks the item list: it is the reason the panel
    // opened, and a client is blocked on the answer.
    if (sshPrompt) {
      currentScreen = "sshApproval"
      return
    }
    if (status === "unlocked") {
      currentScreen = "main"
      ensureItemsFresh()
    } else if (status === "locked") {
      // Still check for a handed-over session: a terminal login leaves the
      // panel locked, which is precisely when the handoff matters.
      refreshStatus()
      prepareUnlock()
      armPresenceUnlock()
    } else {
      refreshStatus()
    }
  }

  // -------------------------------------------------------------------------
  // Status & Keyring Handlers
  // -------------------------------------------------------------------------

  function refreshStatus() {
    errorMessage = ""
    if (logoutPending) return
    // The dependency probe owns the first status transition. Opening the
    // panel before that short probe returns must wait rather than trying to
    // execute a CLI that a first-run install may not have yet.
    if (!depsChecked) {
      checkDependencies()
      return
    }
    // Nothing to ask while a required tool is missing. Every caller reaches
    // here on some ordinary event -- a panel open, an IPC nudge -- and none of
    // them should be able to walk the user past setup into a login form that
    // has no CLI behind it.
    if (setupGated) {
      currentScreen = "setup"
      return
    }
    // Past the gate, so the vault has been asked about. Recorded here rather
    // than at the one call site that waits on the dependency probe, so a panel
    // opened before that probe reports does not earn a second `bw status` --
    // three seconds each, and the first open is where they are felt.
    statusProbeStarted = true
    // A terminal login may have left a session waiting. Check before anything
    // else, including the locked-with-no-session short circuit below, since
    // that is exactly the state a terminal login leaves the panel in.
    //
    // Only a login this panel actually launched, and only for as long as one
    // could still be in progress. Outside that window the file is removed
    // rather than read: nobody is expecting a key, so nothing adopts it, and
    // leaving a live one in the runtime directory is the worse outcome.
    if (sessionHandoffProc.running) return
    var expecting = Model.handoffWindowOpen(terminalLoginStartedAt, Date.now())
    if (!expecting) terminalLoginStartedAt = 0
    beginEpochOperation("sessionHandoff")
    sessionHandoffProc.command = Model.sessionHandoffReadCommand(expecting)
    sessionHandoffProc.running = true
  }

  function onSessionHandoff(raw) {
    if (epochOperationIsStale("sessionHandoff")) return
    var handed = Model.extractSessionToken(String(raw || "").trim())
    if (handed) {
      cancelAuthPrewarm()
      abandonAuthSecrets()
      // Consumed, so the window shuts behind it rather than staying open for
      // whatever is written there next.
      terminalLoginStartedAt = 0
      session = handed
      vaultEpoch += 1
      storeCurrentSession()

      // bw minted this key moments ago, so trust it and start loading rather
      // than spending another `bw status` (~3.3s) to be told what we know.
      // The status check still runs, but alongside the loads instead of in
      // front of them -- it only fills in the account email.
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
      beginEpochOperation("keyringLookup")
      keyringLookupProc.command = Model.keyringLookupCommand()
      keyringLookupProc.running = true
    } else {
      runStatusCheck()
    }
  }

  function onKeyringLookupFinished(rawToken) {
    if (epochOperationIsStale("keyringLookup")) return
    var token = String(rawToken || "").trim()
    if (token) {
      session = token
      vaultEpoch += 1
    }
    runStatusCheck()
  }

  function runStatusCheck(authoritative) {
    if (statusProc.running) return
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
    if (epochOperationIsStale("status")) return
    // A `bw status` answers about the world as it was when it started, and it
    // takes seconds. Landing mid-login, that answer is "unauthenticated" --
    // truthfully, for the moment it was asked -- and acting on it cancelled the
    // login in flight: SIGTERM to a process the user had just submitted, the
    // button dropping back out of "Verifying...", and nothing shown at all. The
    // attempt is the newer news; it will set the state itself when it lands.
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
      // A vault unlocked from another monitor, a terminal handoff, or the CLI
      // leaves a presence gate waiting on a touch that can no longer unlock
      // anything -- a key blinking for an interaction nobody asked for.
      cancelFingerprintUnlock()
      cancelFidoUnlock()
      abandonAuthSecrets()
      status = "unlocked"
      currentScreen = "main"
      ensureItemsFresh()
      resetAutoLockTimer()
      focusAppropriateField()
      // A vault that has never synced holds no ciphers, so the item list is
      // empty and correct -- which looks exactly like a vault with nothing in
      // it. `bw login` is supposed to have synced by now, and reports success
      // whether or not it managed to: it calls fullSync() without
      // allowThrowOnError, so a sync that throws is swallowed, lastSync is
      // never set, and the session it prints is a working session onto an
      // empty local vault. That is not a state to render as an empty vault,
      // so repair it once and reload.
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
  // In-Plugin Login & Authentication
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
    // Back to the remembered method, not to nothing: a fresh attempt should
    // start from what worked last time.
    login2faMethod = rememberedTwoFactorMethod
    syncLoginFieldsToState()
  }

  // The user answering bw's provider question. The pick is not trusted yet --
  // it is sent on its own first, without a code, which makes bw either mail
  // the code (Email), accept it silently (Authenticator, YubiKey), or say the
  // account does not have it. So a wrong pick costs nothing typed.
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

  // Answering bw's new-device prompt, which is the only challenge it will not
  // take from a flag. The code the user just typed goes to the command's
  // environment, the password down the usual FIFO, and bw runs with its
  // prompts enabled for this one call.
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
    // A prewarmed process was started for the ordinary login and cannot answer
    // this; stop it and start the interactive one when it is gone.
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
    // Set before the process starts, because both the environment binding and
    // the exit handler read it.
    deviceVerificationAttempt = true
    loginProc.command = Model.deviceVerificationLoginCommand(
      String(loginEmail || "").trim(), resolvedLoginServerUrl(), login2faMethod)
    loginProc.running = true
    loginSubmitted = true
    writeAuthPassword("login", loginPassword)
  }

  // A login stopped on a challenge it cannot answer without leaving the panel.
  // Only these survive a close, only while the window is open, and only while
  // there is still a password to submit with the answer.
  function pendingSecondFactorLogin() {
    if (status !== "unauthenticated" || loginMethod !== "email") return false
    if (!show2faField && !showDeviceCodeField && !show2faMethodPicker) return false
    if (!String(loginPassword || "")) return false
    return Model.secondFactorWindowOpen(secondFactorStartedAt, Date.now())
  }

  // Every view's login fields, re-pointed at the state behind them. See
  // syncLoginFields() in the View section for why this is never skipped.
  function syncLoginFieldsToState() {
    eachView(function(view) { view.syncSensitiveFields() })
  }

  // Closing on a challenge keeps the stage and the password, and drops the
  // code -- whatever was half-typed before going to look it up is not the code
  // that is about to be read.
  function suspendPendingLogin() {
    login2faCode = ""
    loginDeviceCode = ""
    loginSubmitted = false
    isLoading = false
    syncLoginFieldsToState()
  }

  // What a stopped login process owes whoever stopped it. `mayScrub` is false
  // when the run that just ended was itself the scrub, so one cannot schedule
  // another.
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
    // Configuring a custom server changes bw's persistent global state. Do it
    // only after explicit submission, never merely because the password field
    // received focus. Default-cloud logins still get the full prewarm win.
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

  function abandonAuthSecrets() {
    masterPassword = ""
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
      if (unlockProc.running) unlockProc.running = false
      errorMessage = "Could not deliver the password to Bitwarden. Please try again."
      Qt.callLater(prepareUnlock)
    } else if (target === "login") {
      loginSubmitted = false
      isLoading = false
      if (loginProc.running) loginProc.running = false
      // The writer polls for bw's FIFO and gives up if bw has not opened it in
      // time, which a cold start after the panel has been closed can outrun.
      // Unlock has always re-armed itself here; login left the button for the
      // user to press again, which is what having to click Verify twice was.
      // Once, so a genuinely broken delivery still reports rather than looping.
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

    // Checked before either branch, because both send the master password to
    // whatever this names. See validateServerUrl() for what it refuses.
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

  // Every exit from onLoginOutput says which branch it took. Read with:
  //   quickshell log -f | grep qs-bitwarden
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

    // The interactive login answers for itself. Its output is a prompt session
    // rather than one of bw's one-line refusals, so none of the detectors
    // below should be allowed to read it.
    if (wasDeviceAttempt && !(exitCode === 0 && out.length > 10)) {
      var detail = Model.sanitizeInteractiveStderr(err, loginDeviceCode)
      loginDeviceCode = ""
      loginDeviceVerification = true
      // 124 is `timeout`; the prompt error is inquirer finding nothing left to
      // read. Both mean bw wanted something this login could not give it, and
      // a terminal is the only thing that can.
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

    // Checked before the second-factor branch, which matches the same sentence.
    // A code went out and bw still says a code is required, so this is the
    // new-device challenge -- asking for the code again would loop forever on
    // one bw cannot be given. The terminal login can answer it.
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

    // No --method can answer this one and no terminal helps: the account's
    // two-step methods are ones the CLI cannot perform at all.
    if (Model.loginHasNoUsableProvider(out, err)) {
      resetEmailLoginSecondFactor()
      logLogin("no-usable-provider", out, err, exitCode)
      errorMessage = "This account's two-step method is one the Bitwarden CLI cannot use, "
        + "such as a passkey or Duo. Log in with an API key instead."
      return
    }

    // bw asking which two-step method to use. Answering it by guessing is what
    // costs a real failed attempt, so the panel puts the question to the user.
    if (Model.loginNeedsMethodChoice(out, err)) {
      // A method that was only remembered, never confirmed against this
      // account, is the likeliest thing to be wrong here -- shell.json holds
      // one method for whichever account logged in last. Drop it and let the
      // untargeted attempt say what this account actually needs. The method
      // only ever goes from set to unset here, so this cannot loop.
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
      // A code must never be sent without the method it belongs to. bw only
      // puts the token on the wire when a provider came with it, so without
      // --method the first request is a bare password grant -- and for an
      // email provider the server answers that by issuing a fresh code,
      // invalidating the one the user is about to type. Confirmed against
      // bw 2026.2.0: the same command with --method succeeds and without it
      // returns "Two-step token is invalid."
      //
      // The method cannot be inferred, so it is asked for once per account
      // before any code is collected. An authenticator would survive being
      // asked in the wrong order; an emailed code would not.
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
      // Typed, and `bw` just accepted it: the stored password comes from here
      // for a fresh login. See storeAcceptedMasterPassword().
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
      // bw exited cleanly and said nothing at all. Handing that to the unlock
      // path was silent by construction: prepareUnlock() refuses it because
      // the vault is not locked, so the password went to a FIFO nobody had
      // created and failed two seconds later, after the next click had already
      // cleared the message. Say what happened instead.
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
    // The panel knows whether this is a login or an unlock, so the terminal
    // does not have to spend a `bw status` round trip working it out.
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
    Quickshell.execDetached(Model.terminalLoginCommand(mode, serverUrl))
  }

  function logoutAccount() {
    if (logoutPending) return
    logoutPending = true
    logoutCliDone = false
    logoutCredentialsDone = false
    logoutExitCode = 0
    logoutCredentialsExitCode = 0
    terminalLoginStartedAt = 0
    lockVault()
    // Stronger than the lock above: logout takes the public projection with
    // it, so a new account cannot inherit the last one's identities.
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
    if (logoutExitCode === 0) flashNotification("Logged out")
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
    keyringStoreProc.running = true
  }

  function onSessionStored(exitCode) {
    if (epochOperationIsStale("sessionStore") || status !== "unlocked" || !session) {
      sessionStorePending = rememberSession && status === "unlocked" && !!session
      requestSessionCredentialClear()
      return
    }
    sessionStorePending = false
    if (exitCode !== 0) {
      console.warn("qs-bitwarden-cli: could not store session in keyring (exit " + exitCode + ")")
    }
  }

  function requestSessionCredentialClear() {
    if (keyringClearProc.running) {
      sessionClearPending = true
      return
    }
    sessionClearPending = false
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
    return keyringStoreProc.running || pinStoreProc.running || envelopeProc.running
  }

  function requestAllCredentialClear() {
    if (keyringClearAllProc.running) {
      allCredentialsClearPending = true
      return
    }
    // A clear that wins the race against an older store is not cleanup: that
    // store can recreate the credential immediately afterward. Logout remains
    // pending until every writer has exited and this final sweep has run.
    if (credentialStoresRunning()) {
      allCredentialsClearPending = true
      return
    }
    allCredentialsClearPending = false
    keyringClearAllProc.running = true
  }

  // Logging out takes the keyring with it. Two of the entries there are the
  // master password -- fingerprint unlock keeps it as it is, PIN unlock keeps
  // it encrypted -- and both are written to the default collection so they
  // survive a reboot, which is exactly why a logout has to be the end of them.
  //
  // Nothing here asks whether we think an entry exists. `fingerprintStored`
  // and `pinConfigured` describe what the settings screen last saw, and both
  // go false for reasons that leave the keyring untouched: an unplugged
  // reader, an uninstalled fprintd, a dependency probe that has not answered
  // yet. Gating the clear on them is how a master password came to outlive the
  // account it belonged to. See keyringClearAllCommand() for why asking
  // unconditionally is free.
  function forgetStoredCredentials() {
    dropEnvelopeState()
    requestAllCredentialClear()
    // The learned-suggestion store is this account's data too -- which domains
    // and apps it holds logins for, and when each was last used -- and unlike
    // everything else here it is a plain file with no expiry. It goes with the
    // account rather than waiting for the next user of this machine to read it.
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
    if (pinUnlock) writeSetting("pinUnlock", false, "bool")
  }

  // -------------------------------------------------------------------------
  // Fingerprint Unlock
  // -------------------------------------------------------------------------

  // Secrets go to secret-tool through the environment, never argv. See
  // keyringStoreScript() in BitwardenModel.js for why stdin is not usable.
  function associationsEnv() {
    var env = {}
    env[Model.associationsEnvVar()] = String(pendingAssociationsJson || "")
    return env
  }

  // BW_SESSION rather than --session: bw reads it natively, and it keeps the
  // token out of /proc/<pid>/cmdline, which any local user can read.
  function bwEnv(extra) {
    var env = {}
    if (session) env[Model.sessionEnvVar()] = String(session)
    if (extra) for (var k in extra) env[k] = extra[k]
    return env
  }

  // Authentication credentials enter short-lived processes through the
  // environment. Direct password flows move BW_PASSWORD from the writer into
  // bw's private FIFO; API login reads BW_PASSWORD, BW_CLIENTID and
  // BW_CLIENTSECRET natively. None reaches an argv -- neither bw's nor that of
  // the shell wrapping it.
  // /proc/<pid>/cmdline is world-readable on a default install; environ is not.
  //
  // Read as a binding by loginProc and unlockProc, so it always reflects the
  // fields as they are when the process starts.
  function authEnv(password, clientId, clientSecret, code) {
    var env = bwEnv()
    env[Model.noInteractionEnvVar()] = "true"
    if (password) env[Model.passwordEnvVar()] = String(password)
    if (clientId) env[Model.clientIdEnvVar()] = String(clientId)
    if (clientSecret) env[Model.clientSecretEnvVar()] = String(clientSecret)
    // The only one bw has no environment option for; see the comment on
    // TWOFACTOR_CODE_ENV in BitwardenModel.js.
    if (code) env[Model.twoFactorCodeEnvVar()] = String(code)
    return env
  }

  function loginProcessEnv() {
    if (loginMethod === "apikey") {
      // This is a live Process binding. Keep fields out of its retained value
      // until an actual API login starts, instead of duplicating credentials
      // into both the form and the process object while the user is typing.
      if (!loginSubmitted) return authEnv("", "", "", "")
      return authEnv(loginPassword,
                     String(loginClientId || "").trim(),
                     String(loginClientSecret || "").trim(),
                     String(login2faCode || "").trim())
    }
    // The one login allowed to prompt. BW_NOINTERACTION is left out rather
    // than set to anything, since bw tests it against the literal "true", and
    // the code goes in for the command's own printf to read -- authEnv() is
    // not used here precisely because it would put the flag back.
    if (deviceVerificationAttempt) {
      var deviceEnv = bwEnv()
      deviceEnv[Model.deviceCodeEnvVar()] = String(loginDeviceCode || "").trim()
      return deviceEnv
    }
    // Email/password login reads its password from the FIFO writer. Keeping it
    // out of the long-lived prewarmed process also keeps partial typing out of
    // that process's environment.
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

  function pinEnv(pin, secret) {
    var env = {}
    env[Model.pinEnvVar()] = String(pin || "")
    if (secret) env[Model.keyringSecretEnvVar()] = String(secret)
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
    // bw prints the access URL; put it straight on the clipboard, since a Send
    // is useless until the link reaches someone.
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

  // Reached from the header button on any screen and from the item form's
  // Generate button, which is the same thing: the form is just a caller that
  // wants the value back.
  function openGenerator() {
    closeFilterGroup()
    generatorReturnScreen = (currentScreen === "edit") ? "edit" : "main"
    screenBeforeSettings = "main"
    currentScreen = "generator"
    // A form asking for a password wants a new one every time. A standalone
    // visit keeps whatever was last generated, so reopening does not throw
    // away a value you were about to copy.
    if (generatorFeedsForm || !genValue) regenerate()
  }

  function closeGenerator() {
    var toForm = generatorFeedsForm
    currentScreen = generatorReturnScreen
    generatorReturnScreen = "main"
    // Land back on the field the trip was about, filled in or not.
    if (toForm) Qt.callLater(function() { presenter.focusField("formPass") })
  }

  // The whole point of the round trip: put the value in the field the caller
  // was on, and go back to it.
  function useGeneratedPassword() {
    if (!generatorFeedsForm || genBusy || !genValue) return
    formPassword = genValue
    // Show it. A password you cannot read is hard to trust, and it is going
    // into a form you are still filling in rather than straight to the vault.
    formPasswordRevealed = true
    closeGenerator()
    flashNotification("Generated password filled in")
  }

  // Generation is delegated to Bitwarden's own generator either way; the only
  // question is how we reach it. `bw serve` answers in ~2ms against ~2.9s for
  // a fresh `bw generate`, so the server is started on first use and the CLI
  // stays as the fallback for when it cannot be.
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
    // Nothing to wait on if the server is already coming up -- onExited or the
    // ready poll will drive the request.
    if (!generateServeStarting) regenerateViaCli()
  }

  function regenerateViaCli() {
    genBusy = true
    genRegeneratePending = false
    genRequestSignature = generatorOptionsSignature()
    generateProc.command = Model.generateCommand(genOpts)
    generateProc.running = true
  }

  // A locked server: no session in its environment, so it can generate and
  // nothing else. See the comment on generateServeCommand in BitwardenModel.js
  // for why that restriction is the whole point.
  function generatorServeEnv() {
    var env = {}
    env[Model.sessionEnvVar()] = null
    env[Model.noInteractionEnvVar()] = "true"
    return env
  }

  // Nothing about an HTTP 200 proves the process that sent it is ours. Another
  // account can bind the port first and answer /generate with passwords it
  // already knows, and the panel would show one as freshly generated. There is
  // no handshake to lean on -- `bw serve` prints no banner and offers no
  // authentication -- so the evidence has to be that the port was silent before
  // our own server took it. Anything already answering means the serve path is
  // not available, and the CLI carries the feature instead.
  function startGeneratorServe() {
    if (generateServeReady || generateServeStarting || generateServeFailed) return
    generateServeStarting = true
    probeGeneratorPort()
  }

  // Every request to the generator port goes through a bounded child process
  // rather than QML's XMLHttpRequest. XMLHttpRequest buffers responses in
  // shared shell process memory before JavaScript can inspect or abort them,
  // leaving the shell vulnerable to unbounded allocations from a rogue local
  // port responder. The child process bounds both duration (--max-time) and
  // payload volume (| head -c 65536) on the producer side, ensuring no more
  // than 64KB ever enters the shell process.
  //
  // `done` is called with (exitCode, stdout, stderr).
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
      // The screen can close while a probe is in flight, and starting a server
      // for a screen nobody is looking at is the exposure this all avoids.
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
    // A deliberate shutdown is not the permanent bind failure, so the next
    // visit is free to start a server again.
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

  // The server is up when it answers. Polling rather than trusting a fixed
  // delay: bw takes a couple of seconds to bind, and the first generator open
  // should not sit behind a guess.
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
      // The server went away mid-session, or stopped behaving like one; fall
      // back and stop trusting it.
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

  // Every control funnels through here, so a change always regenerates --
  // matching the extension's live behaviour -- and options stay normalised.
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
  // PIN Unlock
  // -------------------------------------------------------------------------

  function refreshPinConfigured() {
    if (!keyringHasPinProc.running) keyringHasPinProc.running = true
  }

  function onPinConfiguredChecked(raw) {
    pinConfigured = String(raw || "").trim() === "yes"
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
    if (pinStoreProc.running) invalidateEpochOperation("pinStore")
    pinBusy = false
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
  }

  // Encrypting needs the master password, and the vault does not keep it in
  // memory once unlocked, so setting a PIN has to ask for it.
  function submitPinSetup() {
    if (pinBusy || pinStoreProc.running) return
    var err = Model.validatePin(pinSetupPin, pinSetupConfirm)
    if (err) { pinError = err; return }
    if (!pinSetupMaster) { pinError = "Master password is required to encrypt the PIN"; return }

    pinError = ""
    pinUnlockError = ""
    pinBusy = true
    beginEpochOperation("pinStore")
    pinStoreProc.running = true
  }

  function onPinStored(exitCode) {
    pinBusy = false
    if (epochOperationIsStale("pinStore")) {
      pinConfigured = false
      pinSetupPin = ""
      pinSetupConfirm = ""
      pinSetupMaster = ""
      requestPinCredentialClear()
      return
    }
    if (exitCode !== 0) {
      pinError = "Could not save the PIN. Is the OS keyring available?"
      return
    }
    pinConfigured = true
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    pinAttempts = 0
    writeSetting("pinUnlock", true, "bool")
    flashNotification("PIN unlock enabled")
    currentScreen = "settings"
  }

  function submitPinUnlock() {
    if (!sshAuthSurfaceActive || !pinReady || isUnlocking || pinBusy) return
    if (String(pinEntry || "").length < Model.pinMinLength()) {
      pinUnlockError = "PIN must be at least " + Model.pinMinLength() + " digits"
      return
    }
    pinUnlockError = ""
    pinBusy = true
    pinUnlockSubmitted = true
    pinUnlockProc.command = Model.pinUnlockCommand()
    pinUnlockProc.running = true
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
      pinAttempts += 1
      pinEntry = ""
      if (pinAttempts >= pinMaxAttempts) {
        // Refuse to keep serving guesses at the UI. The ciphertext goes too,
        // so re-enabling requires the master password again.
        clearPin()
        pinUnlockError = "Too many incorrect PINs. PIN unlock has been removed -- use your master password."
      } else {
        pinUnlockError = "Incorrect PIN (" + pinAttempts + " of " + pinMaxAttempts + ")"
      }
      return
    }

    pinAttempts = 0
    pendingUnlockFrom = "pin"
    unlockVaultWithPassword(pw)
  }

  function clearPin() {
    requestPinCredentialClear()
    pinConfigured = false
    pinEntry = ""
    pinAttempts = 0
    if (pinUnlock) writeSetting("pinUnlock", false, "bool")
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
  // Setup Wizard & Settings
  // -------------------------------------------------------------------------

  function checkDependencies() {
    if (!depsCheckProc.running) depsCheckProc.running = true
  }

  function onDependenciesChecked(raw) {
    dependencies = Model.parseDependencies(raw)
    depsChecked = true
    if (pinUnlock) refreshPinConfigured()

    // Fingerprint availability comes from the same probe, so keep them in step.
    for (var i = 0; i < dependencies.items.length; i++) {
      if (dependencies.items[i].key === "fprintd") fingerprintAvailable = dependencies.items[i].ready
    }
    if (fingerprintAvailable && fingerprintUnlock) {
      if (!keyringHasMasterProc.running) keyringHasMasterProc.running = true
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
    // Omarchy's setup command owns its own rows; `pkg add` on one of those
    // would install a package and leave the row exactly as red as it was.
    if (dep.setup) {
      runFingerprintSetup()
      return
    }
    var cmd = Model.installPackagesCommand([dep.pkg], dep.label)
    if (!cmd) return
    Quickshell.execDetached(cmd)
    flashNotification("Installing " + dep.pkg + " -- this screen updates itself")
  }

  // Stepping past setup. The gate is what was holding the first status probe
  // back, so opening it has to release that probe as well -- otherwise the
  // panel would sit on a login screen it never actually asked `bw` about.
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

  // A setting whose dependency is missing is inert; the cursor may sit on it,
  // but changing it would silently do nothing.
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

  // PIN, fingerprint and FIDO2 unlock all go through the quick-unlock tool.
  // Without a usable one they cannot be switched on -- but switching one off
  // never needs it, so an option already on stays reachable and can always
  // be turned off. "unknown" is the moment before the first inspection
  // answers, which is not a verdict.
  function quickUnlockToolMissing(entry) {
    if (!entry || !Model.isQuickUnlockSetting(entry.key)) return false
    if (unlockKeyHelper.state === "unknown" || !quickUnlockPrereqs.checked) return false
    if (quickUnlockAvailable) return false
    return !settingValue(entry)
  }

  // The floor rule, said where it applies: the stored password is only as
  // protected as the weakest enabled way into it, and with fingerprint on
  // that is fingerprint -- a finger releases no secret to encrypt with. A PIN
  // or a key does not make the password safer while fingerprint is also on,
  // and the rows that suggest otherwise say so.
  function settingNote(entry) {
    if (!entry || (entry.key !== "pinUnlock" && entry.key !== "fidoUnlock")) return ""
    if (!settingValue(entry) || !fingerprintUnlock || !fingerprintStored) return ""
    return "Fingerprint unlock is also on, so the stored password is only as protected as "
      + "fingerprint unlock: a program running as you can open it without the "
      + (entry.key === "pinUnlock" ? "PIN." : "key.")
  }

  // The reason shown in place of the description, so an inert control says
  // why rather than doing nothing.
  function settingBlockedReason(entry) {
    if (settingDependencyMissing(entry)) return "Needs fingerprint setup -- see Dependencies below."
    if (quickUnlockToolMissing(entry)) {
      return quickUnlockUnavailableReason + " Your master password still unlocks the vault."
    }
    return ""
  }

  // Group headings are rows in the list but not controls, so the cursor steps
  // over them rather than stopping on one and doing nothing when activated.
  function moveSettingsCursor(delta) {
    var n = settingsEntries.length
    if (n === 0) return
    var step = delta < 0 ? -1 : 1
    var i = settingsIndex + delta
    while (i >= 0 && i < n && settingsEntries[i] && settingsEntries[i].kind === "group") i += step
    // A heading at the far end leaves nowhere further to go in that direction;
    // the cursor stays where it was rather than landing on the heading.
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

  // Persisted via `omarchy bar set`, which owns shell.json. The shell reloads
  // on write, so setting() reflects the new value without us caching it.
  function writeSetting(key, value, type) {
    settingWriteProc.command = Model.settingWriteCommand(key, value, type)
    settingWriteProc.running = true
    settingsFlash = "Saved"
    settingsFlashTimer.restart()
  }

  // The remembered two-step method is not a preference anybody set, so it is
  // written without the settings screen's "Saved" flash -- it is a note the
  // login leaves for the next one, and it has no row to flash next to.
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

  // Read back through the same properties the plugin actually runs on, so the
  // settings screen can never show a different value than the one in effect.
  // (setting() alone would miss the manifest defaults for unset keys.)
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
    // FIDO2 readiness comes from its own probe, run here so the setup form
    // opens on the right branch rather than flipping once the probe answers.
    fidoUnlocker.refresh()
  }

  function onFingerprintStoredChecked(raw) {
    legacyFingerprintStored = String(raw || "").trim() === "yes"
    recomputeFingerprintStored()
    maybeMigrateLegacyFingerprint()
    if (sshAuthSurfaceActive && status === "locked") armPresenceUnlock()
  }

  function startFingerprintUnlock() {
    if (!fingerprintReady || status !== "locked" || isUnlocking) return
    if (fingerprintScanning || fingerprintPam.active) return
    // Release rather than cancel: the key holds its request regardless, and
    // keeping the conversation lets a return to the key adopt it.
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
        keyringLookupMasterProc.command = Model.keyringLookupMasterPasswordCommand()
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

  // After PamResult.Success, from the envelope's fingerprint wrap. A missing
  // wrap or envelope falls back to the legacy entry, for the one start before
  // migration runs.
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
          keyringLookupMasterProc.command = Model.keyringLookupMasterPasswordCommand()
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
    // The keyring command removes secret-tool's output newline. Do not trim
    // here: spaces at either end can be part of the actual master password.
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

  // Enrolling asks for the master password up front, the same way setting a
  // PIN does, rather than silently capturing it on some later unlock.
  function beginFingerprintSetup() {
    fpSetupMaster = ""
    fpError = ""
    currentScreen = "fingerprint"
    Qt.callLater(function() { presenter.focusField("fpMaster") })
  }

  function abandonFingerprintSetup() {
    // A wrap still being written is taken back out when it lands: its
    // completion finds the operation stale. See submitFingerprintSetup().
    if (fpBusy) invalidateEpochOperation("fingerprintAdd")
    fpSetupActive = false
    fpBusy = false
    fpSetupMaster = ""
  }

  // The master password here is a check against the stored password: it
  // must open the envelope, and the fingerprint wrap is added to it. Nothing
  // typed is stored.
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
      // Locked, logged out or abandoned while the wrap was being written: a
      // fingerprint wrap for a setting that never turned on is the data key
      // lying in the keyring for nothing. Take it back out.
      if (root.epochOperationIsStale("fingerprintAdd") || !root.fpSetupActive) {
        root.fpSetupActive = false
        if (ok) root.removeQuickUnlockMethod({ kind: "remove", method: "fingerprint" })
        return
      }
      root.fpSetupActive = false
      if (!ok) {
        root.fpError = why === "wrong-password"
          ? "That is not your master password."
          : "Could not enable fingerprint unlock. Is the OS keyring available?"
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
      // Not `if (fingerprintStored)`. That flag is false whenever the reader
      // or fprintd is missing, which says nothing about whether the master
      // password is still sitting in the keyring -- and turning the feature
      // off is precisely when it must not be.
      forgetFingerprintUnlock()
    } else {
      refreshFingerprintAvailability()
    }
  }

  // -------------------------------------------------------------------------
  // FIDO2 Unlock
  // -------------------------------------------------------------------------
  //
  // FidoUnlock.qml owns the whole gate -- its PAM stack, its probe, its
  // keyring entry and the setup form. These are the names the locked screen and
  // the settings row use, kept parallel to the fingerprint's so the two methods
  // read the same way from the outside (and so both halves of the settings
  // screen can dispatch on a single action name).

  // One gate at a time: two armed conversations mean two devices waiting, and
  // whichever answers second is a touch given to nothing.
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

  // Which presence gate arms when the vault needs the screen: the FIDO2 key
  // when one is plugged in and ready, the reader otherwise. Both buttons remain
  // available either way -- this only decides which is already waiting.
  function armPresenceUnlock() {
    if (fidoReady) {
      startFidoUnlock()
      return
    }
    // A key plugged in since the last probe is not ready yet as far as this
    // knows, and the answer arrives too late to choose from. Ask now: the
    // probe arms the key itself when it lands on a locked vault.
    if (fidoUnlock) fidoUnlocker.refresh()
    startFingerprintUnlock()
  }

  // -------------------------------------------------------------------------
  // Vault Unlock & Lock
  // -------------------------------------------------------------------------

  function unlockVault() {
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
    // Kept only until the unlock result is known; cleared on both paths below.
    // The short-lived FIFO writer reads it as BW_PASSWORD. unlockProc was
    // already bootstrapping while the user typed and never receives it.
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
      if (!(pendingUnlockFrom === "fingerprint" && fingerprintFromEnvelope)) pendingUnlockPassword = ""
      // A stored secret the vault no longer accepts is useless: drop it rather
      // than fail on every open, and say which one went stale.
      if (pendingUnlockFrom === "fingerprint" && fingerprintFromEnvelope) {
        // The envelope's password is out of date: the master password was
        // changed elsewhere. Keep fingerprint unlock and remember the old
        // password, so the next typed unlock can re-seal the envelope.
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
      if (pendingUnlockFrom === "fido") {
        pendingUnlockFrom = ""
        fidoUnlocker.forget("Stored password no longer valid. Unlock with your master password to re-enable FIDO2 unlock.", false)
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

    storeCurrentSession()

    // A typed password `bw` just accepted is the one source of the stored
    // password -- never one a quick-unlock method produced. This also
    // re-seals the envelope after a password change made elsewhere.
    if (pendingUnlockPassword && pendingUnlockFrom === "") {
      storeAcceptedMasterPassword(pendingUnlockPassword)
    } else {
      rotationOldPassword = ""
    }
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
    // Before bw lock is launched, so the companion's deny transition is not
    // sequenced behind it. The panel's own lock never waits on the answer.
    applySshAgentLifecycle("lock")
    if (session) {
      lockProc.command = Model.lockCommand()
      lockProc.running = true
    }
    // Not `if (rememberSession)`. The setting says whether to write a token,
    // not whether one is there: turning it off after a session was remembered
    // used to mean the lock skipped the erase and left the token behind.
    // Clearing an entry that was never written is a no-op nobody reads.
    requestSessionCredentialClear()

    dropVaultState()
    status = "locked"
    currentScreen = "locked"
    fingerprintMessage = ""
    fingerprintError = ""
    flashNotification("Vault locked")
    focusAppropriateField()
    // Whichever gate the lock screen is about to offer, not the reader every
    // time: locking from an open panel with a key plugged in used to arm the
    // fingerprint, so a touch went to the focused field instead of to PAM.
    if (sshAuthSurfaceActive) armPresenceUnlock()
  }

  function vaultStatePresent() {
    return !!session || status === "unlocked" || items.length > 0
      || organizations.length > 0 || folders.length > 0 || detailItem !== null
      || sends.length > 0 || itemPayloadJson !== "" || sendPayloadJson !== ""
  }

  // One local purge for every way an open vault stops being usable. Keeping
  // this separate from the `bw lock` and keyring side effects lets a status
  // transition fail closed without pretending that a remote/local CLI error
  // was a successful Bitwarden lock command.
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
    formIsEditing = false
    formItemId = ""
    formTypeCode = 1
    clearTypeFields()
    formName = ""
    formUsername = ""
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

  // A locked vault means the panel is holding nothing out of it, and nothing
  // that would open it again. detailPassword and liveTotp were always dropped
  // here; the rest were not, and each of them is the same kind of thing -- a
  // generated password nobody copied, an item or Send form left mid-compose,
  // the payload JSON on its way to bw, the master password typed into whichever
  // setup form was open. The vault relocks after fifteen idle minutes and the
  // shell process lives for the whole desktop session, so a property that
  // survives a lock survives everything.
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
    loginPassword = ""
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
    loginClientId = ""
    loginClientSecret = ""
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

  // Emptying those properties leaves the values they were copied out of still
  // sitting in the collectors that read them, which is the same residue one
  // step upstream. See the collector-scrubbing note in BitwardenModel.js for
  // why running a command that prints nothing is the way to clear one.
  //
  // Built on demand rather than held as a property: these ids are declared
  // below this point, and a list bound at creation time would be a list of
  // undefineds.
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

  // A process still running when the vault locked cannot be scrubbed yet --
  // its buffer is in the middle of being written, and taking its command away
  // would abandon a read someone is still waiting on. It stays in the queue
  // and the retry comes back for it.
  function scrubStep() {
    var pass = Model.scrubPass(scrubPending)
    for (var i = 0; i < pass.start.length; i++) {
      pass.start[i].command = Model.scrubCommand()
      pass.start[i].running = true
    }
    scrubPending = pass.waiting
  }

  // Complete a scrub before its handler can reuse the same Process. What
  // arrives from a scrub is an empty string and exit status zero, which reads
  // as a successful login, empty vault or saved item unless every handler asks
  // here first.
  function finishScrubRun(proc) {
    if (!Model.isScrubCommand(proc.command)) return false
    scrubPending = Model.finishScrub(scrubPending, proc)
    if (!scrubPending.length) scrubRetry.stop()
    return true
  }

  function clearProcessCollectorSoon(proc) {
    Qt.callLater(function() {
      if (proc.running) return
      // Deferred by a callLater, so a submit can arrive between the schedule
      // and the run. Taking the process here would make that submit wait on
      // the scrub instead of on its own login.
      if (proc === loginProc
          && (loginSubmitAfterPrewarmStop || loginPrepareAfterPrewarmStop
              || deviceVerificationPending || loginSubmitted)) return
      proc.command = Model.scrubCommand()
      proc.running = true
    })
  }

  // -------------------------------------------------------------------------
  // Vault Data Operations
  // -------------------------------------------------------------------------

  // Stamped on a reader as it starts, and checked again where its answer
  // arrives. A `bw` already in flight when the vault locks cannot be called
  // back -- it is past the point where the session mattered -- so the only
  // place left to refuse its answer is the completion handler. See the Vault
  // generation section of BitwardenModel.js for what that answer costs when
  // nobody refuses it.
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

  // The first post-authentication process is always the item list. Organization
  // and folder metadata each need another bw bootstrap, so they are scheduled
  // only after items have reached the model and had time to paint.
  function beginInitialVaultLoad(showSpinner, forceMetadata) {
    metadataLoadPending = true
    metadataForceRefresh = forceMetadata === true
    loadItems(showSpinner)
  }

  // Open-time load: skip the CLI entirely when the in-memory vault is fresh.
  // Stale-while-revalidate. `bw list items` is a CLI bootstrap plus a full
  // vault decrypt, so blocking the panel on it means a spinner on every open
  // once the cache ages out. Show what we already have immediately, refresh
  // behind it, and swap the list in when it lands. The spinner is only for
  // the case where there is genuinely nothing to show yet.
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

  // `showSpinner` defaults to true, so existing callers are unchanged; a
  // background revalidation passes false and refreshes without the UI moving.
  function loadItems(showSpinner) {
    if (!session) return
    if (showSpinner !== false) isLoading = true
    beginVaultRead("items")
    listReadMode = Model.vaultListMode(dependencies)
    if (listReadMode === "blocked") {
      isLoading = false
      if (!vaultReadIsStale("items")) errorMessage = Model.vaultListBlockedMessage(dependencies)
      return
    }
    startVaultListRead(false)
  }

  // The one place the item read is launched, so the agent branch and its
  // retry-without-it cannot drift apart. `retrying` is the second attempt
  // after a fan-out read failed; it never carries the branch.
  function startVaultListRead(retrying) {
    var useAgent = !retrying && sshAgentGateOpen && Model.isValidLoadId(sshAgentNextLoadId)
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

  // The nonce reaches `jq` through the environment rather than argv, because
  // /proc/<pid>/cmdline is world-readable and the nonce's whole purpose is
  // being unguessable by another process running as this user.
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
    if (metadataLoadPending) deferredMetadataTimer.restart()
    // The first read of a session usually beats the helper's handshake, so it
    // carries no keys. Now that it has landed, check whether one is owed.
    maybeStartupLoad()
  }

  function onListProcessExited(exitCode, rawJson, stderrText) {
    if (finishScrubRun(listProc)) return
    var hadAgentBranch = listAgentBranchActive
    listAgentBranchActive = false
    endSshAgentLoad(exitCode === 0)

    if (exitCode === 0) {
      listRetriedWithoutAgent = false
      onListFinished(rawJson)
      return
    }

    // The optional feature is never allowed to cost the user their item list.
    // One retry, without the branch, before anything is reported as an error.
    if (hadAgentBranch && !listRetriedWithoutAgent && !vaultReadIsStale("items")) {
      listRetriedWithoutAgent = true
      beginVaultRead("items")
      startVaultListRead(true)
      return
    }
    listRetriedWithoutAgent = false

    isLoading = false
    isSyncing = false
    syncReloadPending = false
    metadataLoadPending = false
    metadataForceRefresh = false
    if (statusRefreshAfterItems) {
      statusRefreshAfterItems = false
    }
    if (!vaultReadIsStale("items")) {
      errorMessage = Model.vaultListFailureMessage(stderrText, dependencies, listReadMode)
    }
  }

  // Each of these is its own `bw` invocation, and organizations and folders
  // change rarely -- new ones arrive through this panel, which invalidates
  // them explicitly. `force` is for exactly that case.
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
    // Start on whichever option is currently active, so Enter is a no-op
    // rather than a surprise.
    var opts = filterOptions(group)
    filterOptionIndex = 0
    for (var i = 0; i < opts.length; i++) {
      if (opts[i].active) { filterOptionIndex = i; break }
    }
  }

  // Any action that is not part of the drawer closes it, so it never lingers
  // over the results the user just filtered down to.
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

  // Labels for the collapsed buttons, so the current filter is readable
  // without opening anything.
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

  // Option rows for whichever group is open, in one shape so the three lists
  // render identically.
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

  // What Escape does, wherever it is pressed. Kept here rather than inline in
  // the key handler because it has two callers: PanelKeyCatcher's
  // closeRequested, and the shortcut interceptor -- the catcher goes `blocked`
  // on every screen with a text field, which used to take Escape down with it.
  //
  // Innermost thing first: a drawer or picker closes before the screen it is
  // on, and a screen goes back before the panel closes.
  function handleEscape() {
    // Ahead of every other screen: a signing request is a question with a
    // client blocked on the answer, so dismissing it has to mean "no" rather
    // than "later".
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
        // Leaving the composer does not change the screen, so nothing else
        // takes focus off its (now hidden) name field.
        restoreScreenFocus()
      } else {
        currentScreen = "main"
      }
    } else if (currentScreen === "generator") {
      // Back to the item form when that is where this came from, leaving
      // the password field as it was.
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
    } else if (currentScreen === "setup") {
      dismissSetup()
    } else if (currentScreen === "edit") {
      // Editing is abandoned, not saved -- the form is scratch space until
      // Save, and Escape is how you throw it away. Back where the form was
      // opened from, which is what the form's own Cancel button does.
      currentScreen = formIsEditing ? "detail" : "main"
    } else if (currentScreen === "detail") {
      currentScreen = "main"
    } else {
      close()
    }
  }

  // Qt does not clear active focus when an item is hidden, so leaving a screen
  // whose field had focus leaves that field owning the keyboard from behind
  // whatever replaced it -- which is how Escape on the item form reached the
  // search box and closed the panel. Re-home focus whenever the screen
  // changes, and the stale owner goes with it.
  onCurrentScreenChanged: {
    // The server lives as long as the screen that needs it and no longer. A
    // loopback port has no authentication and every account on the machine can
    // reach it, and `bw serve` answers /status with the account email and user
    // id whether the vault is locked or not. Holding that open for hours to
    // save a second on a screen visited for a few is the wrong trade.
    if (currentScreen !== "generator") stopGeneratorServe()
    // Both setup forms ask for the master password, and both used to keep it
    // for the rest of the shell's life: Cancel and Escape only reset the error
    // line. Leaving the form is the answer either way, so the clearing lives
    // here rather than at each of the ways out.
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

  // Changing owner invalidates the collection choice: collections belong to a
  // single organization, and a personal item cannot have any.
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
    // Creating a folder from the item form is only ever a prelude to filing
    // the item into it, so select it straight away.
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

    // The list already fetched the whole item, so render from that rather than
    // spending a second CLI round trip on data we are holding. Only fall back
    // to `bw get item` if this item somehow arrived without its raw object.
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

    // The TOTP code is time-based, so it is the one thing the list cannot
    // carry. It loads alongside rather than in front of the detail view.
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
    // A download holds decrypted bytes and the session it inherited at start.
    // The supervised process group removes its private staging directory and
    // cannot commit a file after the vault or panel has closed.
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
    // The declared size travels with the job so the saver can refuse an
    // oversized attachment before it starts, and check the disk has room.
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
      // bw's own message is the useful one -- "Not found." for an attachment
      // that has since been deleted, or a permission error on the directory.
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
      // Reserve this Process before deferring its restart. Without the flag, a
      // newer request can start in this one-event-loop gap and then be
      // overwritten by the older queued request.
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

  function onTotpFinished(itemId, code) {
    if (vaultReadIsStale("totp")) return
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
  // CRUD Operations (Add, Edit, Delete)
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

  // These ids are Bitwarden's LinkedIdType values. Secure Notes intentionally
  // return no choices, matching the browser extension: there is no native
  // username, card, or identity field for a note to point at.
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

  // A Repeater may expose an object model row as a delegate-local QVariantMap.
  // Writing `modelData.value` can therefore update what the row draws without
  // updating the array saveItemForm later serializes. Always write through the
  // form's authoritative array. No property-change signal is needed here: the
  // editor already owns the value it just drew, and avoiding an array reassign
  // keeps focus stable while the user types.
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
    // A linked field belongs to its cipher type. When a new item changes type,
    // retain its label but reset the link to a valid target; a Secure Note has
    // no target, so the field becomes ordinary text instead of an invalid link.
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

  // The card or identity boxes, in the shape buildCreatePayload and
  // buildEditPayload want. Returns null for a login or a note, and null is
  // exactly what tells buildEditPayload to leave an existing sub-object alone.
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

  // Every card and identity box, emptied. Called wherever the form resets so
  // a new item never opens wearing the last one's card number.
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
    formOrgId = selectedOrg !== "all" ? selectedOrg : ""
    formFolderId = (selectedFolder !== "all" && selectedFolder !== "none") ? selectedFolder : ""
    newFolderName = ""
    formPicker = ""
    formCollections = []
    formCollectionIds = []
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
    formPasswordRevealed = false
    errorMessage = ""
    currentScreen = "edit"
  }

  // The item form as one object, so a save that fails can be reopened exactly
  // as it was rather than costing the user everything they typed.
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
    // The vault has not answered about this row yet, and on a create it does
    // not have an id to edit. Editing it would race the save it is waiting on.
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
    // The list row carries the parsed card and identity, so an edit opens with
    // the real values in the boxes rather than blanks that would be written
    // straight back over them on save.
    loadTypeFields(item)
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
    formPasswordRevealed = false
    errorMessage = ""
    currentScreen = "edit"
  }

  // A save takes as long as `bw` takes -- a second or two of CLI startup, vault
  // decryption and a round trip, none of which this plugin can shorten. What it
  // can do is stop making the user watch. The form closes as soon as the
  // command is launched and the list shows the item as it will be, marked as
  // saving, and the authoritative row replaces it when the vault answers.
  //
  // One at a time. There is a single process per kind, and starting a second
  // command on a running one would lose the first; a save while one is in
  // flight is refused with a reason rather than silently dropped.
  function saveItemForm() {
    if (pendingSave) {
      errorMessage = "Still saving " + pendingSave.name + " -- one moment"
      return
    }

    // Bitwarden refuses an organization item with no collection; say so here
    // rather than letting the CLI fail after the form is gone.
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

    // An edit keeps the item's id; a create has none until the server assigns
    // one, so the row carries a provisional id the response swaps out.
    var rowId = editing ? formItemId : Model.pendingItemId(Date.now())
    var optimistic = Model.optimisticItem(payload, rowId)

    pendingSave = {
      id: rowId,
      isCreate: !editing,
      name: String(formName || "Untitled").trim(),
      // What the list held before, so a failed save can put it back rather
      // than leaving the panel showing something the vault never accepted.
      previous: editing ? Model.findItemById(items, rowId) : null,
      // The form as it was, so a failed save can be reopened and retried
      // instead of costing the user everything they typed.
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
    // The payload carries the item's password in the clear, the same way a
    // Send payload does, so it goes the same way the Send one does: as soon as
    // the process that needed it has exited.
    itemPayloadJson = ""

    var save = pendingSave
    pendingSave = null
    if (vaultReadIsStale("itemSave")) return

    if (exitCode !== 0) {
      // The vault refused it, so the list must stop showing it as though it
      // had not. The optimistic row is taken back out -- replaced by what was
      // there before on an edit, removed entirely on a create -- and what the
      // user typed is kept so they can reopen it instead of retyping it.
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

    // The save printed the item the vault now holds, so the list can be
    // brought up to date from that instead of re-reading and re-decrypting
    // every other item to learn about this one. On a create the row being
    // replaced is the provisional one, whose id the server has just assigned.
    //
    // Any doubt falls back to the full read. The command prints a marker when
    // the item was stored but could not be sanitised, and spliceSavedItem
    // returns null on an envelope it does not recognise; in both cases the
    // item is in the vault and the list simply has to catch up the slow way.
    // A list that quietly disagrees with the vault is worse than a slow one.
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

  // A delete costs the same second or two of `bw` a save does, and used to
  // spend it on a frozen detail screen and then spend more of it re-reading
  // the whole vault to learn about the one row that had gone. The row goes
  // now and the panel comes back; if the vault refuses, the row returns.
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
      // The row is already gone and nothing else about the vault changed, so
      // there is nothing left to read.
      flashNotification("Item deleted")
      return
    }

    // Still in the vault, so it belongs back in the list. Nothing was typed
    // here, so putting the row back is the whole of the recovery.
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
  // Filtering & Selection
  // -------------------------------------------------------------------------

  // Everything downstream of `items`. Suggestions are derived from the item
  // list too, so a change to it that only called rebuildFilter() would leave
  // the suggested rows describing the vault as it was. Both the full load and
  // a single spliced save come through here so they cannot drift.
  function refreshDerivedFromItems() {
    if (activeWindowData) {
      handleActiveWindowDetected(activeWindowData)
    } else {
      rebuildFilter()
    }
  }

  // The search box calls this on every keystroke; the rebuild itself waits for
  // typing to pause. A function rather than the timer, because an id is not
  // reachable from the views.
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

  // What the list says when it has nothing to show. The SSH filter gets its own
  // answer: a vault that returned no SSH keys is not the same as a server that
  // never confirmed it can store them, and only the first is worth waiting on.
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

  // Every main-screen shortcut in one place. Reached two ways: bare letters
  // when the list has focus, and Alt+letter from inside the search box, where
  // a bare letter is search text and must stay that way.
  // Alt+letter. Same table as the bare letters, except Alt+s opens Sends --
  // Send has no bare letter of its own, and plain s is already Settings.
  function runAltShortcut(lower) {
    // Alt+s is Send, which has no bare letter of its own, so Settings keeps
    // its own Alt binding on the comma rather than losing one.
    if (lower === "s") { openSends(); return true }
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
    // Moving to an item means the user is done filtering; get the list out of
    // the way rather than leaving it covering the results.
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
  // Clipboard Actions & Sequential Password -> TOTP Follow-Up
  // -------------------------------------------------------------------------

  function copyToClipboard(text, label) {
    if (!text) return
    resetAutoLockTimer()
    // The value goes through the environment: `printf %s '<secret>'` would put
    // the password or TOTP code straight into /proc/<pid>/cmdline. Remove that
    // variable before starting wl-copy, whose clipboard owner can outlive this
    // short shell after it forks into the background.
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
    // The clipboard has its own expiry; the pipe buffer needs one too. Once
    // the value has been handed to wl-copy there is no reason to keep a second
    // plaintext copy in this long-lived Process object.
    clearProcessCollectorSoon(copyPasswordProc)
    if (vaultReadIsStale("passwordCopy")) return
    var password = String(text || "")
    if (exitCode === 0 && requested && password) {
      copyToClipboard(password, "Password")
      return
    }
    errorMessage = "Could not read this password"
  }

  // Smart sequential Enter handler: Copies Password, then arms and auto-copies TOTP
  // Enter on a list row does the obvious thing for the item under it. For a
  // login that is "copy the password", which is what this used to be and the
  // only thing it did: every other type fell out of the guard below and Enter
  // did nothing at all, on an item whose whole content was one keystroke away.
  //
  // A card, an identity, a note and an SSH key have no default secret to put
  // on the clipboard, and neither does a login that was saved without a
  // password. In all of those cases the useful answer is to open the item,
  // which is what a user pressing Enter on a row they cannot copy from was
  // reaching for anyway.
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
    // Recorded even when auto-lock is off, so turning it back on mid-session
    // starts counting from the last thing the user did rather than from zero.
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
    // One frame at 60 Hz is ~17 ms. Fifty milliseconds leaves room for the
    // parsed item model to polish and render before two more bw processes
    // begin their startup work.
    interval: 50
    repeat: false
    onTriggered: {
      if (root.status !== "unlocked" || !root.metadataLoadPending) return
      var force = root.metadataForceRefresh
      root.metadataLoadPending = false
      root.metadataForceRefresh = false
      root.loadOrganizations(force)
      root.loadFolders(force)
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
        // The code itself stays out of the notification. It is already on the
        // clipboard, and a notification is not a private channel: the daemon
        // keeps history and can render the body over a lock screen. The panel
        // shows the digits on screen instead, where you asked for them.
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

  // The timer above measures the time the shell was awake for, which on a
  // laptop is not the time the vault was exposed for: Qt schedules on
  // CLOCK_MONOTONIC and Linux stops that clock across a suspend, so a lock
  // armed before the lid closed still had its full countdown left when the lid
  // opened. This is the wall-clock half of the same deadline; see the
  // Auto-lock section of BitwardenModel.js.
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
  // Both are the same conclusion the auto-lock reaches on a timer, arrived at
  // from evidence instead: the vault is no longer being attended. Neither
  // replaces the countdown -- a vault left open at an unlocked desk is still
  // the case only elapsed time can catch.

  // The last reading from the screen-lock poll, with the moment it was taken.
  // The agent needs this even when lockOnScreenLock is off, because it must
  // never raise an approval prompt over a locked screen.
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
      // Coming back is not by itself a reason to do anything -- the watchdog
      // below already notices a countdown that expired across the suspend --
      // but the panel should not be showing a vault state from before the lid
      // closed either.
      if (opened) refreshStatus()
      return
    }
    if (token !== Model.sleepSignalToken()) return
    if (!lockOnSuspend || status !== "unlocked") return
    // Synchronous as far as the session key in this process is concerned; the
    // keyring clear it spawns is what the inhibitor's held second is for.
    lockVault()
  }

  Timer {
    id: screenLockPoll
    interval: Model.screenLockPollMs()
    repeat: true
    // Nothing to ask while the setting is off or the vault is already locked,
    // which between them is every state but the one this is for.
    // Also while the agent is serving: an approval prompt must never appear
    // over a locked screen, and that needs a current reading regardless of
    // whether the vault is set to lock with the screen.
    running: (root.lockOnScreenLock && root.status === "unlocked") || root.sshAgentGateOpen
    onTriggered: {
      if (!screenLockStateProc.running) screenLockStateProc.running = true
    }
  }

  // Comes back for the processes that were mid-read when the vault locked.
  // Stops as soon as the queue empties, which is the same tick for everything
  // that was already idle.
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

  // The SSH companion. Tracked and non-detached so it dies with the shell and
  // with a configuration reload, rather than outliving the panel that holds
  // its control channel: the helper treats stdin EOF as "drop the keys and
  // exit", and that only works if this Process really owns the child.
  //
  // clearEnvironment strips everything the shell was started with -- PATH,
  // HOME, and above all BW_SESSION -- and `environment` puts back the single
  // variable the helper reads. It runs no `bw` and spawns nothing, so it needs
  // nothing else.
  Process {
    id: sshAgentProc
    // Whichever candidate the inspection accepted -- the shipped artifact by
    // preference, a local development build otherwise.
    command: Model.sshAgentHelperCommand(root.sshAgentPluginDir, root.sshAgentHelper.source)
    clearEnvironment: true
    environment: Model.sshAgentHelperEnv(root.sshAgentRuntimeDir) || ({})
    stdinEnabled: true
    // Attached from startup, so the `ready` that answers hello cannot be
    // missed by a parser wired up after the fact.
    stdout: SplitParser {
      onRead: function(line) { root.applySshAgentEvent({ kind: "line", line: line, nowMs: Date.now() }) }
    }
    onStarted: root.applySshAgentEvent({ kind: "started", nowMs: Date.now() })
    onExited: function(exitCode) {
      sshAgentTerminateTimer.stop()
      root.onSshAgentHelperExited(exitCode)
    }
  }

  // The bound on the handshake. QML never waits for `ready`; it arms this and
  // carries on, and a helper that has not answered by the time it fires is
  // stopped and retried like any other failure.
  Timer {
    id: sshAgentHandshakeTimer
    interval: Model.sshAgentHandshakeTimeoutMs()
    repeat: false
    running: root.sshAgentPhase === "starting" || root.sshAgentPhase === "handshaking"
    onTriggered: root.applySshAgentEvent({ kind: "handshakeTimeout", nowMs: Date.now() })
  }

  // Only while there is something to count down. A grant is at most fifteen
  // minutes, so this is never a timer that runs for the life of the shell.
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

  // The grace period between asking the helper to shut down and making it.
  // Two seconds is far longer than dropping keys and unlinking two paths
  // takes, and short enough that a wedged helper does not delay a restart.
  Timer {
    id: sshAgentTerminateTimer
    interval: 2000
    repeat: false
    onTriggered: if (sshAgentProc.running) sshAgentProc.running = false
  }

  // Capped restart backoff. The interval is set by the reducer before each
  // restart; the timer only reports that it elapsed.
  Timer {
    id: sshAgentRestartTimer
    repeat: false
    onTriggered: root.applySshAgentEvent({ kind: "restartTimer", nowMs: Date.now() })
  }

  // Long-lived: it holds the sleep inhibitor that makes the lock land before
  // the machine is frozen, so it runs whenever the setting is on rather than
  // only while the vault happens to be unlocked -- a suspend announcement is
  // no use to a panel that started listening after it.
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
  // Processes (Quickshell.Io)
  // -------------------------------------------------------------------------

  Process {
    id: statusProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      id: statusStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(statusProc)) return
      root.onStatusFinished(exitCode === 0 ? statusStdout.text : "")
    }
  }

  Process {
    id: sessionHandoffProc
    // Set by refreshStatus(), which decides whether this is a read or a
    // discard. Defaults to the discard form so a run that somehow starts
    // without going through there cannot adopt a key -- and a scrub, which
    // replaces this command with one that reads nothing at all, only makes
    // that stricter.
    command: Model.sessionHandoffReadCommand(false)
    stdout: StdioCollector {
      id: sessionHandoffStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(sessionHandoffProc)) return
      root.onSessionHandoff(exitCode === 0 ? sessionHandoffStdout.text : "")
    }
  }

  Process {
    id: keyringLookupProc
    command: Model.keyringLookupCommand()
    stdout: StdioCollector {
      id: keyringLookupStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (root.finishScrubRun(keyringLookupProc)) return
      root.onKeyringLookupFinished(exitCode === 0 ? keyringLookupStdout.text : "")
    }
  }

  Process {
    id: keyringStoreProc
    command: Model.keyringStoreCommand()
    environment: root.secretEnv(root.session)
    onExited: function(exitCode) {
      root.onSessionStored(exitCode)
      if (root.logoutPending && root.allCredentialsClearPending)
        Qt.callLater(root.requestAllCredentialClear)
    }
  }

  Process {
    id: keyringClearProc
    command: Model.keyringClearCommand()
    onExited: function(exitCode) {
      if (root.sessionClearPending) {
        Qt.callLater(root.requestSessionCredentialClear)
        return
      }
      if (root.sessionStorePending) Qt.callLater(root.storeCurrentSession)
    }
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

  // The generator server. A managed Process rather than execDetached, so it
  // exits with the shell instead of outliving it.
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

  // ---- PIN unlock ----
  //
  // PIN and master password are handed over in the environment; encrypt-and-store
  // and lookup-and-decrypt each run inside one process, so the plaintext never
  // travels back through QML on its way to or from the keyring.

  Process {
    id: pinStoreProc
    command: Model.pinStoreCommand()
    environment: root.pinEnv(root.pinSetupPin, root.pinSetupMaster)
    onExited: function(exitCode) {
      root.onPinStored(exitCode)
      if (root.logoutPending && root.allCredentialsClearPending)
        Qt.callLater(root.requestAllCredentialClear)
    }
  }

  Process {
    id: pinUnlockProc
    command: Model.pinUnlockCommand()
    environment: root.pinEnv(root.pinEntry, "")
    stdout: StdioCollector { id: pinUnlockStdout; waitForEnd: true }
    onExited: function(exitCode) {
      if (root.finishScrubRun(pinUnlockProc)) return
      root.onPinUnlockResult(exitCode, pinUnlockStdout.text)
    }
  }

  Process {
    id: keyringHasPinProc
    command: Model.keyringHasPinCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onPinConfiguredChecked(text)
    }
  }

  Process {
    id: keyringClearPinProc
    command: Model.keyringClearPinCommand()
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

  // An install runs in a terminal this panel does not own, so there is nothing
  // to wait on and no exit code to hear about. Re-probing while the setup
  // screen is up is what closes that loop: the moment `bw` lands on PATH the
  // screen turns green and onDependenciesChecked moves on to the vault, with
  // no second visit to a Re-check button. Only while the panel is open and
  // only on that screen, so it costs nothing the rest of the time.
  Timer {
    id: setupPollTimer
    interval: 2500
    running: root.opened && root.currentScreen === "setup" && root.setupActionsPending
    repeat: true
    onTriggered: root.checkDependencies()
  }

  // The whole first paint now waits behind the dependency probe. If that probe
  // never reports -- a shell that will not start, a mangled PATH -- the vault
  // should still be reachable instead of the panel sitting on "checking"
  // forever, so the status probe goes ahead on its own after a few seconds.
  Timer {
    id: statusProbeFallbackTimer
    interval: 4000
    running: root.live && !root.statusProbeStarted
    repeat: false
    onTriggered: {
      if (root.statusProbeStarted || root.setupGated) return
      // Four seconds of silence from a probe that takes milliseconds means it
      // is not coming. Treating that as "checked, nothing missing" is what
      // gets past refreshStatus()'s own !depsChecked guard -- an unanswered
      // probe must not be the thing that keeps the vault out of reach.
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
    command: Model.keyringHasMasterPasswordCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onFingerprintStoredChecked(text)
    }
  }

  Process {
    id: keyringLookupMasterProc
    command: Model.keyringLookupMasterPasswordCommand()
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
    command: Model.keyringClearMasterPasswordCommand()
    onExited: function(exitCode) {
      if (root.masterClearPending) Qt.callLater(root.requestMasterCredentialClear)
    }
  }

  // Logout's clean sweep; see forgetStoredCredentials().
  Process {
    id: keyringClearAllProc
    command: Model.keyringClearAllCommand()
    onExited: function(exitCode) {
      if (root.allCredentialsClearPending) {
        Qt.callLater(root.requestAllCredentialClear)
        return
      }
      root.onLogoutCredentialsFinished(exitCode)
    }
  }

  // ---- Learned associations ----

  Process {
    id: associationsReadProc
    command: Model.associationsReadCommand()
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
    command: Model.associationsWriteCommand()
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
      if (root.associationsWritePending) {
        root.associationsWritePending = false
        associationsWriteProc.running = true
        return
      }
      root.pendingAssociationsJson = ""
    }
  }

  Process {
    id: associationsClearProc
    command: Model.associationsClearCommand()
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

  // The lid, for the fingerprint reader's reachability. Its own file; the vault
  // reads only whether the lid is shut.
  LidState {
    id: lidState
    vault: root
  }

  // FIDO2 unlock, in its own file. It is handed the vault and the setting and
  // gives back a password once a key touch has been verified; everything else
  // FIDO2 -- its PAM stack, its probe, its keyring entry -- stays in there.
  FidoUnlock {
    id: fidoUnlocker
    vault: root
    armed: root.fidoUnlock

    onUnlocked: function(password) {
      root.pendingUnlockFrom = "fido"
      root.unlockVaultWithPassword(password)
    }
  }

  // Polls rather than counting down, for the same reason the auto-lock does:
  // a monotonic timer stops while the machine is suspended, and a login left
  // pending across a lid close must expire on the time that actually passed.
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
      // A scrub is started from this same handler and claims the process for a
      // moment, so a submit arriving in that moment waits on the scrub's exit
      // rather than the login's. Returning here without dispatching used to
      // drop that submit on the floor -- the click did nothing at all, and the
      // one after it worked because by then nothing held the process. That was
      // "I had to press Verify twice".
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
  // IPC Handler
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
    // Which vault this view is showing and how many views share it. Non-secret:
    // it exists so a multi-monitor report can be checked from a terminal.
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
    // Non-secret diagnostics for the SSH agent. No key material, no
    // fingerprints, no process paths -- just enough to tell why a signature
    // was or was not answered.
    function sshAgentStatus(): string {
      return JSON.stringify({
        enabled: root.sshAgentEnabled,
        phase: root.sshAgentPhase,
        // Named for what it is: the control channel to the helper is up and
        // handshaked. It is not "signing is allowed" -- that is the vault
        // state below, and reading this as the former is misleading next to a
        // locked vault.
        helperChannelOpen: root.sshAgentGateOpen,
        vaultState: Model.sshAgentVaultState({
          enabled: root.sshAgentEnabled,
          helperReady: root.sshAgentGateOpen,
          loggedIn: root.status !== "unauthenticated",
          unlocked: root.status === "unlocked",
          loading: root.sshAgentLoadActive,
          hasPublicCache: root.sshAgentKeyCount > 0
        }),
        setupState: root.sshAgentSetup.state,
        // Which binary is actually running, and whether its digest was
        // checked. A shipped helper and a silently substituted development
        // build behave identically until one of them misbehaves, and without
        // these two fields the terminal cannot tell them apart at all.
        helperSource: root.sshAgentHelper.source,
        helperChecksum: root.sshAgentHelper.checksum,
        // Why inspection rejected it, in the inspector's own vocabulary:
        // checksum-mismatch, not-elf, wrong-architecture, not-executable,
        // self-test-failed. errorCode covers the running helper and stays
        // empty for all of these, so without this the terminal is told the
        // feature is in error and never told what the error was.
        helperState: root.sshAgentHelper.state,
        // What the panel believes about client routing: the file it last
        // inspected, and whether that produced a notice. Both are read from
        // the same state the settings screen draws, so a disagreement between
        // this and the screen is itself the answer.
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
