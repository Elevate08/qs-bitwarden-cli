import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Services.Pam
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

Panel {
  id: root
  moduleName: "io.github.elevate08.qs-bitwarden-cli"
  ipcTarget: "io.github.elevate08.qs-bitwarden-cli"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

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
  readonly property bool pinUnlock: Model.boolSetting("pinUnlock", setting("pinUnlock", false))
  // The SSH agent is opt-in. Nothing starts a helper, creates a socket, or
  // touches a FIFO while this is false.
  readonly property bool sshAgentEnabled: Model.boolSetting("sshAgentEnabled", setting("sshAgentEnabled", false))
  readonly property bool sshAgentUnlockOnDemand: Model.boolSetting("sshAgentUnlockOnDemand", setting("sshAgentUnlockOnDemand", false))
  readonly property bool sshAgentApprovalPopup: Model.boolSetting("sshAgentApprovalPopup", setting("sshAgentApprovalPopup", true))
  readonly property int sshAgentApprovalWindowSec: Model.intSetting("sshAgentApprovalWindowSec", setting("sshAgentApprovalWindowSec"))

  // The SSH sections' own section header. PanelSectionHeader comes from the
  // Omarchy shell, and its defaults are the global theme's -- `Color.foreground`
  // and `Style.font.family` -- while everything around it here follows the bar's
  // own foreground and font family. Stating them once keeps the headers matching
  // the captions beneath them, and keeps `textFormat` explicit, which this
  // panel requires of every text element whether or not its text is constant
  // today.
  component SshSectionHeader: PanelSectionHeader {
    textFormat: Text.PlainText
    foreground: root.fg
    fontFamily: root.fontFamily
  }

  component SshCaption: Text {
    textFormat: Text.PlainText
    width: parent ? parent.width : 0
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  // One of the three vault filters at the foot of the list, collapsed to its
  // current value. Declared once so the three cannot drift apart and start
  // reading as different kinds of control.
  //
  // The button names its filter as well as showing its value. The glyphs alone
  // do not carry it: the three sit together reading "All", "All", "All" for as
  // long as nothing is filtered, which is exactly when the value says least and
  // the name says most. So the name stays, and the row is allowed to take a
  // second line on the rarer occasions all three are set to something long.
  //
  // The value is still clipped. `Ui.Button` has no elide, so a folder named
  // after a whole client engagement would make one button wider than the whole
  // panel -- and a row that wraps can move a button to the next line but can
  // never make one narrower than the panel it is in.
  component VaultFilterButton: Button {
    required property string group
    required property string glyph
    required property string name
    required property string value
    required property string shortcut

    // Clipped first, then neutralized: plainLabel may return a <span>, and
    // slicing that would cut the tag in half.
    text: Model.plainLabel(name + ": " + Model.clipLabel(value, 20))
    iconText: root.openFilterGroup === group ? "󰅀" : glyph
    selected: root.openFilterGroup === group
    accent: Color.accent
    fontFamily: root.fontFamily
    fontSize: Style.font.caption
    horizontalPadding: Style.space(10)
    // The full value, unclipped, is still one hover away -- and the tooltip is
    // drawn by the kit's own auto-detecting Text, so it is neutralized too.
    tooltipText: Model.plainLabel(name + " filter (" + shortcut + "): " + value)
    onClicked: root.toggleFilterGroup(group)
  }

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
  // is not scoped to an account -- so an unconfirmed one is dropped and
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

  // Screens: "main" | "detail" | "edit" | "locked" | "login" | "settings" | "setup"
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
  // Which picker in the item form is expanded: "" | "folder" | "organization"
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
  property string masterToStore: ""
  // Item JSON on its way to `bw encode`. Held here so the create/edit processes
  // can pass it in the environment instead of on the command line.
  property string itemPayloadJson: ""
  property bool fpSetupActive: false
  property string fpSetupMaster: ""
  property string fpError: ""
  property bool fpBusy: false
  // Which credential source drove the in-flight unlock, so a stale stored
  // secret can be discarded rather than retried forever. "" | "fingerprint" | "pin"
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
  property string pinError: ""
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
  readonly property bool fingerprintReady: fingerprintUnlock && fingerprintAvailable && fingerprintStored

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

  // Visual styles
  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property color dim: Qt.darker(fg, 1.5)
  readonly property color barIconColor: {
    var base = bar ? bar.barForeground : Color.foreground
    if (status === "unlocked") return Color.accent
    if (status === "locked" || status === "checking") return base
    return bar ? bar.urgent : Color.urgent
  }
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  Component.onCompleted: {
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

  // Live companion events. Task 10 supervises the channel; the vault
  // lifecycle, approval UI and key loading that consume these arrive with
  // Tasks 12-14. Until then an unhandled event is deliberately inert rather
  // than an error: it is a valid v1 message the panel simply has no use for
  // yet.
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
    cancelAuthPrewarm()
    if (pinUnlockProc.running) pinUnlockProc.running = false
    root.pinUnlockSubmitted = false
    root.pinBusy = false
    root.masterPassword = ""
    root.pendingUnlockPassword = ""
    root.pendingUnlockFrom = ""
    root.pinEntry = ""
    root.pinError = ""
    root.fingerprintMessage = ""
    root.errorMessage = ""
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
        if (message.reason !== "released") {
          root.sshCooldown = Model.sshAgentCooldownAfter(root.sshCooldown, "timeout", Date.now())
          noteSshCooldown()
        } else {
          return
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
      // The set is complete: every public_key for this epoch arrived ahead of
      // this message.
      if (root.sshPendingPublicEpoch === message.epoch) exportSshPublicKeys()
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
    // unlock_required, approval_required and grants_changed are the signing
    // UX, and arrive with Task 14. Ignoring a valid v1 message is deliberate
    // here; an unknown *type* is a protocol failure and never reaches this.
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

  function primeSshAgentLoadId() {
    if (loadIdProc.running || sshAgentNextLoadId !== "") return
    loadIdProc.running = true
  }

  function onSshAgentLoadIdRead(raw) {
    var candidate = String(raw || "").trim()
    root.sshAgentNextLoadId = Model.isValidLoadId(candidate) ? candidate : ""
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

  function open() {
    errorMessage = ""
    flashMessage = ""
    revealedFields = ({})
    cursorActive = true
    showDeleteConfirm = false
    totpFollowupActive = false
    isUnlocking = false
    suggestionsDismissed = false
    fingerprintMessage = ""

    // controller.show() flips `opened`, which runs onPanelOpened via
    // onOpenedChanged. Only drive it directly when the panel was already open
    // and that signal will not fire -- otherwise every open did its startup
    // work twice, including two `bw status` calls at ~3s each.
    var wasOpen = opened
    root.controller.show()
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
    cancelAttachmentDownloads()
    stopGeneratorServe()
    root.controller.hide()
  }

  function toggle() {
    if (opened) close()
    else open()
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

  // Every field on the login screen, and every field on the unlock screen.
  // focusAppropriateField() consults these before it moves the cursor.
  function loginFieldHasFocus() {
    return emailField.activeFocus || loginPassField.activeFocus
      || code2faField.activeFocus || deviceCodeField.activeFocus
      || serverUrlField.activeFocus
      || apiClientIdField.activeFocus || apiClientSecretField.activeFocus
      || apiMasterField.activeFocus
  }

  function unlockFieldHasFocus() {
    return passField.activeFocus || pinField.activeFocus
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
        if (!searchField.activeFocus) searchField.forceActiveFocus()
      } else if (status === "locked" || status === "checking") {
        if (unlockFieldHasFocus()) return
        if (pinReady) pinField.forceActiveFocus()
        else passField.forceActiveFocus()
      } else if (status === "unauthenticated") {
        if (loginFieldHasFocus()) return
        // A login resumed on a challenge opens on the field that is waiting,
        // not back at the top of the form.
        if (showDeviceCodeField) deviceCodeField.forceActiveFocus()
        else if (show2faField) code2faField.forceActiveFocus()
        else if (!show2faMethodPicker) emailField.forceActiveFocus()
      }
    })
  }

  onOpenedChanged: {
    if (opened) onPanelOpened()
    else {
      cancelFingerprintUnlock()
      cancelAuthPrewarm()
      if (pendingSecondFactorLogin()) suspendPendingLogin()
      else abandonAuthSecrets()
      // A closed panel must not keep a field focused, or the next open would
      // count as "already typing here" and skip the field the screen opens on.
      keyCatcher.forceActiveFocus()
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
      startFingerprintUnlock()
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
      if (sshAuthSurfaceActive) startFingerprintUnlock()
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
      Qt.callLater(function() { deviceCodeField.forceActiveFocus() })
      return
    }
    if (!String(loginPassword || "")) {
      errorMessage = "Your master password is needed again for this step."
      resetEmailLoginSecondFactor()
      Qt.callLater(function() { loginPassField.forceActiveFocus() })
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

  // Typing into a TextField assigns to its own `text`, which breaks the binding
  // back to the property behind it. After that the two are independent, and
  // clearing the property alone leaves the field showing what was typed --
  // while every submit reads the property. That is exactly how a login came to
  // be sent with no code at all while the user was looking at a filled-in
  // field: bw answered "Code is required.", the panel reported the code as
  // rejected, and retyping it repaired the property so the next click worked.
  //
  // So a field is never cleared by clearing what is behind it. These go
  // together, always.
  function syncLoginFieldsToState() {
    code2faField.text = login2faCode
    deviceCodeField.text = loginDeviceCode
    loginPassField.text = loginPassword
    apiMasterField.text = loginPassword
    apiClientIdField.text = loginClientId
    apiClientSecretField.text = loginClientSecret
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
        Qt.callLater(function() { code2faField.forceActiveFocus() })
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
      Qt.callLater(function() { deviceCodeField.forceActiveFocus() })
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
      Qt.callLater(function() { deviceCodeField.forceActiveFocus() })
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
      Qt.callLater(function() { code2faField.forceActiveFocus() })
      return
    }

    if (exitCode === 0 && out.length > 10) {
      rememberTwoFactorMethod(login2faMethod)
      loginPassword = ""
      login2faCode = ""
      logLogin("success", out, err, exitCode)
      onUnlockSuccess(out)
      return
    }

    if (err) {
      logLogin("bw-error", out, err, exitCode)
      errorMessage = err
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
    return keyringStoreProc.running || pinStoreProc.running || keyringStoreMasterProc.running
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
    pinConfigured = false
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
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
    Qt.callLater(function() { sendNameField.forceActiveFocus() })
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
    if (toForm) Qt.callLater(function() { formPassField.forceActiveFocus() })
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
    screenBeforeSettings = "main"
    currentScreen = "pin"
    Qt.callLater(function() { pinSetupPinField.forceActiveFocus() })
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
      pinError = "PIN must be at least " + Model.pinMinLength() + " digits"
      return
    }
    pinError = ""
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
        pinError = "Too many incorrect PINs. PIN unlock has been removed -- use your master password."
      } else {
        pinError = "Incorrect PIN (" + pinAttempts + " of " + pinMaxAttempts + ")"
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
    if (!entry || !entry.requires) return false
    for (var i = 0; i < dependencies.items.length; i++) {
      if (dependencies.items[i].key === entry.requires) return !dependencies.items[i].ready
    }
    return false
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

  // The lane every vertical scrollbar in this panel gets to itself.
  //
  // These bars are overlays: left alone they draw on top of whatever occupies
  // the right edge of the view, which across these screens is toggles, number
  // fields, copy buttons and the ends of elided text. Every scrolling view
  // subtracts this from its content width, so the bar has somewhere to be and
  // the right-hand edges of all of them line up.
  //
  // Measured from a real scrollbar rather than guessed at, so a theme with a
  // wider one does not put it back over the controls. One bar stands in for
  // all of them because they are the same control with the same style; the
  // floor covers both a null reference and the frames before it has an
  // implicit width of its own.
  readonly property real scrollGutter:
    Math.max(settingsScrollBar ? settingsScrollBar.implicitWidth : 0, Style.space(10))

  // Which section the view is currently inside, named by the pinned indicator.
  // Held rather than derived, because it depends on delegate geometry the
  // Repeater only knows after layout, and a binding cannot read that without
  // fighting it.
  property var settingsStickyEntry: null

  // The settings view's two geometry questions, in one place. Everything else
  // that needs them goes through these rather than reaching into the Flickable
  // and the Repeater by id from across the file.
  function settingsViewportTop() { return settingsFlick ? settingsFlick.contentY : 0 }
  function settingsRepeaterItem(i) {
    return settingsRepeater ? settingsRepeater.itemAt(i) : null
  }

  // The section the view is currently inside: the last heading at or above the
  // top of the viewport, while any part of its section is still on screen.
  //
  // Both halves matter. Without the first the bar sits empty until the user
  // has scrolled, which is the one position everybody starts from. Without the
  // second the last group stays named through the maintenance and danger-zone
  // rows below it, which belong to no section and would leave the bar
  // describing somewhere the user had already scrolled past.
  //
  // Drawing the heading twice is prevented at the other end: the in-list
  // heading of whichever section this names is drawn transparent, so it keeps
  // its place in the layout without appearing alongside its own copy.
  function updateSettingsSticky() {
    var entries = settingsEntries
    var top = settingsViewportTop()
    var found = null

    for (var i = 0; i < entries.length; i++) {
      if (!entries[i] || entries[i].kind !== "group") continue
      var row = settingsRepeaterItem(i)
      if (!row) continue
      // Still below the top edge: the section before this one is the one the
      // view is in.
      if (row.y > top + 1) break
      if (top < settingsSectionEnd(i)) found = entries[i]
    }
    settingsStickyEntry = found
  }

  // Where the section beginning at `index` stops: the next heading, or for the
  // last one, the bottom of the final row before the trailing action blocks.
  function settingsSectionEnd(index) {
    var entries = settingsEntries
    for (var i = index + 1; i < entries.length; i++) {
      if (!entries[i] || entries[i].kind !== "group") continue
      var next = settingsRepeaterItem(i)
      if (next) return next.y
    }
    for (var j = entries.length - 1; j > index; j--) {
      var last = settingsRepeaterItem(j)
      if (last) return last.y + last.height
    }
    var self = settingsRepeaterItem(index)
    return self ? self.y + self.height : 0
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
    Qt.callLater(updateSettingsSticky)
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
  }

  function onFingerprintStoredChecked(raw) {
    fingerprintStored = String(raw || "").trim() === "yes"
    if (sshAuthSurfaceActive && status === "locked") startFingerprintUnlock()
  }

  function startFingerprintUnlock() {
    if (!fingerprintReady || status !== "locked" || isUnlocking) return
    if (fingerprintScanning || fingerprintPam.active) return
    if (!userName) {
      fingerprintMessage = "Cannot determine current user for fingerprint verification"
      return
    }

    errorMessage = ""
    fingerprintAuthorized = false
    fingerprintScanning = true
    fingerprintMessage = "󰈷  Touch the fingerprint reader..."
    if (!fingerprintPam.start()) {
      fingerprintScanning = false
      fingerprintMessage = "Could not start fingerprint verification"
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
      fingerprintMessage = "󰈷  Fingerprint verified, unlocking..."
      if (!keyringLookupMasterProc.running) {
        keyringLookupMasterProc.command = Model.keyringLookupMasterPasswordCommand()
        keyringLookupMasterProc.running = true
      }
    } else if (result === PamResult.MaxTries) {
      fingerprintMessage = "Too many fingerprint attempts. Use your master password."
    } else {
      fingerprintMessage = "Fingerprint not recognised. Try again or use your master password."
    }
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
      fingerprintMessage = "No stored master password. Unlock with your password once to enable this."
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
    Qt.callLater(function() { fpMasterField.forceActiveFocus() })
  }

  function abandonFingerprintSetup() {
    var active = fpSetupActive
    if (active && keyringStoreMasterProc.running) invalidateEpochOperation("masterStore")
    fpSetupActive = false
    fpBusy = false
    fpSetupMaster = ""
    if (active) masterToStore = ""
  }

  function submitFingerprintSetup() {
    if (fpBusy || keyringStoreMasterProc.running) return
    if (!fpSetupMaster) {
      fpError = "Master password is required to enable fingerprint unlock"
      return
    }
    fpError = ""
    fpBusy = true
    fpSetupActive = true
    masterToStore = fpSetupMaster
    beginEpochOperation("masterStore")
    keyringStoreMasterProc.running = true
  }

  function onMasterPasswordStored(exitCode) {
    masterToStore = ""
    pendingUnlockPassword = ""
    if (epochOperationIsStale("masterStore")) {
      fpSetupActive = false
      fpBusy = false
      fpSetupMaster = ""
      fingerprintStored = false
      requestMasterCredentialClear()
      return
    }
    fingerprintStored = (exitCode === 0)

    if (fpSetupActive) {
      fpSetupActive = false
      fpBusy = false
      fpSetupMaster = ""
      if (exitCode !== 0) {
        fpError = "Could not save the master password. Is the OS keyring available?"
        return
      }
      writeSetting("fingerprintUnlock", true, "bool")
      flashNotification("Fingerprint unlock enabled")
      currentScreen = "settings"
      return
    }

    if (exitCode !== 0) {
      errorMessage = "Could not save master password to the OS keyring, so fingerprint unlock is unavailable."
    }
  }

  function forgetFingerprintUnlock() {
    requestMasterCredentialClear()
    fingerprintStored = false
    cancelFingerprintUnlock()
    fingerprintMessage = ""
    flashNotification("Fingerprint unlock forgotten")
  }

  onFingerprintUnlockChanged: {
    if (!fingerprintUnlock) {
      cancelFingerprintUnlock()
      fingerprintMessage = ""
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
      onUnlockSuccess(out)
    } else {
      pendingUnlockPassword = ""
      // A stored secret the vault no longer accepts is useless: drop it rather
      // than fail on every open, and say which one went stale.
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
      if (pendingUnlockFrom === "pin") {
        pendingUnlockFrom = ""
        clearPin()
        pinError = "Your master password changed, so the PIN no longer works. Unlock with your password and set a new PIN."
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

    // Opting in stores the master password so a finger can stand in for it later.
    // Keep an existing enrolment current after a master password change. It no
    // longer creates one -- that is what the setup form is for.
    if (fingerprintUnlock && fingerprintAvailable && fingerprintStored
        && pendingUnlockPassword && pendingUnlockFrom === ""
        && !keyringStoreMasterProc.running) {
      masterToStore = pendingUnlockPassword
      beginEpochOperation("masterStore")
      keyringStoreMasterProc.running = true
    } else {
      pendingUnlockPassword = ""
    }
    pendingUnlockFrom = ""
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
    fingerprintMessage = ""

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
    flashNotification("Vault locked")
    focusAppropriateField()
    if (sshAuthSurfaceActive) startFingerprintUnlock()
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
    cancelAttachmentDownloads()
    session = ""
    vaultEpoch += 1
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
    masterToStore = ""
    pendingAssociationsJson = ""
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
    ]
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
    } else if (currentScreen === "pin") {
      pinError = ""
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
    restoreScreenFocus()
  }

  function restoreScreenFocus() {
    Qt.callLater(function() {
      if (status !== "unlocked") { focusAppropriateField(); return }
      switch (currentScreen) {
        case "main": searchField.forceActiveFocus(); return
        case "edit": formNameField.forceActiveFocus(); return
        // These open through a function that focuses their own first field.
        case "pin": case "fingerprint": return
        case "sends": if (sendMode === "create") return; break
      }
      // Everything else is keyboard-navigated rather than typed into.
      keyCatcher.forceActiveFocus()
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
      typeFields: formTypeFields()
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
    var problem = Model.validateItemForm(formName, formOrgId, formCollectionIds)
    if (problem) {
      errorMessage = problem
      return
    }

    var editing = formIsEditing
    var payload = editing
      ? Model.buildEditPayload(detailItem, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId, formFolderId, formCollectionIds, formTypeFields())
      : Model.buildCreatePayload(formTypeCode, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId, formFolderId, formCollectionIds, formTypeFields())
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
    if (itemsListView) {
      itemsListView.positionViewAtIndex(selectedIndex, ListView.Contain)
    }
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
      root.applySshAgentEvent({ kind: "exited", exitCode: exitCode, nowMs: Date.now() })
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
    running: root.lockOnSuspend
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
    running: !root.statusProbeStarted
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
    id: keyringStoreMasterProc
    command: Model.keyringStoreMasterPasswordCommand()
    environment: root.secretEnv(root.masterToStore)
    onExited: function(exitCode) {
      root.onMasterPasswordStored(exitCode)
      if (root.logoutPending && root.allCredentialsClearPending)
        Qt.callLater(root.requestAllCredentialClear)
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

  Component {
    id: shieldIconComp

    Item {
      anchors.fill: parent

      // Constant Base Shield
      TextMetrics {
        id: shieldGlyphMetrics
        font.family: root.fontFamily
        font.pixelSize: Style.bar.iconFont
        text: "󰞀"
      }

      Text {
        textFormat: Text.PlainText
        id: shieldGlyph
        // Native text is snapped before fractional output scaling. Keep this
        // glyph in Qt's scene graph so its corrected painted center stays on
        // the same logical centerline as the bar's panel-open indicator.
        anchors.centerIn: parent
        anchors.horizontalCenterOffset: shieldGlyph.implicitWidth / 2
          - (shieldGlyphMetrics.tightBoundingRect.x
            + shieldGlyphMetrics.tightBoundingRect.width / 2)
        text: "󰞀"
        font.family: root.fontFamily
        font.pixelSize: Style.bar.iconFont
        color: root.colorizeIcon ? Color.accent : (bar ? bar.barForeground : Color.foreground)
        renderType: Text.QtRendering
      }

      // Mini Install Badge in the same corner while a required tool is absent.
      // A freshly installed widget has to say "click me, there is one step
      // left" rather than sit there looking like it failed, so this outranks
      // the padlock: with no `bw` there is no lock state worth reporting.
      Item {
        visible: root.missingRequired.length > 0
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.rightMargin: -Style.space(2)
        anchors.bottomMargin: -Style.space(2)
        width: Style.space(10)
        height: Style.space(10)

        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: bar ? bar.background : Color.background
        }

        Text {
          textFormat: Text.PlainText
          anchors.centerIn: parent
          text: "󰐕"
          font.family: root.fontFamily
          font.pixelSize: Style.space(8)
          color: bar ? bar.urgent : Color.urgent
          renderType: Text.NativeRendering
        }
      }

      // Mini Padlock Badge in Bottom-Right Corner when locked
      Item {
        visible: root.status === "locked" && root.missingRequired.length === 0
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.rightMargin: -Style.space(2)
        anchors.bottomMargin: -Style.space(2)
        width: Style.space(10)
        height: Style.space(10)

        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: bar ? bar.background : Color.background
        }

        Text {
          textFormat: Text.PlainText
          anchors.centerIn: parent
          text: "󰌾"
          font.family: root.fontFamily
          font.pixelSize: Style.space(8)
          color: bar ? bar.barForeground : Color.foreground
          renderType: Text.NativeRendering
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Status Bar Button
  // -------------------------------------------------------------------------

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: shieldIconComp
    useActiveColor: false
    dimmed: root.status === "unauthenticated" || root.status === "checking"
    tooltipText: {
      // Ahead of every status: with a required tool missing, whatever `bw`
      // last said about the vault is beside the point.
      if (root.missingRequired.length > 0) {
        return "Bitwarden (Click to finish setup)"
      }
      if (root.status === "unlocked") {
        return "Bitwarden (" + (root.items.length > 0 ? root.items.length + " items" : "Unlocked") + ")"
      }
      if (root.status === "locked") {
        return "Bitwarden (Locked)"
      }
      return "Bitwarden (Not Logged In)"
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) {
        if (root.status === "unlocked") root.lockVault()
        else root.open()
      } else if (buttonCode === Qt.MiddleButton) {
        root.syncVault()
      } else {
        root.toggle()
      }
    }
  }

  // -------------------------------------------------------------------------
  // Popup Window (KeyboardPanel)
  // -------------------------------------------------------------------------

  SshApprovalPopup {
    panel: root
    anchorItem: button
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    // Every unlocked screen except the two that are text entry drives the key
    // catcher, so arrow navigation works on settings and the generator too.
    // Setup is buttons, not text entry, and it is reached with the vault state
    // still unknown -- so it takes the key catcher outright rather than
    // handing focus to a password field that is not even on screen.
    focusTarget: root.currentScreen === "setup"
      ? keyCatcher
      : ((root.status === "unlocked"
          && root.currentScreen !== "edit"
          && root.currentScreen !== "pin"
          && root.currentScreen !== "fingerprint")
        ? keyCatcher
        : (root.status === "unauthenticated"
          ? (root.show2faField ? code2faField : emailField)
          : passField))
    contentWidth: panel.fittedContentWidth(Style.space(450))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight, Style.space(640) + root.filterDrawerHeight)

    // PanelKeyCatcher maps h/j/k/l to arrow navigation and consumes them before
    // its textKey signal fires, which silently swallowed the l (lock) shortcut.
    // Forwarding here first gives our letter bindings the first look; anything
    // we do not accept falls through to the catcher's own navigation.
    Item {
      id: shortcutInterceptor
      Keys.onPressed: function(event) {
        // Escape is handled here rather than in the key catcher because the
        // catcher is blocked on every screen built around a text field -- the
        // item form, the PIN and fingerprint screens, the Send composer --
        // and a blocked catcher swallows Escape along with everything else.
        // This interceptor runs first and is not gated by `blocked`, so
        // cancelling out of a form works while the cursor is in a field.
        if (event.key === Qt.Key_Escape && !(event.modifiers & ~Qt.KeypadModifier)) {
          root.handleEscape()
          event.accepted = true
          return
        }

        // Alt may arrive with no text depending on the keymap, so fall back to
        // the key code for A-Z.
        var t = event.text ? String(event.text).toLowerCase() : ""
        if (!t && event.key >= Qt.Key_A && event.key <= Qt.Key_Z) {
          t = String.fromCharCode(event.key).toLowerCase()
        }

        if (event.modifiers & Qt.AltModifier) {
          if (t && root.status === "unlocked" && root.runAltShortcut(t)) event.accepted = true
          return
        }

        if (event.modifiers & ~Qt.KeypadModifier) return
        if (!t || root.currentScreen !== "main") return
        if (root.openFilterGroup !== "") return
        if (t !== "h" && t !== "j" && t !== "k" && t !== "l") return
        if (root.runShortcut(t)) event.accepted = true
      }
    }

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      Keys.forwardTo: [shortcutInterceptor]
      blocked: searchField.activeFocus
        || emailField.activeFocus
        || loginPassField.activeFocus
        || code2faField.activeFocus
        || passField.activeFocus
        || pinField.activeFocus
        || (root.currentScreen === "edit")
        || (root.currentScreen === "pin")
        || (root.currentScreen === "fingerprint")
        || (root.currentScreen === "sends" && root.sendMode === "create")

      // Reached only on screens where the catcher is not blocked; the
      // interceptor handles Escape everywhere else. Same dispatch either way.
      onCloseRequested: root.handleEscape()
      onTabRequested: function(direction) {
        if (root.currentScreen === "main") {
          root.cycleCategory(direction)
        } else {
          root.switchPanel(direction)
        }
      }
      onMoveRequested: function(dx, dy) {
        if (root.currentScreen === "sends" && root.sendMode === "list") {
          if (dy !== 0) root.moveSendCursor(dy)
          return
        }
        if (root.currentScreen === "settings") {
          if (dy !== 0) root.moveSettingsCursor(dy)
          else if (dx !== 0) root.adjustSetting(dx)
          return
        }
        // While a filter drawer is open the arrows drive it, not the item list.
        if (root.openFilterGroup !== "" && root.currentScreen === "main") {
          if (dy !== 0) root.moveFilterCursor(dy)
          return
        }
        if (!root.cursorActive) {
          root.cursorActive = true
          return
        }
        if (root.currentScreen === "main") {
          if (dy !== 0) root.moveCursor(dy)
          else if (dx !== 0) root.cycleCategory(dx)
        }
      }
      onActivateRequested: {
        if (root.currentScreen === "generator" && root.generatorFeedsForm) {
          root.useGeneratedPassword()
          return
        }
        if (root.currentScreen === "sends" && root.sendMode === "list") {
          if (root.sendIndex < root.sends.length) root.copySendLink(root.sends[root.sendIndex])
          return
        }
        if (root.currentScreen === "settings") {
          root.activateSettingRow()
          return
        }
        if (root.openFilterGroup !== "" && root.currentScreen === "main") {
          root.activateFilterOption()
          return
        }
        if (root.currentScreen === "main") {
          var item = root.getSelectedItem()
          if (item) {
            root.handleSmartEnter(item)
          }
          return
        }
        // The password row has always been labelled "Copy password (y / Enter)"
        // and the detail screen has never handled Enter, so that half of the
        // tooltip was a promise nothing kept. Enter copies the item's primary
        // secret here, the same one `y` reaches: the password on a login, the
        // number on a card. A note or an identity has no single such value, so
        // Enter stays inert on those rather than guessing at one.
        if (root.currentScreen === "detail") {
          if (root.detailIsCard) {
            if (root.detailCard && root.detailCard.number) {
              root.copyToClipboard(root.detailCard.number, "Card number")
            }
          } else if (root.detailIsLoginLike && root.detailPassword) {
            root.copyToClipboard(root.detailPassword, "Password")
          }
        }
      }
      onTextKey: function(key) {
        var lower = String(key).toLowerCase()
        if (root.currentScreen === "sends" && root.sendMode === "list") {
          if (lower === "n") root.beginCreateSend()
          else if (lower === "r") root.loadSends()
          else if (lower === "x" && root.sendIndex < root.sends.length) root.deleteSend(root.sends[root.sendIndex])
          return
        }
        if (root.currentScreen === "main") {
          if (lower === "/") searchField.forceActiveFocus()
          else root.runShortcut(lower)
        } else if (root.currentScreen === "detail") {
          // `y` is "copy the thing this item is for". On a login that is the
          // password; on a card it is the number. Keeping one key for the
          // primary secret is worth more than a key that means `password`
          // everywhere and does nothing on two of the four types.
          if (lower === "y" || lower === "p") {
            if (root.detailIsCard) {
              if (root.detailCard && root.detailCard.number) root.copyToClipboard(root.detailCard.number, "Card number")
            } else if (root.detailPassword) {
              root.copyToClipboard(root.detailPassword, "Password")
            }
          } else if (lower === "n") {
            if (root.detailIsCard && root.detailCard && root.detailCard.number) {
              root.copyToClipboard(root.detailCard.number, "Card number")
            }
          } else if (lower === "k") {
            if (root.detailIsCard && root.detailCard && root.detailCard.code) {
              root.copyToClipboard(root.detailCard.code, "Security code")
            }
          } else if (lower === "u" || lower === "c") {
            // `u` copies the identifier, `c` the contact address. On a login
            // both land on the one username field, which is what they have
            // always done.
            if (root.detailIsIdentity && root.detailIdentity) {
              if (lower === "c" && root.detailIdentity.email) {
                root.copyToClipboard(root.detailIdentity.email, "Email")
              } else if (root.detailIdentity.username) {
                root.copyToClipboard(root.detailIdentity.username, "Username")
              }
            } else if (root.detailItem && root.detailItem.username) {
              root.copyToClipboard(root.detailItem.username, "Username")
            }
          } else if (lower === "m") {
            if (root.liveTotp) root.copyToClipboard(root.liveTotp, "TOTP")
          } else if (lower === "e") {
            if (root.detailItem) root.startEditItem(root.detailItem)
          } else if (lower === "x") {
            if (root.detailItem && root.detailItem.typeCode !== 5) root.showDeleteConfirm = true
          } else if (lower === "v") {
            if (root.primaryRevealKey !== "") root.toggleFieldReveal(root.primaryRevealKey)
          } else if (lower === "a") {
            root.saveAllAttachments()
          } else if (lower === "b" || lower === "q") {
            root.currentScreen = "main"
          }
        }
      }

      Column {
        id: mainColumn
        anchors.fill: parent
        spacing: Style.space(12)

        // -------------------------------------------------------------------
        // Hero Header
        // -------------------------------------------------------------------
        PanelHero {
          width: parent.width
          title: "Bitwarden"
          meta: {
            if (root.status === "unlocked") {
              if (root.isSyncing) return "Syncing..."
              if (root.isLoading && root.items.length === 0) return "Loading items..."
              // The email arrives with `bw status`, which lags the item list on
              // a cold start and after a terminal-login handoff. Fall back to
              // the count so the subtitle is never blank in that gap.
              return root.userEmail || (root.filteredItems.length + " items")
            }
            if (root.status === "locked") return "Vault Locked"
            if (root.status === "checking") return "Checking status..."
            return "Log In"
          }
          foreground: root.fg
          fontFamily: root.fontFamily

          iconComponent: Text {
            textFormat: Text.PlainText
            text: "󰞀"
            color: root.barIconColor
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
          }

          trailingControl: Row {
            spacing: Style.space(6)

            // New Item Button
            PanelActionButton {
              visible: root.status === "unlocked" && root.activeScreen === "main"
              iconText: "󰐕"
              tooltipText: "New item (n)"
              fontFamily: root.fontFamily
              onClicked: root.startAddNewItem()
            }

            // Sync Vault Button
            PanelActionButton {
              visible: root.status === "unlocked"
              iconText: "󰑐"
              tooltipText: root.isSyncing ? "Syncing..." : "Sync vault (r)"
              fontFamily: root.fontFamily
              enabled: !root.isSyncing
              onClicked: root.syncVault()
            }

            // Send Button
            PanelActionButton {
              visible: root.status === "unlocked" && root.activeScreen !== "sends"
              iconText: "󰒗"
              tooltipText: "Bitwarden Send (Alt+S)"
              fontFamily: root.fontFamily
              onClicked: root.openSends()
            }

            // Generator Button
            PanelActionButton {
              visible: root.status === "unlocked" && root.activeScreen !== "generator"
              iconText: "󰌆"
              tooltipText: "Password generator (g)"
              fontFamily: root.fontFamily
              onClicked: root.openGenerator()
            }

            // Settings Button
            PanelActionButton {
              visible: root.activeScreen !== "settings" && root.activeScreen !== "setup" && root.activeScreen !== "pin"
              iconText: "󰒓"
              tooltipText: "Settings (s)"
              fontFamily: root.fontFamily
              onClicked: root.openSettings()
            }

            // Lock Vault Button
            PanelActionButton {
              visible: root.status === "unlocked"
              iconText: "󰌾"
              tooltipText: "Lock vault (l)"
              fontFamily: root.fontFamily
              onClicked: root.lockVault()
            }

            // Close Panel Button
            PanelActionButton {
              iconText: "󰅖"
              tooltipText: "Close (Esc)"
              fontFamily: root.fontFamily
              onClicked: root.close()
            }
          }
        }

        // -------------------------------------------------------------------
        // Sequential TOTP Follow-Up Action Banner
        // -------------------------------------------------------------------
        BorderSurface {
          visible: root.totpFollowupActive && root.totpFollowupItem !== null
          width: parent.width
          implicitHeight: Style.space(42)
          color: Util.alpha(Color.accent, 0.2)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.accent, 1)

          Row {
            anchors.fill: parent
            anchors.leftMargin: Style.space(10)
            anchors.rightMargin: Style.space(10)
            spacing: Style.space(8)

            Text {
              textFormat: Text.PlainText
              anchors.verticalCenter: parent.verticalCenter
              text: "󰄬"
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Column {
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - copyFollowupTotpBtn.width - Style.space(40)
              spacing: 1

              Text {
                textFormat: Text.PlainText
                text: "Password copied! Press Enter for TOTP"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                text: root.totpFollowupCode ? ("Code: " + root.totpFollowupCode + " (expires in " + root.totpSecRemaining + "s)") : "Fetching 2FA code..."
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            Button {
              id: copyFollowupTotpBtn
              anchors.verticalCenter: parent.verticalCenter
              text: "Copy TOTP (Enter)"
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: {
                if (root.totpFollowupItem) root.copyTotpCode(root.totpFollowupItem)
                root.totpFollowupActive = false
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // Development Helper Banner
        // -------------------------------------------------------------------
        // The shipped helper is what a user installed and what CI verified.
        // Falling back to a local build is deliberate -- a broken release must
        // not strand a working one -- but it is a state you can sit in for
        // days without noticing, signing with a binary nobody checked. The
        // settings screen says so in passing; this says so wherever you are.
        BorderSurface {
          visible: root.sshAgentHelper.source === "development" && root.activeScreen !== "settings"
          width: parent.width
          implicitHeight: sshDevHelperText.implicitHeight + Style.space(12)
          color: Util.alpha(Color.urgent, 0.15)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

          Row {
            anchors.centerIn: parent
            width: parent.width - Style.space(16)
            spacing: Style.space(8)
            Text {
              textFormat: Text.PlainText
              text: "󰀪"
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              textFormat: Text.PlainText
              id: sshDevHelperText
              text: Model.sshAgentDevelopmentHelperWarning(root.sshAgentHelper)
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
              width: parent.width - Style.space(24)
            }
          }
        }

        // -------------------------------------------------------------------
        // SSH Signing Cooldown Banner
        // -------------------------------------------------------------------
        // A five-minute signing outage is not noticed on the SSH agent
        // settings screen: the requests it refuses arrive while the panel is
        // showing something else, or while the vault is locked and no prompt
        // can be raised at all. So the explanation lives on every screen,
        // and carries the only control that ends the cooldown early -- an
        // approval cannot, because there is no prompt left to approve.
        BorderSurface {
          visible: root.sshCooldownStatus.active
          width: parent.width
          implicitHeight: sshCooldownBannerBody.implicitHeight + Style.space(12)
          color: Util.alpha(Color.urgent, 0.15)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

          Row {
            anchors.centerIn: parent
            width: parent.width - Style.space(16)
            spacing: Style.space(8)
            Text {
              textFormat: Text.PlainText
              text: "󰀪"
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Column {
              id: sshCooldownBannerBody
              width: parent.width - Style.space(24)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                id: sshCooldownBannerText
                text: root.sshCooldownStatus.message
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.Wrap
                width: parent.width
              }

              Button {
                text: "Resume Signing Now"
                iconText: "󰐊"
                tooltipText: "End the cooldown; the next signing request asks again"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.resumeSshSigning()
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0f: BITWARDEN SEND
        // -------------------------------------------------------------------
        Flickable {
          id: sendFlick
          visible: root.activeScreen === "sends"
          width: parent.width
          height: Math.min(Style.space(520), sendCol.implicitHeight)
          contentWidth: width
          contentHeight: sendCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: sendFlick }

          Column {
            id: sendCol
            width: sendFlick.width - root.scrollGutter
            spacing: Style.space(10)

            PanelSeparator { width: parent.width }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.sendMode === "create" ? "Back to Sends" : "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: {
                  if (root.sendMode === "create") { root.sendError = ""; root.sendMode = "list" }
                  else root.currentScreen = "main"
                }
              }

              Button {
                visible: root.sendMode === "list"
                text: "New Send"
                iconText: "󰐕"
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.beginCreateSend()
              }

              Button {
                visible: root.sendMode === "list"
                text: "Refresh"
                iconText: "󰑐"
                iconSpinning: root.sendsLoading
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.loadSends()
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: root.sendError !== ""
              width: parent.width
              text: root.sendError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            // ---------------- list ----------------
            Column {
              visible: root.sendMode === "list"
              width: parent.width
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                visible: !root.sendsLoading && root.sends.length === 0
                width: parent.width
                text: "No Sends yet. A Send shares a secret through a link that expires on its own -- useful for handing someone a credential without it living in a chat log."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                visible: root.sendsLoading
                text: "Loading Sends..."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Repeater {
                model: root.sends

                delegate: BorderSurface {
                  required property var modelData
                  required property int index
                  width: parent.width
                  implicitHeight: sendRowCol.implicitHeight + Style.space(16)
                  radius: Style.cornerRadius
                  readonly property bool cursored: index === root.sendIndex
                  color: cursored ? Style.hoverFillFor(root.fg, Color.accent) : "transparent"
                  borderSpec: Border.surfaceSpec("menu", "border",
                    cursored ? Color.accent : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.18), 1)

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    onEntered: root.sendIndex = index
                  }

                  Row {
                    anchors.fill: parent
                    anchors.margins: Style.space(8)
                    spacing: Style.space(8)

                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: modelData.isFile ? "󰈤" : "󰈙"
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.subtitle
                    }

                    Column {
                      id: sendRowCol
                      width: parent.width - Style.space(110)
                      spacing: Style.space(2)

                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        text: modelData.name
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                        elide: Text.ElideRight
                      }

                      Row {
                        spacing: Style.space(6)

                        Text {
                          textFormat: Text.PlainText
                          text: Model.sendExpiryLabel(modelData, Date.now())
                          color: Model.sendExpiryLabel(modelData, Date.now()) === "expired" ? root.urgent : root.dim
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                        }
                        Text {
                          textFormat: Text.PlainText
                          text: "\u00b7 " + Model.sendAccessLabel(modelData)
                          color: root.dim
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                        }
                        Text {
                          textFormat: Text.PlainText
                          visible: modelData.passwordSet
                          text: "\u00b7 󰌾 password"
                          color: Color.accent
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                        }
                      }
                    }

                    PanelActionButton {
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰆏"
                      tooltipText: "Copy Send link"
                      fontFamily: root.fontFamily
                      onClicked: root.copySendLink(modelData)
                    }

                    PanelActionButton {
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰆴"
                      tooltipText: "Delete this Send"
                      fontFamily: root.fontFamily
                      enabled: !root.sendBusy
                      onClicked: root.deleteSend(modelData)
                    }
                  }
                }
              }
            }

            // ---------------- create ----------------
            Column {
              visible: root.sendMode === "create"
              width: parent.width
              spacing: Style.space(8)

              Text { textFormat: Text.PlainText; text: "NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: sendNameField
                width: parent.width
                placeholderText: "What is this? (optional)"
                text: root.sendFormName
                onTextChanged: root.sendFormName = text
                enabled: !root.sendBusy
              }

              Text { textFormat: Text.PlainText; text: "TEXT TO SEND"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "The secret to share..."
                text: root.sendFormText
                onTextChanged: root.sendFormText = text
                enabled: !root.sendBusy
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Hide text by default"
                  tooltipText: "The recipient must click to reveal it"
                  selected: root.sendFormHidden
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.sendFormHidden = !root.sendFormHidden
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Delete after"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: "days"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.sendFormDays
                  from: 1
                  to: 31
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.sendFormDays = v }
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Maximum views"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.sendFormMaxAccess === 0 ? "unlimited" : ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.sendFormMaxAccess
                  from: 0
                  to: 100
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.sendFormMaxAccess = v }
                }
              }

              Text { textFormat: Text.PlainText; text: "PASSWORD (OPTIONAL)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "Recipient must enter this to open the Send..."
                password: true
                text: root.sendFormPassword
                onTextChanged: root.sendFormPassword = text
                enabled: !root.sendBusy
              }

              Button {
                width: parent.width
                text: root.sendBusy ? "Creating..." : "Create Send & Copy Link"
                iconText: root.sendBusy ? "󰑐" : "󰒗"
                iconSpinning: root.sendBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.sendBusy
                onClicked: root.submitCreateSend()
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0e: FINGERPRINT SETUP
        // -------------------------------------------------------------------
        Flickable {
          id: fpFlick
          visible: root.activeScreen === "fingerprint"
          width: parent.width
          height: Math.min(Style.space(520), fpCol.implicitHeight)
          contentWidth: width
          contentHeight: fpCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: fpFlick }

          Column {
            id: fpCol
            width: fpFlick.width - root.scrollGutter
            spacing: Style.space(12)

            PanelSeparator { width: parent.width }

            Column {
              width: parent.width
              spacing: Style.space(4)

              Text {
                textFormat: Text.PlainText
                text: "Enable fingerprint unlock"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "A fingerprint proves you are present but cannot produce your master password, and bw unlock accepts nothing else. The password is stored in the OS login keyring, and a verified fingerprint is the gate on reading it back."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Anyone who can read your unlocked login keyring can read the password. A PIN stores it encrypted instead."
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(8)

              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

              TextField {
                id: fpMasterField
                width: parent.width
                placeholderText: "Needed once, to store for fingerprint unlock..."
                password: true
                text: root.fpSetupMaster
                onTextChanged: root.fpSetupMaster = text
                onAccepted: root.submitFingerprintSetup()
                enabled: !root.fpBusy
              }

              Text {
                textFormat: Text.PlainText
                visible: root.fpError !== ""
                width: parent.width
                text: root.fpError
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Row {
                width: parent.width
                spacing: Style.space(8)

                Button {
                  text: root.fpBusy ? "Saving..." : "Enable"
                  iconText: root.fpBusy ? "󰑐" : "󰈷"
                  iconSpinning: root.fpBusy
                  selected: true
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  enabled: !root.fpBusy
                  onClicked: root.submitFingerprintSetup()
                }

                Button {
                  text: "Cancel"
                  iconText: "󰅖"
                  fontFamily: root.fontFamily
                  enabled: !root.fpBusy
                  onClicked: { root.fpError = ""; root.currentScreen = "settings" }
                }
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0c: PIN SETUP
        // -------------------------------------------------------------------
        // -------------------------------------------------------------------
        // SCREEN 0d: GENERATOR
        // -------------------------------------------------------------------
        Flickable {
          id: genFlick
          visible: root.activeScreen === "generator"
          width: parent.width
          height: Math.min(Style.space(520), genCol.implicitHeight)
          contentWidth: width
          contentHeight: genCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: genFlick }

          Column {
            id: genCol
            width: genFlick.width - root.scrollGutter
            spacing: Style.space(10)

            PanelSeparator { width: parent.width }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.generatorFeedsForm ? "Back to item (Esc)" : "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.closeGenerator()
              }

              // Only when the generator was opened from the item form: hand
              // the value back to the password field and return there.
              Button {
                visible: root.generatorFeedsForm
                text: "Use this password (Enter)"
                iconText: "󰄬"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                selected: true
                accent: Color.accent
                enabled: !root.genBusy && root.genValue !== ""
                onClicked: root.useGeneratedPassword()
              }
            }

            // Generated value
            BorderSurface {
              width: parent.width
              implicitHeight: Style.space(58)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.fg, Color.accent)
              borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

              Row {
                anchors.fill: parent
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(6)
                spacing: Style.space(4)

                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(90)
                  text: root.genBusy ? "Generating..." : (root.genValue || "-")
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  wrapMode: Text.WrapAnywhere
                  maximumLineCount: 2
                  elide: Text.ElideRight
                }

                PanelActionButton {
                  anchors.verticalCenter: parent.verticalCenter
                  iconText: "󰑐"
                  tooltipText: "Regenerate"
                  fontFamily: root.fontFamily
                  enabled: !root.genBusy
                  onClicked: root.regenerate()
                }

                PanelActionButton {
                  anchors.verticalCenter: parent.verticalCenter
                  iconText: "󰆏"
                  tooltipText: "Copy"
                  fontFamily: root.fontFamily
                  enabled: !root.genBusy && root.genValue !== ""
                  onClicked: root.copyGenerated()
                }
              }
            }

            // Strength meter
            Column {
              width: parent.width
              spacing: Style.space(3)

              readonly property var strength: Model.generatorStrength(root.genOpts)

              Row {
                width: parent.width
                Text {
                  textFormat: Text.PlainText
                  text: parent.parent.strength.label
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                Item { width: Style.space(6); height: 1 }
                Text {
                  textFormat: Text.PlainText
                  text: "~" + parent.parent.strength.bits + " bits of entropy"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }

              Rectangle {
                width: parent.width
                height: Style.space(4)
                radius: height / 2
                color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.15)

                Rectangle {
                  width: parent.width * parent.parent.strength.fraction
                  height: parent.height
                  radius: height / 2
                  color: Color.accent
                }
              }
            }

            PanelSeparator { width: parent.width }

            // Type
            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Password"
                iconText: "󰌆"
                selected: root.genOpts.type === "password"
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.setGenOpt("type", "password")
              }

              Button {
                text: "Passphrase"
                iconText: "󰈚"
                selected: root.genOpts.type === "passphrase"
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.setGenOpt("type", "passphrase")
              }
            }

            // ---- Password options ----
            Column {
              visible: root.genOpts.type === "password"
              width: parent.width
              spacing: Style.space(8)

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Length"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.length
                  from: 5
                  to: 128
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("length", v) }
                }
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "A-Z"
                  selected: root.genOpts.uppercase
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("uppercase", !root.genOpts.uppercase)
                }
                Button {
                  text: "a-z"
                  selected: root.genOpts.lowercase
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("lowercase", !root.genOpts.lowercase)
                }
                Button {
                  text: "0-9"
                  selected: root.genOpts.numbers
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("numbers", !root.genOpts.numbers)
                }
                Button {
                  text: "!@#$%^&*"
                  selected: root.genOpts.special
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("special", !root.genOpts.special)
                }
                Button {
                  text: "Avoid ambiguous"
                  tooltipText: "Exclude characters that are easy to confuse, such as l, 1, I, O and 0"
                  selected: root.genOpts.ambiguous
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("ambiguous", !root.genOpts.ambiguous)
                }
              }

              Row {
                visible: root.genOpts.numbers
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Minimum numbers"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.minNumber
                  from: 0
                  to: 9
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("minNumber", v) }
                }
              }

              Row {
                visible: root.genOpts.special
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Minimum special"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.minSpecial
                  from: 0
                  to: 9
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("minSpecial", v) }
                }
              }
            }

            // ---- Passphrase options ----
            Column {
              visible: root.genOpts.type === "passphrase"
              width: parent.width
              spacing: Style.space(8)

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Number of words"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.words
                  from: 3
                  to: 20
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("words", v) }
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Word separator"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                TextField {
                  anchors.verticalCenter: parent.verticalCenter
                  width: Style.space(90)
                  text: root.genOpts.separator
                  onTextChanged: if (text && text !== root.genOpts.separator) root.setGenOpt("separator", text.charAt(0))
                }
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Capitalize"
                  selected: root.genOpts.capitalize
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("capitalize", !root.genOpts.capitalize)
                }
                Button {
                  text: "Include number"
                  selected: root.genOpts.includeNumber
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("includeNumber", !root.genOpts.includeNumber)
                }
              }
            }
          }
        }

        // Scrolls rather than overflowing the panel: this screen is taller
        // than the popup's height cap on smaller displays.
        Flickable {
          id: pinFlick
          visible: root.activeScreen === "pin"
          width: parent.width
          height: Math.min(Style.space(520), pinCol.implicitHeight)
          contentWidth: width
          contentHeight: pinCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: pinFlick }

          Column {
            id: pinCol
            width: pinFlick.width - root.scrollGutter
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Text {
              textFormat: Text.PlainText
              text: "Set an unlock PIN"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: "Your master password is encrypted with a key derived from this PIN, and only the encrypted form is stored. "
                + "Use " + Model.pinRecommendedLength() + " digits or more; " + Model.pinMinLength()
                + " is the floor, and every extra digit multiplies an attacker's work by ten."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Column {
            width: parent.width
            spacing: Style.space(8)

            Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
            TextField {
              width: parent.width
              placeholderText: "Needed once, to encrypt the PIN..."
              password: true
              text: root.pinSetupMaster
              onTextChanged: root.pinSetupMaster = text
              enabled: !root.pinBusy
            }

            Text {
              textFormat: Text.PlainText
              text: "PIN"
              // The label turns with the field, so the warning is visible even
              // when the cursor has moved on to Confirm.
              color: root.pinSetupWeak ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }
            TextField {
              id: pinSetupPinField
              width: parent.width
              placeholderText: Model.pinRecommendedLength() + " digits or more..."
              password: true
              text: root.pinSetupPin
              onTextChanged: root.pinSetupPin = text.replace(/[^0-9]/g, "")
              enabled: !root.pinBusy
              // A short PIN is allowed but not waved through: the border goes
              // red rather than accent while it is under the recommendation.
              accent: root.pinSetupWeak ? root.urgent : Color.accent
              foreground: root.pinSetupWeak ? root.urgent : root.fg
            }

            Text {
              textFormat: Text.PlainText
              visible: root.pinSetupWeak
              width: parent.width
              text: "󰀪  " + Model.pinWeakWarning(root.pinSetupPin)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Text { textFormat: Text.PlainText; text: "CONFIRM PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
            TextField {
              width: parent.width
              placeholderText: "Repeat the PIN..."
              password: true
              text: root.pinSetupConfirm
              onTextChanged: root.pinSetupConfirm = text.replace(/[^0-9]/g, "")
              onAccepted: root.submitPinSetup()
              enabled: !root.pinBusy
            }

            Text {
              textFormat: Text.PlainText
              visible: root.pinError !== ""
              width: parent.width
              text: root.pinError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.pinBusy ? "Encrypting..." : "Save PIN"
                iconText: root.pinBusy ? "󰑐" : "󰄬"
                iconSpinning: root.pinBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.pinBusy
                onClicked: root.submitPinSetup()
              }

              Button {
                text: "Cancel"
                iconText: "󰅖"
                fontFamily: root.fontFamily
                enabled: !root.pinBusy
                onClicked: { root.pinError = ""; root.currentScreen = "settings" }
              }
            }
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 0a: SETUP WIZARD (missing dependencies)
        // -------------------------------------------------------------------
        // Scrolls rather than overflowing the panel: this screen is taller
        // than the popup's height cap on smaller displays.
        Flickable {
          id: setupFlick
          visible: root.activeScreen === "setup"
          width: parent.width
          height: Math.min(Style.space(520), setupCol.implicitHeight)
          contentWidth: width
          contentHeight: setupCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: setupFlick }

          Column {
            id: setupCol
            width: setupFlick.width - root.scrollGutter
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Text {
              textFormat: Text.PlainText
              text: root.missingRequired.length > 0 ? "One more step" : "All set"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.missingRequired.length > 0
                ? "The plugin drives these tools rather than bundling them. Install the required ones below and the panel picks them up on its own -- no terminal work to come back from."
                : "Every required tool is installed. Optional ones below unlock extra features."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Repeater {
            // Only rows this machine can act on. A desktop with no fingerprint
            // reader is not missing a dependency.
            model: Model.applicableDependencies(root.dependencies)

            delegate: BorderSurface {
              required property var modelData
              width: parent.width
              implicitHeight: depRow.implicitHeight + Style.space(16)
              radius: Style.cornerRadius
              color: modelData.ready ? "transparent" : Util.alpha(root.urgent, 0.12)
              borderSpec: Border.surfaceSpec("menu", "border",
                modelData.ready ? Color.accent : root.urgent, 1)

              Row {
                id: depRow
                anchors.fill: parent
                anchors.margins: Style.space(8)
                spacing: Style.space(10)

                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData.ready ? "󰄬" : (modelData.required ? "󰅖" : "󰋗")
                  color: modelData.ready ? Color.accent : (modelData.required ? root.urgent : root.dim)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.subtitle
                }

                Column {
                  width: parent.width - Style.space(170)
                  spacing: Style.space(2)

                  Row {
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: modelData.label
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: modelData.required ? "required" : "optional"
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: modelData.purpose
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }

                  Text {
                    textFormat: Text.PlainText
                    visible: !!modelData.note
                    width: parent.width
                    text: modelData.note
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }

                  // The package being on PATH is not the finish line for a
                  // setup row: fingerprint unlock also wants an enrolled
                  // finger and the PAM stack, and only the setup command
                  // produces those.
                  Text {
                    textFormat: Text.PlainText
                    visible: modelData.setup && modelData.installed && !modelData.ready
                    width: parent.width
                    text: "Reader stack is installed, but no finger is enrolled yet."
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }

                // One button per row, whichever door this row goes through.
                Button {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: modelData.setup ? !modelData.ready : !modelData.installed
                  text: modelData.setup ? "Set up" : "Install"
                  iconText: modelData.setup ? "󰈷" : "󰐕"
                  tooltipText: modelData.setup
                    ? "omarchy setup security fingerprint"
                    : "omarchy install app " + modelData.pkg
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.installOne(modelData)
                }
              }
            }
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Re-check"
              iconText: "󰑐"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.checkDependencies()
            }

            // The one button a first run needs. It covers the optional tools
            // too, so a single trip through the terminal leaves every feature
            // working rather than only the ones that block startup.
            Button {
              visible: root.installablePackages.length > 0
              text: root.installablePackages.length > 1 ? "Install all missing" : "Install"
              iconText: "󰐕"
              selected: true
              accent: Color.accent
              tooltipText: "omarchy install app " + root.installablePackages.join(" ")
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.installMissing()
            }

            Button {
              text: root.missingRequired.length > 0 ? "Continue anyway" : "Done"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.dismissSetup()
            }
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 0b: SETTINGS
        // -------------------------------------------------------------------
        // Scrolls rather than overflowing the panel: this screen is taller
        // than the popup's height cap on smaller displays.
        Column {
          id: settingsScreen
          visible: root.activeScreen === "settings"
          width: parent.width
          spacing: Style.space(10)

          PanelSeparator { width: parent.width }

          // Pinned above the scroll area rather than scrolling with it. The
          // right half is the way out, which should never require scrolling to
          // find. The left half is the section the view is currently inside,
          // and it folds that section -- so a user twenty rows into Security
          // can shut it without first scrolling back to its heading.
          Item {
            width: parent.width
            height: Style.space(26)

            // An indicator, not a control. It says which section the view is
            // inside; the heading it stands for is a plain heading too.
            Row {
              id: stickySection
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(6)
              visible: root.settingsStickyEntry !== null

              PanelSectionHeader {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.settingsStickyEntry
                  ? String(root.settingsStickyEntry.label || "").toUpperCase() : ""
                foreground: root.fg
                fontFamily: root.fontFamily
              }
            }

            Row {
              anchors.right: parent.right
              // Flush with the scrolling rows below, which stop short of the
              // scrollbar. Without this the Back button overhangs every
              // control it sits above.
              anchors.rightMargin: root.scrollGutter
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                visible: root.settingsFlash !== ""
                text: "󰄬 " + root.settingsFlash
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Button {
                text: "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.closeSettings()
              }
            }
          }


          Flickable {
            id: settingsFlick
            width: parent.width
            height: Math.min(Style.space(520), settingsCol.implicitHeight)
            contentWidth: width
            contentHeight: settingsCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            ScrollBar.vertical: ScrollBar {
              id: settingsScrollBar
              policy: ScrollBar.AsNeeded
            }

            WheelScroll { view: settingsFlick }

            // The pinned bar names the section the view is inside, so it has to
            // be recomputed as the view moves and whenever the content resizes.
            // The height case runs a frame later, after layout.
            onContentYChanged: root.updateSettingsSticky()
            onContentHeightChanged: Qt.callLater(root.updateSettingsSticky)

            Column {
              id: settingsCol
              // Short of the scrollbar rather than under it. The bar is an
              // overlay, so without this it sits on top of whatever is at the
              // right edge -- which on this screen is every toggle and every
              // number field. Reserved unconditionally: the width would
              // otherwise change as the bar came and went, reflowing the rows
              // underneath it.
              width: settingsFlick.width - root.scrollGutter
            spacing: Style.space(10)

            Connections {
              target: root
              function onSettingsIndexChanged() {
                var row = settingsRepeater.itemAt(root.settingsIndex)
                if (!row) return
                if (row.y < settingsFlick.contentY) {
                  settingsFlick.contentY = Math.max(0, row.y - Style.space(8))
                } else if (row.y + row.height > settingsFlick.contentY + settingsFlick.height) {
                  settingsFlick.contentY = Math.min(
                    Math.max(0, settingsFlick.contentHeight - settingsFlick.height),
                    row.y + row.height - settingsFlick.height + Style.space(8))
                }
              }
            }

            Repeater {
              id: settingsRepeater
              model: root.settingsEntries

              delegate: Column {
                required property var modelData
                required property int index
                width: parent.width
                spacing: Style.space(4)
                readonly property bool cursored: index === root.settingsIndex

                readonly property bool isGroup: modelData.kind === "group"

              // This heading is the one the pinned bar is currently drawing.
              // The bar stands in for it completely, so the row gives up its
              // space rather than sitting there empty -- a transparent row
              // left a heading-sized hole directly under the bar.
              //
              // Exactly one heading is ever in this state, so the content
              // height does not change as the pinned section changes: the
              // heading taking over collapses at the same moment the previous
              // one is restored, and the view does not jump.
              readonly property bool yieldsToBar: isGroup
                && Boolean(root.settingsStickyEntry)
                && root.settingsStickyEntry.group === modelData.group

                // Breathing room above each heading, except the first.
                Item {
                  visible: isGroup && index > 0 && !yieldsToBar
                  width: parent.width
                  height: visible ? Style.space(18) : 0
                }

                // A group heading is a row of its own rather than a label on
                // the first setting under it: the pinned indicator reads
                // delegate geometry to tell which section the view is inside,
                // and a heading carried by another row has no position of its
                // own to be found at.
                Item {
                  visible: isGroup && !yieldsToBar
                  width: parent.width
                  height: visible ? Style.space(22) : 0

                  PanelSectionHeader {
                    textFormat: Text.PlainText
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    text: String(modelData.label || "").toUpperCase()
                    foreground: root.fg
                    fontFamily: root.fontFamily
                  }
                }

                // A setting whose dependency is missing is shown but inert, with
                // the reason stated rather than the control silently doing nothing.
                readonly property bool blocked: !isGroup && root.settingBlocked(modelData)

                Item {
                  visible: !isGroup
                  width: parent.width
                  implicitHeight: visible
                    ? Math.max(settingTextCol.implicitHeight, settingControlRow.implicitHeight, Style.space(32))
                    : 0

                  // Keyboard cursor: a bar in the gutter, so the row it marks is
                  // unmistakable without recolouring the whole row.
                  Rectangle {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    width: Style.space(3)
                    height: parent.height - Style.space(6)
                    radius: width / 2
                    color: Color.accent
                    visible: cursored
                  }

                  Column {
                    id: settingTextCol
                    anchors.left: parent.left
                    anchors.leftMargin: cursored ? Style.space(10) : 0
                    anchors.right: settingControlRow.left
                    anchors.rightMargin: Style.space(12)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(2)

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: modelData.label
                      color: blocked ? root.dim : root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                    }

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      // `|| ""` because this binding also runs for the heading
                      // rows, which carry no description: an invisible item's
                      // bindings are evaluated all the same, and undefined
                      // reaches a QString property as a warning per frame.
                      text: blocked
                        ? "Needs fingerprint setup -- see Dependencies below."
                        : (modelData.description || "")
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                    }
                  }

                  Row {
                    id: settingControlRow
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(8)

                    ToggleSwitch {
                      anchors.verticalCenter: parent.verticalCenter
                      visible: modelData.type === "bool"
                      checked: modelData.type === "bool" && root.settingValue(modelData)
                      interactive: !blocked
                      foreground: root.fg
                      accent: Color.accent
                      onToggled: {
                        if (blocked) return
                        // A PIN cannot simply be switched on: it has to be chosen,
                        // and encrypting it needs the master password.
                        if (modelData.action === "pin") {
                          if (checked) root.disablePinUnlock()
                          else root.beginPinSetup()
                          return
                        }
                        if (modelData.action === "fingerprint") {
                          if (checked) root.forgetFingerprintUnlock()
                          else root.beginFingerprintSetup()
                          return
                        }
                        root.writeSetting(modelData.key, !checked, "bool")
                      }
                    }

                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      visible: modelData.type === "int" && !!modelData.unit
                      text: modelData.unit || ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }

                    NumberField {
                      anchors.verticalCenter: parent.verticalCenter
                      visible: modelData.type === "int"
                      value: modelData.type === "int" ? root.settingValue(modelData) : 0
                      from: modelData.min || 0
                      to: modelData.max || 100
                      stepSize: modelData.step || 1
                      foreground: root.fg
                      accent: Color.accent
                      fontFamily: root.fontFamily
                      onModified: function(v) { root.writeSetting(modelData.key, v, "int") }
                    }
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: modelData.type === "int" && root.settingValue(modelData) === 0 && !!modelData.zeroLabel
                  text: (modelData.zeroLabel || "") + " -- this is disabled."
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                PanelSeparator { width: parent.width }

                // The SSH agent has more to say than its four toggles: what the
                // helper is doing, and whether the user's terminals will reach
                // it. That block used to sit after all four groups, which was
                // survivable while nothing folded -- now it would leave a
                // collapsed SSH Agent section with its status still on screen,
                // attached to nothing. It loads at the end of the group it
                // belongs to, so folding the section folds the whole section.
                //
                // A Loader rather than a visible binding: this delegate is
                // instantiated for every row, and only one of them wants it.
                Loader {
                  width: parent.width
                  active: !isGroup && modelData.group === "sshAgent"
                    && modelData.lastInGroup === true
                  visible: active
                  sourceComponent: SshAgentSettings { panel: root }
                }
              }
            }

            Item { width: parent.width; height: Style.space(18) }

            PanelSectionHeader {
              textFormat: Text.PlainText
              text: "MAINTENANCE"
              foreground: root.fg
              fontFamily: root.fontFamily
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Dependencies"
                iconText: "󰏗"
                tooltipText: "Check the tools this plugin needs"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: {
                  root.setupDismissed = false
                  root.checkDependencies()
                  root.currentScreen = "setup"
                }
              }

              Button {
                visible: root.fingerprintStored
                text: "Forget Fingerprint"
                iconText: "󰈷"
                tooltipText: "Remove the stored master password from the OS keyring"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.forgetFingerprintUnlock()
              }
            }

            // Everything below this line destroys something. It was drawn in a
            // row visually identical to the one above it, so "Dependencies" and
            // "Remove Plugin Data" looked equally safe to press.
            Item { width: parent.width; height: Style.space(18) }

            PanelSeparator { width: parent.width }

            PanelSectionHeader {
              textFormat: Text.PlainText
              text: "DANGER ZONE"
              foreground: Color.urgent
              fontFamily: root.fontFamily
            }

            // Its own row: this sits beside two buttons already, and a third
            // one plus the two the confirmation adds overflow the panel width
            // and elide their labels -- "Remove Plugin Data" reading as
            // "Remove Plugin" is a considerably more alarming button.
            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                visible: !root.pluginDataConfirmPending
                text: "Remove Plugin Data"
                iconText: "󰩹"
                tooltipText: "Clear the keyring entries, learned suggestions and exported public keys this plugin stored"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                enabled: !root.pluginDataBusy
                onClicked: root.beginPluginDataRemoval()
              }

              Button {
                visible: root.pluginDataConfirmPending
                text: "Remove Everything"
                iconText: "󰩹"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                enabled: !root.pluginDataBusy
                onClicked: root.beginPluginDataRemoval()
              }

              Button {
                visible: root.pluginDataConfirmPending
                text: "Cancel"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.cancelPluginDataRemoval()
              }
            }

            // Run this before removing the plugin: once the folder is gone
            // there is no code left to do it, and `omarchy plugin remove` has
            // no uninstall hook to call.
            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.pluginDataConfirmPending
              text: "This clears the stored master password, learned suggestions and exported public keys. "
                + "Settings and your vault are untouched. It cannot be undone."
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.pluginDataFlash !== ""
              text: root.pluginDataFlash
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: "Saved to the plugin's entry in ~/.config/omarchy/shell.json via `omarchy bar set`."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
                    }
          }
        }

        // An SSH request waiting on an unlock. Shown above whatever unlock
        // control the vault is configured for, so the reason for the prompt
        // is visible without the unlock itself authorising anything.
        Column {
          // Stays up through the load as well as the unlock: the request is
          // held across the vault read, so dropping the block the moment the
          // vault unlocks would leave the user watching nothing for seconds.
          visible: !root.sshAgentApprovalPopup && root.sshUnlockRequest !== null
            && (root.status === "locked" || root.sshAgentLoadActive)
          width: parent.width
          spacing: Style.space(6)

          PanelSeparator { width: parent.width }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: "󰌆  An SSH key is needed"
            color: Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          SshCaption {
            text: !root.sshUnlockRequest
              ? ""
              : (root.sshUnlockRequest.keyName !== ""
                  ? root.sshUnlockRequest.keyName + " · requested by "
                    + root.sshUnlockRequest.processName
                  // An identity listing names no key: the client is asking
                  // which keys exist, and until the vault is open there is no
                  // answer to give.
                  : root.sshUnlockRequest.processName
                    + " is asking which SSH keys are available")
            color: root.fg
          }

          SshCaption {
            text: root.sshAgentLoadActive
              ? Model.sshAgentLoadingNote()
              : "Unlocking loads your keys. You will still be asked before anything is signed."
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              visible: !root.sshAgentLoadActive
              text: "Not now (Esc)"
              iconText: "󰅘"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.denySshRequest()
            }

            Text {
              textFormat: Text.PlainText
              anchors.verticalCenter: parent.verticalCenter
              text: root.sshPromptRemainingSec + "s left"
              color: root.sshPromptRemainingSec <= 5 ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }

        // SCREEN: SSH signing approval, in SshApprovalScreen.qml.
        SshApprovalScreen {
          panel: root
          active: !root.sshAgentApprovalPopup && root.activeScreen === "sshApproval"
        }

        // -------------------------------------------------------------------
        // SCREEN 1: LOGIN VIEW (When unauthenticated)
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unauthenticated" && root.activeScreen !== "settings" && root.activeScreen !== "setup" && root.activeScreen !== "pin" && root.activeScreen !== "fingerprint"
          width: parent.width
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: "Email & Password"
              iconText: "󰇮"
              selected: root.loginMethod === "email"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: {
                root.invalidateEmailLoginPrewarm()
                root.resetEmailLoginSecondFactor()
                root.loginMethod = "email"
              }
            }

            Button {
              text: "API Key"
              iconText: "󰌋"
              selected: root.loginMethod === "apikey"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: {
                root.invalidateEmailLoginPrewarm()
                root.resetEmailLoginSecondFactor()
                root.loginMethod = "apikey"
              }
            }
          }

          Column {
            visible: root.loginMethod !== "email" || root.loginCredentialsStage
            width: parent.width
            spacing: Style.space(5)

            Text {
              textFormat: Text.PlainText
              text: "SERVER REGION"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Row {
              anchors.horizontalCenter: parent.horizontalCenter
              spacing: Style.space(6)

              Button {
                text: "US"
                selected: root.loginServerRegion === "us"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.selectLoginServerRegion("us")
              }

              Button {
                text: "EU"
                selected: root.loginServerRegion === "eu"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.selectLoginServerRegion("eu")
              }

              Button {
                text: "Custom"
                selected: root.loginServerRegion === "custom"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.selectLoginServerRegion("custom")
              }
            }

            TextField {
              id: serverUrlField
              visible: root.loginServerRegion === "custom"
              width: parent.width
              placeholderText: "https://vault.example.com"
              text: root.loginServerUrl
              onTextChanged: root.loginServerUrl = text
              onTextEdited: {
                root.loginServerUrl = text
                root.resetEmailLoginSecondFactor()
                root.invalidateEmailLoginPrewarm()
              }
            }
          }

          // METHOD A: Email & Password
          Column {
            visible: root.loginMethod === "email"
            width: parent.width
            spacing: Style.space(10)

            Column {
              visible: root.loginCredentialsStage
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "EMAIL ADDRESS"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: emailField
                width: parent.width
                placeholderText: "you@example.com"
                text: root.loginEmail
                onTextChanged: root.loginEmail = text
                onTextEdited: {
                  root.loginEmail = text
                  root.resetEmailLoginSecondFactor()
                  root.invalidateEmailLoginPrewarm()
                }
                onAccepted: loginPassField.forceActiveFocus()
              }
            }

            Column {
              visible: root.loginCredentialsStage
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              Row {
                width: parent.width
                spacing: Style.space(6)
                TextField {
                  id: loginPassField
                  width: parent.width - eyeBtnLogin.width - Style.space(6)
                  placeholderText: "Master password..."
                  password: !eyeBtnLogin.revealed
                  text: root.loginPassword
                  onTextChanged: root.loginPassword = text
                  onTextEdited: {
                    root.loginPassword = text
                    if (root.show2faField) {
                      root.resetEmailLoginSecondFactor()
                      root.invalidateEmailLoginPrewarm()
                    }
                  }
                  onActiveFocusChanged: {
                    if (activeFocus) root.prepareEmailLogin()
                  }
                  onAccepted: root.show2faField ? code2faField.forceActiveFocus() : root.submitLogin()
                }
                Button {
                  id: eyeBtnLogin
                  property bool revealed: false
                  iconText: revealed ? "󰈉" : "󰈈"
                  tooltipText: revealed ? "Hide password" : "Show password"
                  fontFamily: root.fontFamily
                  onClicked: revealed = !revealed
                }
              }
            }

            // New-device verification. bw takes this code from a prompt and
            // from nothing else, so answering it here is the difference
            // between finishing the login in the panel and sending the user to
            // a terminal to do it. See deviceVerificationLoginCommand().
            Column {
              visible: root.showDeviceCodeField
              width: parent.width
              spacing: Style.space(3)

              Text {
                textFormat: Text.PlainText
                text: "NEW DEVICE VERIFICATION"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Bitwarden has not seen this machine before and emailed a code to "
                  + "your login address. This is asked once per device."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              TextField {
                id: deviceCodeField
                width: parent.width
                placeholderText: "Code from your email..."
                text: root.loginDeviceCode
                onTextChanged: root.loginDeviceCode = text
                onAccepted: root.submitDeviceVerification()
              }

              Button {
                width: parent.width
                text: root.isLoading ? "Verifying device..." : "Verify Device & Unlock"
                iconText: root.isLoading ? "󰑐" : "󰌋"
                iconSpinning: root.isLoading
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.isLoading
                onClicked: root.submitDeviceVerification()
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Back to credentials"
                  iconText: "󰁍"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: {
                    root.errorMessage = ""
                    root.resetEmailLoginSecondFactor()
                    root.invalidateEmailLoginPrewarm()
                    Qt.callLater(function() { loginPassField.forceActiveFocus() })
                  }
                }

                // Still here, because bw in a real terminal can answer
                // anything this path cannot.
                Button {
                  text: "Use Terminal Instead"
                  iconText: "󰞷"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.launchTerminalLogin()
                }
              }
            }

            // bw asks this question only when an account has more than one
            // method it can use, and only a terminal ever got to see it. The
            // pick is sent on its own, before any code is collected, so a
            // wrong one costs a round trip rather than a typed code.
            Column {
              visible: root.show2faMethodPicker
              width: parent.width
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                text: "TWO-STEP METHOD"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Which one do you use for this account? Bitwarden is asked for a code "
                  + "only after you choose, and the choice is remembered for next time."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              Repeater {
                model: Model.twoFactorMethods()

                Column {
                  width: parent.width
                  spacing: Style.space(2)

                  Button {
                    width: parent.width
                    text: modelData.label
                    iconText: "󰌋"
                    fontFamily: root.fontFamily
                    enabled: !root.isLoading
                    onClicked: root.chooseTwoFactorMethod(modelData.method)
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: modelData.hint
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }
              }

              Button {
                text: "Back to credentials"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: {
                  root.errorMessage = ""
                  root.resetEmailLoginSecondFactor()
                  root.invalidateEmailLoginPrewarm()
                  Qt.callLater(function() { loginPassField.forceActiveFocus() })
                }
              }
            }

            // Bitwarden tells us whether this account needs a second factor.
            Column {
              visible: root.show2faField
              width: parent.width
              spacing: Style.space(3)

              Text {
                textFormat: Text.PlainText
                text: root.login2faMethodLabel
                  ? "TWO-STEP CODE (" + root.login2faMethodLabel.toUpperCase() + ")"
                  : "TWO-STEP VERIFICATION CODE (2FA)"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              TextField {
                id: code2faField
                width: parent.width
                placeholderText: "6-digit Authenticator / Email verification code..."
                text: root.login2faCode
                onTextChanged: {
                  root.login2faCode = text
                  root.invalidateEmailLoginPrewarm()
                }
                onAccepted: root.submitLogin()
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Back to credentials"
                  iconText: "󰁍"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: {
                    root.errorMessage = ""
                    root.resetEmailLoginSecondFactor()
                    root.invalidateEmailLoginPrewarm()
                    Qt.callLater(function() { loginPassField.forceActiveFocus() })
                  }
                }

                // The escape hatch from a remembered method. It is the only
                // way back to the question once an account has answered it, so
                // it stays available even when nothing has gone wrong yet.
                Button {
                  text: "Change method"
                  iconText: "󰑐"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: {
                    root.invalidateEmailLoginPrewarm()
                    root.reopenTwoFactorMethodPicker()
                  }
                }
              }
            }

            Button {
              // The picker stage submits by choosing, and the device stage has
              // its own button, so this one belongs to the stages that share
              // the ordinary login command.
              visible: !root.show2faMethodPicker && !root.showDeviceCodeField
              width: parent.width
              text: root.emailLoginButtonText()
              iconText: root.logoutCleanupFailed ? "󰑐" : ((root.logoutPending || root.isLoading) ? "󰑐" : "󰌋")
              iconSpinning: !root.logoutCleanupFailed && (root.logoutPending || root.isLoading)
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: root.logoutCleanupFailed || (!root.logoutPending && !root.isLoading)
              onClicked: root.logoutCleanupFailed ? root.retryLogoutCleanup() : root.submitLogin()
            }
          }

          // METHOD B: API Key
          Column {
            visible: root.loginMethod === "apikey"
            width: parent.width
            spacing: Style.space(10)

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "CLIENT ID"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: apiClientIdField
                width: parent.width
                placeholderText: "user.xxxxxxxx-xxxx-xxxx..."
                text: root.loginClientId
                onTextChanged: root.loginClientId = text
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "CLIENT SECRET"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: apiClientSecretField
                width: parent.width
                placeholderText: "Client secret string..."
                password: true
                text: root.loginClientSecret
                onTextChanged: root.loginClientSecret = text
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: apiMasterField
                width: parent.width
                placeholderText: "Master password to unlock vault..."
                password: true
                text: root.loginPassword
                onTextChanged: root.loginPassword = text
                onAccepted: root.submitLogin()
              }
            }

            Button {
              width: parent.width
              text: root.logoutCleanupFailed ? "Retry Logout Cleanup" : (root.logoutPending ? "Finishing logout..." : (root.isLoading ? "Logging in..." : "Log In with API Key"))
              iconText: root.logoutCleanupFailed ? "󰑐" : ((root.logoutPending || root.isLoading) ? "󰑐" : "󰌋")
              iconSpinning: !root.logoutCleanupFailed && (root.logoutPending || root.isLoading)
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: root.logoutCleanupFailed || (!root.logoutPending && !root.isLoading)
              onClicked: root.logoutCleanupFailed ? root.retryLogoutCleanup() : root.submitLogin()
            }
          }

          // Normally the quieter of the two ways in. When Bitwarden has asked
          // to verify this device it is the only one, so it stops being an
          // aside and says what it is for.
          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)
            Text {
              textFormat: Text.PlainText
              text: root.loginDeviceVerification
                ? "Device verification needs a terminal:"
                : "Prefer interactive TTY login?"
              color: root.loginDeviceVerification ? Color.accent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: root.loginDeviceVerification
              anchors.verticalCenter: parent.verticalCenter
            }
            Button {
              text: root.loginDeviceVerification ? "Finish in Terminal" : "Launch Terminal"
              iconText: "󰞷"
              selected: root.loginDeviceVerification
              accent: Color.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.launchTerminalLogin()
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 2: LOCKED VIEW (When authenticated, but vault locked)
        // -------------------------------------------------------------------
        Column {
          visible: (root.status === "locked" || root.status === "checking")
            && root.currentScreen !== "settings" && root.currentScreen !== "setup" && root.currentScreen !== "pin" && root.currentScreen !== "fingerprint"
          width: parent.width
          spacing: Style.space(14)

          PanelSeparator { width: parent.width }

          Item { height: Style.space(8); width: 1 }

          Column {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)

            Text {
              textFormat: Text.PlainText
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.fingerprintScanning ? "󰈷" : "󰌋"
              color: root.fingerprintScanning ? Color.accent : root.fg
              opacity: 0.85
              font.family: root.fontFamily
              font.pixelSize: Style.space(38)

              SequentialAnimation on opacity {
                running: root.fingerprintScanning
                loops: Animation.Infinite
                NumberAnimation { to: 0.35; duration: 700; easing.type: Easing.InOutQuad }
                NumberAnimation { to: 0.95; duration: 700; easing.type: Easing.InOutQuad }
                onStopped: parent.opacity = 0.85
              }
            }

            Text {
              textFormat: Text.PlainText
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.fingerprintReady ? "Unlock Vault" : "Enter Master Password"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              visible: root.userEmail !== ""
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.userEmail
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }
          }

          // Fingerprint status / prompt
          Text {
            textFormat: Text.PlainText
            visible: root.fingerprintMessage !== ""
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: root.fingerprintMessage
            color: root.fingerprintScanning ? Color.accent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // Offered when fingerprint unlock is on but nothing is stored yet.
          Text {
            textFormat: Text.PlainText
            visible: root.fingerprintUnlock && root.fingerprintAvailable && !root.fingerprintStored
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: "󰈷  Unlock once with your master password to enable fingerprint unlock."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          // PIN entry, offered above the password field when one is set.
          Column {
            visible: root.pinReady
            width: parent.width
            spacing: Style.space(8)

            Text { textFormat: Text.PlainText; text: "PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

            Row {
              width: parent.width
              spacing: Style.space(8)

              TextField {
                id: pinField
                width: parent.width - pinUnlockBtn.width - Style.space(8)
                placeholderText: "Enter your PIN..."
                password: true
                text: root.pinEntry
                onTextChanged: root.pinEntry = text.replace(/[^0-9]/g, "")
                onAccepted: root.submitPinUnlock()
                enabled: !root.pinBusy && !root.isUnlocking
              }

              Button {
                id: pinUnlockBtn
                text: root.pinBusy ? "Checking..." : "Unlock"
                iconText: root.pinBusy ? "󰑐" : "󰌿"
                iconSpinning: root.pinBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.pinBusy && !root.isUnlocking
                onClicked: root.submitPinUnlock()
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: root.pinError !== ""
              width: parent.width
              text: root.pinError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Text {
              textFormat: Text.PlainText
              text: "or use your master password below"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          // A PIN was set but the vault rejected it -- surfaced even once
          // pinReady has gone false, so the reason is not lost.
          Text {
            textFormat: Text.PlainText
            visible: !root.pinReady && root.pinError !== ""
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: root.pinError
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Column {
            width: parent.width
            spacing: Style.space(10)

            Button {
              visible: root.fingerprintReady
              width: parent.width
              text: root.fingerprintScanning ? "Waiting for fingerprint..." : "Unlock with Fingerprint"
              iconText: "󰈷"
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: !root.isUnlocking && !root.fingerprintScanning
              onClicked: root.startFingerprintUnlock()
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              TextField {
                id: passField
                width: parent.width - eyeBtnUnlock.width - Style.space(8)
                placeholderText: "Master password..."
                password: !eyeBtnUnlock.revealed
                text: root.masterPassword
                onTextChanged: root.masterPassword = text
                onActiveFocusChanged: {
                  if (activeFocus) root.prepareUnlock()
                }
                onAccepted: root.unlockVault()
                enabled: !root.isUnlocking
              }

              Button {
                id: eyeBtnUnlock
                property bool revealed: false
                iconText: revealed ? "󰈉" : "󰈈"
                tooltipText: revealed ? "Hide password" : "Show password"
                fontFamily: root.fontFamily
                onClicked: revealed = !revealed
              }
            }

            Button {
              width: parent.width
              text: root.isUnlocking ? "Unlocking..." : "Unlock Vault"
              iconText: root.isUnlocking ? "󰑐" : "󰌋"
              iconSpinning: root.isUnlocking
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: !root.isUnlocking
              onClicked: root.unlockVault()
            }
          }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: "Switch / Log Out"
              iconText: "󰍃"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.logoutAccount()
            }

            Button {
              visible: root.fingerprintStored
              text: "Forget Fingerprint"
              iconText: "󰈷"
              tooltipText: "Remove the stored master password from the OS keyring"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.forgetFingerprintUnlock()
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 3: UNLOCKED - ITEM LIST VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.activeScreen === "main"
          width: parent.width
          spacing: Style.space(8)

          // Search Field
          Row {
            width: parent.width
            spacing: Style.space(6)

            TextField {
              id: searchField
              width: parent.width - (root.searchQuery ? clearSearchBtn.width + Style.space(6) : 0)
              placeholderText: "Search items, usernames, URLs, public keys, fingerprints..."
              text: root.searchQuery
              onTextChanged: {
                root.searchQuery = text
                root.selectedIndex = 0
                root.closeFilterGroup()
                searchDebounceTimer.restart()
              }
              // Alt+letter runs the same shortcuts without leaving the box.
              Keys.onPressed: function(event) {
                if (!(event.modifiers & Qt.AltModifier)) return
                if (!event.text) return
                if (root.runAltShortcut(String(event.text).toLowerCase())) {
                  event.accepted = true
                }
              }
              Keys.onDownPressed: {
                keyCatcher.forceActiveFocus()
                root.moveCursor(1)
              }
              Keys.onReturnPressed: {
                var itm = root.getSelectedItem()
                if (itm) root.handleSmartEnter(itm)
              }
              // Only while the search box is the screen. A hidden item keeps
              // active focus in Qt, so without this guard the search field
              // still owned Escape from behind the item form and closed the
              // whole panel instead of cancelling the edit.
              Keys.onEscapePressed: function(event) {
                if (root.currentScreen !== "main") {
                  event.accepted = false   // let it reach the panel's dispatch
                  return
                }
                if (text) text = ""
                else root.handleEscape()
              }
            }

            PanelActionButton {
              id: clearSearchBtn
              visible: root.searchQuery !== ""
              iconText: "󰅖"
              tooltipText: "Clear search"
              fontFamily: root.fontFamily
              onClicked: searchField.text = ""
            }
          }

          // Contextual Suggestion Banner
          BorderSurface {
            visible: Boolean(root.suggestedItems.length > 0 && !root.suggestionsDismissed && root.searchQuery.trim() === "" && root.detectedContext && root.detectedContext.displayName)
            width: parent.width
            implicitHeight: Style.space(28)
            radius: Style.cornerRadius
            color: Style.selectedFillFor(root.fg, Color.accent)
            borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)

            // A RowLayout, so the label can be told to take whatever the glyph
            // and the dismiss button leave rather than a hand-measured slice of
            // the banner. The name in it is a window title, so its length is
            // not ours to predict.
            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(8)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                Layout.alignment: Qt.AlignVCenter
                text: "󰌠"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                Layout.alignment: Qt.AlignVCenter
                Layout.fillWidth: true
                text: "Suggested for " + (root.detectedContext ? root.detectedContext.displayName : "active window")
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideRight
              }

              PanelActionButton {
                Layout.alignment: Qt.AlignVCenter
                iconText: "󰅖"
                tooltipText: "Dismiss suggestion"
                fontFamily: root.fontFamily
                size: Style.space(18)
                fontSize: Style.font.caption
                onClicked: {
                  root.suggestionsDismissed = true
                  root.rebuildFilter()
                }
              }
            }
          }

          PanelSeparator { width: parent.width }

          // Item List View (Fast Virtualized ListView with Delegate Recycling)
          Item {
            width: parent.width
            height: Style.space(320)

            ListView {
              id: itemsListView
              anchors.fill: parent
              clip: true
              model: root.filteredItems
              spacing: Style.space(4)
              boundsBehavior: Flickable.StopAtBounds
              reuseItems: true
              currentIndex: root.selectedIndex
              ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

              WheelScroll { view: itemsListView }

              delegate: BorderSurface {
                id: itemRow
                required property var modelData
                required property int index

                readonly property var itemData: modelData
                readonly property bool isSelected: root.cursorActive && root.selectedIndex === index
                readonly property bool isHovered: rowMouseArea.containsMouse

                width: ListView.view.width - root.scrollGutter
                implicitHeight: Style.space(46)
                radius: Style.cornerRadius
                color: isSelected
                  ? Style.selectedFillFor(root.fg, Color.accent)
                  : (isHovered ? Style.hoverFillFor(root.fg, Color.accent) : "transparent")
                borderSpec: isSelected
                  ? Border.controlSpec("selected", root.fg, Color.accent)
                  : Border.none()

                Row {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(8)
                  spacing: Style.space(10)

                  // Type Icon, or a spinner while the vault is being told about
                  // this row. The glyph is the row's identity, so the saving
                  // state borrows it rather than adding a second marker and
                  // reflowing everything beside it.
                  Text {
                    textFormat: Text.PlainText
                    anchors.verticalCenter: parent.verticalCenter
                    text: itemData.pending ? "󰑐" : Model.itemTypeGlyph(itemData.typeCode)
                    color: itemData.pending
                      ? root.dim
                      : (itemData.favorite ? Color.accent : root.fg)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.title
                    width: Style.space(20)
                    // The glyph is narrower than the column it sits in, so
                    // without centring it the spin happens about the middle of
                    // the box and the icon orbits that point instead of
                    // turning on its own axis. Same shape the kit's own
                    // spinning button icon uses.
                    horizontalAlignment: Text.AlignHCenter
                    transformOrigin: Item.Center

                    RotationAnimation on rotation {
                      running: Boolean(itemData.pending)
                      loops: Animation.Infinite
                      from: 0
                      to: 360
                      duration: 900
                    }
                  }

                  // Labels (Title + Subtitle + Org Tag)
                  Column {
                    anchors.verticalCenter: parent.verticalCenter
                    width: parent.width - Style.space(20) - actionButtonsRow.implicitWidth - Style.space(28)
                    spacing: Style.space(1)

                    Row {
                      spacing: Style.space(4)
                      width: parent.width

                      Text {
                        textFormat: Text.PlainText
                        text: itemData.name
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                        elide: Text.ElideRight
                        width: Math.min(implicitWidth, parent.width
                          - (itemData.favorite ? Style.space(16) : 0)
                          - (itemData.hasAttachments ? Style.space(18) : 0))
                      }

                      Text {
                        textFormat: Text.PlainText
                        visible: itemData.favorite
                        text: "★"
                        color: Color.accent
                        font.pixelSize: Style.font.bodySmall
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      // A paperclip is the whole badge: the file names live in
                      // the detail view, and the row only has to say they exist.
                      Text {
                        textFormat: Text.PlainText
                        visible: Boolean(itemData.hasAttachments)
                        text: "󰏢"
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        anchors.verticalCenter: parent.verticalCenter
                      }
                    }

                    Row {
                      spacing: Style.space(4)
                      width: parent.width

                      Text {
                        textFormat: Text.PlainText
                        visible: Boolean(itemData.isSuggested)
                        text: root.learnedIds[itemData.id] ? "󰐾 Suggested" : "󰌠 Suggested"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        textFormat: Text.PlainText
                        visible: Boolean(itemData.organizationId)
                        text: "󰓹 Org"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        textFormat: Text.PlainText
                        id: rowSubtitle
                        text: itemData.subtitle || Model.itemTypeLabel(itemData.typeCode)
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                        // Take only what is needed, so the folder tag that follows
                        // keeps its place instead of being pushed off the row.
                        width: Math.min(implicitWidth,
                          parent.width
                            - (itemData.organizationId ? Style.space(40) : 0)
                            - (itemData.isSuggested ? Style.space(75) : 0)
                            - (rowFolderTag.visible ? Style.space(90) : 0))
                      }

                      Text {
                        textFormat: Text.PlainText
                        id: rowFolderTag
                        // Only worth showing when it is not already implied by the filter.
                        visible: Boolean(itemData.folderId) && root.selectedFolder === "all"
                        text: "· 󰉋 " + Model.folderName(root.folders, itemData.folderId)
                        color: Qt.darker(root.dim, 1.1)
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                        width: Math.min(implicitWidth, Style.space(90))
                      }
                    }
                  }

                  // Quick Action Buttons
                  Row {
                    id: actionButtonsRow
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(4)
                    visible: isSelected || isHovered

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.hasPassword
                      iconText: "󰌆"
                      tooltipText: "Copy password (Enter / y)"
                      fontFamily: root.fontFamily
                      onClicked: root.handleSmartEnter(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.username !== ""
                      iconText: ""
                      tooltipText: "Copy username (u)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyUsername(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.hasTotp
                      iconText: "󰥔"
                      tooltipText: "Copy TOTP code (m)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyTotpCode(itemData)
                    }

                    PanelActionButton {
                      iconText: "󰏫"
                      tooltipText: itemData.typeCode === 5 ? "View public key" : "View / Edit item (e)"
                      fontFamily: root.fontFamily
                      onClicked: root.openDetail(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.uris && itemData.uris.length > 0
                      iconText: "󰖟"
                      tooltipText: "Open URL (w)"
                      fontFamily: root.fontFamily
                      onClicked: root.openUrl(itemData.uris[0])
                    }
                  }
                }

                MouseArea {
                  id: rowMouseArea
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.cursorActive = true
                    root.openFilterGroup = ""
                    root.selectedIndex = index
                    root.openDetail(itemData)
                  }
                }
              }
            }

            // Empty state overlay
            Item {
              visible: root.filteredItems.length === 0
              anchors.fill: parent

              Column {
                anchors.centerIn: parent
                spacing: Style.space(6)

                Text {
                  textFormat: Text.PlainText
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.isLoading && root.items.length === 0 ? "󰑐" : (root.items.length === 0 ? "󰞀" : "󰍡")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(36)
                  RotationAnimation on rotation {
                    running: root.isLoading && root.items.length === 0
                    from: 0
                    to: 360
                    duration: 900
                    loops: Animation.Infinite
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.isLoading && root.items.length === 0
                    ? "Loading items..."
                    : root.emptyListMessage()
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
              }
            }
          }

          // -----------------------------------------------------------------
          // Bottom filter bar: Folders / Vaults / Types
          // -----------------------------------------------------------------
          // Three horizontally scrolling strips were easy to miss and awkward
          // to reach. One collapsed row instead, each opening a vertical list
          // in place; the item list gives back exactly the height the open
          // list takes, so the panel does not jump.

          PanelSeparator { width: parent.width }

          // The open group's options: a pinned header naming the group, then up
          // to five rows with the rest scrolling underneath it.
          Column {
            id: filterDrawer
            width: parent.width
            height: root.filterDrawerHeight
            visible: height > 0
            clip: true
            spacing: 0

            Behavior on height { NumberAnimation { duration: 130; easing.type: Easing.OutQuad } }

            // Pinned header -- stays put while the options scroll.
            Row {
              width: parent.width
              height: Style.space(30)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.openFilterGroup === "folders" ? "󰉋"
                    : root.openFilterGroup === "organizations" ? "󰦑"
                    : "󰀻"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.openFilterGroup === "folders" ? "FOLDERS"
                    : root.openFilterGroup === "organizations" ? "ORGANIZATIONS"
                    : "TYPES"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Item { width: parent.width - Style.space(190); height: 1 }

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                visible: root.currentFilterOptions.length > root.currentFilterVisibleRows
                text: root.currentFilterOptions.length + " total"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            Flickable {
              id: filterOptionsList
              width: parent.width
              height: Math.min(root.currentFilterVisibleRows, root.currentFilterOptions.length) * root.filterRowHeight
              contentWidth: width
              contentHeight: filterOptionsCol.implicitHeight
              clip: true
              boundsBehavior: Flickable.StopAtBounds
              flickableDirection: Flickable.VerticalFlick
              ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

              WheelScroll { view: filterOptionsList }

              // Keep the keyboard cursor in view when it runs past the fold.
              function revealCursor() {
                var y = root.filterOptionIndex * root.filterRowHeight
                if (y < contentY) contentY = y
                else if (y + root.filterRowHeight > contentY + height) {
                  contentY = y + root.filterRowHeight - height
                }
              }

              Connections {
                target: root
                function onFilterOptionIndexChanged() { filterOptionsList.revealCursor() }
              }

              Column {
                id: filterOptionsCol
                width: filterOptionsList.width - root.scrollGutter
                spacing: 0

                Repeater {
                  model: root.currentFilterOptions

                  delegate: BorderSurface {
                    required property var modelData
                    required property int index
                    width: filterOptionsCol.width
                    implicitHeight: root.filterRowHeight
                    radius: Style.cornerRadius
                    readonly property bool cursored: index === root.filterOptionIndex
                    color: modelData.active ? Style.selectedFillFor(root.fg, Color.accent)
                         : (cursored || optionMouse.containsMouse) ? Style.hoverFillFor(root.fg, Color.accent)
                         : "transparent"
                    borderSpec: Border.surfaceSpec("menu", "border",
                      (modelData.active || cursored) ? Color.accent : "transparent",
                      (modelData.active || cursored) ? 1 : 0)

                    MouseArea {
                      id: optionMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onEntered: root.filterOptionIndex = index
                      onClicked: root.applyFilterOption(root.openFilterGroup, modelData.id)
                    }

                    Row {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)
                      spacing: Style.space(8)

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData.icon
                        color: modelData.active ? Color.accent : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                      }

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        width: parent.width - Style.space(50)
                        text: modelData.label
                        color: modelData.active ? Color.accent : root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        font.bold: modelData.active
                        elide: Text.ElideRight
                      }

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        visible: modelData.active
                        text: "󰄬"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }
                    }
                  }
                }
              }
            }
          }

          // The three collapsed buttons. Identical shape, so none reads as a
          // different kind of control from the others -- which is why they are
          // one component declared three times rather than three buttons.
          //
          // A Flow rather than a Row. Two of the three carry a vault name, so
          // their width is whatever the user typed, and a Row can neither
          // shrink a child nor start a second line -- it lays the overflow out
          // past the panel edge, off both sides at once because the group is
          // centred. `width` is the group's own combined width while the three
          // share a line, which is what keeps it centred, and the panel's when
          // they cannot. It reads the buttons' implicitWidth, never their
          // width, so the layout's width never depends on its own result.
          //
          // This is what pays for the labels naming their filters: the three
          // fit one line in the ordinary case and take a second when they do
          // not, instead of the names having to be dropped to guarantee one.
          Flow {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)
            readonly property real naturalWidth: folderFilterButton.implicitWidth
              + organizationFilterButton.implicitWidth
              + typeFilterButton.implicitWidth
              + spacing * 2
            width: Math.min(parent.width, naturalWidth)

            VaultFilterButton {
              id: folderFilterButton
              group: "folders"
              glyph: "󰉋"
              name: "Folders"
              value: root.folderFilterLabel()
              shortcut: "f"
            }

            VaultFilterButton {
              id: organizationFilterButton
              group: "organizations"
              glyph: "󰦑"
              name: "Organizations"
              value: root.organizationFilterLabel()
              shortcut: "o"
            }

            VaultFilterButton {
              id: typeFilterButton
              group: "types"
              glyph: "󰀻"
              name: "Types"
              value: root.typeFilterLabel()
              shortcut: "t"
            }
          }

        }

        // -------------------------------------------------------------------
        // SCREEN 4: UNLOCKED - ITEM DETAIL VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.activeScreen === "detail"
          width: parent.width
          spacing: Style.space(12)

          // Back Navigation & Action Header
          //
          // A Flow, not a Row, because how many buttons are here is decided at
          // runtime: the suggestion button appears only on a recognised window,
          // and it is the widest of the four. A Row cannot shrink a child or
          // start a second line, so the fourth button was laid out past the
          // panel's right edge and Delete simply left the panel -- worse still
          // only once the suggestion was pinned, because "Suggested here" is a
          // character wider than "Suggest here" and that character was the one
          // that overflowed. The panel is also narrower than its 450 ask on a
          // small screen (see fittedContentWidth), so no arrangement of fixed
          // labels is safe; wrapping is. Everything still fits on one line at
          // the default size, so this only shows itself when it has to.
          Flow {
            width: parent.width
            spacing: Style.space(8)

            Button {
              // "Back to list" spelled out cost more width than the row could
              // spare, and the Sends screen already says just "Back (Esc)".
              text: "Back (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.currentScreen = "main"
            }

            Button {
              visible: Boolean(root.detectedContext && root.detectedContext.displayName && root.detailItem && root.detailItem.typeCode !== 5)
              readonly property bool pinned: Boolean(root.detailItem
                && Model.isAssociated(root.associations, root.detectedContext, root.detailItem.id))
              text: pinned ? "Suggested here" : "Suggest here"
              iconText: pinned ? "󰐾" : "󰐽"
              selected: pinned
              accent: Color.accent
              // The window title is no more trustworthy than a vault value,
              // and the kit renders tooltips with an auto-detecting Text.
              tooltipText: Model.plainLabel((pinned ? "Stop suggesting this for " : "Always suggest this for ")
                + (root.detectedContext ? root.detectedContext.displayName : ""))
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.toggleAssociation(root.detailItem)
            }

            Button {
              visible: Boolean(root.detailItem && root.detailItem.typeCode !== 5)
              text: "Edit"
              iconText: "󰏫"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: if (root.detailItem) root.startEditItem(root.detailItem)
            }

            Button {
              visible: Boolean(root.detailItem && root.detailItem.typeCode !== 5)
              text: "Delete"
              iconText: "󰆴"
              accent: Color.urgent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.showDeleteConfirm = true
            }
          }

          // Delete Confirmation Banner
          BorderSurface {
            visible: root.showDeleteConfirm
            width: parent.width
            implicitHeight: Style.space(64)
            color: Util.alpha(Color.urgent, 0.15)
            radius: Style.cornerRadius
            borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

            Row {
              anchors.centerIn: parent
              spacing: Style.space(12)

              Text {
                textFormat: Text.PlainText
                text: "Permanently delete this item?"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                anchors.verticalCenter: parent.verticalCenter
              }

              Button {
                text: "Confirm Delete"
                iconText: "󰆴"
                selected: true
                accent: Color.urgent
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.deleteCurrentItem()
              }

              Button {
                text: "Cancel"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.showDeleteConfirm = false
              }
            }
          }

          PanelSeparator { width: parent.width }

          Flickable {
            id: detailFlickable
            width: parent.width
            height: Math.min(Style.space(380), detailContentColumn.implicitHeight)
            contentWidth: width
            contentHeight: detailContentColumn.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            WheelScroll { view: detailFlickable }

            Column {
              id: detailContentColumn
              width: detailFlickable.width - root.scrollGutter
              spacing: Style.space(12)

              // Item Header
              Row {
                width: parent.width
                spacing: Style.space(10)

                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.detailItem ? Model.itemTypeGlyph(root.detailItem.typeCode) : "󰌋"
                  color: (root.detailItem && root.detailItem.favorite) ? Color.accent : root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(26)
                }

                Column {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(40)
                  spacing: Style.space(2)

                  Row {
                    spacing: Style.space(6)
                    width: parent.width

                    Text {
                      textFormat: Text.PlainText
                      text: root.detailItem ? root.detailItem.name : "Loading..."
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      font.bold: true
                      elide: Text.ElideRight
                      width: Math.min(implicitWidth, parent.width - Style.space(20))
                    }

                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.detailItem && root.detailItem.favorite)
                      text: "★"
                      color: Color.accent
                      font.pixelSize: Style.font.body
                    }
                  }

                  Row {
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: root.detailItem ? Model.itemTypeLabel(root.detailItem.typeCode) : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.detailItem && root.detailItem.organizationId)
                      text: "• Shared Organization"
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.detailItem && root.detailItem.folderId)
                      text: root.detailItem
                        ? "• 󰉋 " + Model.folderName(root.folders, root.detailItem.folderId)
                        : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }
                }
              }

              // FIELD: Public SSH key (type 5 is deliberately read-only)
              Column {
                visible: Boolean(root.detailItem && root.detailItem.typeCode === 5)
                width: parent.width
                spacing: Style.space(4)
                PanelSectionHeader { text: "PUBLIC KEY" }
                BorderSurface {
                  width: parent.width
                  implicitHeight: Math.max(Style.space(54), sshPublicKeyText.implicitHeight + Style.space(20))
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)
                  Text {
                    textFormat: Text.PlainText
                    id: sshPublicKeyText
                    anchors.fill: parent
                    anchors.margins: Style.space(10)
                    text: root.detailItem ? (root.detailItem.publicKey || "No public key") : ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WrapAnywhere
                  }
                }
                Text {
                  textFormat: Text.PlainText
                  visible: Boolean(root.detailItem && root.detailItem.fingerprint)
                  text: "Fingerprint: " + (root.detailItem ? root.detailItem.fingerprint : "")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WrapAnywhere
                }
              }

              // FIELD: Username
              DetailField {
                visible: root.detailIsLoginLike && Boolean(root.detailItem) && root.detailItem.username !== ""
                label: "Username / Email"
                copyLabel: "Username"
                shortcutHint: "u"
                copyIcon: ""
                value: root.detailItem ? root.detailItem.username : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailItem ? root.detailItem.username : "", "Username")
              }

              // FIELD: Password
              Column {
                visible: root.detailIsLoginLike && Boolean(root.detailItem) && (root.detailPassword !== "" || root.detailItem.hasPassword)
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "PASSWORD" }

                BorderSurface {
                  width: parent.width
                  implicitHeight: Style.space(34)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(10)
                    anchors.rightMargin: Style.space(6)

                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.isFieldRevealed("password")
                        ? root.detailPassword : Model.maskString(root.detailPassword || "password")
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      elide: Text.ElideRight
                      width: parent.width - passActions.width - Style.space(10)
                    }

                    Row {
                      id: passActions
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(4)

                      PanelActionButton {
                        iconText: root.isFieldRevealed("password") ? "󰈉" : "󰈈"
                        tooltipText: root.isFieldRevealed("password") ? "Hide password (v)" : "Reveal password (v)"
                        fontFamily: root.fontFamily
                        onClicked: root.toggleFieldReveal("password")
                      }

                      PanelActionButton {
                        iconText: "󰌆"
                        tooltipText: "Copy password (y / Enter)"
                        fontFamily: root.fontFamily
                        onClicked: root.copyToClipboard(root.detailPassword, "Password")
                      }
                    }
                  }
                }
              }

              // FIELD: TOTP (2FA Code)
              Column {
                visible: root.detailIsLoginLike && Boolean(root.detailItem) && root.detailItem.hasTotp
                width: parent.width
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width
                  PanelSectionHeader { text: "VERIFICATION CODE (TOTP)" }
                  Item { Layout.fillWidth: true }
                  Text {
                    textFormat: Text.PlainText
                    text: root.totpSecRemaining + "s"
                    color: Color.accent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    Layout.alignment: Qt.AlignVCenter
                  }
                }

                BorderSurface {
                  width: parent.width
                  implicitHeight: Style.space(44)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Rectangle {
                    anchors.left: parent.left
                    anchors.bottom: parent.bottom
                    height: Style.space(3)
                    radius: Style.cornerRadius
                    width: parent.width * (root.totpSecRemaining / 30.0)
                    color: Color.accent
                  }

                  Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(12)
                    anchors.rightMargin: Style.space(6)

                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.liveTotp ? (root.liveTotp.length === 6 ? root.liveTotp.slice(0, 3) + " " + root.liveTotp.slice(3) : root.liveTotp) : "Loading..."
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      font.bold: true
                      font.letterSpacing: 2.0
                      width: parent.width - copyTotpBtn.width - Style.space(10)
                    }

                    PanelActionButton {
                      id: copyTotpBtn
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰥔"
                      tooltipText: "Copy TOTP code (m)"
                      fontFamily: root.fontFamily
                      enabled: root.liveTotp !== ""
                      onClicked: root.copyToClipboard(root.liveTotp, "TOTP code")
                    }
                  }
                }
              }

              // FIELD: Website / URIs
              Column {
                visible: root.detailIsLoginLike && Boolean(root.detailItem) && root.detailItem.uris && root.detailItem.uris.length > 0
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "WEBSITE" }

                Repeater {
                  model: root.detailItem ? root.detailItem.uris : []
                  delegate: BorderSurface {
                    width: detailContentColumn.width
                    implicitHeight: Style.space(34)
                    radius: Style.cornerRadius
                    color: Style.hoverFillFor(root.fg, Color.accent)
                    borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                    Row {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(6)

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Text.ElideRight
                        width: parent.width - openUriBtn.width - Style.space(10)
                      }

                      PanelActionButton {
                        id: openUriBtn
                        anchors.verticalCenter: parent.verticalCenter
                        iconText: "󰖟"
                        tooltipText: "Open in browser (w)"
                        fontFamily: root.fontFamily
                        onClicked: root.openUrl(modelData)
                      }
                    }
                  }
                }
              }

              // FIELD: Attachments
              //
              // The metadata came down with the item, so the list is here the
              // moment the detail view opens; only the bytes cost a CLI call,
              // and only for the file the user actually asks for.
              //
              // Above NOTES on purpose. Notes is the one section with no height
              // of its own -- it grows with the text -- and this Flickable is
              // capped, so anything after it starts below the fold on exactly
              // the items whose note is long. A secure note with a file
              // attached is that case, and the files were the thing being
              // pushed out of sight.
              Column {
                visible: Boolean(root.detailItem && root.detailItem.typeCode !== 5 && root.detailItem.hasAttachments)
                width: parent.width
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)
                  PanelSectionHeader { text: "ATTACHMENTS" }
                  Item { Layout.fillWidth: true }
                  PanelActionButton {
                    visible: Boolean(root.detailItem && root.detailItem.attachments
                      && root.detailItem.attachments.length > 1)
                    iconText: "󰇚"
                    tooltipText: "Save all attachments (a)"
                    size: Style.space(20)
                    fontFamily: root.fontFamily
                    onClicked: root.saveAllAttachments()
                  }
                }

                Repeater {
                  model: root.detailItem ? root.detailItem.attachments : []
                  delegate: BorderSurface {
                    readonly property string savedPath: root.attachmentSavedPath(modelData.id)
                    readonly property bool busy: root.attachmentBusyId === modelData.id
                    readonly property bool queued: root.isAttachmentQueued(modelData.id)

                    width: detailContentColumn.width
                    implicitHeight: Style.space(34)
                    radius: Style.cornerRadius
                    color: Style.hoverFillFor(root.fg, Color.accent)
                    borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                    Row {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(6)
                      spacing: Style.space(6)

                      Text {
                        textFormat: Text.PlainText
                        id: attachmentGlyph
                        anchors.verticalCenter: parent.verticalCenter
                        text: "󰈔"
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }

                      // The file name is vault text, so it is drawn as text.
                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData.fileName
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Text.ElideRight
                        width: Math.max(0, parent.width - attachmentGlyph.width
                          - attachmentStatus.width - attachmentActions.width - Style.space(34))
                      }

                      Text {
                        textFormat: Text.PlainText
                        id: attachmentStatus
                        anchors.verticalCenter: parent.verticalCenter
                        text: busy ? "Saving..." : queued ? "Queued" : modelData.sizeName
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                      }

                      Row {
                        id: attachmentActions
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.space(2)

                        PanelActionButton {
                          visible: savedPath === ""
                          enabled: !busy && !queued
                          iconText: "󰇚"
                          tooltipText: "Save to your download folder"
                          fontFamily: root.fontFamily
                          onClicked: root.queueAttachment(modelData)
                        }

                        PanelActionButton {
                          visible: savedPath !== ""
                          iconText: "󰏌"
                          tooltipText: "Open the saved file"
                          fontFamily: root.fontFamily
                          onClicked: root.openSavedAttachment(modelData.id)
                        }

                        PanelActionButton {
                          visible: savedPath !== ""
                          iconText: "󰝰"
                          // The path is ours -- a download directory plus a
                          // sanitised name -- but it is still drawn as text.
                          tooltipText: Model.plainLabel("Show in " + Model.parentDirectory(savedPath))
                          fontFamily: root.fontFamily
                          onClicked: root.revealSavedAttachment(modelData.id)
                        }
                      }
                    }
                  }
                }
              }

              // FIELD: Notes
              Column {
                visible: Boolean(root.detailItem && root.detailItem.typeCode !== 5 && root.detailItem.notes !== "")
                width: parent.width
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width
                  PanelSectionHeader { text: "NOTES" }
                  Item { Layout.fillWidth: true }
                  PanelActionButton {
                    iconText: "󰈙"
                    tooltipText: "Copy notes"
                    size: Style.space(20)
                    fontFamily: root.fontFamily
                    onClicked: if (root.detailItem) root.copyToClipboard(root.detailItem.notes, "Notes")
                  }
                }

                BorderSurface {
                  width: parent.width
                  implicitHeight: notesText.implicitHeight + Style.space(16)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Text {
                    textFormat: Text.PlainText
                    id: notesText
                    anchors.fill: parent
                    anchors.margins: Style.space(10)
                    text: root.detailItem ? root.detailItem.notes : ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.Wrap
                  }
                }
              }

              // -----------------------------------------------------------
              // FIELDS: Card
              // -----------------------------------------------------------
              // Expiry is one field rather than two. It is written, read and
              // typed as a unit, and a vault that shows "04" above "2030" in
              // two labelled boxes is describing its storage rather than the
              // card in your hand.
              DetailField {
                visible: root.detailIsCard
                label: "Cardholder Name"
                value: root.detailCard ? root.detailCard.cardholderName : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailCard ? root.detailCard.cardholderName : "", "Cardholder name")
              }

              DetailField {
                visible: root.detailIsCard
                label: "Brand"
                value: root.detailCard ? root.detailCard.brand : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailCard ? root.detailCard.brand : "", "Brand")
              }

              DetailField {
                visible: root.detailIsCard
                label: "Card Number"
                copyLabel: "Card number"
                shortcutHint: "n / Enter"
                revealHint: "v"
                sensitive: true
                revealed: root.isFieldRevealed("cardNumber")
                value: root.detailCard ? root.detailCard.number : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.toggleFieldReveal("cardNumber")
                onCopyRequested: root.copyToClipboard(root.detailCard ? root.detailCard.number : "", "Card number")
              }

              DetailField {
                visible: root.detailIsCard
                label: "Expires"
                value: root.detailCardExpiry
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailCardExpiry, "Expiry")
              }

              DetailField {
                visible: root.detailIsCard
                label: "Security Code"
                copyLabel: "Security code"
                shortcutHint: "k"
                sensitive: true
                revealed: root.isFieldRevealed("cardCode")
                value: root.detailCard ? root.detailCard.code : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.toggleFieldReveal("cardCode")
                onCopyRequested: root.copyToClipboard(root.detailCard ? root.detailCard.code : "", "Security code")
              }

              // -----------------------------------------------------------
              // FIELDS: Identity
              // -----------------------------------------------------------
              // Every field an identity can carry is declared; DetailField
              // hides the empty ones. Most identities fill in a handful, and
              // the alternative -- deciding here which are worth drawing --
              // is how the useful one for somebody ends up missing.
              DetailField {
                visible: root.detailIsIdentity
                label: "Name"
                value: root.detailIdentityName
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailIdentityName, "Name")
              }

              DetailField {
                visible: root.detailIsIdentity
                label: "Username"
                shortcutHint: "u"
                value: root.detailIdentity ? root.detailIdentity.username : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.username : "", "Username")
              }

              DetailField {
                visible: root.detailIsIdentity
                label: "Company"
                value: root.detailIdentity ? root.detailIdentity.company : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.company : "", "Company")
              }

              DetailField {
                visible: root.detailIsIdentity
                label: "Email"
                shortcutHint: "c"
                value: root.detailIdentity ? root.detailIdentity.email : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.email : "", "Email")
              }

              DetailField {
                visible: root.detailIsIdentity
                label: "Phone"
                value: root.detailIdentity ? root.detailIdentity.phone : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.phone : "", "Phone")
              }

              // The three an identity item usually exists to hold. Masked for
              // the same reason a password is: a shoulder is enough to lose
              // them, and unlike a password they cannot be rotated.
              DetailField {
                visible: root.detailIsIdentity
                label: "Social Security Number"
                copyLabel: "SSN"
                sensitive: true
                revealed: root.isFieldRevealed("ssn")
                value: root.detailIdentity ? root.detailIdentity.ssn : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.toggleFieldReveal("ssn")
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.ssn : "", "SSN")
              }

              DetailField {
                visible: root.detailIsIdentity
                label: "Passport Number"
                copyLabel: "Passport number"
                sensitive: true
                revealed: root.isFieldRevealed("passport")
                value: root.detailIdentity ? root.detailIdentity.passportNumber : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.toggleFieldReveal("passport")
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.passportNumber : "", "Passport number")
              }

              DetailField {
                visible: root.detailIsIdentity
                label: "Licence Number"
                copyLabel: "Licence number"
                sensitive: true
                revealed: root.isFieldRevealed("licence")
                value: root.detailIdentity ? root.detailIdentity.licenseNumber : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.toggleFieldReveal("licence")
                onCopyRequested: root.copyToClipboard(root.detailIdentity ? root.detailIdentity.licenseNumber : "", "Licence number")
              }

              PanelSectionHeader {
                visible: root.detailIsIdentity && root.detailIdentityAddress !== ""
                text: "ADDRESS"
              }

              // One block, not seven rows. An address is copied as an address.
              BorderSurface {
                visible: root.detailIsIdentity && root.detailIdentityAddress !== ""
                width: parent.width
                implicitHeight: addressText.implicitHeight + Style.space(16)
                radius: Style.cornerRadius
                color: Style.hoverFillFor(root.fg, Color.accent)
                borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                Row {
                  anchors.fill: parent
                  anchors.margins: Style.space(8)
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    id: addressText
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.detailIdentityAddress
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    wrapMode: Text.Wrap
                    width: parent.width - copyAddressBtn.width - Style.space(10)
                  }

                  PanelActionButton {
                    id: copyAddressBtn
                    anchors.verticalCenter: parent.verticalCenter
                    iconText: "󰈙"
                    tooltipText: "Copy address"
                    fontFamily: root.fontFamily
                    onClicked: root.copyToClipboard(root.detailIdentityAddress, "Address")
                  }
                }
              }


            }
          }

        }

        // -------------------------------------------------------------------
        // SCREEN 5: ADD / EDIT ITEM FORM VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.activeScreen === "edit"
          width: parent.width
          spacing: Style.space(10)

          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Cancel (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.currentScreen = root.formIsEditing ? "detail" : "main"
            }

            Item { Layout.fillWidth: true }

            Text {
              textFormat: Text.PlainText
              Layout.alignment: Qt.AlignVCenter
              text: root.formIsEditing ? "Edit Item" : "New Vault Item"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }
          }

          PanelSeparator { width: parent.width }

          Flickable {
            id: editFlickable
            width: parent.width
            height: Math.min(Style.space(420), editFormCol.implicitHeight)
            contentWidth: width
            contentHeight: editFormCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            WheelScroll { view: editFlickable }

            Column {
              id: editFormCol
              width: editFlickable.width - root.scrollGutter
              spacing: Style.space(10)

              // Item Type Selector (only for new items)
              Row {
                visible: !root.formIsEditing
                spacing: Style.space(8)

                Button {
                  text: "Login"
                  iconText: "󰌋"
                  selected: root.formTypeCode === 1
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.formTypeCode = 1
                }

                Button {
                  text: "Secure Note"
                  iconText: "󰈙"
                  selected: root.formTypeCode === 2
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.formTypeCode = 2
                }
                Button {
                  text: "Card"
                  iconText: "󰿯"
                  selected: root.formTypeCode === 3
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.formTypeCode = 3
                }

                Button {
                  text: "Identity"
                  iconText: ""
                  selected: root.formTypeCode === 4
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.formTypeCode = 4
                }
              }

              // FIELD: Title / Name
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "TITLE / NAME *"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  id: formNameField
                  width: parent.width
                  placeholderText: "e.g. GitHub, Google, Work Server..."
                  text: root.formName
                  onTextChanged: root.formName = text
                }
              }

              // FIELD: Folder -- expandable list rather than a wrapping row of
              // buttons, which grew unreadable once a vault had more than a few.
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "FOLDER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

                Button {
                  width: parent.width
                  text: Model.plainLabel(root.formFolderLabel())
                  iconText: root.formPicker === "folder" ? "\u{F0140}" : "\u{F024B}"
                  selected: root.formPicker === "folder"
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  leftAlign: true
                  onClicked: root.toggleFormPicker("folder")
                }

                Flickable {
                  id: folderPickList
                  visible: root.formPicker === "folder"
                  width: parent.width
                  height: visible ? Math.min(Style.space(150), folderPickCol.implicitHeight) : 0
                  contentWidth: width
                  contentHeight: folderPickCol.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  flickableDirection: Flickable.VerticalFlick
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  WheelScroll { view: folderPickList }

                  Column {
                    id: folderPickCol
                    width: folderPickList.width - root.scrollGutter
                    spacing: Style.space(2)

                    FormPickerRow {
                      width: parent.width
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      label: "No Folder"
                      glyph: "\u{F0256}"
                      picked: !root.formFolderId
                      onActivated: root.setFormFolder("")
                    }

                    Repeater {
                      model: root.folders
                      delegate: FormPickerRow {
                        required property var modelData
                        width: parent.width
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        label: modelData.name
                        glyph: "\u{F024B}"
                        picked: root.formFolderId === modelData.id
                        onActivated: root.setFormFolder(modelData.id)
                      }
                    }
                  }
                }

                // Creating a folder here saves leaving the form to make one.
                Row {
                  width: parent.width
                  spacing: Style.space(6)

                  TextField {
                    width: parent.width - Style.space(96)
                    placeholderText: "New folder name..."
                    text: root.newFolderName
                    onTextChanged: root.newFolderName = text
                    onAccepted: root.submitNewFolder()
                    enabled: !root.creatingFolder
                  }

                  Button {
                    text: root.creatingFolder ? "Adding..." : "Add"
                    iconText: root.creatingFolder ? "\u{F0450}" : "\u{F0415}"
                    iconSpinning: root.creatingFolder
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    enabled: !root.creatingFolder && root.newFolderName.trim() !== ""
                    onClicked: root.submitNewFolder()
                  }
                }
              }

              // FIELD: Organization, and the collections it files items into.
              Column {
                visible: root.organizations.length > 0
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ORGANIZATION"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

                Button {
                  width: parent.width
                  text: Model.plainLabel(root.formOrgLabel())
                  iconText: root.formPicker === "organization" ? "\u{F0140}" : "\u{F0991}"
                  selected: root.formPicker === "organization"
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  leftAlign: true
                  onClicked: root.toggleFormPicker("organization")
                }

                Flickable {
                  id: orgPickList
                  visible: root.formPicker === "organization"
                  width: parent.width
                  height: visible ? Math.min(Style.space(150), orgPickCol.implicitHeight) : 0
                  contentWidth: width
                  contentHeight: orgPickCol.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  flickableDirection: Flickable.VerticalFlick
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  WheelScroll { view: orgPickList }

                  Column {
                    id: orgPickCol
                    width: orgPickList.width - root.scrollGutter
                    spacing: Style.space(2)

                    FormPickerRow {
                      width: parent.width
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      label: "My Vault"
                      glyph: "\u{F0004}"
                      picked: !root.formOrgId || root.formOrgId === "personal"
                      onActivated: root.setFormOrganization("")
                    }

                    Repeater {
                      model: root.organizations
                      delegate: FormPickerRow {
                        required property var modelData
                        width: parent.width
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        label: modelData.name
                        glyph: "\u{F0991}"
                        picked: root.formOrgId === modelData.id
                        onActivated: root.setFormOrganization(modelData.id)
                      }
                    }
                  }
                }

                // Collections only exist for org-owned items, and Bitwarden
                // requires at least one, so this appears with the choice.
                Column {
                  visible: Boolean(root.formOrgId) && root.formOrgId !== "personal"
                  width: parent.width
                  spacing: Style.space(3)

                  Item { width: 1; height: Style.space(4) }

                  Row {
                    width: parent.width
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: "COLLECTIONS"
                      color: root.formCollectionIds.length === 0 ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      text: root.formCollectionsLoading
                        ? "loading..."
                        : (root.formCollectionIds.length === 0
                            ? "pick at least one"
                            : root.formCollectionIds.length + " selected")
                      color: root.formCollectionIds.length === 0 ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Flickable {
                    id: collectionList
                    width: parent.width
                    height: Math.min(Style.space(150), collectionCol.implicitHeight)
                    contentWidth: width
                    contentHeight: collectionCol.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    flickableDirection: Flickable.VerticalFlick
                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                    WheelScroll { view: collectionList }

                    Column {
                      id: collectionCol
                      width: collectionList.width - root.scrollGutter
                      spacing: Style.space(2)

                      Text {
                        textFormat: Text.PlainText
                        visible: !root.formCollectionsLoading && root.formCollections.length === 0
                        width: parent.width
                        text: "No collections available in this organization."
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WordWrap
                      }

                      Repeater {
                        model: root.formCollections
                        delegate: FormPickerRow {
                          required property var modelData
                          width: parent.width
                          foreground: root.fg
                          fontFamily: root.fontFamily
                          label: modelData.name
                          glyph: "\u{F0290}"
                          picked: root.isFormCollectionSelected(modelData.id)
                          // Several collections may hold one item, so these
                          // toggle instead of replacing the choice.
                          multi: true
                          onActivated: root.toggleFormCollection(modelData.id)
                        }
                      }
                    }
                  }
                }
              }

              // FIELD: Username (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "USERNAME / EMAIL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "username or email address..."
                  text: root.formUsername
                  onTextChanged: root.formUsername = text
                }
              }

              // FIELD: Password with Generator (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                RowLayout {
                  width: parent.width
                  Text { textFormat: Text.PlainText; text: "PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Item { Layout.fillWidth: true }
                  // Opens the real generator, which fills this field in and
                  // comes back. The ellipsis says it goes somewhere first.
                  Button {
                    text: "Generate..."
                    iconText: "󰌆"
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    onClicked: root.openGenerator()
                  }
                }
                Row {
                  width: parent.width
                  spacing: Style.space(6)
                  TextField {
                    id: formPassField
                    width: parent.width - eyeBtnForm.width - Style.space(6)
                    placeholderText: "Password..."
                    password: !root.formPasswordRevealed
                    text: root.formPassword
                    onTextChanged: root.formPassword = text
                  }
                  Button {
                    id: eyeBtnForm
                    iconText: root.formPasswordRevealed ? "󰈉" : "󰈈"
                    tooltipText: root.formPasswordRevealed ? "Hide password" : "Show password"
                    fontFamily: root.fontFamily
                    onClicked: root.formPasswordRevealed = !root.formPasswordRevealed
                  }
                }
              }

              // FIELD: TOTP Authenticator Key (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "AUTHENTICATOR KEY (TOTP SECRET)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "e.g. JBSWY3DPEHPK3PXP (optional)..."
                  text: root.formTotp
                  onTextChanged: root.formTotp = text
                }
              }

              // FIELD: Website URL (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "WEBSITE URL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "https://example.com/login..."
                  text: root.formUri
                  onTextChanged: root.formUri = text
                }
              }

              // -----------------------------------------------------------
              // FORM FIELDS: Card
              // -----------------------------------------------------------
              // Expiry is split here, unlike the detail view, because these
              // are two values the vault stores separately and a single box
              // would have to guess where the boundary between them falls.
              Column {
                visible: root.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "CARDHOLDER NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Name as printed on the card"
                  text: root.formCardholderName
                  onTextChanged: root.formCardholderName = text
                }
              }
              Column {
                visible: root.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "BRAND"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Visa, Mastercard, Amex..."
                  text: root.formCardBrand
                  onTextChanged: root.formCardBrand = text
                }
              }
              Column {
                visible: root.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "CARD NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "1234 5678 9012 3456"
                  text: root.formCardNumber
                  onTextChanged: root.formCardNumber = text
                }
              }
              Column {
                visible: root.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "EXPIRY MONTH"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "MM"
                  text: root.formCardExpMonth
                  onTextChanged: root.formCardExpMonth = text
                }
              }
              Column {
                visible: root.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "EXPIRY YEAR"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "YYYY"
                  text: root.formCardExpYear
                  onTextChanged: root.formCardExpYear = text
                }
              }
              Column {
                visible: root.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "SECURITY CODE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "CVV / CVC"
                  text: root.formCardCode
                  onTextChanged: root.formCardCode = text
                }
              }

              // -----------------------------------------------------------
              // FORM FIELDS: Identity
              // -----------------------------------------------------------
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "TITLE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Mr, Ms, Dr..."
                  text: root.formIdTitle
                  onTextChanged: root.formIdTitle = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "FIRST NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdFirstName
                  onTextChanged: root.formIdFirstName = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "MIDDLE NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdMiddleName
                  onTextChanged: root.formIdMiddleName = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "LAST NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdLastName
                  onTextChanged: root.formIdLastName = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "USERNAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdUsername
                  onTextChanged: root.formIdUsername = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "COMPANY"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdCompany
                  onTextChanged: root.formIdCompany = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "EMAIL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "name@example.com"
                  text: root.formIdEmail
                  onTextChanged: root.formIdEmail = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "PHONE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdPhone
                  onTextChanged: root.formIdPhone = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "SOCIAL SECURITY NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdSsn
                  onTextChanged: root.formIdSsn = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "PASSPORT NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdPassport
                  onTextChanged: root.formIdPassport = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "LICENCE NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdLicense
                  onTextChanged: root.formIdLicense = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ADDRESS LINE 1"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdAddress1
                  onTextChanged: root.formIdAddress1 = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ADDRESS LINE 2"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdAddress2
                  onTextChanged: root.formIdAddress2 = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ADDRESS LINE 3"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdAddress3
                  onTextChanged: root.formIdAddress3 = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "CITY / TOWN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdCity
                  onTextChanged: root.formIdCity = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "STATE / COUNTY"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdState
                  onTextChanged: root.formIdState = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "POSTAL CODE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdPostalCode
                  onTextChanged: root.formIdPostalCode = text
                }
              }
              Column {
                visible: root.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "COUNTRY"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.formIdCountry
                  onTextChanged: root.formIdCountry = text
                }
              }

              // FIELD: Notes
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "NOTES"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Additional secure notes..."
                  text: root.formNotes
                  onTextChanged: root.formNotes = text
                }
              }

              // Favorite Star Toggle
              Row {
                spacing: Style.space(8)
                Button {
                  text: root.formFavorite ? "★ In Favorites" : "☆ Add to Favorites"
                  selected: root.formFavorite
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.formFavorite = !root.formFavorite
                }
              }

              // Enter saves from anywhere in the form, so a long item does not
              // have to be scrolled to the bottom to be committed.
              //
              // A Shortcut rather than `onAccepted` on each field: there are
              // more than thirty of them and the next one added would silently
              // not save. It is scoped tightly instead -- only on this screen,
              // and not while a picker is open, where Enter belongs to the
              // list being picked from.
              Shortcut {
                sequences: ["Return", "Enter"]
                enabled: root.activeScreen === "edit" && root.formPicker === ""
                onActivated: root.saveItemForm()
              }

              // Save Action Button
              Button {
                width: parent.width
                text: root.isLoading
                  ? "Saving..."
                  : (root.formIsEditing ? "Save Changes (Enter)" : "Create Item (Enter)")
                iconText: root.isLoading ? "󰑐" : "󰄬"
                iconSpinning: root.isLoading
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.isLoading
                onClicked: root.saveItemForm()
              }

              Item { height: Style.space(12); width: 1 }
            }
          }
        }
      }

      // Transient updates belong to the panel, but not to its layout. Keeping
      // this beside mainColumn means fittedContentHeight never sees it, so an
      // unlock, copy, save, or error cannot shove the active screen down and
      // pull it back up when the message clears.
      StatusNotice {
        id: statusNotice
        statusMessage: root.flashMessage
        errorMessage: root.errorMessage
        statusSuppressed: root.totpFollowupActive
        foreground: root.fg
        surfaceColor: root.bar ? root.bar.background : Color.background
        accentColor: root.accent
        urgentColor: root.urgent
        fontFamily: root.fontFamily
        actionLabel: root.failedSave ? "Reopen " + root.failedSave.name : ""
        onActionRequested: root.reopenFailedSave()
        onErrorDismissed: {
          // Dismissing the message drops the recovery with it: the list is
          // already back to what the vault holds, so what is being discarded
          // is the attempt, and leaving a Reopen behind an invisible message
          // would be a button for something the user has said they are done
          // with.
          root.failedSave = null
          root.errorMessage = ""
        }
      }
    }
  }
}
