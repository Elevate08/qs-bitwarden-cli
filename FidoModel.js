// FidoModel.js — FIDO2 unlock helpers for the Bitwarden plugin.
//
// Kept separate from BitwardenModel.js on purpose: this is the whole of the
// FIDO2-specific surface (its PAM stack, its readiness probe, its setup
// hand-off), so rebasing onto upstream stays a copy job. The keyring commands
// that store and read the master password behind the gate live in
// BitwardenModel.js with the other keyring commands they share helpers with.

.pragma library

// -------------------------------------------------------------------------
// FIDO2 Unlock
// -------------------------------------------------------------------------
//
// A FIDO2 authenticator proves presence, but it cannot produce the Bitwarden
// master password, and `bw unlock` accepts nothing else. So FIDO2 unlock keeps
// the master password in the OS login keyring and uses a verified key touch as
// the gate on reading it back -- the same trade fingerprint unlock makes, and
// the same one the Bitwarden desktop client makes for its own biometrics.
//
// Two things differ from the fingerprint path, both deliberate:
//
//  * The PAM configuration is shipped inside this plugin rather than installed
//    under /etc/pam.d. Quickshell's PamContext takes a `configDirectory`,
//    resolved against this plugin's own files and passed to Linux-PAM's
//    pam_start_confdir, so no privileged step is needed to enable the option.
//
//  * The credential is not registered here. Omarchy's own FIDO2 setup writes it
//    to the global authfile, and that one registration serves sudo, polkit and
//    this plugin alike. Only a device that is actually plugged in at unlock
//    time can answer an assertion.

// Relative to FidoUnlock.qml. Quickshell resolves a non-absolute
// configDirectory against the QML file's URL and requires it to be a real
// directory holding a regular file named by `config`; a missing dir or file
// makes the conversation fail to start, which is why the probe below is not
// the only guard.
var FIDO_PAM_DIR = "pam"
var FIDO_PAM_CONFIG = "qs-bitwarden-fido2"
// Omarchy's global registration. root:root 0644, so a user-run PAM stack can
// read it -- and it must be the very file /etc/pam.d/sudo already names, or a
// single touch would no longer answer for both.
var FIDO_AUTHFILE = "/etc/fido2/fido2"
// A probe answer is a handful of `key=value` lines; the cap is the same shape
// every other stream this shell buffers uses.
var FIDO_MAX_PROBE_BYTES = 4096

function fidoPamConfigName() { return FIDO_PAM_CONFIG }
function fidoPamDirectory() { return FIDO_PAM_DIR }
function fidoAuthfile() { return FIDO_AUTHFILE }

// Omarchy owns the enrolment end to end, exactly as it does for the reader:
// `omarchy setup security fido2` installs libfido2/pam-u2f, checks the device,
// registers it, wires sudo and polkit, and tests it. It runs in the same
// floating terminal as an install, since it is interactive (sudo, then a
// touch). There is no `pkg add pam-u2f` button for the same reason there is no
// `pkg add fprintd` one: installing the package alone leaves the option
// exactly as unconfigured as it was.
function fidoSetupCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy setup security fido2"]
}

// Why `omarchy remove security fido2` is the only supported way to turn this
// off again: it is what removes the authfile the stack reads and unwires sudo
// and polkit. Unregistering here would leave those two broken.
function fidoRemoveCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy remove security fido2"]
}

// One shell round trip: `key=value` per line, capped at the producer. Readiness
// needs more than a binary on PATH --
//   * pamu2fcfg present  => the libfido2/pam-u2f packages are installed,
//   * the authfile a regular, non-empty, non-symlink file => Omarchy has
//     registered a credential (a symlink is refused for the same reason
//     omarchy-setup-security-fido2 refuses one: it is not a registration the
//     module can trust),
//   * fido2-token listing a device => a key is plugged in right now.
// A machine with no key at all is not offered the option, exactly as a machine
// with no reader is not offered the fingerprint one.
function fidoProbeCommand() {
  var auth = "'" + FIDO_AUTHFILE + "'"
  var script =
    "if command -v pamu2fcfg >/dev/null 2>&1; then echo fido_installed=1; else echo fido_installed=0; fi; "
    + "if [ -f " + auth + " ] && [ -s " + auth + " ] && [ ! -L " + auth + " ]; then echo fido_registered=1; else echo fido_registered=0; fi; "
    + "if command -v fido2-token >/dev/null 2>&1 && [ -n \"$(fido2-token -L 2>/dev/null)\" ]; then echo fido_token=1; else echo fido_token=0; fi"
  return ["bash", "-c", "{ " + script + "; } | head -c " + FIDO_MAX_PROBE_BYTES]
}

// Absent keys are false rather than an error: a probe that half-answered (or a
// `fido2-token` that is not installed) must not read as "ready". `applicable`
// only decides whether the settings row is worth drawing at all -- a machine
// with none of the three parts has no FIDO2 to offer.
function parseFidoProbe(raw) {
  var found = {}
  var lines = String(raw === undefined || raw === null ? "" : raw).split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (!line) continue
    var eq = line.indexOf("=")
    if (eq <= 0) continue
    found[line.slice(0, eq)] = line.slice(eq + 1).trim()
  }
  var installed = found["fido_installed"] === "1"
  var registered = found["fido_registered"] === "1"
  var tokenPresent = found["fido_token"] === "1"
  return {
    installed: installed,
    registered: registered,
    tokenPresent: tokenPresent,
    ready: installed && registered && tokenPresent,
    applicable: installed || registered || tokenPresent
  }
}
