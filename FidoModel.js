// FidoModel.js — FIDO2 unlock helpers for the Bitwarden plugin.
//
// Kept separate from BitwardenModel.js on purpose: this is the FIDO2-specific
// surface (the readiness probe that finds which plugged-in key holds which
// registered credential, and the setup hand-off to Omarchy). The pipelines
// that touch the key and open the envelope live in BitwardenModel.js beside
// the envelope builders they compose.

.pragma library

// -------------------------------------------------------------------------
// FIDO2 Unlock
// -------------------------------------------------------------------------
//
// The credential is not registered here. Omarchy's own FIDO2 setup writes it
// to the global authfile through pam-u2f, and that one registration serves
// this plugin and the system's own authentication prompts alike. A touch asks
// the key for that credential's hmac-secret, which opens the envelope's FIDO
// wrap; see BitwardenModel.js. Only a device that is actually plugged in at
// unlock time can answer.

// Omarchy's global registration. root:root 0644, so the probe can read it --
// and it must be the very file the system's own PAM stacks already name, so
// one registration keeps answering for both.
var FIDO_AUTHFILE = "/etc/fido2/fido2"
// A probe answer is a handful of `key=value` lines; the cap is the same shape
// every other stream this shell buffers uses.
var FIDO_MAX_PROBE_BYTES = 4096

function fidoAuthfile() { return FIDO_AUTHFILE }

// Omarchy owns the enrolment end to end, exactly as it does for the reader:
// `omarchy setup security fido2` installs libfido2/pam-u2f, checks the device,
// registers it, wires the system's own authentication prompts, and tests it.
// It runs in the same floating terminal as an install, since it is interactive
// (an administrator prompt, then a touch). There is no `pkg add pam-u2f` button for the same reason there is no
// `pkg add fprintd` one: installing the package alone leaves the option
// exactly as unconfigured as it was.
function fidoSetupCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy setup security fido2"]
}

// Why `omarchy remove security fido2` is the only supported way to turn this
// off again: it is what removes the authfile the stack reads and unwires the
// system's own prompts. Unregistering here would leave those broken.
function fidoRemoveCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy remove security fido2"]
}

// One shell round trip: `key=value` per line, capped at the producer. Readiness
// needs more than a binary on PATH --
//   * fido2-assert and fido2-token present => libfido2's tools, which pam-u2f
//     itself depends on, are installed,
//   * the authfile a regular, non-empty, non-symlink file => Omarchy has
//     registered a credential (a symlink is refused for the same reason
//     omarchy-setup-security-fido2 refuses one: it is not a registration the
//     module can trust),
//   * fido2-token listing a device => a key is plugged in right now.
// Then, for each of this user's registered credentials, which plugged-in key
// holds it -- asked with a silent assertion (`up=false`, no hmac-secret): no
// touch, no secret, and an answer in a fraction of a second either way.
// An hmac-secret request for a credential a key does not hold would wait for
// a touch before saying so, which is why that is never used to search.
//
// Each credential line is `cred=<id>|<options>|<device or ->`. None of it is
// secret: credential ids and options are in a world-readable file.
function fidoProbeCommand() {
  var auth = "'" + FIDO_AUTHFILE + "'"
  var script =
    "if command -v fido2-assert >/dev/null 2>&1 && command -v fido2-token >/dev/null 2>&1; "
    + "then echo fido_installed=1; else echo fido_installed=0; fi; "
    + "if [ -f " + auth + " ] && [ -s " + auth + " ] && [ ! -L " + auth + " ]; then echo fido_registered=1; else echo fido_registered=0; fi; "
    + "__devs=\"$(fido2-token -L 2>/dev/null | cut -d: -f1)\"; "
    + "if command -v fido2-token >/dev/null 2>&1 && [ -n \"$__devs\" ]; then echo fido_token=1; else echo fido_token=0; fi; "
    + "__rp=\"pam://$(hostname 2>/dev/null)\"; printf 'rp=%s\\n' \"$__rp\"; "
    + "[ -f " + auth + " ] && [ ! -L " + auth + " ] || exit 0; "
    + "__line=\"$(awk -F: -v u=\"$(id -un)\" '$1 == u { print; exit }' " + auth + ")\"; "
    + "[ -n \"$__line\" ] || exit 0; "
    + "IFS=: read -r -a __parts <<< \"$__line\"; "
    + "for __entry in \"${__parts[@]:1}\"; do "
    + "  __cred=\"${__entry%%,*}\"; __opts=\"${__entry##*,}\"; __at=-; "
    + "  case \"$__cred\" in ''|*[!A-Za-z0-9+/=]*) continue ;; esac; "
    + "  for __dev in $__devs; do "
    + "    if printf '%s\\n%s\\n%s\\n' \"$(head -c 32 /dev/urandom | base64 -w0)\" \"$__rp\" \"$__cred\" "
    + "      | timeout 5 fido2-assert -G -t up=false \"$__dev\" >/dev/null 2>&1; then __at=\"$__dev\"; break; fi; "
    + "  done; "
    + "  printf 'cred=%s|%s|%s\\n' \"$__cred\" \"$__opts\" \"$__at\"; "
    + "done"
  return ["bash", "-c", "{ " + script + "; } | head -c " + FIDO_MAX_PROBE_BYTES]
}

// Absent keys are false rather than an error: a probe that half-answered (or a
// `fido2-token` that is not installed) must not read as "ready". `applicable`
// only decides whether the settings row is worth drawing at all -- a machine
// with none of the three parts has no FIDO2 to offer.
//
// A credential registered with `+pin` or `+verification` asks sudo for the
// key's PIN as well as a touch. This unlock cannot collect that PIN yet, and a
// touch alone would be weaker than what the registration asks of the system,
// so such credentials are listed but never used.
function parseFidoProbe(raw) {
  var found = {}
  var creds = []
  var lines = String(raw === undefined || raw === null ? "" : raw).split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (!line) continue
    var eq = line.indexOf("=")
    if (eq <= 0) continue
    var key = line.slice(0, eq)
    var value = line.slice(eq + 1).trim()
    if (key === "cred") {
      var parts = value.split("|")
      if (parts.length !== 3 || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[0])) continue
      var needsPin = /\+(pin|verification)\b/.test(parts[1])
      creds.push({ cred: parts[0], options: parts[1], device: parts[2] === "-" ? "" : parts[2],
        needsPin: needsPin })
    } else {
      found[key] = value
    }
  }
  var installed = found["fido_installed"] === "1"
  var registered = found["fido_registered"] === "1"
  var tokenPresent = found["fido_token"] === "1"
  var rp = /^pam:\/\/[A-Za-z0-9.-]+$/.test(found["rp"] || "") ? found["rp"] : ""
  var usable = creds.filter(function(c) { return c.device !== "" && !c.needsPin })
  var pinOnly = creds.some(function(c) { return c.device !== "" && c.needsPin }) && usable.length === 0
  return {
    installed: installed,
    registered: registered,
    tokenPresent: tokenPresent,
    rp: rp,
    credentials: creds,
    usable: usable,
    pinOnly: pinOnly,
    ready: installed && registered && tokenPresent && rp !== "" && usable.length > 0,
    applicable: installed || registered || tokenPresent
  }
}
