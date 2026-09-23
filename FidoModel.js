// FidoModel.js -- FIDO2 unlock helpers: the probe that finds which plugged-in
// key holds which registered credential, and the hand-off to Omarchy's setup.
// The pipelines that use the key live in BitwardenModel.js with the envelope.

.pragma library

// Credentials are registered by Omarchy's FIDO2 setup (pam-u2f), in the same
// world-readable authfile the system's PAM stacks use, so one registration
// serves both.
var FIDO_AUTHFILE = "/etc/fido2/fido2"
var FIDO_MAX_PROBE_BYTES = 4096

// Omarchy's interactive enrolment (packages, registration, PAM wiring), in a
// floating terminal; a package install alone would configure nothing.
function fidoSetupCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy setup security fido2"]
}

// The only supported removal: it also unwires the system's own prompts.
function fidoRemoveCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy remove security fido2"]
}

// One capped round trip of `key=value` lines: libfido2 tools installed, a
// registration present (regular non-empty file, not a symlink), a key plugged
// in, and the rp. Then per registered credential of this user, which plugged-in
// key holds it, found with a silent assertion (`up=false`, no hmac-secret, so
// no touch). Lines are `cred=<id>|<options>|<device or ->`; nothing secret.
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

// Missing fields read as false, so a partial probe is never "ready".
// `applicable`: whether to show the settings row at all. Credentials
// registered with `+pin`/`+verification` are listed but not used: this unlock
// cannot collect the key's PIN, and a touch alone would be weaker.
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
