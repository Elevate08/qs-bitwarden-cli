#!/usr/bin/env node
// Local TOTP codes: they must equal what `bw get totp` prints, so the vectors
// are the Bitwarden SDK's own (bitwarden-vault/src/totp.rs) plus RFC 6238, and
// every key shape the SDK might read differently must fall back to bw.
//
//   node tests/totp.test.js

const crypto = require("crypto")
const { createSuite, functionBody, loadModule, read } = require("./harness")

const Totp = loadModule("TotpModel.js")
const { check, done } = createSuite("totp")

const SDK_TIME = Date.parse("2023-01-01T00:00:00.000Z")
const code = (key, t = SDK_TIME) => {
  const r = Totp.generate(key, t)
  return r ? r.code : null
}

// --- the SDK's own vectors ---------------------------------------------------
const sdkCases = [
  ["WQIQ25BRKZYCJVYP", "194506"],
  ["wqiq25brkzycjvyp", "194506"],
  ["PIUDISEQYA", "829846"],
  ["PIUDISEQYA======", "829846"],
  ["PIUD1IS!EQYA=", "829846"],
  ["steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "7W6CJ"],
  ["StEam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "7W6CJ"],
  ["steam://ABCD123", "N26DF"],
  ["ddfdf", "932653"],
  ["HJSGFJHDFDJDJKSDFD", "000034"],
  ["xvdsfasdfasdasdghsgsdfg", "403786"],
  ["KAKFJWOSFJ12NWL", "093430"],
  ["otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP", "194506"],
  ["OTPauth://totp/test-account?secret=WQIQ25BRKZYCJVYP", "194506"],
  ["otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&period=60", "730364"],
  ["otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&algorithm=SHA256", "842615"]
]
for (const [key, expected] of sdkCases) {
  check(`SDK vector ${key}`, code(key) === expected, `got ${code(key)}, want ${expected}`)
}
check("the SDK's sloppy base32 decode is mirrored",
  JSON.stringify(Totp.decodeBase32("WQIQ25BRKZYCJVYP")) === "[180,17,13,116,49,86,112,36,215,15]"
    && JSON.stringify(Totp.decodeBase32("ABCD123")) === "[0,68,61]",
  JSON.stringify(Totp.decodeBase32("ABCD123")))
check("the period is reported with the code",
  Totp.generate("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&period=60", SDK_TIME).period === 60
    && Totp.generate("WQIQ25BRKZYCJVYP", SDK_TIME).period === 30,
  "period")

// --- RFC 6238 appendix B -----------------------------------------------------
const b32 = buf => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = "", out = ""
  for (const b of buf) bits += b.toString(2).padStart(8, "0")
  for (let i = 0; i + 5 <= bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5), 2)]
  const rest = bits.length % 5
  if (rest) out += A[parseInt(bits.slice(bits.length - rest).padEnd(5, "0"), 2)]
  return out
}
const sha1Secret = b32(Buffer.from("12345678901234567890"))
const sha256Secret = b32(Buffer.from("12345678901234567890123456789012"))
const rfc = [
  [59, "94287082", "46119246"],
  [1111111109, "07081804", "68084774"],
  [1111111111, "14050471", "67062674"],
  [1234567890, "89005924", "91819424"],
  [2000000000, "69279037", "90698825"],
  [20000000000, "65353130", "77737706"]
]
for (const [t, want1, want256] of rfc) {
  const k1 = `otpauth://totp/rfc?secret=${sha1Secret}&digits=8`
  const k256 = `otpauth://totp/rfc?secret=${sha256Secret}&digits=8&algorithm=SHA256`
  check(`RFC 6238 SHA-1 at ${t}`, code(k1, t * 1000) === want1, `got ${code(k1, t * 1000)}`)
  check(`RFC 6238 SHA-256 at ${t}`, code(k256, t * 1000) === want256, `got ${code(k256, t * 1000)}`)
}

// --- the hashes against Node's, including multi-block and long HMAC keys -----
let hashMismatch = ""
for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 200]) {
  const data = [...crypto.randomBytes(len)]
  for (const alg of ["sha1", "sha256"]) {
    const ours = Buffer.from(Totp[alg](data)).toString("hex")
    const node = crypto.createHash(alg).update(Buffer.from(data)).digest("hex")
    if (ours !== node) hashMismatch += `${alg}/${len} `
    const key = [...crypto.randomBytes(len)]
    const mac = Buffer.from(Totp.hmac(Totp[alg], key, data)).toString("hex")
    const nodeMac = crypto.createHmac(alg, Buffer.from(key)).update(Buffer.from(data)).digest("hex")
    if (mac !== nodeMac) hashMismatch += `hmac-${alg}/${len} `
  }
}
check("SHA-1, SHA-256 and HMAC match Node's crypto", hashMismatch === "", hashMismatch)

// --- shapes left to bw ---------------------------------------------------------
const fallbacks = [
  ["", "empty key"],
  ["otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&algorithm=SHA512", "SHA-512"],
  ["otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&digits=0", "0 digits"],
  ["otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&digits=10", "10 digits"],
  ["otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&digits=12", "digits clamped to 10"],
  ["otpauth://totp/x?digits=6", "no secret"],
  ["otpauth://to tp/x?secret=WQIQ25BRKZYCJVYP", "a host the URL parser rejects"],
  ["otpauth://totp:99/x?secret=WQIQ25BRKZYCJVYP", "a port"],
  ["otpauth://totp/x?secret=WQIQ%ZZ25BRKZYCJVYP", "a broken escape"],
  ["WQIQ25BRKZYCJVYPé", "non-ASCII"]
]
for (const [key, why] of fallbacks) {
  check(`falls back to bw: ${why}`, Totp.generate(key, SDK_TIME) === null, JSON.stringify(Totp.generate(key, SDK_TIME)))
}
check("SDK defaults apply to unreadable digits and period",
  code("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&digits=six&period=-5") === "194506"
    && code("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&digits=+6&period=+30") === "194506",
  code("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&digits=six&period=-5"))
check("a zero period is raised to one second, as the SDK does",
  Totp.generate("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&period=0", SDK_TIME).period === 1,
  "period 0")
check("the last duplicate parameter wins, as in the SDK's map",
  code("otpauth://totp/x?secret=AAAA&secret=WQIQ25BRKZYCJVYP") === "194506",
  code("otpauth://totp/x?secret=AAAA&secret=WQIQ25BRKZYCJVYP"))
check("a percent-encoded secret and label decode like query_pairs()",
  code("otpauth://totp/ACME%20Co:me?issuer=ACME&secret=WQIQ%2025BRKZYCJVYP") === "194506",
  code("otpauth://totp/ACME%20Co:me?issuer=ACME&secret=WQIQ%2025BRKZYCJVYP"))

// --- Service wiring ---------------------------------------------------------------
const svc = read("Service.qml")
check("Service imports the TOTP model", /import "TotpModel\.js" as Totp/.test(svc), "missing import")
const fetch = functionBody(svc, "fetchTotp")
check("a code is computed locally before any bw start",
  /localTotp\(/.test(fetch) && fetch.indexOf("localTotp(") < fetch.indexOf("startTotpFetch("),
  fetch)
const local = functionBody(svc, "localTotp")
check("the local code comes from the key the list already holds",
  /Totp\.generate\(/.test(local) && /totpKey/.test(local),
  local)

done()
