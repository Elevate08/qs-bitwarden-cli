// TotpModel.js -- TOTP codes computed in the shell from the key the item list
// already holds, instead of a `bw get totp` start (~3 s) per code.
//
// It mirrors the Bitwarden SDK's reader (bitwarden-vault/src/totp.rs), quirks
// included, so a code always matches what `bw get totp` would print. Anything
// it does not mirror exactly (SHA-512, 0 or 10 digits, an otpauth URI the
// SDK's URL parser might read differently) returns null, and the caller asks
// bw as before.

.pragma library

var BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
var STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"
var DEFAULT_DIGITS = 6
var DEFAULT_PERIOD = 30

// { code, period } for `key` at `nowMs`, or null when bw has to answer.
function generate(key, nowMs) {
  var params = parseKey(key)
  if (!params) return null
  var counter = Math.floor(Math.floor(Number(nowMs) / 1000) / params.period)
  if (!isFinite(counter) || counter < 0) return null
  return { code: deriveOtp(params, counter), period: params.period }
}

// { algorithm: "sha1" | "sha256" | "steam", digits, period, secret: bytes }.
function parseKey(key) {
  if (typeof key !== "string" || key === "") return null
  // Unicode case rules are where Rust and JS could part ways.
  if (/[^\x00-\x7f]/.test(key)) return null
  var k = key.toLowerCase()

  if (k.indexOf("otpauth://") === 0) return parseOtpauth(k)
  if (k.indexOf("steam://") === 0) {
    return { algorithm: "steam", digits: 5, period: DEFAULT_PERIOD,
      secret: decodeBase32(k.slice("steam://".length)) }
  }
  return { algorithm: "sha1", digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD, secret: decodeBase32(k) }
}

function parseOtpauth(k) {
  var rest = k.slice("otpauth://".length)
  var hash = rest.indexOf("#")
  if (hash !== -1) rest = rest.slice(0, hash)
  var q = rest.indexOf("?")
  var authority = (q === -1 ? rest : rest.slice(0, q)).split("/")[0]
  // A host the URL parser would refuse (or a port) is bw's to judge.
  if (!/^[a-z0-9._~-]*$/.test(authority)) return null
  if (/[\s\x00-\x1f\x7f]/.test(rest)) return null

  var parts = {}
  var query = q === -1 ? "" : rest.slice(q + 1)
  var pairs = query.split("&")
  for (var i = 0; i < pairs.length; i++) {
    if (pairs[i] === "") continue
    var eq = pairs[i].indexOf("=")
    var name = formDecode(eq === -1 ? pairs[i] : pairs[i].slice(0, eq))
    var value = formDecode(eq === -1 ? "" : pairs[i].slice(eq + 1))
    if (name === null || value === null) return null
    // The SDK collects into a map, so the last duplicate wins.
    parts[name] = value
  }
  if (!Object.prototype.hasOwnProperty.call(parts, "secret")) return null

  var algorithm = "sha1"
  if (parts.algorithm === "sha256") algorithm = "sha256"
  else if (parts.algorithm === "sha512") return null

  var digits = parseU32(parts.digits)
  digits = digits === null ? DEFAULT_DIGITS : Math.min(digits, 10)
  // 0 and 10 digits hit integer edge cases in the SDK; leave those to it.
  if (digits < 1 || digits > 9) return null

  var period = parseU32(parts.period)
  period = period === null ? DEFAULT_PERIOD : Math.max(period, 1)

  return { algorithm: algorithm, digits: digits, period: period, secret: decodeBase32(parts.secret) }
}

// application/x-www-form-urlencoded, as the SDK's query_pairs() reads it.
function formDecode(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "))
  } catch (e) {
    return null
  }
}

// Rust's `str::parse::<u32>()`: optional `+`, digits, no overflow.
function parseU32(v) {
  if (v === undefined) return null
  if (!/^\+?[0-9]+$/.test(v)) return null
  var n = Number(v.replace(/^\+/, ""))
  return n <= 4294967295 ? n : null
}

// Not strict base32, on purpose: the SDK drops every character outside the
// alphabet and discards trailing bits that do not fill a byte.
function decodeBase32(s) {
  var upper = String(s).toUpperCase()
  var bytes = []
  var buffer = 0
  var bits = 0
  for (var i = 0; i < upper.length; i++) {
    var idx = BASE32_CHARS.indexOf(upper.charAt(i))
    if (idx === -1) continue
    buffer = ((buffer << 5) | idx) & 0xffff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >>> bits) & 0xff)
    }
  }
  return bytes
}

function deriveOtp(params, counter) {
  var time = []
  var hi = Math.floor(counter / 4294967296)
  var lo = counter % 4294967296
  for (var i = 3; i >= 0; i--) time.push((hi >>> (i * 8)) & 0xff)
  for (var j = 3; j >= 0; j--) time.push((lo >>> (j * 8)) & 0xff)

  var hash = hmac(params.algorithm === "sha256" ? sha256 : sha1, params.secret, time)
  var offset = hash[hash.length - 1] & 15
  var binary = ((hash[offset] & 127) * 16777216)
    + (hash[offset + 1] << 16) + (hash[offset + 2] << 8) + hash[offset + 3]

  if (params.algorithm === "steam") {
    var code = ""
    var full = binary
    for (var d = 0; d < params.digits; d++) {
      code += STEAM_CHARS.charAt(full % STEAM_CHARS.length)
      full = Math.floor(full / STEAM_CHARS.length)
    }
    return code
  }
  var otp = String(binary % Math.pow(10, params.digits))
  while (otp.length < params.digits) otp = "0" + otp
  return otp
}

// -------------------------------------------------------------------------
// HMAC, SHA-1 and SHA-256 over byte arrays
// -------------------------------------------------------------------------

function hmac(hashFn, key, message) {
  var block = 64
  var k = key.length > block ? hashFn(key) : key.slice()
  while (k.length < block) k.push(0)
  var inner = []
  var outer = []
  for (var i = 0; i < block; i++) {
    inner.push(k[i] ^ 0x36)
    outer.push(k[i] ^ 0x5c)
  }
  return hashFn(outer.concat(hashFn(inner.concat(message))))
}

// Message padding shared by both: 0x80, zeros, then the bit length as 64 bits.
function padMessage(bytes) {
  var padded = bytes.slice()
  var bitLength = bytes.length * 8
  padded.push(0x80)
  while (padded.length % 64 !== 56) padded.push(0)
  var hi = Math.floor(bitLength / 4294967296)
  for (var i = 3; i >= 0; i--) padded.push((hi >>> (i * 8)) & 0xff)
  for (var j = 3; j >= 0; j--) padded.push((bitLength >>> (j * 8)) & 0xff)
  return padded
}

function wordsToBytes(words) {
  var out = []
  for (var i = 0; i < words.length; i++) {
    out.push((words[i] >>> 24) & 0xff, (words[i] >>> 16) & 0xff, (words[i] >>> 8) & 0xff, words[i] & 0xff)
  }
  return out
}

function rotl(x, n) {
  return (x << n) | (x >>> (32 - n))
}

function sha1(bytes) {
  var m = padMessage(bytes)
  var h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
  var w = new Array(80)
  for (var off = 0; off < m.length; off += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) | (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3]
    }
    for (var t = 16; t < 80; t++) w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4]
    for (var s = 0; s < 80; s++) {
      var f, k
      if (s < 20) { f = (b & c) | (~b & d); k = 0x5a827999 }
      else if (s < 40) { f = b ^ c ^ d; k = 0x6ed9eba1 }
      else if (s < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc }
      else { f = b ^ c ^ d; k = 0xca62c1d6 }
      var temp = (rotl(a, 5) + f + e + k + w[s]) | 0
      e = d; d = c; c = rotl(b, 30); b = a; a = temp
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0
    h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0
  }
  return wordsToBytes(h)
}

var SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n))
}

function sha256(bytes) {
  var m = padMessage(bytes)
  var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  var w = new Array(64)
  for (var off = 0; off < m.length; off += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) | (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3]
    }
    for (var t = 16; t < 64; t++) {
      var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)
      var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0
    }
    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
    for (var r = 0; r < 64; r++) {
      var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      var ch = (e & f) ^ (~e & g)
      var temp1 = (hh + S1 + ch + SHA256_K[r] + w[r]) | 0
      var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      var maj = (a & b) ^ (a & c) ^ (b & c)
      var temp2 = (S0 + maj) | 0
      hh = g; g = f; f = e; e = (d + temp1) | 0
      d = c; c = b; b = a; a = (temp1 + temp2) | 0
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0
  }
  return wordsToBytes(h)
}
