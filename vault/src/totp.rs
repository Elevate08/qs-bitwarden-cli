//! TOTP codes from an item's key, mirroring the Bitwarden SDK's reader
//! (bitwarden-vault/src/totp.rs) quirks included, as TotpModel.js does, so a
//! code always matches what `bw get totp` prints. Anything not mirrored
//! exactly (SHA-512, 0 or 10 digits, an otpauth URI the SDK's URL parser might
//! read differently) is `None`, and the panel asks `bw`.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Steam,
}

struct Params {
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    secret: Zeroizing<Vec<u8>>,
}

/// The code for `key` at `now_secs`, and its period.
pub fn generate(key: &str, now_secs: u64) -> Option<(String, u64)> {
    let params = parse_key(key)?;
    let counter = now_secs / params.period;
    Some((derive(&params, counter), params.period))
}

fn parse_key(key: &str) -> Option<Params> {
    // Unicode case rules are where Rust and JS could part ways.
    if key.is_empty() || !key.is_ascii() {
        return None;
    }
    let lower = Zeroizing::new(key.to_ascii_lowercase());
    if let Some(rest) = lower.strip_prefix("otpauth://") {
        return parse_otpauth(rest);
    }
    if let Some(rest) = lower.strip_prefix("steam://") {
        return Some(Params {
            algorithm: Algorithm::Steam,
            digits: 5,
            period: DEFAULT_PERIOD,
            secret: base32(rest),
        });
    }
    Some(Params {
        algorithm: Algorithm::Sha1,
        digits: DEFAULT_DIGITS,
        period: DEFAULT_PERIOD,
        secret: base32(&lower),
    })
}

fn parse_otpauth(rest: &str) -> Option<Params> {
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = match rest.find('?') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, ""),
    };
    let authority = path.split('/').next().unwrap_or("");
    // A host the URL parser would refuse (or a port) is bw's to judge.
    if !authority
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._~-".contains(&b))
    {
        return None;
    }
    if rest
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b < 0x20 || b == 0x7f)
    {
        return None;
    }
    let mut secret: Option<Zeroizing<String>> = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = match pair.find('=') {
            Some(at) => (&pair[..at], &pair[at + 1..]),
            None => (pair, ""),
        };
        let name = form_decode(name)?;
        let value = Zeroizing::new(form_decode(value)?);
        // The SDK collects into a map, so the last duplicate wins.
        match name.as_str() {
            "secret" => secret = Some(value),
            "algorithm" => algorithm = Some(value.to_string()),
            "digits" => digits = Some(value.to_string()),
            "period" => period = Some(value.to_string()),
            _ => {}
        }
    }
    let secret = secret?;
    let algorithm = match algorithm.as_deref() {
        Some("sha256") => Algorithm::Sha256,
        Some("sha512") => return None,
        _ => Algorithm::Sha1,
    };
    let digits = digits
        .as_deref()
        .and_then(parse_u32)
        .map_or(DEFAULT_DIGITS, |d| d.min(10));
    // 0 and 10 digits hit integer edge cases in the SDK; leave those to it.
    if !(1..=9).contains(&digits) {
        return None;
    }
    let period = period
        .as_deref()
        .and_then(parse_u32)
        .map_or(DEFAULT_PERIOD, |p| u64::from(p.max(1)));
    Some(Params {
        algorithm,
        digits,
        period,
        secret: base32(&secret),
    })
}

/// application/x-www-form-urlencoded, as the SDK's query_pairs() reads it;
/// `None` where JS's decodeURIComponent would throw.
fn form_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                // Exactly two hex digits: from_str_radix would also take a
                // leading `+`, so `%+f` would decode.
                let hex = bytes.get(i + 1..i + 3)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                let text = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(text, 16).ok()?);
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Rust's `str::parse::<u32>()`: optional `+`, digits, no overflow.
fn parse_u32(value: &str) -> Option<u32> {
    value.parse::<u32>().ok()
}

/// Not strict base32, on purpose: the SDK drops every character outside the
/// alphabet and discards trailing bits that do not fill a byte.
fn base32(input: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in input.bytes() {
        let Some(index) = BASE32.iter().position(|c| *c == byte.to_ascii_uppercase()) else {
            continue;
        };
        buffer = ((buffer << 5) | index as u32) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

fn derive(params: &Params, counter: u64) -> String {
    let time = counter.to_be_bytes();
    let hash: Zeroizing<Vec<u8>> = Zeroizing::new(match params.algorithm {
        Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(&params.secret, &time),
        Algorithm::Sha1 | Algorithm::Steam => mac::<Hmac<sha1::Sha1>>(&params.secret, &time),
    });
    let offset = usize::from(hash[hash.len() - 1] & 15);
    let binary = (u32::from(hash[offset] & 127) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    if params.algorithm == Algorithm::Steam {
        let mut full = binary;
        let mut code = String::with_capacity(params.digits as usize);
        for _ in 0..params.digits {
            code.push(char::from(STEAM[(full % 26) as usize]));
            full /= 26;
        }
        return code;
    }
    let modulus = 10_u32.pow(params.digits);
    format!(
        "{:0width$}",
        binary % modulus,
        width = params.digits as usize
    )
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B: the ASCII secret "12345678901234567890" (base32
    // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ), 8 digits via otpauth.
    const RFC_SHA1: &str = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";

    #[test]
    fn form_decode_needs_two_hex_digits() {
        assert_eq!(form_decode("%41").as_deref(), Some("A"));
        assert_eq!(form_decode("a%2Fb+c").as_deref(), Some("a/b c"));
        for bad in ["%+f", "%-1", "%2", "%zz", "%", "%4"] {
            assert_eq!(form_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn rfc_6238_vectors() {
        assert_eq!(generate(RFC_SHA1, 59).unwrap().0, "94287082");
        assert_eq!(generate(RFC_SHA1, 1111111109).unwrap().0, "07081804");
        assert_eq!(generate(RFC_SHA1, 20000000000).unwrap().0, "65353130");
        let sha256 = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256";
        assert_eq!(generate(sha256, 59).unwrap().0, "46119246");
    }

    #[test]
    fn plain_keys_and_quirks() {
        // Lowercase, spaces and padding are dropped like the SDK does.
        let (code, period) = generate("gezd gnbv gy3t qojq gezd gnbv gy3t qojq====", 59).unwrap();
        assert_eq!((code.as_str(), period), ("287082", 30));
        assert_eq!(
            generate(
                "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA512",
                59
            ),
            None
        );
        assert_eq!(
            generate("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=10", 59),
            None
        );
        assert_eq!(generate("otpauth://totp/x?digits=6", 59), None);
        assert_eq!(generate("otpauth://host:443/x?secret=AAAA", 59), None);
        assert_eq!(generate("ünicode", 59), None);
        assert_eq!(generate("", 59), None);
        assert_eq!(
            generate("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=60", 59)
                .unwrap()
                .1,
            60
        );
        assert_eq!(
            generate("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=0", 59)
                .unwrap()
                .1,
            1
        );
    }

    #[test]
    fn steam_codes_are_five_letters_from_its_alphabet() {
        let (code, _) = generate("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM.contains(&b)));
    }
}
