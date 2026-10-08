//! The data of an Assuan `D` line, as `pinentry` sends it: `%`, CR and LF
//! are written as `%25`, `%0D` and `%0A`, and any byte may be written as
//! `%XX`. Unlike a URL's query, `+` stands for itself.

use zeroize::Zeroizing;

/// The decoded text, or `None` for a `%` without two hex digits, a NUL, or
/// bytes that are not UTF-8 (an environment value must be a string).
pub fn decode(encoded: &str) -> Option<Zeroizing<String>> {
    let bytes = encoded.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        let byte = if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            i += 2;
            u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?
        } else {
            bytes[i]
        };
        if byte == 0 {
            return None;
        }
        out.push(byte);
        i += 1;
    }
    let text = std::str::from_utf8(&out).ok()?;
    Some(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(value: &str) -> Option<String> {
        decode(value).map(|text| text.as_str().to_owned())
    }

    #[test]
    fn percent_and_line_breaks_come_back() {
        assert_eq!(decoded("a%25b").as_deref(), Some("a%b"));
        assert_eq!(decoded("a%0Ab%0dc").as_deref(), Some("a\nb\rc"));
        assert_eq!(decoded("%2525").as_deref(), Some("%25"));
        assert_eq!(decoded("%e2%82%ac").as_deref(), Some("\u{20ac}"));
        assert_eq!(decoded("").as_deref(), Some(""));
    }

    #[test]
    fn plus_is_not_a_space() {
        assert_eq!(decoded("a+b%2B").as_deref(), Some("a+b+"));
    }

    #[test]
    fn malformed_data_is_refused() {
        for bad in ["%", "%2", "%zz", "%+f", "%-1", "a%", "%00", "%ff", "%c3"] {
            assert_eq!(decoded(bad), None, "{bad}");
        }
    }
}
