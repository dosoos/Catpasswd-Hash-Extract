//! PDF extractor (`$pdf$`, hashcat 10400/10500/10600/10700).
//!
//! Locates the `/Encrypt` dictionary via the trailer reference and parses the
//! standard security handler fields (V, R, Length, P, O, U, OE, UE, ID,
//! EncryptMetadata). Output follows the documented hashcat shape:
//! `$pdf$V*R*Length*P*EncryptMeta*IDLen*ID*ULen*U*OLen*O*[UELen*UE*OELen*OE]`.
//! Implemented from the PDF encryption-dictionary specification.

use std::path::Path;

use super::util::hex_encode;
use crate::models::HashResult;

const FORMAT: &str = "pdf";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let buf = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}")),
    };

    if find(&buf, b"/Encrypt").is_none() {
        return HashResult::warn(
            FORMAT,
            source_name,
            "PDF has no /Encrypt: not password-protected",
        );
    }

    let dict = match locate_encrypt_dict(&buf) {
        Some(d) => d,
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                "found /Encrypt but could not locate its dictionary",
            )
        }
    };

    // Only the standard security handler is supported here.
    if let Some(filter) = name_after(&dict, b"/Filter") {
        if filter != "Standard" {
            return HashResult::warn(
                FORMAT,
                source_name,
                format!("unsupported PDF security handler /Filter /{filter}"),
            );
        }
    }

    let v = int_after(&dict, b"/V").unwrap_or(0);
    let r = match int_after(&dict, b"/R") {
        Some(r) => r,
        None => return HashResult::err(FORMAT, source_name, "PDF /Encrypt missing /R revision"),
    };
    let length = int_after(&dict, b"/Length").unwrap_or(40);
    let p = match int_after(&dict, b"/P") {
        Some(p) => p,
        None => return HashResult::err(FORMAT, source_name, "PDF /Encrypt missing /P permissions"),
    };
    let encrypt_meta = match bool_after(&dict, b"/EncryptMetadata") {
        Some(false) => 0,
        _ => 1,
    };

    let o = string_after(&dict, b"/O");
    let u = string_after(&dict, b"/U");
    let (o, u) = match (o, u) {
        (Some(o), Some(u)) => (o, u),
        _ => return HashResult::err(FORMAT, source_name, "PDF /Encrypt missing /O or /U string"),
    };

    let id = trailer_id(&buf).unwrap_or_default();

    let mode = match r {
        2 => 10400,
        3 | 4 => 10500,
        5 => 10600,
        6 => 10700,
        other => {
            return HashResult::warn(
                FORMAT,
                source_name,
                format!("unsupported PDF revision R={other}"),
            )
        }
    };

    let mut line = format!(
        "$pdf${v}*{r}*{length}*{p}*{meta}*{idlen}*{id}*{ulen}*{u}*{olen}*{o}",
        v = v,
        r = r,
        length = length,
        p = p,
        meta = encrypt_meta,
        idlen = id.len(),
        id = hex_encode(&id),
        ulen = u.len(),
        u = hex_encode(&u),
        olen = o.len(),
        o = hex_encode(&o),
    );

    let mut warnings: Vec<String> = Vec::new();

    if r >= 5 {
        // Revision 5/6 also require the OE / UE encryption keys.
        let oe = string_after(&dict, b"/OE");
        let ue = string_after(&dict, b"/UE");
        match (ue, oe) {
            (Some(ue), Some(oe)) => {
                line.push_str(&format!(
                    "*{uelen}*{ue}*{oelen}*{oe}",
                    uelen = ue.len(),
                    ue = hex_encode(&ue),
                    oelen = oe.len(),
                    oe = hex_encode(&oe),
                ));
            }
            _ => warnings.push("PDF R>=5 missing /UE or /OE; hash line is incomplete".to_string()),
        }
    }

    let mut res = HashResult::ok(FORMAT, source_name, line, Some(mode));
    for w in warnings {
        res = res.with_warning(w);
    }
    res
}

/// Find the `/Encrypt` reference in the file and return the bytes of the
/// referenced object's dictionary (between `<<` and its matching `>>`).
fn locate_encrypt_dict(buf: &[u8]) -> Option<Vec<u8>> {
    // Scan every "/Encrypt" occurrence; the trailer one points to `N G R`.
    let mut from = 0usize;
    while let Some(rel) = find(&buf[from..], b"/Encrypt") {
        let pos = from + rel + b"/Encrypt".len();
        from = pos;
        if let Some((obj_num, is_ref)) = parse_ref(buf, pos) {
            if is_ref {
                if let Some(d) = object_dict(buf, obj_num) {
                    return Some(d);
                }
            } else if let Some(d) = inline_dict(buf, pos) {
                // Direct dictionary immediately after /Encrypt.
                return Some(d);
            }
        }
    }
    None
}

/// Parse an indirect reference `N G R` following `pos`. Returns (obj_num, true)
/// on a reference, or (0, false) if what follows looks like an inline dict.
fn parse_ref(buf: &[u8], pos: usize) -> Option<(u64, bool)> {
    let mut i = pos;
    skip_ws(buf, &mut i);
    if buf.get(i) == Some(&b'<') {
        return Some((0, false));
    }
    let num = read_uint(buf, &mut i)?;
    skip_ws(buf, &mut i);
    let _gen = read_uint(buf, &mut i)?;
    skip_ws(buf, &mut i);
    if buf.get(i) == Some(&b'R') {
        return Some((num, true));
    }
    None
}

fn object_dict(buf: &[u8], obj_num: u64) -> Option<Vec<u8>> {
    // Find "<obj_num> <gen> obj".
    let needle = format!("{obj_num} ");
    let mut from = 0usize;
    while let Some(rel) = find(&buf[from..], needle.as_bytes()) {
        let pos = from + rel;
        // Require token boundary before the number.
        let ok_before = pos == 0 || is_ws(buf[pos - 1]) || buf[pos - 1] == b'>';
        let mut i = pos + needle.len();
        let _gen = read_uint(buf, &mut i);
        skip_ws(buf, &mut i);
        if ok_before && buf.get(i..i + 3) == Some(b"obj") {
            return inline_dict(buf, i + 3);
        }
        from = pos + needle.len();
    }
    None
}

/// Extract the bytes inside the first balanced `<< >>` at/after `start`.
///
/// The scan is string-aware: literal `( )` and hex `< >` strings are skipped so
/// that a hex string closing right before the dict end (`<...>>>`) or a `>>`
/// byte sequence inside a string does not terminate the dictionary early.
fn inline_dict(buf: &[u8], start: usize) -> Option<Vec<u8>> {
    let open = find(&buf[start..], b"<<").map(|r| start + r)?;
    let mut depth = 0i32;
    let mut i = open;
    while i < buf.len() {
        if i + 1 < buf.len() && &buf[i..i + 2] == b"<<" {
            depth += 1;
            i += 2;
            continue;
        }
        if i + 1 < buf.len() && &buf[i..i + 2] == b">>" {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Some(buf[open + 2..i - 2].to_vec());
            }
            continue;
        }
        match buf[i] {
            b'(' => i = end_of_literal(buf, i),
            b'<' => {
                // Single '<' begins a hex string; skip to its '>'.
                i += 1;
                while i < buf.len() && buf[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Return the index just past the closing `)` of the literal string at `start`.
fn end_of_literal(buf: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    let mut depth = 1i32;
    while i < buf.len() {
        match buf[i] {
            b'\\' => i += 2,
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    i
}

fn trailer_id(buf: &[u8]) -> Option<Vec<u8>> {
    let mut i = find(buf, b"/ID")? + b"/ID".len();
    skip_ws(buf, &mut i);
    if buf.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    skip_ws(buf, &mut i);
    read_string_at(buf, i)
}

// ------------------------- dictionary value readers -------------------------

fn int_after(dict: &[u8], key: &[u8]) -> Option<i64> {
    let mut i = key_value_pos(dict, key)?;
    let start = i;
    if matches!(dict.get(i), Some(b'-') | Some(b'+')) {
        i += 1;
    }
    while i < dict.len() && dict[i].is_ascii_digit() {
        i += 1;
    }
    if i == start || (i == start + 1 && !dict[start].is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(&dict[start..i]).ok()?.parse().ok()
}

fn bool_after(dict: &[u8], key: &[u8]) -> Option<bool> {
    let i = key_value_pos(dict, key)?;
    if dict[i..].starts_with(b"true") {
        Some(true)
    } else if dict[i..].starts_with(b"false") {
        Some(false)
    } else {
        None
    }
}

fn name_after(dict: &[u8], key: &[u8]) -> Option<String> {
    let mut i = key_value_pos(dict, key)?;
    if dict.get(i) != Some(&b'/') {
        return None;
    }
    i += 1;
    let start = i;
    while i < dict.len() && !is_delim(dict[i]) && !is_ws(dict[i]) {
        i += 1;
    }
    Some(String::from_utf8_lossy(&dict[start..i]).into_owned())
}

fn string_after(dict: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let i = key_value_pos(dict, key)?;
    read_string_at(dict, i)
}

/// Position of the value byte immediately following `key` (whitespace skipped),
/// requiring a delimiter/whitespace right after the key name.
fn key_value_pos(dict: &[u8], key: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    while let Some(rel) = find(&dict[from..], key) {
        let pos = from + rel;
        let after = pos + key.len();
        let boundary = dict
            .get(after)
            .map(|&b| is_ws(b) || is_delim(b))
            .unwrap_or(true);
        if boundary {
            let mut i = after;
            skip_ws(dict, &mut i);
            if i < dict.len() {
                return Some(i);
            }
        }
        from = pos + key.len();
    }
    None
}

fn read_string_at(buf: &[u8], i: usize) -> Option<Vec<u8>> {
    match buf.get(i)? {
        b'(' => parse_literal_string(buf, i),
        b'<' => parse_hex_string(buf, i),
        _ => None,
    }
}

fn parse_hex_string(buf: &[u8], start: usize) -> Option<Vec<u8>> {
    let mut i = start + 1; // skip '<'
    let mut nibbles = Vec::new();
    while i < buf.len() && buf[i] != b'>' {
        let c = buf[i];
        if let Some(v) = hex_val(c) {
            nibbles.push(v);
        }
        i += 1;
    }
    if buf.get(i) != Some(&b'>') {
        return None;
    }
    let mut out = Vec::with_capacity((nibbles.len() + 1) / 2);
    let mut it = nibbles.chunks(2);
    for chunk in &mut it {
        let hi = chunk[0];
        let lo = if chunk.len() == 2 { chunk[1] } else { 0 };
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn parse_literal_string(buf: &[u8], start: usize) -> Option<Vec<u8>> {
    let mut i = start + 1; // skip '('
    let mut depth = 1i32;
    let mut out = Vec::new();
    while i < buf.len() {
        let c = buf[i];
        match c {
            b'\\' => {
                i += 1;
                let e = *buf.get(i)?;
                match e {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'(' => out.push(b'('),
                    b')' => out.push(b')'),
                    b'\\' => out.push(b'\\'),
                    b'0'..=b'7' => {
                        // up to 3 octal digits
                        let mut val = (e - b'0') as u32;
                        for _ in 0..2 {
                            if let Some(&d) = buf.get(i + 1) {
                                if (b'0'..=b'7').contains(&d) {
                                    val = val * 8 + (d - b'0') as u32;
                                    i += 1;
                                    continue;
                                }
                            }
                            break;
                        }
                        out.push(val as u8);
                    }
                    b'\n' => {}
                    b'\r' => {
                        if buf.get(i + 1) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    other => out.push(other),
                }
                i += 1;
            }
            b'(' => {
                depth += 1;
                out.push(c);
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(out);
                }
                out.push(c);
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    None
}

// ------------------------------- byte helpers -------------------------------

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x00 | 0x0c)
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn skip_ws(buf: &[u8], i: &mut usize) {
    while *i < buf.len() && is_ws(buf[*i]) {
        *i += 1;
    }
}

fn read_uint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let start = *i;
    while *i < buf.len() && buf[*i].is_ascii_digit() {
        *i += 1;
    }
    if *i == start {
        return None;
    }
    std::str::from_utf8(&buf[start..*i]).ok()?.parse().ok()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ints_and_bools() {
        let dict = b"/V 4 /R 4 /P -1028 /Length 128 /EncryptMetadata false";
        assert_eq!(int_after(dict, b"/V"), Some(4));
        assert_eq!(int_after(dict, b"/P"), Some(-1028));
        assert_eq!(int_after(dict, b"/Length"), Some(128));
        assert_eq!(bool_after(dict, b"/EncryptMetadata"), Some(false));
    }

    #[test]
    fn parses_hex_string() {
        let dict = b"/O <41424300>";
        assert_eq!(string_after(dict, b"/O"), Some(vec![0x41, 0x42, 0x43, 0x00]));
    }

    #[test]
    fn parses_literal_string_with_escape() {
        let dict = b"/U (AB\\)C)";
        assert_eq!(string_after(dict, b"/U"), Some(b"AB)C".to_vec()));
    }

    #[test]
    fn full_r4_line() {
        let buf = b"trailer<</Encrypt 5 0 R/ID[<0011>]>>\n5 0 obj<</Filter/Standard/V 4/R 4/Length 128/P -1028/O <4f4f4f4f>/U <55555555>>>endobj";
        let res = extract_bytes(buf, "t.pdf");
        assert_eq!(res.hashcat_mode, Some(10500));
        assert!(res.hash_line.contains("$pdf$4*4*128*-1028*1*2*0011*4*55555555*4*4f4f4f4f"));
    }

    // Test-only helper mirroring `extract` but taking bytes.
    fn extract_bytes(buf: &[u8], source_name: &str) -> HashResult {
        let dict = locate_encrypt_dict(buf).expect("dict");
        let v = int_after(&dict, b"/V").unwrap();
        let r = int_after(&dict, b"/R").unwrap();
        let length = int_after(&dict, b"/Length").unwrap();
        let p = int_after(&dict, b"/P").unwrap();
        let o = string_after(&dict, b"/O").unwrap();
        let u = string_after(&dict, b"/U").unwrap();
        let id = trailer_id(buf).unwrap_or_default();
        let mode = match r {
            2 => 10400,
            3 | 4 => 10500,
            5 => 10600,
            6 => 10700,
            _ => 0,
        };
        let line = format!(
            "$pdf${v}*{r}*{length}*{p}*1*{idlen}*{id}*{ulen}*{u}*{olen}*{o}",
            idlen = id.len(),
            id = hex_encode(&id),
            ulen = u.len(),
            u = hex_encode(&u),
            olen = o.len(),
            o = hex_encode(&o),
        );
        HashResult::ok(FORMAT, source_name, line, Some(mode))
    }
}
