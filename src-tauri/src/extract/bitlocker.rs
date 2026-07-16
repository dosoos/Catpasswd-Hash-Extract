//! BitLocker (FVE) extractor (`$bitlocker$`, hashcat 22100).
//!
//! Pure functions over byte slices (unit-testable without a real disk):
//!
//! * [`parse_volume_header`] — BitLocker volume header → three FVE metadata offsets
//! * [`extract_from_fve_block`] — walk FVE entries for a password-protected VMK
//!
//! Layout follows the public BDE format (libbde) and hashcat's MIT
//! `bitlocker2hashcat.py`: password VMK → stretch-key salt + AES-CCM nonce/MAC/key
//! → `$bitlocker$0$16$<salt>$1048576$12$<nonce>$<mac+key_len>$<mac><key>`.

use super::util::{hex_encode, read_u16_le, read_u32_le, read_u64_le};
use crate::models::HashResult;

pub const FORMAT: &str = "bitlocker";

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const MAC_SIZE: usize = 16;
/// BitLocker password KDF iteration count (2^20).
const ITERATIONS: u32 = 0x0010_0000;

const FVE_SIGNATURE: &[u8] = b"-FVE-FS-";
const TOGO_SIGNATURE: &[u8] = b"MSWIN4.1";

/// Nested property: stretch key (holds the password salt).
const VALUE_STRETCH_KEY: u16 = 0x0003;
/// Nested property: AES-CCM encrypted VMK.
const VALUE_AES_CCM: u16 = 0x0005;
/// Top-level FVE value type: Volume Master Key structure.
const VALUE_VMK: u16 = 0x0008;

const PROT_PASSWORD: u16 = 0x2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    Vista,
    Win7,
    ToGo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FveLocation {
    pub kind: HeaderKind,
    pub offsets: [u64; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protector {
    Clear,
    Tpm,
    StartupKey,
    TpmAndPin,
    Recovery,
    Password,
    Other(u16),
}

impl Protector {
    fn from_raw(v: u16) -> Self {
        match v {
            0x0000 => Protector::Clear,
            0x0100 => Protector::Tpm,
            0x0200 => Protector::StartupKey,
            0x0500 => Protector::TpmAndPin,
            0x0800 => Protector::Recovery,
            0x2000 => Protector::Password,
            other => Protector::Other(other),
        }
    }

    fn label(self) -> String {
        match self {
            Protector::Clear => "clear key".into(),
            Protector::Tpm => "TPM".into(),
            Protector::StartupKey => "startup key".into(),
            Protector::TpmAndPin => "TPM+PIN".into(),
            Protector::Recovery => "recovery password".into(),
            Protector::Password => "password".into(),
            Protector::Other(v) => format!("unknown (0x{v:04x})"),
        }
    }
}

pub fn parse_volume_header(sector: &[u8]) -> Option<FveLocation> {
    if sector.len() < 512 {
        return None;
    }
    let sig = &sector[3..11];

    if sig == FVE_SIGNATURE {
        if sector[1] == 0x52 {
            let bytes_per_sector = read_u16_le(sector, 11)? as u64;
            let sectors_per_cluster = sector[13] as u64;
            let cluster = read_u64_le(sector, 56)?;
            let cluster_size = bytes_per_sector.checked_mul(sectors_per_cluster)?;
            let off = cluster.checked_mul(cluster_size)?;
            return Some(FveLocation {
                kind: HeaderKind::Vista,
                offsets: [off, 0, 0],
            });
        }
        return Some(FveLocation {
            kind: HeaderKind::Win7,
            offsets: [
                read_u64_le(sector, 176)?,
                read_u64_le(sector, 184)?,
                read_u64_le(sector, 192)?,
            ],
        });
    }

    if sig == TOGO_SIGNATURE {
        return Some(FveLocation {
            kind: HeaderKind::ToGo,
            offsets: [
                read_u64_le(sector, 440)?,
                read_u64_le(sector, 448)?,
                read_u64_le(sector, 456)?,
            ],
        });
    }

    None
}

#[allow(dead_code)]
pub fn is_bitlocker_header(sector: &[u8]) -> bool {
    parse_volume_header(sector).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordVmk {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub mac: [u8; MAC_SIZE],
    /// AES-CCM ciphertext of the VMK (typically 44 bytes).
    pub enc_key: Vec<u8>,
}

impl PasswordVmk {
    pub fn hash_line(&self) -> String {
        let mac_and_key_len = MAC_SIZE + self.enc_key.len();
        format!(
            "$bitlocker$0${}${}${}${}${}${}${}{}",
            SALT_SIZE,
            hex_encode(&self.salt),
            ITERATIONS,
            NONCE_SIZE,
            hex_encode(&self.nonce),
            mac_and_key_len,
            hex_encode(&self.mac),
            hex_encode(&self.enc_key),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub password: Option<PasswordVmk>,
    pub protectors: Vec<Protector>,
    /// Password VMK was seen but stretch-key / AES-CCM material could not be parsed.
    pub password_parse_failed: bool,
}

/// Scan one FVE metadata block for a password-protected VMK.
pub fn extract_from_fve_block(block: &[u8]) -> ScanResult {
    if let Some(off) = find_fve_signature(block) {
        return walk_fve_entries(&block[off..]);
    }
    ScanResult::default()
}

fn find_fve_signature(block: &[u8]) -> Option<usize> {
    block.windows(FVE_SIGNATURE.len()).position(|w| w == FVE_SIGNATURE)
}

fn walk_fve_entries(block: &[u8]) -> ScanResult {
    let mut result = ScanResult::default();
    if block.len() < 112 + 8 || &block[0..8] != FVE_SIGNATURE {
        return result;
    }

    // Metadata header starts at offset 64; size includes that header.
    let meta_size = match read_u32_le(block, 64) {
        Some(s) if s >= 48 => s as usize,
        _ => return result,
    };
    let end = (64usize.saturating_add(meta_size)).min(block.len());

    let mut pos = 112usize;
    while pos + 8 <= end {
        let entry_size = match read_u16_le(block, pos) {
            Some(s) if (s as usize) >= 8 => s as usize,
            _ => break,
        };
        if pos + entry_size > block.len() {
            break;
        }
        let value_type = match read_u16_le(block, pos + 4) {
            Some(v) => v,
            None => break,
        };
        let data = &block[pos + 8..pos + entry_size];

        if value_type == VALUE_VMK {
            parse_vmk_entry(data, &mut result);
        }

        pos += entry_size;
    }

    result
}

fn parse_vmk_entry(vmk_data: &[u8], result: &mut ScanResult) {
    if vmk_data.len() < 28 {
        return;
    }
    let raw = match read_u16_le(vmk_data, 26) {
        Some(v) => v,
        None => return,
    };
    let protector = Protector::from_raw(raw);
    if !result.protectors.contains(&protector) {
        result.protectors.push(protector);
    }

    if protector != Protector::Password {
        return;
    }

    match parse_password_vmk_properties(vmk_data) {
        Some(vmk) if result.password.is_none() => {
            result.password = Some(vmk);
        }
        None => {
            result.password_parse_failed = true;
        }
        _ => {}
    }
}

/// Walk nested FVE properties under a password VMK: stretch key (salt) + AES-CCM.
fn parse_password_vmk_properties(vmk_data: &[u8]) -> Option<PasswordVmk> {
    let prot = read_u16_le(vmk_data, 26)?;
    if prot != PROT_PASSWORD {
        return None;
    }

    let mut salt: Option<[u8; SALT_SIZE]> = None;
    let mut nonce = [0u8; NONCE_SIZE];
    let mut mac = [0u8; MAC_SIZE];
    let mut enc_key: Option<Vec<u8>> = None;

    let mut pos = 28usize;
    while pos + 8 <= vmk_data.len() {
        let entry_size = read_u16_le(vmk_data, pos)? as usize;
        if entry_size < 8 || pos + entry_size > vmk_data.len() {
            break;
        }
        let value_type = read_u16_le(vmk_data, pos + 4)?;
        let data = &vmk_data[pos + 8..pos + entry_size];

        match value_type {
            VALUE_STRETCH_KEY => {
                if data.len() >= 4 + SALT_SIZE {
                    let mut s = [0u8; SALT_SIZE];
                    s.copy_from_slice(&data[4..4 + SALT_SIZE]);
                    salt = Some(s);
                }
            }
            VALUE_AES_CCM => {
                if data.len() >= NONCE_SIZE + MAC_SIZE + 1 {
                    nonce.copy_from_slice(&data[0..NONCE_SIZE]);
                    mac.copy_from_slice(&data[NONCE_SIZE..NONCE_SIZE + MAC_SIZE]);
                    enc_key = Some(data[NONCE_SIZE + MAC_SIZE..].to_vec());
                }
            }
            _ => {}
        }

        pos += entry_size;
    }

    Some(PasswordVmk {
        salt: salt?,
        nonce,
        mac,
        enc_key: enc_key?,
    })
}

pub fn result_from_scans(source_name: &str, scans: &[ScanResult]) -> HashResult {
    for scan in scans {
        if let Some(vmk) = &scan.password {
            return HashResult::ok(FORMAT, source_name, vmk.hash_line(), Some(22100));
        }
    }

    let mut protectors: Vec<String> = Vec::new();
    let mut password_parse_failed = false;
    for scan in scans {
        password_parse_failed |= scan.password_parse_failed;
        for p in &scan.protectors {
            let label = p.label();
            if !protectors.contains(&label) {
                protectors.push(label);
            }
        }
    }

    if protectors.is_empty() {
        return HashResult::warn(
            FORMAT,
            source_name,
            "BitLocker volume found but no VMK key protectors were located in the FVE metadata",
        );
    }

    if password_parse_failed || protectors.iter().any(|p| p == "password") {
        return HashResult::warn(
            FORMAT,
            source_name,
            format!(
                "password protector present but hash material could not be parsed \
                 (protectors: {}). Try again or report this volume layout.",
                protectors.join(", ")
            ),
        );
    }

    HashResult::warn(
        FORMAT,
        source_name,
        format!(
            "no password protector found; protectors present: {}. \
             TPM / recovery / startup-key VMKs are not crackable with hashcat 22100",
            protectors.join(", ")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win7_header_with_offsets(o1: u64, o2: u64, o3: u64) -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        s[3..11].copy_from_slice(FVE_SIGNATURE);
        s[176..184].copy_from_slice(&o1.to_le_bytes());
        s[184..192].copy_from_slice(&o2.to_le_bytes());
        s[192..200].copy_from_slice(&o3.to_le_bytes());
        s
    }

    #[test]
    fn parses_win7_offsets() {
        let s = win7_header_with_offsets(0x10000, 0x20000, 0x30000);
        let loc = parse_volume_header(&s).expect("header");
        assert_eq!(loc.kind, HeaderKind::Win7);
        assert_eq!(loc.offsets, [0x10000, 0x20000, 0x30000]);
    }

    #[test]
    fn parses_togo_offsets() {
        let mut s = vec![0u8; 512];
        s[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        s[3..11].copy_from_slice(TOGO_SIGNATURE);
        s[440..448].copy_from_slice(&0xaaaau64.to_le_bytes());
        s[448..456].copy_from_slice(&0xbbbbu64.to_le_bytes());
        s[456..464].copy_from_slice(&0xccccu64.to_le_bytes());
        let loc = parse_volume_header(&s).expect("header");
        assert_eq!(loc.kind, HeaderKind::ToGo);
        assert_eq!(loc.offsets, [0xaaaa, 0xbbbb, 0xcccc]);
    }

    #[test]
    fn rejects_non_bitlocker_header() {
        let mut s = vec![0u8; 512];
        s[3..11].copy_from_slice(b"NTFS    ");
        assert!(parse_volume_header(&s).is_none());
        assert!(!is_bitlocker_header(&s));
    }

    fn push_entry(buf: &mut Vec<u8>, entry_type: u16, value_type: u16, data: &[u8]) {
        let entry_size = (8 + data.len()) as u16;
        buf.extend_from_slice(&entry_size.to_le_bytes());
        buf.extend_from_slice(&entry_type.to_le_bytes());
        buf.extend_from_slice(&value_type.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // version
        buf.extend_from_slice(data);
    }

    /// Realistic FVE block: block header + metadata header + password VMK entry.
    fn fve_block_password_vmk(
        salt: &[u8; 16],
        nonce: &[u8; 12],
        mac: &[u8; 16],
        enc: &[u8],
    ) -> Vec<u8> {
        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&PROT_PASSWORD.to_le_bytes());

        // Nested stretch key: method(4) + salt(16)
        let mut stretch = vec![0u8; 4];
        stretch.extend_from_slice(salt);
        push_entry(&mut vmk_data, 0, VALUE_STRETCH_KEY, &stretch);

        // Nested AES-CCM: nonce + mac + enc
        let mut aes = Vec::new();
        aes.extend_from_slice(nonce);
        aes.extend_from_slice(mac);
        aes.extend_from_slice(enc);
        push_entry(&mut vmk_data, 0, VALUE_AES_CCM, &aes);

        let mut entries = Vec::new();
        push_entry(&mut entries, 0x0002, VALUE_VMK, &vmk_data);

        let meta_size = 48 + entries.len();
        let mut block = vec![0u8; 112];
        block[0..8].copy_from_slice(FVE_SIGNATURE);
        block[64..68].copy_from_slice(&(meta_size as u32).to_le_bytes());
        block[68..72].copy_from_slice(&1u32.to_le_bytes()); // version
        block[72..76].copy_from_slice(&48u32.to_le_bytes()); // header size
        block.extend_from_slice(&entries);
        block
    }

    #[test]
    fn extracts_password_vmk_and_formats_line() {
        let salt = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let mac = [0x33u8; 16];
        let enc = vec![0x44u8; 44];
        let block = fve_block_password_vmk(&salt, &nonce, &mac, &enc);

        let scan = extract_from_fve_block(&block);
        assert!(scan.protectors.contains(&Protector::Password));
        let pw = scan.password.clone().expect("password vmk");
        assert_eq!(pw.salt, salt);
        assert_eq!(pw.nonce, nonce);
        assert_eq!(pw.mac, mac);
        assert_eq!(pw.enc_key, enc);

        let line = pw.hash_line();
        let expected = format!(
            "$bitlocker$0$16${}$1048576$12${}$60${}{}",
            "11".repeat(16),
            "22".repeat(12),
            "33".repeat(16),
            "44".repeat(44),
        );
        assert_eq!(line, expected);

        let hr = result_from_scans("Disk 0 — E:", &[scan]);
        assert_eq!(hr.hashcat_mode, Some(22100));
        assert_eq!(hr.hash_line, expected);
        assert!(hr.error.is_none());
    }

    #[test]
    fn tpm_only_warns_and_lists_protectors() {
        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&0x0100u16.to_le_bytes());
        let mut entries = Vec::new();
        push_entry(&mut entries, 0x0002, VALUE_VMK, &vmk_data);
        let meta_size = 48 + entries.len();
        let mut block = vec![0u8; 112];
        block[0..8].copy_from_slice(FVE_SIGNATURE);
        block[64..68].copy_from_slice(&(meta_size as u32).to_le_bytes());
        block.extend_from_slice(&entries);

        let scan = extract_from_fve_block(&block);
        assert!(scan.password.is_none());
        assert!(scan.protectors.contains(&Protector::Tpm));

        let hr = result_from_scans("Disk 0 partition 2", &[scan]);
        assert!(hr.hash_line.is_empty());
        assert!(hr.warnings.iter().any(|w| w.contains("TPM")));
    }

    #[test]
    fn empty_block_warns_no_protectors() {
        let hr = result_from_scans("Disk 0", &[extract_from_fve_block(&[0u8; 256])]);
        assert!(hr.warnings.iter().any(|w| w.contains("no VMK key protectors")));
    }

    #[test]
    fn password_with_extra_description_entry_still_extracts() {
        // Real volumes often have a UTF-16 description property before stretch key.
        let salt = [0xAAu8; 16];
        let nonce = [0xBBu8; 12];
        let mac = [0xCCu8; 16];
        let enc = vec![0xDDu8; 44];

        let mut vmk_data = vec![0u8; 28];
        vmk_data[26..28].copy_from_slice(&PROT_PASSWORD.to_le_bytes());
        // description (value type 0x2)
        let desc: Vec<u8> = "ExternalKey\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        push_entry(&mut vmk_data, 0, 0x0002, &desc);
        let mut stretch = vec![0u8; 4];
        stretch.extend_from_slice(&salt);
        push_entry(&mut vmk_data, 0, VALUE_STRETCH_KEY, &stretch);
        let mut aes = Vec::new();
        aes.extend_from_slice(&nonce);
        aes.extend_from_slice(&mac);
        aes.extend_from_slice(&enc);
        push_entry(&mut vmk_data, 0, VALUE_AES_CCM, &aes);

        let mut entries = Vec::new();
        push_entry(&mut entries, 0x0002, VALUE_VMK, &vmk_data);
        let meta_size = 48 + entries.len();
        let mut block = vec![0u8; 112];
        block[0..8].copy_from_slice(FVE_SIGNATURE);
        block[64..68].copy_from_slice(&(meta_size as u32).to_le_bytes());
        block.extend_from_slice(&entries);

        let scan = extract_from_fve_block(&block);
        let pw = scan.password.expect("should parse despite description");
        assert_eq!(pw.salt, salt);
        assert_eq!(pw.enc_key, enc);
    }
}
