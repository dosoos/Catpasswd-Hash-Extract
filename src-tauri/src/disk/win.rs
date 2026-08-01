//! Windows disk enumeration + BitLocker volume inspection using native Win32
//! IOCTLs (no PowerShell / WMI).
//!
//! Enumeration probes `\\.\PhysicalDriveN`, reads geometry and the partition
//! layout, synthesizes unallocated gaps, and maps drive letters / labels via the
//! volume APIs. Inspection reads the raw partition bytes (through the physical
//! drive so BitLocker metadata is visible even on an unlocked volume) and hands
//! the FVE metadata blocks to [`crate::extract::bitlocker`].

#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, GENERIC_READ, HANDLE, MAX_PATH};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
    GetVolumePathNamesForVolumeNameW, ReadFile, SetFilePointerEx, FILE_BEGIN,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
    OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    DISK_GEOMETRY_EX, DRIVE_LAYOUT_INFORMATION_EX, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
    IOCTL_DISK_GET_DRIVE_LAYOUT_EX, PARTITION_INFORMATION_EX, PARTITION_STYLE_GPT,
    PARTITION_STYLE_MBR, VOLUME_DISK_EXTENTS,
};
use windows::Win32::System::IO::DeviceIoControl;

use crate::extract::bitlocker;
use crate::hash_cache;
use crate::models::{DiskInfo, FileMeta, HashResult, InspectResult, PartitionInfo};

/// Number of `\\.\PhysicalDriveN` slots to probe.
const MAX_PHYSICAL_DRIVES: u32 = 32;
/// Unallocated gaps smaller than this are treated as alignment padding.
const MIN_GAP: u64 = 1 << 20;
/// FVE metadata block window read from each on-volume offset.
const FVE_BLOCK_LEN: usize = 64 * 1024;
/// Bytes hashed for the header-only volume fingerprints.
const HEADER_DIGEST_LEN: u64 = 1 << 20;

// Well-known GPT partition type GUIDs.
const GPT_EFI: GUID = GUID::from_u128(0xc12a7328_f81f_11d2_ba4b_00a0c93ec93b);
const GPT_MSR: GUID = GUID::from_u128(0xe3c9e316_0b5c_4db8_817d_f92df00215ae);
const GPT_BASIC: GUID = GUID::from_u128(0xebd0a0a2_b9e5_4433_87c0_68b6b72699c7);
const GPT_RECOVERY: GUID = GUID::from_u128(0xde94bba4_06d1_4d40_a16a_bfd50179d6ac);

/// RAII wrapper around a Win32 device handle.
struct Device(HANDLE);

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// UTF-16, NUL-terminated copy of `s` for the wide Win32 APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(context: &str) -> String {
    let code = unsafe { GetLastError().0 };
    format!("{context} (Win32 error {code})")
}

/// Open a device path (`\\.\PhysicalDrive0`, `\\.\C:`, ...). `access` of 0 is
/// enough for metadata IOCTLs; use `GENERIC_READ.0` to read sector data.
fn open_device(path: &str, access: u32) -> Result<Device, String> {
    let wpath = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wpath.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };
    match handle {
        Ok(h) if !h.is_invalid() => Ok(Device(h)),
        _ => Err(last_error(&format!("cannot open {path}"))),
    }
}

/// Issue a `DeviceIoControl` that only reads into `out`.
fn device_io(dev: &Device, code: u32, out: *mut c_void, out_len: u32) -> Result<u32, String> {
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dev.0,
            code,
            None,
            0,
            Some(out),
            out_len,
            Some(&mut returned),
            None,
        )
    };
    ok.map_err(|e| format!("ioctl 0x{code:x} failed: {}", e.message()))?;
    Ok(returned)
}

/// Read exactly `len` bytes at absolute `offset`, honoring sector alignment
/// required by raw device handles.
fn read_at(dev: &Device, offset: u64, len: usize) -> Result<Vec<u8>, String> {
    const ALIGN: u64 = 4096;
    let start = offset & !(ALIGN - 1);
    let head = (offset - start) as usize;
    let aligned_len = {
        let total = head + len;
        ((total as u64 + ALIGN - 1) & !(ALIGN - 1)) as usize
    };

    unsafe {
        SetFilePointerEx(dev.0, start as i64, None, FILE_BEGIN)
            .map_err(|e| format!("seek failed: {}", e.message()))?;
    }

    let mut buf = vec![0u8; aligned_len];
    let mut filled = 0usize;
    while filled < aligned_len {
        let mut read = 0u32;
        unsafe {
            ReadFile(dev.0, Some(&mut buf[filled..]), Some(&mut read), None)
                .map_err(|e| format!("read failed: {}", e.message()))?;
        }
        if read == 0 {
            break; // EOF
        }
        filled += read as usize;
    }

    if filled < head + len {
        return Err("short read from device".to_string());
    }
    Ok(buf[head..head + len].to_vec())
}

/// Public: enumerate all physical disks and their partitions.
pub fn list_disks() -> Result<Vec<DiskInfo>, String> {
    let volumes = enumerate_volumes();
    let mut disks = Vec::new();

    for index in 0..MAX_PHYSICAL_DRIVES {
        let path = format!("\\\\.\\PhysicalDrive{index}");
        let dev = match open_device(&path, 0) {
            Ok(d) => d,
            Err(_) => continue, // absent drive slot
        };
        if let Some(disk) = read_disk(&dev, index, &volumes) {
            disks.push(disk);
        }
    }

    if disks.is_empty() {
        return Err(
            "no physical disks could be opened (raw disk access usually requires Administrator)"
                .to_string(),
        );
    }
    Ok(disks)
}

/// Volume metadata keyed by its physical location.
struct VolumeMeta {
    disk_index: u32,
    offset: u64,
    letter: Option<String>,
    label: String,
    file_system: Option<String>,
}

/// Read geometry + layout for one physical disk and build its `DiskInfo`.
fn read_disk(dev: &Device, index: u32, volumes: &[VolumeMeta]) -> Option<DiskInfo> {
    let mut geo: DISK_GEOMETRY_EX = unsafe { zeroed() };
    device_io(
        dev,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        &mut geo as *mut _ as *mut c_void,
        size_of::<DISK_GEOMETRY_EX>() as u32,
    )
    .ok()?;
    let disk_size = geo.DiskSize as u64;

    let (layout, raw_parts) = read_layout(dev).unwrap_or((String::from("Basic"), Vec::new()));

    let mut parts = build_partitions(index, disk_size, raw_parts, volumes);
    // Ensure a stable partition_index even if empty.
    for (i, p) in parts.iter_mut().enumerate() {
        p.partition_index = i as u32;
        p.id = format!("{index}:{i}");
    }

    Some(DiskInfo {
        index,
        name: format!("Disk {index}"),
        layout,
        size: disk_size,
        status: "Online".to_string(),
        partitions: parts,
    })
}

/// A partition as read from the drive layout (before gaps are inserted).
struct RawPart {
    start: u64,
    len: u64,
    kind: String,
}

/// Read `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` and return `(layout_label, partitions)`.
fn read_layout(dev: &Device) -> Option<(String, Vec<RawPart>)> {
    const MAX_PARTS: usize = 128;
    let buf_size =
        size_of::<DRIVE_LAYOUT_INFORMATION_EX>() + MAX_PARTS * size_of::<PARTITION_INFORMATION_EX>();
    let mut buf = vec![0u8; buf_size];

    device_io(
        dev,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        buf.as_mut_ptr() as *mut c_void,
        buf_size as u32,
    )
    .ok()?;

    let layout = unsafe { &*(buf.as_ptr() as *const DRIVE_LAYOUT_INFORMATION_EX) };
    // `DRIVE_LAYOUT_INFORMATION_EX::PartitionStyle` is a raw `u32`.
    let style = layout.PartitionStyle;
    let is_gpt = style == PARTITION_STYLE_GPT.0 as u32;
    let is_mbr = style == PARTITION_STYLE_MBR.0 as u32;
    let count = (layout.PartitionCount as usize).min(MAX_PARTS);

    let label = if is_gpt {
        "GPT"
    } else if is_mbr {
        "MBR"
    } else {
        "Basic"
    }
    .to_string();

    let entries = layout.PartitionEntry.as_ptr();
    let mut extended_range: Option<(u64, u64)> = None;
    let mut raw = Vec::new();

    for i in 0..count {
        let e = unsafe { &*entries.add(i) };
        let start = e.StartingOffset as u64;
        let len = e.PartitionLength as u64;
        if len == 0 {
            continue;
        }

        let kind = if is_gpt {
            let ty = unsafe { e.Anonymous.Gpt.PartitionType };
            classify_gpt(&ty)
        } else if is_mbr {
            let mbr = unsafe { e.Anonymous.Mbr };
            if !mbr.RecognizedPartition && mbr.PartitionType == 0 {
                continue;
            }
            match mbr.PartitionType {
                0x05 | 0x0f => {
                    extended_range = Some((start, start + len));
                    "extended".to_string()
                }
                _ => "primary".to_string(),
            }
        } else {
            "unknown".to_string()
        };

        raw.push(RawPart { start, len, kind });
    }

    // MBR: partitions living inside the extended container are logical drives.
    if let Some((ext_start, ext_end)) = extended_range {
        for p in raw.iter_mut() {
            if p.kind == "primary" && p.start > ext_start && p.start < ext_end {
                p.kind = "logical".to_string();
            }
        }
    }

    raw.sort_by_key(|p| p.start);
    Some((label, raw))
}

fn classify_gpt(ty: &GUID) -> String {
    if *ty == GPT_EFI {
        "efi"
    } else if *ty == GPT_RECOVERY {
        "recovery"
    } else if *ty == GPT_BASIC {
        "primary"
    } else if *ty == GPT_MSR {
        "unknown"
    } else {
        "unknown"
    }
    .to_string()
}

/// Turn raw partitions into the final list, inserting unallocated gaps and
/// attaching volume metadata (letter / label / file system).
fn build_partitions(
    disk_index: u32,
    disk_size: u64,
    raw: Vec<RawPart>,
    volumes: &[VolumeMeta],
) -> Vec<PartitionInfo> {
    let mut out = Vec::new();
    let mut cursor = 0u64;

    for p in raw {
        if p.start > cursor && p.start - cursor > MIN_GAP {
            out.push(unallocated(disk_index, cursor, p.start - cursor));
        }
        out.push(make_partition(disk_index, &p, volumes));
        cursor = p.start + p.len;
    }

    if disk_size > cursor && disk_size - cursor > MIN_GAP {
        out.push(unallocated(disk_index, cursor, disk_size - cursor));
    }

    out
}

fn unallocated(disk_index: u32, offset: u64, size: u64) -> PartitionInfo {
    PartitionInfo {
        id: String::new(),
        disk_index,
        partition_index: 0,
        offset,
        size,
        letter: None,
        label: String::new(),
        file_system: None,
        kind: "unallocated".to_string(),
        status: "Unallocated".to_string(),
        selectable: false,
    }
}

fn make_partition(disk_index: u32, p: &RawPart, volumes: &[VolumeMeta]) -> PartitionInfo {
    let vol = volumes
        .iter()
        .find(|v| v.disk_index == disk_index && v.offset == p.start);

    let letter = vol.and_then(|v| v.letter.clone());
    let label = vol.map(|v| v.label.clone()).unwrap_or_default();
    let file_system = vol.and_then(|v| v.file_system.clone());

    let status = match p.kind.as_str() {
        "efi" => "Healthy (EFI System Partition)".to_string(),
        "recovery" => "Healthy (Recovery Partition)".to_string(),
        _ => "Healthy".to_string(),
    };

    PartitionInfo {
        id: String::new(),
        disk_index,
        partition_index: 0,
        offset: p.start,
        size: p.len,
        letter,
        label,
        file_system,
        kind: p.kind.clone(),
        status,
        selectable: p.len > 0 && p.kind != "unallocated",
    }
}

/// Enumerate mounted volumes and resolve their disk/offset via disk extents.
fn enumerate_volumes() -> Vec<VolumeMeta> {
    let mut result = Vec::new();
    let mut name = [0u16; MAX_PATH as usize];

    let find = match unsafe { FindFirstVolumeW(&mut name) } {
        Ok(h) if !h.is_invalid() => h,
        _ => return result,
    };

    loop {
        if let Some(meta) = describe_volume(&name) {
            result.extend(meta);
        }

        name = [0u16; MAX_PATH as usize];
        let more = unsafe { FindNextVolumeW(find, &mut name) };
        if more.is_err() {
            break;
        }
    }

    unsafe {
        let _ = FindVolumeClose(find);
    }
    result
}

/// Build `VolumeMeta` (one per disk extent) for a `\\?\Volume{guid}\` name.
fn describe_volume(name_w: &[u16]) -> Option<Vec<VolumeMeta>> {
    let name = String::from_utf16_lossy(&name_w[..wlen(name_w)]);

    let letter = volume_letter(name_w);
    let (label, file_system) = volume_info(name_w);

    // Open the volume (name without the trailing backslash) for the extents IOCTL.
    let dev_path = name.trim_end_matches('\\').to_string();
    let dev = open_device(&dev_path, 0).ok()?;

    let mut extents: VolumeDiskExtentsBuf = unsafe { zeroed() };
    device_io(
        &dev,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        &mut extents as *mut _ as *mut c_void,
        size_of::<VolumeDiskExtentsBuf>() as u32,
    )
    .ok()?;

    let header = unsafe { &*(&extents as *const _ as *const VOLUME_DISK_EXTENTS) };
    let count = (header.NumberOfDiskExtents as usize).min(MAX_EXTENTS);

    let mut metas = Vec::new();
    for i in 0..count {
        let ext = &extents.extents[i];
        metas.push(VolumeMeta {
            disk_index: ext.DiskNumber,
            offset: ext.StartingOffset as u64,
            letter: letter.clone(),
            label: label.clone(),
            file_system: file_system.clone(),
        });
    }
    Some(metas)
}

const MAX_EXTENTS: usize = 16;

/// `VOLUME_DISK_EXTENTS` with room for several extents (spanned volumes).
#[repr(C)]
struct VolumeDiskExtentsBuf {
    header: VOLUME_DISK_EXTENTS,
    extents: [windows::Win32::System::Ioctl::DISK_EXTENT; MAX_EXTENTS],
}

/// First drive letter (without colon) mounted for this volume, if any.
fn volume_letter(name_w: &[u16]) -> Option<String> {
    let mut buf = vec![0u16; 512];
    let mut needed = 0u32;
    let ok = unsafe {
        GetVolumePathNamesForVolumeNameW(
            PCWSTR(name_w.as_ptr()),
            Some(&mut buf),
            &mut needed,
        )
    };
    if ok.is_err() {
        return None;
    }
    // Multi-string of mount points; take the first "X:\" style entry.
    let s = String::from_utf16_lossy(&buf);
    for path in s.split('\0') {
        let bytes: Vec<char> = path.chars().collect();
        if bytes.len() >= 2 && bytes[1] == ':' && bytes[0].is_ascii_alphabetic() {
            return Some(bytes[0].to_ascii_uppercase().to_string());
        }
    }
    None
}

/// `(label, file_system)` via `GetVolumeInformationW`; empty on failure (e.g. a
/// locked BitLocker volume).
fn volume_info(name_w: &[u16]) -> (String, Option<String>) {
    let mut label = [0u16; MAX_PATH as usize];
    let mut fs = [0u16; MAX_PATH as usize];
    let ok = unsafe {
        GetVolumeInformationW(
            PCWSTR(name_w.as_ptr()),
            Some(&mut label),
            None,
            None,
            None,
            Some(&mut fs),
        )
    };
    if ok.is_err() {
        return (String::new(), None);
    }
    let label = String::from_utf16_lossy(&label[..wlen(&label)]);
    let fs = String::from_utf16_lossy(&fs[..wlen(&fs)]);
    let fs = if fs.is_empty() { None } else { Some(fs) };
    (label, fs)
}

/// Length of a NUL-terminated wide buffer.
fn wlen(buf: &[u16]) -> usize {
    buf.iter().position(|&c| c == 0).unwrap_or(buf.len())
}

/// Public: inspect a single partition and extract a BitLocker hash.
pub fn inspect_volume(disk_index: u32, partition_index: u32) -> Result<InspectResult, String> {
    let disks = list_disks()?;
    let disk = disks
        .iter()
        .find(|d| d.index == disk_index)
        .ok_or_else(|| format!("disk {disk_index} not found"))?;
    let part = disk
        .partitions
        .iter()
        .find(|p| p.partition_index == partition_index)
        .ok_or_else(|| format!("partition {partition_index} not found on disk {disk_index}"))?;

    if !part.selectable || part.kind == "unallocated" {
        return Err("this entry is unallocated space and cannot be inspected".to_string());
    }

    let display_name = match &part.letter {
        Some(l) => format!("Disk {disk_index} — {l}:"),
        None => format!("Disk {disk_index} partition {partition_index}"),
    };

    // Read raw sectors via the physical drive so BitLocker metadata is visible
    // even when the volume is currently unlocked. Fall back to the letter.
    let (dev, base) = open_for_read(disk_index, part)?;

    let header = read_at(&dev, base, 512)?;
    let digest = header_digests(&dev, base, part.size);

    let (format_label, hash) = match bitlocker::parse_volume_header(&header) {
        Some(loc) => {
            let mut scans = Vec::new();
            for off in loc.offsets.iter().copied().filter(|o| *o != 0) {
                if let Ok(block) = read_at(&dev, base + off, FVE_BLOCK_LEN) {
                    scans.push(bitlocker::extract_from_fve_block(&block));
                }
            }
            let mut hr = bitlocker::result_from_scans(&display_name, &scans);
            hr = hr.with_warning(
                "fingerprints are computed from the volume header only (not the full disk)",
            );
            ("BitLocker".to_string(), hr)
        }
        None => {
            let hr = HashResult::warn(
                bitlocker::FORMAT,
                &display_name,
                "volume is not BitLocker-encrypted (no FVE signature in the volume header)",
            )
            .with_warning(
                "fingerprints are computed from the volume header only (not the full disk)",
            );
            ("Volume".to_string(), hr)
        }
    };

    let meta = FileMeta {
        name: display_name,
        format_label,
        size: part.size,
        modified_ms: None,
        crc32: digest.crc32,
        md5: digest.md5,
        sha256: digest.sha256,
        sha512: digest.sha512,
    };

    Ok(hash_cache::finalize(meta, hash))
}

/// Open the device to read a partition's raw bytes, returning `(device, base
/// offset)`. Prefers the physical drive; falls back to the volume letter.
fn open_for_read(disk_index: u32, part: &PartitionInfo) -> Result<(Device, u64), String> {
    let phys = format!("\\\\.\\PhysicalDrive{disk_index}");
    match open_device(&phys, GENERIC_READ.0) {
        Ok(dev) => Ok((dev, part.offset)),
        Err(phys_err) => {
            if let Some(letter) = &part.letter {
                let vol = format!("\\\\.\\{letter}:");
                match open_device(&vol, GENERIC_READ.0) {
                    Ok(dev) => Ok((dev, 0)),
                    Err(_) => Err(format!(
                        "{phys_err}. Reading raw disk sectors requires running as Administrator"
                    )),
                }
            } else {
                Err(format!(
                    "{phys_err}. Reading raw disk sectors requires running as Administrator"
                ))
            }
        }
    }
}

struct HeaderDigests {
    crc32: String,
    md5: String,
    sha256: String,
    sha512: String,
}

/// Header-only digests over the first `HEADER_DIGEST_LEN` bytes of the volume.
fn header_digests(dev: &Device, base: u64, part_size: u64) -> HeaderDigests {
    use crc32fast::Hasher as Crc32;
    use md5::{Digest, Md5};
    use sha2::{Sha256, Sha512};

    let want = HEADER_DIGEST_LEN.min(part_size.max(512)) as usize;
    let data = read_at(dev, base, want).unwrap_or_default();

    let mut crc = Crc32::new();
    crc.update(&data);
    let mut md5 = Md5::new();
    md5.update(&data);
    let mut sha256 = Sha256::new();
    sha256.update(&data);
    let mut sha512 = Sha512::new();
    sha512.update(&data);

    HeaderDigests {
        crc32: format!("{:08x}", crc.finalize()),
        md5: hex::encode(md5.finalize()),
        sha256: hex::encode(sha256.finalize()),
        sha512: hex::encode(sha512.finalize()),
    }
}
