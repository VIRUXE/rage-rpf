use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

use crate::crypto::{decrypt_aes, decrypt_ng, GtaKeys};

pub const RPF0_MAGIC: u32 = 0x30465052; // Table Tennis
pub const RPF2_MAGIC: u32 = 0x32465052; // GTA IV
pub const RPF3_MAGIC: u32 = 0x33465052; // GTA IV Audio / MCLA (hashed names)
pub const RPF4_MAGIC: u32 = 0x34465052; // Max Payne 3
pub const RPF6_MAGIC: u32 = 0x36465052; // Red Dead Redemption
pub const RPF7_MAGIC: u32 = 0x52504637;
pub const RSC7_MAGIC: u32 = 0x37435352;

// ─── Version ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpfVersion {
    V0, // Table Tennis — no encryption, deflate, TOC at 0x800
    V2, // GTA IV — optional AES, byte offsets, TOC at 0x800
    V3, // GTA IV Audio / MCLA — like V2 but hashed names
    V4, // Max Payne 3 — like V2 but offsets * 8
    V6, // Red Dead Redemption — big-endian entries, 20-byte, offsets * 8, optional debug names
    V7, // GTA V / FiveM — AES or NG encryption, 512-byte block offsets
}

// ─── Encryption ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpfEncryption {
    None,
    Open,
    Aes,
    Ng,
}

impl RpfEncryption {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x00000000 => Self::None,
            0x4E45504F => Self::Open,
            0x0FFFFFF9 => Self::Aes,
            0x0FEFFFFF => Self::Ng,
            _          => Self::Ng,
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::None => 0x00000000,
            Self::Open => 0x4E45504F,
            Self::Aes  => 0x0FFFFFF9,
            Self::Ng   => 0x0FEFFFFF,
        }
    }

    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Aes | Self::Ng)
    }
}

// ─── Entry kinds ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RpfEntryKind {
    Directory {
        entries_index: u32,
        entries_count: u32,
    },
    BinaryFile {
        /// For V7: 512-byte block number. For all other versions: byte offset.
        file_offset      : u32,
        /// Compressed size (0 = stored, use uncompressed_size for read length).
        file_size        : u32,
        uncompressed_size: u32,
        is_encrypted     : bool,
    },
    ResourceFile {
        /// For V7: 512-byte block number. For all other versions: byte offset.
        file_offset   : u32,
        file_size     : u32,
        system_flags  : u32,
        graphics_flags: u32,
        is_encrypted  : bool,
    },
}

#[derive(Debug, Clone)]
pub struct RpfEntry {
    pub name      : String,
    pub name_lower: String,
    pub kind      : RpfEntryKind,
}

impl RpfEntry {
    pub fn is_directory(&self) -> bool {
        matches!(self.kind, RpfEntryKind::Directory { .. })
    }

    pub fn is_file(&self) -> bool {
        !self.is_directory()
    }
}

// ─── RpfArchive — parsed metadata ────────────────────────────────────────────

pub struct RpfArchive {
    pub name        : String,
    pub start_offset: usize,
    pub encryption  : RpfEncryption,
    pub entries     : Vec<RpfEntry>,
    pub version     : RpfVersion,
}

impl RpfArchive {
    pub fn parse(data: &[u8], name: &str, keys: Option<&GtaKeys>) -> Result<Self> {
        Self::parse_at(data, 0, name, keys)
    }

    pub fn parse_at(data: &[u8], offset: usize, name: &str, keys: Option<&GtaKeys>) -> Result<Self> {
        let d = data.get(offset..).context("offset out of bounds")?;
        if d.len() < 12 { bail!("RPF data too short"); }

        let magic = u32::from_le_bytes(d[0..4].try_into().unwrap());
        let version = match magic {
            RPF0_MAGIC => RpfVersion::V0,
            RPF2_MAGIC => RpfVersion::V2,
            RPF3_MAGIC => RpfVersion::V3,
            RPF4_MAGIC => RpfVersion::V4,
            RPF6_MAGIC => RpfVersion::V6,
            RPF7_MAGIC => RpfVersion::V7,
            _ => bail!("Unknown RPF magic: {:#010x}", magic),
        };

        let (entries, encryption) = match version {
            RpfVersion::V7 => parse_rpf7_toc(d, name, keys)?,
            RpfVersion::V0 => parse_rpf0_toc(d)?,
            RpfVersion::V6 => parse_rpf6_toc(d)?,
            _              => parse_rpf2_toc(d, version)?,
        };

        let mut archive = Self { name: name.to_string(), start_offset: offset, encryption, entries, version };

        // Resolve V7 resource entries with file_size == 0xFFFFFF (actual size in RSC7 header)
        if version == RpfVersion::V7 {
            for entry in &mut archive.entries {
                if let RpfEntryKind::ResourceFile { file_offset, file_size, .. } = &mut entry.kind {
                    if *file_size == 0xFFFFFF {
                        let body_off = offset + (*file_offset as usize * 512);
                        if body_off + 16 <= data.len() {
                            let b = &data[body_off..body_off + 16];
                            *file_size = ((b[7]  as u32) <<  0)
                                       | ((b[14] as u32) <<  8)
                                       | ((b[5]  as u32) << 16)
                                       | ((b[2]  as u32) << 24);
                        }
                    }
                }
            }
        }

        Ok(archive)
    }

    // ─── Extraction ──────────────────────────────────────────────────────────

    pub fn extract_entry(
        &self,
        data: &[u8],
        entry: &RpfEntry,
        keys: Option<&GtaKeys>,
    ) -> Result<Vec<u8>> {
        match &entry.kind {
            RpfEntryKind::Directory { .. } => bail!("Cannot extract a directory entry"),

            RpfEntryKind::BinaryFile {
                file_offset, file_size, uncompressed_size, is_encrypted
            } => {
                let byte_off = self.offset_to_bytes(*file_offset);
                let size = if *file_size > 0 { *file_size as usize } else { *uncompressed_size as usize };
                if size == 0 { bail!("Binary file has zero size"); }

                let raw = data.get(byte_off..byte_off + size)
                    .with_context(|| format!("{}: binary file out of bounds", entry.name_lower))?;
                let mut buf = raw.to_vec();

                if *is_encrypted {
                    buf = self.decrypt(&buf, &entry.name, *uncompressed_size, keys)?;
                }

                if *file_size > 0 && *file_size < *uncompressed_size {
                    buf = inflate(&buf).unwrap_or(buf);
                }

                Ok(buf)
            }

            RpfEntryKind::ResourceFile {
                file_offset, file_size, system_flags, graphics_flags, is_encrypted
            } => {
                let total = *file_size as usize;
                let rsc_hdr = self.resource_header_size();
                if total < rsc_hdr { bail!("{}: resource too small ({} bytes)", entry.name_lower, total); }

                let byte_off = self.offset_to_bytes(*file_offset);
                let body_off = byte_off + rsc_hdr;
                let body_len = total - rsc_hdr;

                let raw = data.get(body_off..body_off + body_len)
                    .with_context(|| format!("{}: resource out of bounds", entry.name_lower))?;
                let mut body = raw.to_vec();

                if *is_encrypted {
                    body = self.decrypt(&body, &entry.name, *file_size, keys)?;
                }

                if self.version == RpfVersion::V7 {
                    // Rebuild as standalone RSC7 file
                    let version = resource_version_from_flags(*system_flags, *graphics_flags);
                    let mut out = Vec::with_capacity(body.len() + 16);
                    out.extend_from_slice(&RSC7_MAGIC.to_le_bytes());
                    out.extend_from_slice(&version.to_le_bytes());
                    out.extend_from_slice(&system_flags.to_le_bytes());
                    out.extend_from_slice(&graphics_flags.to_le_bytes());
                    out.extend_from_slice(&body);
                    Ok(out)
                } else {
                    // For V2/V6: return raw body (resource format is game-specific)
                    Ok(body)
                }
            }
        }
    }

    pub fn walk_files(
        &self,
        data: &[u8],
        keys: Option<&GtaKeys>,
        path_prefix: &str,
        on_file: &mut dyn FnMut(&str, Vec<u8>),
    ) -> Result<()> {
        self.walk_inner(data, keys, path_prefix, on_file, 0)
    }

    fn walk_inner(
        &self,
        data: &[u8],
        keys: Option<&GtaKeys>,
        path_prefix: &str,
        on_file: &mut dyn FnMut(&str, Vec<u8>),
        depth: usize,
    ) -> Result<()> {
        const MAX_DEPTH: usize = 16;
        if depth > MAX_DEPTH { return Ok(()); }

        let is_aes = self.encryption == RpfEncryption::Aes;

        for entry in &self.entries {
            if entry.is_directory() { continue; }

            let path = if path_prefix.is_empty() {
                entry.name_lower.clone()
            } else {
                format!("{}/{}", path_prefix, entry.name_lower)
            };

            match &entry.kind {
                RpfEntryKind::BinaryFile {
                    file_offset, file_size, uncompressed_size, is_encrypted
                } => {
                    let byte_off = self.offset_to_bytes(*file_offset);
                    let size = if *file_size > 0 { *file_size as usize } else { *uncompressed_size as usize };
                    if size == 0 { continue; }
                    if byte_off + size > data.len() {
                        eprintln!("[RPF] {} out of bounds, skipping", path);
                        continue;
                    }

                    let mut buf = data[byte_off..byte_off + size].to_vec();

                    if *is_encrypted {
                        if let Some(k) = keys {
                            buf = if is_aes {
                                decrypt_aes(&buf, &k.aes_key)
                            } else {
                                decrypt_ng(&buf, k, &entry.name, *uncompressed_size)
                            };
                        }
                    }

                    let out = if *file_size > 0 && *file_size < *uncompressed_size {
                        inflate(&buf).unwrap_or(buf)
                    } else {
                        buf
                    };

                    if entry.name_lower.ends_with(".rpf") {
                        match RpfArchive::parse(&out, &entry.name_lower, keys) {
                            Ok(nested) => {
                                let prefix = if path_prefix.is_empty() {
                                    entry.name_lower.clone()
                                } else {
                                    format!("{}/{}", path_prefix, entry.name_lower)
                                };
                                if let Err(e) = nested.walk_inner(&out, keys, &prefix, on_file, depth + 1) {
                                    eprintln!("[RPF] Error in nested {}: {}", path, e);
                                }
                            }
                            Err(e) => eprintln!("[RPF] Failed to parse nested {}: {}", path, e),
                        }
                    } else {
                        on_file(&path, out);
                    }
                }

                RpfEntryKind::ResourceFile {
                    file_offset, file_size, system_flags, graphics_flags, is_encrypted
                } => {
                    let total = *file_size as usize;
                    let rsc_hdr = self.resource_header_size();
                    if total < rsc_hdr { continue; }

                    let byte_off = self.offset_to_bytes(*file_offset);
                    let body_off = byte_off + rsc_hdr;
                    let body_len = total - rsc_hdr;
                    if body_off + body_len > data.len() {
                        eprintln!("[RPF] {} out of bounds, skipping", path);
                        continue;
                    }

                    let mut body = data[body_off..body_off + body_len].to_vec();

                    if *is_encrypted {
                        if let Some(k) = keys {
                            body = if is_aes {
                                decrypt_aes(&body, &k.aes_key)
                            } else {
                                decrypt_ng(&body, k, &entry.name, *file_size)
                            };
                        }
                    }

                    let out = if self.version == RpfVersion::V7 {
                        let version = resource_version_from_flags(*system_flags, *graphics_flags);
                        let mut v = Vec::with_capacity(body.len() + 16);
                        v.extend_from_slice(&RSC7_MAGIC.to_le_bytes());
                        v.extend_from_slice(&version.to_le_bytes());
                        v.extend_from_slice(&system_flags.to_le_bytes());
                        v.extend_from_slice(&graphics_flags.to_le_bytes());
                        v.extend_from_slice(&body);
                        v
                    } else {
                        body
                    };

                    on_file(&path, out);
                }

                RpfEntryKind::Directory { .. } => {}
            }
        }

        Ok(())
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    /// Convert a stored file_offset to an absolute byte position in `data`.
    /// V7 stores 512-byte block numbers; all other versions store byte offsets.
    fn offset_to_bytes(&self, raw_offset: u32) -> usize {
        self.start_offset + match self.version {
            RpfVersion::V7 => raw_offset as usize * 512,
            _              => raw_offset as usize,
        }
    }

    fn resource_header_size(&self) -> usize {
        match self.version {
            RpfVersion::V7 => 16,
            _              => 12,
        }
    }

    fn decrypt(&self, data: &[u8], name: &str, length: u32, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        match self.encryption {
            RpfEncryption::Aes => {
                let k = keys.context("AES-encrypted entry requires --keys")?;
                Ok(decrypt_aes(data, &k.aes_key))
            }
            RpfEncryption::Ng => {
                let k = keys.context("NG-encrypted entry requires --keys")?;
                Ok(decrypt_ng(data, k, name, length))
            }
            _ => Ok(data.to_vec()),
        }
    }
}

// ─── RpfFile — owns the raw bytes ────────────────────────────────────────────

pub struct RpfFile {
    pub archive: RpfArchive,
    data: Vec<u8>,
}

impl RpfFile {
    pub fn open(path: &Path, keys: Option<&GtaKeys>) -> Result<Self> {
        let data = fs::read(path)
            .with_context(|| format!("Cannot read {}", path.display()))?;

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| path.to_str().unwrap_or(""));

        let archive = RpfArchive::parse(&data, name, keys)?;
        Ok(Self { archive, data })
    }

    pub fn extract_by_name(&self, name: &str, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        let entry = self.archive.entries.iter()
            .find(|e| e.name_lower == name.to_lowercase())
            .with_context(|| format!("Entry '{}' not found", name))?;
        self.archive.extract_entry(&self.data, entry, keys)
    }

    pub fn extract(&self, entry: &RpfEntry, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        self.archive.extract_entry(&self.data, entry, keys)
    }

    pub fn walk(
        &self,
        keys: Option<&GtaKeys>,
        on_file: &mut dyn FnMut(&str, Vec<u8>),
    ) -> Result<()> {
        self.archive.walk_files(&self.data, keys, "", on_file)
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }
}

// ─── Resource page-flag helpers ───────────────────────────────────────────────

pub fn resource_version_from_flags(sys_flags: u32, gfx_flags: u32) -> u32 {
    let sv = (sys_flags  >> 28) & 0xF;
    let gv = (gfx_flags  >> 28) & 0xF;
    (sv << 4) | gv
}

pub fn resource_size_from_flags(flags: u32) -> usize {
    let s0 = ((flags >> 27) & 0x1)  << 0;
    let s1 = ((flags >> 26) & 0x1)  << 1;
    let s2 = ((flags >> 25) & 0x1)  << 2;
    let s3 = ((flags >> 24) & 0x1)  << 3;
    let s4 = ((flags >> 17) & 0x7F) << 4;
    let s5 = ((flags >> 11) & 0x3F) << 5;
    let s6 = ((flags >> 7)  & 0xF)  << 6;
    let s7 = ((flags >> 5)  & 0x3)  << 7;
    let s8 = ((flags >> 4)  & 0x1)  << 8;
    let ss = (flags & 0xF) as usize;
    let base_size = 0x200usize << ss;
    base_size * (s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8) as usize
}

// ─── RPF7 TOC ────────────────────────────────────────────────────────────────

fn parse_rpf7_toc(d: &[u8], name: &str, keys: Option<&GtaKeys>) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 16 { bail!("RPF7 header too short"); }

    let entry_count  = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let names_length = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    let encryption   = RpfEncryption::from_u32(u32::from_le_bytes(d[12..16].try_into().unwrap()));

    let entries_off  = 16;
    let entries_size = entry_count * 16;
    let names_off    = entries_off + entries_size;

    if d.len() < names_off + names_length { bail!("RPF7 header truncated"); }

    let mut entries_data = d[entries_off..entries_off + entries_size].to_vec();
    let mut names_data   = d[names_off..names_off + names_length].to_vec();

    match (encryption, keys) {
        (RpfEncryption::Aes, Some(k)) => {
            entries_data = decrypt_aes(&entries_data, &k.aes_key);
            names_data   = decrypt_aes(&names_data,   &k.aes_key);
        }
        (RpfEncryption::Ng, Some(k)) => {
            let file_size = d.len() as u32;
            entries_data = decrypt_ng(&entries_data, k, name, file_size);
            names_data   = decrypt_ng(&names_data,   k, name, file_size);
        }
        _ => {}
    }

    let entries = parse_rpf7_entries(&entries_data, &names_data, entry_count)?;
    Ok((entries, encryption))
}

fn parse_rpf7_entries(entries_data: &[u8], names_data: &[u8], count: usize) -> Result<Vec<RpfEntry>> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * 16;
        if off + 16 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 16];
        let h2 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());

        let entry = if h2 == 0x7FFFFF00 {
            parse_v7_directory(chunk, names_data, i)
        } else if (h2 & 0x80000000) == 0 {
            parse_v7_binary(chunk, names_data, i)
        } else {
            parse_v7_resource(chunk, names_data, i)
        };

        entries.push(entry);
    }

    Ok(entries)
}

fn parse_v7_directory(chunk: &[u8], names: &[u8], idx: usize) -> RpfEntry {
    let name_offset   = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as usize;
    let entries_index = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
    let entries_count = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
    let name = read_cstring(names, name_offset).unwrap_or_else(|| format!("dir_{}", idx));
    let name_lower = name.to_lowercase();
    RpfEntry { name, name_lower, kind: RpfEntryKind::Directory { entries_index, entries_count } }
}

fn parse_v7_binary(chunk: &[u8], names: &[u8], idx: usize) -> RpfEntry {
    let name_offset       = u16::from_le_bytes(chunk[0..2].try_into().unwrap()) as usize;
    let file_size         = (chunk[2] as u32) | ((chunk[3] as u32) << 8) | ((chunk[4] as u32) << 16);
    let file_offset       = (chunk[5] as u32) | ((chunk[6] as u32) << 8) | ((chunk[7] as u32) << 16);
    let uncompressed_size = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
    let is_encrypted      = u32::from_le_bytes(chunk[12..16].try_into().unwrap()) == 1;
    let name = read_cstring(names, name_offset).unwrap_or_else(|| format!("binary_{}", idx));
    let name_lower = name.to_lowercase();
    RpfEntry { name, name_lower, kind: RpfEntryKind::BinaryFile { file_offset, file_size, uncompressed_size, is_encrypted } }
}

fn parse_v7_resource(chunk: &[u8], names: &[u8], idx: usize) -> RpfEntry {
    let name_offset    = u16::from_le_bytes(chunk[0..2].try_into().unwrap()) as usize;
    let file_size      = (chunk[2] as u32) | ((chunk[3] as u32) << 8) | ((chunk[4] as u32) << 16);
    let file_offset    = ((chunk[5] as u32) | ((chunk[6] as u32) << 8) | ((chunk[7] as u32) << 16)) & 0x7FFFFF;
    let system_flags   = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
    let graphics_flags = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
    let name = read_cstring(names, name_offset).unwrap_or_else(|| format!("resource_{}", idx));
    let name_lower = name.to_lowercase();
    let is_encrypted = name_lower.ends_with(".ysc");
    RpfEntry { name, name_lower, kind: RpfEntryKind::ResourceFile { file_offset, file_size, system_flags, graphics_flags, is_encrypted } }
}

// ─── RPF0 TOC ────────────────────────────────────────────────────────────────

fn parse_rpf0_toc(d: &[u8]) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 12 { bail!("RPF0 header too short"); }

    // Header: Magic(4) + HeaderSize(4) + EntryCount(4). TOC at 0x800.
    let header_size = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let entry_count = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;

    let toc_start    = 0x800;
    let entries_size = entry_count * 16;
    let names_size   = header_size.saturating_sub(entries_size);

    if d.len() < toc_start + entries_size + names_size {
        bail!("RPF0 TOC truncated");
    }

    let entries_data = &d[toc_start..toc_start + entries_size];
    let names_data   = &d[toc_start + entries_size..toc_start + entries_size + names_size];

    let entries = parse_rpf0_entries(entries_data, names_data, entry_count)?;
    Ok((entries, RpfEncryption::None))
}

fn parse_rpf0_entries(entries_data: &[u8], names_data: &[u8], count: usize) -> Result<Vec<RpfEntry>> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * 16;
        if off + 16 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 16];

        let dword0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let dword4 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let dword8 = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let dwordc = u32::from_le_bytes(chunk[12..16].try_into().unwrap());

        let is_dir      = dword0 & 0x80000000 != 0;
        let name_offset = (dword0 & 0x7FFFFFFF) as usize;
        let name = read_cstring(names_data, name_offset)
            .unwrap_or_else(|| if is_dir { format!("dir_{}", i) } else { format!("file_{}", i) });
        let name_lower = name.to_lowercase();

        let kind = if is_dir {
            // dword4=EntryIndex, dword8=EntryCount
            RpfEntryKind::Directory { entries_index: dword4, entries_count: dword8 }
        } else {
            // dword4=ByteOffset, dword8=OnDiskSize, dwordC=UncompressedSize
            let file_offset       = dword4;
            let disk_size         = dword8;
            let uncompressed_size = dwordc;
            // When disk_size == uncompressed_size the file is stored (not compressed).
            let file_size = if disk_size != uncompressed_size { disk_size } else { 0 };
            RpfEntryKind::BinaryFile { file_offset, file_size, uncompressed_size, is_encrypted: false }
        };

        entries.push(RpfEntry { name, name_lower, kind });
    }

    Ok(entries)
}

// ─── RPF2/3/4 TOC ────────────────────────────────────────────────────────────

fn parse_rpf2_toc(d: &[u8], version: RpfVersion) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 24 { bail!("RPF2 header too short"); }

    // Header (24 bytes): Magic + HeaderSize + EntryCount + unused + HeaderDecryptionTag + FileDecryptionTag
    let header_size    = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let entry_count    = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    let decryption_tag = u32::from_le_bytes(d[16..20].try_into().unwrap());

    let toc_start    = 0x800;
    let entries_size = entry_count * 16;
    let names_size   = header_size.saturating_sub(entries_size);

    if d.len() < toc_start + entries_size + names_size {
        bail!("RPF2 TOC truncated");
    }

    let entries_data = d[toc_start..toc_start + entries_size].to_vec();
    let names_data   = d[toc_start + entries_size..toc_start + entries_size + names_size].to_vec();

    let encryption = if decryption_tag != 0 {
        // Encrypted with GTA IV AES key — we don't hold that key, so we can't decrypt.
        eprintln!("[RPF2] Encrypted TOC (tag={:#010x}): header decryption not supported", decryption_tag);
        RpfEncryption::Aes
    } else {
        RpfEncryption::None
    };

    let entries = parse_rpf2_entries(&entries_data, &names_data, entry_count, version)?;
    Ok((entries, encryption))
}

fn parse_rpf2_entries(
    entries_data: &[u8],
    names_data   : &[u8],
    count        : usize,
    version      : RpfVersion,
) -> Result<Vec<RpfEntry>> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * 16;
        if off + 16 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 16];

        let dword0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let dword4 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let dword8 = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let dwordc = u32::from_le_bytes(chunk[12..16].try_into().unwrap());

        let is_dir      = dword8 & 0x80000000 != 0;
        let is_resource = dwordc & 0x80000000 != 0;
        let is_compressed = dwordc & 0x40000000 != 0;

        let name = if version == RpfVersion::V3 {
            format!("{:08X}", dword0)
        } else {
            let name_offset = dword0 as usize;
            read_cstring(names_data, name_offset)
                .unwrap_or_else(|| if is_dir { format!("dir_{}", i) } else { format!("file_{}", i) })
        };
        let name_lower = name.to_lowercase();

        let kind = if is_dir {
            RpfEntryKind::Directory {
                entries_index: dword8 & 0x7FFFFFFF,
                entries_count: dwordc & 0x3FFFFFFF,
            }
        } else if is_resource {
            // dword4 = OnDiskSize, dword8[8-30] = byte offset (resource version in bits 0-7)
            let byte_offset = dword8 & 0x7FFFFF00; // already byte offset
            let resource_flags = dwordc & 0x3FFFFFFF;
            // Decode virtual and physical sizes from resource flags
            let virt_size = (resource_flags & 0x7FF) << (((resource_flags >> 11) & 0xF) + 8);
            let phys_size = ((resource_flags >> 15) & 0x7FF) << (((resource_flags >> 26) & 0xF) + 8);
            RpfEntryKind::ResourceFile {
                file_offset  : byte_offset,
                file_size    : dword4,
                system_flags : virt_size,
                graphics_flags: phys_size,
                is_encrypted : false,
            }
        } else {
            // dword4 = UncompressedSize, dword8[0-30] = raw offset
            // dwordC[0-29] = OnDiskSize (compressed)
            let raw_offset = dword8 & 0x7FFFFFFF;
            // V4 stores offset / 8; multiply back to get byte offset
            let file_offset = if version == RpfVersion::V4 { raw_offset * 8 } else { raw_offset };
            let uncompressed_size = dword4;
            let disk_size         = dwordc & 0x3FFFFFFF;
            let file_size = if is_compressed { disk_size } else { 0 };
            RpfEntryKind::BinaryFile { file_offset, file_size, uncompressed_size, is_encrypted: false }
        };

        entries.push(RpfEntry { name, name_lower, kind });
    }

    Ok(entries)
}

// ─── RPF6 TOC ────────────────────────────────────────────────────────────────

fn parse_rpf6_toc(d: &[u8]) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 16 { bail!("RPF6 header too short"); }

    // Header (16 bytes, big-endian): Magic + EntryCount + DebugDataOffset + DecryptionTag
    let entry_count       = u32::from_be_bytes(d[4..8].try_into().unwrap()) as usize;
    let debug_data_offset = u32::from_be_bytes(d[8..12].try_into().unwrap()) as u64 * 8;
    let decryption_tag    = u32::from_be_bytes(d[12..16].try_into().unwrap());

    // Entries follow immediately after the 16-byte header (20 bytes each, big-endian)
    let entries_start = 16;
    let entries_size  = entry_count * 20;

    if d.len() < entries_start + entries_size { bail!("RPF6 entries truncated"); }

    let encryption = if decryption_tag != 0 {
        eprintln!("[RPF6] Encrypted TOC (tag={:#010x}): header decryption not supported", decryption_tag);
        RpfEncryption::Aes
    } else {
        RpfEncryption::None
    };

    // Read optional debug data (names)
    let debug_names: Option<(Vec<u8>, Vec<u8>)> = if debug_data_offset != 0 {
        let debug_start = debug_data_offset as usize;
        if debug_start < d.len() {
            let debug_len    = d.len() - debug_start;
            let debug_entries_size = entry_count * 8; // 2 × u32 per entry
            if debug_len >= debug_entries_size {
                let name_offsets = d[debug_start..debug_start + debug_entries_size].to_vec();
                let names_data   = d[debug_start + debug_entries_size..].to_vec();
                Some((name_offsets, names_data))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let entries_data = &d[entries_start..entries_start + entries_size];
    let entries = parse_rpf6_entries(entries_data, debug_names.as_ref(), entry_count)?;

    Ok((entries, encryption))
}

fn parse_rpf6_entries(
    entries_data: &[u8],
    debug       : Option<&(Vec<u8>, Vec<u8>)>,
    count       : usize,
) -> Result<Vec<RpfEntry>> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * 20;
        if off + 20 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 20];

        // All fields are big-endian
        let dword0 = u32::from_be_bytes(chunk[0..4].try_into().unwrap());  // NameHash
        let dword4 = u32::from_be_bytes(chunk[4..8].try_into().unwrap());  // OnDiskSize:31 + IsXenonResource:1
        let dword8 = u32::from_be_bytes(chunk[8..12].try_into().unwrap()); // IsDir:1 + version:8 + offset:23 (resource) / offset:31 (binary) / index:31 (dir)
        let dwordc = u32::from_be_bytes(chunk[12..16].try_into().unwrap());// IsResource:1 + IsCompressed:1 + flags:30
        let dword10= u32::from_be_bytes(chunk[16..20].try_into().unwrap());// Extended resource flags

        let is_dir      = dword8 & 0x80000000 != 0;
        let is_resource = dwordc & 0x80000000 != 0;
        let is_compressed = dwordc & 0x40000000 != 0;

        // Name from debug data (string table), or hash as hex
        let name = if let Some((offsets, names)) = debug {
            let off_idx = i * 8; // 2×u32 per entry; NameOffset is first
            if off_idx + 4 <= offsets.len() {
                let name_off = u32::from_be_bytes(offsets[off_idx..off_idx+4].try_into().unwrap()) as usize;
                read_cstring(names, name_off).unwrap_or_else(|| format!("{:08X}", dword0))
            } else {
                format!("{:08X}", dword0)
            }
        } else {
            format!("{:08X}", dword0)
        };
        let name_lower = name.to_lowercase();

        let kind = if is_dir {
            RpfEntryKind::Directory {
                entries_index: dword8 & 0x7FFFFFFF,
                entries_count: dwordc & 0x3FFFFFFF,
            }
        } else if is_resource {
            // Byte offset: (dword8 & 0x7FFFFF00) << 3. Store pre-computed byte offset as u32.
            let byte_offset = (((dword8 & 0x7FFFFF00) as u64) << 3) as u32;
            let on_disk_size = dword4 & 0x7FFFFFFF;
            let has_extended = dword10 & 0x80000000 != 0;
            let virt_size = if has_extended {
                (dword10 & 0x3FFF) << 12
            } else {
                (dwordc & 0x7FF) << (((dwordc >> 11) & 0xF) + 8)
            };
            let phys_size = if has_extended {
                ((dword10 >> 14) & 0x3FFF) << 12
            } else {
                ((dwordc >> 15) & 0x7FF) << (((dwordc >> 26) & 0xF) + 8)
            };
            RpfEntryKind::ResourceFile {
                file_offset  : byte_offset,
                file_size    : on_disk_size,
                system_flags : virt_size,
                graphics_flags: phys_size,
                is_encrypted : false,
            }
        } else {
            // Byte offset: (dword8 & 0x7FFFFFFF) << 3
            let byte_offset = (((dword8 & 0x7FFFFFFF) as u64) << 3) as u32;
            let on_disk_size = dword4 & 0x7FFFFFFF;
            let uncompressed_size = dwordc & 0x3FFFFFFF;
            let file_size = if is_compressed { on_disk_size } else { 0 };
            RpfEntryKind::BinaryFile {
                file_offset      : byte_offset,
                file_size,
                uncompressed_size,
                is_encrypted     : false,
            }
        };

        entries.push(RpfEntry { name, name_lower, kind });
    }

    Ok(entries)
}

// ─── Common helpers ───────────────────────────────────────────────────────────

fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() { return None; }
    let end = data[offset..].iter().position(|&b| b == 0).map(|p| offset + p).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    if DeflateDecoder::new(data).read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    use flate2::read::ZlibDecoder;
    out.clear();
    if ZlibDecoder::new(data).read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    None
}
