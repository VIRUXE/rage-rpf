use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

use crate::crypto::{decrypt_aes, decrypt_ng, GtaKeys};

pub const RPF0_MAGIC: u32 = 0x30465052; // Table Tennis
pub const RPF2_MAGIC: u32 = 0x32465052; // GTA IV
pub const RPF3_MAGIC: u32 = 0x33465052; // GTA IV Audio / MCLA (hashed names)
pub const RPF4_MAGIC: u32 = 0x34465052; // Max Payne 3
pub const RPF6_MAGIC: u32 = 0x36465052; // Red Dead Redemption
pub const RPF7_MAGIC: u32 = 0x52504637; // GTA V
pub const RPF8_MAGIC: u32 = 0x52504638; // Red Dead Redemption 2 (PC/y platform)
pub const RSC7_MAGIC: u32 = 0x37435352;
pub const RSC8_MAGIC: u32 = 0x38435352;
pub const IMG3_MAGIC: u32 = 0xA94E2A52; // GTA SA / GTA IV (IMG v3)

// ─── Version ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpfVersion {
    V0,   // Table Tennis — no encryption, deflate, TOC at 0x800
    V2,   // GTA IV — optional AES, byte offsets, TOC at 0x800
    V3,   // GTA IV Audio / MCLA — like V2 but hashed names
    V4,   // Max Payne 3 — like V2 but offsets * 8
    V6,   // Red Dead Redemption — big-endian 20-byte entries, offsets * 8
    V7,   // GTA V / FiveM — AES or NG encryption, 512-byte block offsets
    V8,   // Red Dead Redemption 2 — TFIT cipher, 24-byte entries, hash names
    Img3, // GTA SA / GTA IV IMG v3 — flat archive, offsets * 2048
}

// ─── Encryption ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpfEncryption {
    None,
    Open,
    Aes,
    Ng,
    Tfit, // RPF8 TFIT cipher (keys not held)
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
            Self::Tfit => 0x00000000,
        }
    }

    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Aes | Self::Ng | Self::Tfit)
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
        /// V7: 512-byte block number.  All other versions: pre-computed byte offset.
        file_offset      : u32,
        /// Compressed on-disk size (0 = stored, use uncompressed_size for read length).
        file_size        : u32,
        uncompressed_size: u32,
        is_encrypted     : bool,
    },
    ResourceFile {
        /// V7: 512-byte block number.  All other versions: pre-computed byte offset.
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
        if d.len() < 12 { bail!("data too short"); }

        let magic = u32::from_le_bytes(d[0..4].try_into().unwrap());
        let version = match magic {
            RPF0_MAGIC => RpfVersion::V0,
            RPF2_MAGIC => RpfVersion::V2,
            RPF3_MAGIC => RpfVersion::V3,
            RPF4_MAGIC => RpfVersion::V4,
            RPF6_MAGIC => RpfVersion::V6,
            RPF7_MAGIC => RpfVersion::V7,
            RPF8_MAGIC => RpfVersion::V8,
            IMG3_MAGIC => RpfVersion::Img3,
            _ => bail!("unknown archive magic: {:#010x}", magic),
        };

        let (entries, encryption) = match version {
            RpfVersion::V7   => parse_rpf7_toc(d, name, keys)?,
            RpfVersion::V0   => parse_rpf0_toc(d)?,
            RpfVersion::V6   => parse_rpf6_toc(d)?,
            RpfVersion::V8   => parse_rpf8_toc(d)?,
            RpfVersion::Img3 => parse_img3_toc(d)?,
            _                => parse_rpf2_toc(d, version)?,
        };

        let mut archive = Self { name: name.to_string(), start_offset: offset, encryption, entries, version };

        // Resolve V7 resource entries with sentinel file_size 0xFFFFFF
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
            RpfEntryKind::Directory { .. } => bail!("cannot extract a directory entry"),

            RpfEntryKind::BinaryFile {
                file_offset, file_size, uncompressed_size, is_encrypted
            } => {
                let byte_off = self.offset_to_bytes(*file_offset);
                let size = if *file_size > 0 { *file_size as usize } else { *uncompressed_size as usize };
                if size == 0 { bail!("binary file has zero size"); }

                let raw = data.get(byte_off..byte_off + size)
                    .with_context(|| format!("{}: binary file out of bounds", entry.name_lower))?;
                let mut buf = raw.to_vec();

                if *is_encrypted {
                    buf = self.decrypt(&buf, &entry.name, *uncompressed_size, keys)?;
                }

                if *file_size > 0 && *file_size < *uncompressed_size {
                    buf = self.decompress(&buf, *uncompressed_size as usize).unwrap_or(buf);
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

                match self.version {
                    RpfVersion::V7 => {
                        let version = resource_version_from_flags(*system_flags, *graphics_flags);
                        let mut out = Vec::with_capacity(body.len() + 16);
                        out.extend_from_slice(&RSC7_MAGIC.to_le_bytes());
                        out.extend_from_slice(&version.to_le_bytes());
                        out.extend_from_slice(&system_flags.to_le_bytes());
                        out.extend_from_slice(&graphics_flags.to_le_bytes());
                        out.extend_from_slice(&body);
                        Ok(out)
                    }
                    RpfVersion::V8 => {
                        // Rebuild as RSC8 file
                        let mut out = Vec::with_capacity(body.len() + 16);
                        out.extend_from_slice(&RSC8_MAGIC.to_le_bytes());
                        out.extend_from_slice(&[0u8; 4]); // flags placeholder
                        out.extend_from_slice(&system_flags.to_le_bytes());
                        out.extend_from_slice(&graphics_flags.to_le_bytes());
                        out.extend_from_slice(&body);
                        Ok(out)
                    }
                    _ => Ok(body), // V2/V6: return raw body
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
                        self.decompress(&buf, *uncompressed_size as usize).unwrap_or(buf)
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
                                    eprintln!("[RPF] error in nested {}: {}", path, e);
                                }
                            }
                            Err(e) => eprintln!("[RPF] failed to parse nested {}: {}", path, e),
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

                    let out = match self.version {
                        RpfVersion::V7 => {
                            let version = resource_version_from_flags(*system_flags, *graphics_flags);
                            let mut v = Vec::with_capacity(body.len() + 16);
                            v.extend_from_slice(&RSC7_MAGIC.to_le_bytes());
                            v.extend_from_slice(&version.to_le_bytes());
                            v.extend_from_slice(&system_flags.to_le_bytes());
                            v.extend_from_slice(&graphics_flags.to_le_bytes());
                            v.extend_from_slice(&body);
                            v
                        }
                        RpfVersion::V8 => {
                            let mut v = Vec::with_capacity(body.len() + 16);
                            v.extend_from_slice(&RSC8_MAGIC.to_le_bytes());
                            v.extend_from_slice(&[0u8; 4]);
                            v.extend_from_slice(&system_flags.to_le_bytes());
                            v.extend_from_slice(&graphics_flags.to_le_bytes());
                            v.extend_from_slice(&body);
                            v
                        }
                        _ => body,
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
            RpfVersion::V7 | RpfVersion::V8 => 16,
            _ => 12,
        }
    }

    fn decompress(&self, data: &[u8], uncompressed_size: usize) -> Option<Vec<u8>> {
        match self.version {
            RpfVersion::V6 => decompress_detect(data, uncompressed_size),
            RpfVersion::V8 => inflate_raw(data),
            _              => inflate(data),
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
            RpfEncryption::Tfit => {
                bail!("TFIT decryption is not supported (RDR2 keys not held)")
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
            .with_context(|| format!("cannot read {}", path.display()))?;

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
            .with_context(|| format!("entry '{}' not found", name))?;
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
    let header_size = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let entry_count = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;

    let toc_start    = 0x800;
    let entries_size = entry_count * 16;
    let names_size   = header_size.saturating_sub(entries_size);

    if d.len() < toc_start + entries_size + names_size { bail!("RPF0 TOC truncated"); }

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
            RpfEntryKind::Directory { entries_index: dword4, entries_count: dword8 }
        } else {
            let file_offset       = dword4;
            let disk_size         = dword8;
            let uncompressed_size = dwordc;
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
    let header_size    = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let entry_count    = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    let decryption_tag = u32::from_le_bytes(d[16..20].try_into().unwrap());

    let toc_start    = 0x800;
    let entries_size = entry_count * 16;
    let names_size   = header_size.saturating_sub(entries_size);

    if d.len() < toc_start + entries_size + names_size { bail!("RPF2 TOC truncated"); }

    let entries_data = d[toc_start..toc_start + entries_size].to_vec();
    let names_data   = d[toc_start + entries_size..toc_start + entries_size + names_size].to_vec();

    let encryption = if decryption_tag != 0 {
        eprintln!("[RPF2] encrypted TOC (tag={:#010x}): GTA IV key not supported", decryption_tag);
        RpfEncryption::Aes
    } else {
        RpfEncryption::None
    };

    let entries = parse_rpf2_entries(&entries_data, &names_data, entry_count, version)?;
    Ok((entries, encryption))
}

fn parse_rpf2_entries(
    entries_data: &[u8],
    names_data  : &[u8],
    count       : usize,
    version     : RpfVersion,
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

        let is_dir        = dword8 & 0x80000000 != 0;
        let is_resource   = dwordc & 0x80000000 != 0;
        let is_compressed = dwordc & 0x40000000 != 0;

        let name = if version == RpfVersion::V3 {
            format!("{:08X}", dword0)
        } else {
            read_cstring(names_data, dword0 as usize)
                .unwrap_or_else(|| if is_dir { format!("dir_{}", i) } else { format!("file_{}", i) })
        };
        let name_lower = name.to_lowercase();

        let kind = if is_dir {
            RpfEntryKind::Directory {
                entries_index: dword8 & 0x7FFFFFFF,
                entries_count: dwordc & 0x3FFFFFFF,
            }
        } else if is_resource {
            let byte_offset    = dword8 & 0x7FFFFF00;
            let resource_flags = dwordc & 0x3FFFFFFF;
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
            let raw_offset    = dword8 & 0x7FFFFFFF;
            let file_offset   = if version == RpfVersion::V4 { raw_offset * 8 } else { raw_offset };
            let disk_size     = dwordc & 0x3FFFFFFF;
            let file_size     = if is_compressed { disk_size } else { 0 };
            RpfEntryKind::BinaryFile {
                file_offset,
                file_size,
                uncompressed_size: dword4,
                is_encrypted: false,
            }
        };
        entries.push(RpfEntry { name, name_lower, kind });
    }
    Ok(entries)
}

// ─── RPF6 TOC ────────────────────────────────────────────────────────────────

fn parse_rpf6_toc(d: &[u8]) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 16 { bail!("RPF6 header too short"); }
    let entry_count       = u32::from_be_bytes(d[4..8].try_into().unwrap()) as usize;
    let debug_data_offset = u32::from_be_bytes(d[8..12].try_into().unwrap()) as u64 * 8;
    let decryption_tag    = u32::from_be_bytes(d[12..16].try_into().unwrap());

    let entries_start = 16;
    let entries_size  = entry_count * 20;

    if d.len() < entries_start + entries_size { bail!("RPF6 entries truncated"); }

    let encryption = if decryption_tag != 0 {
        eprintln!("[RPF6] encrypted TOC (tag={:#010x}): RDR1 key not supported", decryption_tag);
        RpfEncryption::Aes
    } else {
        RpfEncryption::None
    };

    let debug: Option<(Vec<u8>, Vec<u8>)> = if debug_data_offset != 0 {
        let start = debug_data_offset as usize;
        if start < d.len() {
            let debug_len         = d.len() - start;
            let debug_entries_size = entry_count * 8;
            if debug_len >= debug_entries_size {
                Some((
                    d[start..start + debug_entries_size].to_vec(),
                    d[start + debug_entries_size..].to_vec(),
                ))
            } else { None }
        } else { None }
    } else { None };

    let entries_data = &d[entries_start..entries_start + entries_size];
    let entries = parse_rpf6_entries(entries_data, debug.as_ref(), entry_count)?;
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

        let dword0  = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        let dword4  = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
        let dword8  = u32::from_be_bytes(chunk[8..12].try_into().unwrap());
        let dwordc  = u32::from_be_bytes(chunk[12..16].try_into().unwrap());
        let dword10 = u32::from_be_bytes(chunk[16..20].try_into().unwrap());

        let is_dir        = dword8 & 0x80000000 != 0;
        let is_resource   = dwordc & 0x80000000 != 0;
        let is_compressed = dwordc & 0x40000000 != 0;

        let name = if let Some((offsets, names)) = debug {
            let oi = i * 8;
            if oi + 4 <= offsets.len() {
                let name_off = u32::from_be_bytes(offsets[oi..oi+4].try_into().unwrap()) as usize;
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
            let byte_offset  = (((dword8 & 0x7FFFFF00) as u64) << 3) as u32;
            let on_disk_size = dword4 & 0x7FFFFFFF;
            let has_ext      = dword10 & 0x80000000 != 0;
            let virt_size    = if has_ext { (dword10 & 0x3FFF) << 12 }
                               else       { (dwordc & 0x7FF) << (((dwordc >> 11) & 0xF) + 8) };
            let phys_size    = if has_ext { ((dword10 >> 14) & 0x3FFF) << 12 }
                               else       { ((dwordc >> 15) & 0x7FF) << (((dwordc >> 26) & 0xF) + 8) };
            RpfEntryKind::ResourceFile {
                file_offset  : byte_offset,
                file_size    : on_disk_size,
                system_flags : virt_size,
                graphics_flags: phys_size,
                is_encrypted : false,
            }
        } else {
            let byte_offset      = (((dword8 & 0x7FFFFFFF) as u64) << 3) as u32;
            let on_disk_size     = dword4 & 0x7FFFFFFF;
            let uncompressed_size = if is_compressed { dwordc & 0x3FFFFFFF } else { on_disk_size };
            let file_size        = if is_compressed { on_disk_size } else { 0 };
            RpfEntryKind::BinaryFile {
                file_offset: byte_offset,
                file_size,
                uncompressed_size,
                is_encrypted: false,
            }
        };
        entries.push(RpfEntry { name, name_lower, kind });
    }
    Ok(entries)
}

// ─── RPF8 TOC ────────────────────────────────────────────────────────────────

// File extension table matching Swage's GetFileExt (# replaced by 'y' for PC).
static RPF8_BASE_EXTS: &[&str] = &[
    "rpf", "ymf", "ydr", "yft", "ydd", "ytd", "ybn", "ybd", "ypd", "ybs",
    "ysd", "ymt", "ysc", "ycs",
];
static RPF8_EXTRA_EXTS: &[&str] = &[
    "mrf", "cut", "gfx", "ycd", "yld", "ypmd", "ypm", "yed", "ypt",
    "ymap", "ytyp", "ych", "yldb", "yjd", "yad", "ynv", "yhn", "ypl",
    "ynd", "yvr", "ywr", "ynh", "yfd", "yas",
];

fn rpf8_ext(id: u8) -> &'static str {
    if (id as usize) < RPF8_BASE_EXTS.len() {
        RPF8_BASE_EXTS[id as usize]
    } else if id >= 64 {
        let idx = (id - 64) as usize;
        if idx < RPF8_EXTRA_EXTS.len() { RPF8_EXTRA_EXTS[idx] } else { "bin" }
    } else {
        "bin"
    }
}

fn parse_rpf8_toc(d: &[u8]) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 16 { bail!("RPF8 header too short"); }

    // Header: Magic(4) + EntryCount(4) + NamesLength(4) + DecryptionTag(2) + PlatformId(2)
    let entry_count    = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
    let _names_length  = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    let decryption_tag = u16::from_le_bytes(d[12..14].try_into().unwrap());

    // RSA signature (256 bytes) immediately after header
    let entries_start = 16 + 256;
    let entries_size  = entry_count * 24;

    if d.len() < entries_start + entries_size { bail!("RPF8 entries truncated"); }

    let encryption = if decryption_tag != 0xFF {
        eprintln!("[RPF8] TFIT-encrypted TOC (tag={:#06x}): RDR2 keys not supported", decryption_tag);
        RpfEncryption::Tfit
    } else {
        RpfEncryption::None
    };

    let entries_data = &d[entries_start..entries_start + entries_size];
    let entries = parse_rpf8_entries(entries_data, entry_count)?;

    Ok((entries, encryption))
}

fn parse_rpf8_entries(entries_data: &[u8], count: usize) -> Result<Vec<RpfEntry>> {
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 24;
        if off + 24 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 24];

        let qword0  = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let qword8  = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let qword10 = u64::from_le_bytes(chunk[16..24].try_into().unwrap());

        let hash         = (qword0 & 0xFFFFFFFF) as u32;
        let _enc_config  = ((qword0 >> 32) & 0xFF) as u8;
        let enc_key_id   = ((qword0 >> 40) & 0xFF) as u8;
        let ext_id       = ((qword0 >> 48) & 0xFF) as u8;
        let is_resource  = (qword0 >> 56) & 1 != 0;

        let on_disk_size = ((qword8 & 0xFFFFFFF) << 4) as u32;
        let byte_offset  = ((((qword8 >> 28) & 0x7FFFFFFF) << 4) & 0xFFFFFFFF) as u32;
        let compressor   = ((qword8 >> 59) & 0x1F) as u8;

        let is_encrypted = enc_key_id != 0xFF;
        let is_dir       = ext_id == 0xFE;

        let ext = if ext_id == 0xFF { "bin" } else { rpf8_ext(ext_id) };
        let name = format!("{:08X}.{}", hash, ext);
        let name_lower = name.to_lowercase();

        let kind = if is_dir {
            // RPF8 directories are currently unused per Swage comment
            RpfEntryKind::Directory { entries_index: 0, entries_count: 0 }
        } else if is_resource {
            let virt_flags = (qword10 & 0xFFFFFFFF) as u32;
            let phys_flags = (qword10 >> 32) as u32;
            let file_size  = on_disk_size;
            RpfEntryKind::ResourceFile {
                file_offset  : byte_offset,
                file_size,
                system_flags : virt_flags,
                graphics_flags: phys_flags,
                is_encrypted,
            }
        } else {
            let uncompressed_size = (qword10 & 0xFFFFFFFF) as u32;
            let file_size = if compressor != 0 { on_disk_size } else { 0 };
            RpfEntryKind::BinaryFile {
                file_offset: byte_offset,
                file_size,
                uncompressed_size,
                is_encrypted,
            }
        };
        entries.push(RpfEntry { name, name_lower, kind });
    }
    Ok(entries)
}

// ─── IMG3 TOC ────────────────────────────────────────────────────────────────

fn parse_img3_toc(d: &[u8]) -> Result<(Vec<RpfEntry>, RpfEncryption)> {
    if d.len() < 0x14 { bail!("IMG3 header too short"); }

    // Header (20 bytes): Magic(4) + Version(4) + EntryCount(4) + HeaderSize(4) + EntrySize(2) + pad(2)
    let entry_count = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    let header_size = u32::from_le_bytes(d[12..16].try_into().unwrap()) as usize;
    let entry_size  = u16::from_le_bytes(d[16..18].try_into().unwrap()) as usize;

    let entry_size  = if entry_size == 0 { 16 } else { entry_size };
    let entries_start = 0x14;
    let entries_size  = entry_count * entry_size;
    let names_start   = entries_start + entries_size;

    if d.len() < entries_start + header_size { bail!("IMG3 TOC truncated"); }

    let entries_data = &d[entries_start..entries_start + entries_size];
    let names_data   = &d[names_start..entries_start + header_size];

    let entries = parse_img3_entries(entries_data, names_data, entry_count, entry_size)?;
    Ok((entries, RpfEncryption::None))
}

fn parse_img3_entries(
    entries_data: &[u8],
    names_data  : &[u8],
    count       : usize,
    entry_size  : usize,
) -> Result<Vec<RpfEntry>> {
    let mut entries  = Vec::with_capacity(count);
    let mut name_pos = 0usize;

    for i in 0..count {
        let off = i * entry_size;
        if off + 16 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 16];

        let dword0 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let dword4 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let dword8 = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let wordc  = u16::from_le_bytes(chunk[12..14].try_into().unwrap());
        let worde  = u16::from_le_bytes(chunk[14..16].try_into().unwrap());

        // Name: sequential null-terminated strings in names_data
        let name_end = names_data[name_pos..].iter().position(|&b| b == 0)
            .map(|p| name_pos + p)
            .unwrap_or(names_data.len());
        let name = String::from_utf8_lossy(&names_data[name_pos..name_end]).into_owned();
        name_pos = name_end + 1;
        let name_lower = name.to_lowercase();

        let is_resource     = worde & 0x2000 != 0;
        let _is_old_resource = worde & 0x4000 != 0;

        let raw_offset = dword8 << 11; // * 2048
        let on_disk_size = ((wordc as u32) << 11).saturating_sub((worde & 0x7FF) as u32);

        let kind = if is_resource {
            let virt_size = (dword0 & 0x7FF) << (((dword0 >> 11) & 0xF) + 8);
            let phys_size = ((dword0 >> 15) & 0x7FF) << (((dword0 >> 26) & 0xF) + 8);
            let total_size = virt_size.saturating_add(phys_size);
            // Store as BinaryFile: offset past 12-byte resource header, zlib-compressed body
            let body_offset = raw_offset.saturating_add(12);
            let body_size   = on_disk_size.saturating_sub(12);
            RpfEntryKind::BinaryFile {
                file_offset      : body_offset,
                file_size        : body_size,
                uncompressed_size: total_size,
                is_encrypted     : false,
            }
        } else {
            let _ = dword4; // resource_type, ignored for non-resource
            RpfEntryKind::BinaryFile {
                file_offset      : raw_offset,
                file_size        : 0, // stored
                uncompressed_size: on_disk_size,
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

/// Auto-detect and decompress RPF6 data (zstd, LZXD, zlib, raw deflate).
fn decompress_detect(data: &[u8], uncompressed_size: usize) -> Option<Vec<u8>> {
    if data.len() < 4 { return None; }

    // zstd frame magic: first byte matches 0x2x, then 0xB5 0x2F 0xFD
    if (data[0] & 0xF0) == 0x20 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
        return decompress_zstd(data);
    }

    // LZXD: magic 0x0F F5 12 F1, followed by 4-byte big-endian uncompressed size (8 bytes total header)
    if data.len() >= 8 && data[0] == 0x0F && data[1] == 0xF5 && data[2] == 0x12 && data[3] == 0xF1 {
        return decompress_lzxd(&data[8..], uncompressed_size);
    }

    // Zlib / deflate fallback
    inflate(data)
}

fn decompress_zstd(data: &[u8]) -> Option<Vec<u8>> {
    use ruzstd::decoding::StreamingDecoder;
    use ruzstd::io::Read;
    let cursor = std::io::Cursor::new(data);
    let mut dec = StreamingDecoder::new(cursor).ok()?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok()?;
    if out.is_empty() { None } else { Some(out) }
}

fn decompress_lzxd(data: &[u8], uncompressed_size: usize) -> Option<Vec<u8>> {
    use lzxd::{Lzxd, WindowSize};
    // 256 KB window is a safe upper bound for RAGE game assets
    let mut dec = Lzxd::new(WindowSize::KB256);
    dec.decompress_next(data, uncompressed_size)
       .ok()
       .map(|s| s.to_vec())
}

/// Raw deflate (no zlib header) — used by RPF8.
fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    if DeflateDecoder::new(data).read_to_end(&mut out).is_ok() && !out.is_empty() {
        Some(out)
    } else {
        None
    }
}

/// Try raw deflate then zlib — used by RPF0, RPF7, IMG3, RPF2.
fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::{DeflateDecoder, ZlibDecoder};
    use std::io::Read;
    let mut out = Vec::new();
    if DeflateDecoder::new(data).read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    out.clear();
    if ZlibDecoder::new(data).read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    None
}
