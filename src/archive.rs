use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

use crate::crypto::{decrypt_aes, decrypt_ng, GtaKeys};

pub const RPF7_MAGIC: u32 = 0x52504637;
pub const RSC7_MAGIC: u32 = 0x37435352;

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
            _          => Self::Ng,   // unknown → assume NG (matches CodeWalker default)
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
        file_offset      : u32,
        file_size        : u32,
        uncompressed_size: u32,
        is_encrypted     : bool,
    },
    ResourceFile {
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

/// Parsed RPF7 archive header + entry table.
/// Does not own the file data — pass the raw bytes to extraction methods.
pub struct RpfArchive {
    /// Filename or path label used for NG key selection.
    pub name      : String,
    /// Byte offset within the raw data slice where this archive starts.
    pub start_offset: usize,
    pub encryption: RpfEncryption,
    pub entries   : Vec<RpfEntry>,
}

impl RpfArchive {
    /// Parse an RPF7 archive that starts at byte 0 of `data`.
    pub fn parse(data: &[u8], name: &str, keys: Option<&GtaKeys>) -> Result<Self> {
        Self::parse_at(data, 0, name, keys)
    }

    /// Parse an RPF7 archive starting at `offset` within `data`.
    /// `name` is the archive filename, used for NG key selection.
    pub fn parse_at(data: &[u8], offset: usize, name: &str, keys: Option<&GtaKeys>) -> Result<Self> {
        let d = data.get(offset..).context("offset out of bounds")?;

        if d.len() < 16 {
            bail!("RPF data too short");
        }

        let magic = u32::from_le_bytes(d[0..4].try_into().unwrap());
        if magic != RPF7_MAGIC {
            bail!("Not an RPF7 archive (magic={:#010x})", magic);
        }

        let entry_count  = u32::from_le_bytes(d[4..8].try_into().unwrap()) as usize;
        let names_length = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
        let enc_raw      = u32::from_le_bytes(d[12..16].try_into().unwrap());
        let encryption   = RpfEncryption::from_u32(enc_raw);

        let entries_off  = 16;
        let entries_size = entry_count * 16;
        let names_off    = entries_off + entries_size;

        if d.len() < names_off + names_length {
            bail!("RPF header truncated");
        }

        let mut entries_data = d[entries_off..entries_off + entries_size].to_vec();
        let mut names_data   = d[names_off..names_off + names_length].to_vec();

        // Decrypt entries + names tables if needed
        match (encryption, keys) {
            (RpfEncryption::Aes, Some(k)) => {
                entries_data = decrypt_aes(&entries_data, &k.aes_key);
                names_data   = decrypt_aes(&names_data,   &k.aes_key);
            }
            (RpfEncryption::Ng, Some(k)) => {
                let file_size = data.len() as u32;
                entries_data = decrypt_ng(&entries_data, k, name, file_size);
                names_data   = decrypt_ng(&names_data,   k, name, file_size);
            }
            _ => {}
        }

        let mut entries = parse_entries(&entries_data, &names_data, entry_count)?;

        // Resolve resource entries with file_size == 0xFFFFFF
        for entry in &mut entries {
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

        Ok(Self { name: name.to_string(), start_offset: offset, encryption, entries })
    }

    // ─── Extraction ──────────────────────────────────────────────────────────

    /// Extract the data for a single binary or resource file entry.
    ///
    /// For binary files: decrypts (if needed) then deflate-decompresses.
    /// For resource files: decrypts (if needed), then prepends a fresh RSC7
    /// header so the output is a valid standalone resource file for FiveM /
    /// OpenIV / CodeWalker.
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
                let byte_off = self.start_offset + (*file_offset as usize * 512);
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
                if total < 16 { bail!("{}: resource too small ({} bytes)", entry.name_lower, total); }

                let byte_off = self.start_offset + (*file_offset as usize * 512);
                // Skip the in-RPF RSC7 header (16 bytes); the body follows.
                let body_off = byte_off + 16;
                let body_len = total - 16;

                let raw = data.get(body_off..body_off + body_len)
                    .with_context(|| format!("{}: resource out of bounds", entry.name_lower))?;
                let mut body = raw.to_vec();

                if *is_encrypted {
                    body = self.decrypt(&body, &entry.name, *file_size, keys)?;
                }

                // Rebuild as a standalone RSC7 file with a fresh 16-byte header.
                let version = resource_version_from_flags(*system_flags, *graphics_flags);
                let mut out = Vec::with_capacity(body.len() + 16);
                out.extend_from_slice(&RSC7_MAGIC.to_le_bytes());
                out.extend_from_slice(&version.to_le_bytes());
                out.extend_from_slice(&system_flags.to_le_bytes());
                out.extend_from_slice(&graphics_flags.to_le_bytes());
                out.extend_from_slice(&body);
                Ok(out)
            }
        }
    }

    /// Walk every file in this archive (and recursively into nested RPF7s),
    /// calling `on_file(path, data)` for each.
    ///
    /// `path_prefix` is prepended to entry names (use `""` for the root archive).
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
        if depth > MAX_DEPTH {
            return Ok(());
        }

        let is_aes = self.encryption == RpfEncryption::Aes;

        for entry in &self.entries {
            if entry.is_directory() {
                continue;
            }

            let path = if path_prefix.is_empty() {
                entry.name_lower.clone()
            } else {
                format!("{}/{}", path_prefix, entry.name_lower)
            };

            match &entry.kind {
                RpfEntryKind::BinaryFile {
                    file_offset, file_size, uncompressed_size, is_encrypted
                } => {
                    let byte_off = self.start_offset + (*file_offset as usize * 512);
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

                    let out = if *file_size > 0 {
                        inflate(&buf).unwrap_or(buf)
                    } else {
                        buf
                    };

                    // Recurse into nested RPFs
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
                    if total < 16 { continue; }

                    let byte_off = self.start_offset + (*file_offset as usize * 512);
                    let body_off = byte_off + 16;
                    let body_len = total - 16;
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

                    let version = resource_version_from_flags(*system_flags, *graphics_flags);
                    let mut out = Vec::with_capacity(body.len() + 16);
                    out.extend_from_slice(&RSC7_MAGIC.to_le_bytes());
                    out.extend_from_slice(&version.to_le_bytes());
                    out.extend_from_slice(&system_flags.to_le_bytes());
                    out.extend_from_slice(&graphics_flags.to_le_bytes());
                    out.extend_from_slice(&body);

                    on_file(&path, out);
                }

                RpfEntryKind::Directory { .. } => {}
            }
        }

        Ok(())
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

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

/// An RPF7 archive loaded into memory. Owns both the raw bytes and the parsed
/// metadata, so you can call `extract` and `walk` without keeping a separate
/// `Vec<u8>` around.
pub struct RpfFile {
    pub archive: RpfArchive,
    data: Vec<u8>,
}

impl RpfFile {
    /// Read the file at `path` into memory and parse the RPF7 header.
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

    /// Extract a single entry by name.
    pub fn extract_by_name(&self, name: &str, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        let entry = self.archive.entries.iter()
            .find(|e| e.name_lower == name.to_lowercase())
            .with_context(|| format!("Entry '{}' not found", name))?;
        self.archive.extract_entry(&self.data, entry, keys)
    }

    /// Extract a single entry.
    pub fn extract(&self, entry: &RpfEntry, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        self.archive.extract_entry(&self.data, entry, keys)
    }

    /// Walk every file (recursing into nested RPFs), calling `on_file(path, data)`.
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

/// Compute the RSC7 version byte from system + graphics page flags.
/// Matches CodeWalker's `GetVersionFromFlags`.
pub fn resource_version_from_flags(sys_flags: u32, gfx_flags: u32) -> u32 {
    let sv = (sys_flags  >> 28) & 0xF;
    let gv = (gfx_flags  >> 28) & 0xF;
    (sv << 4) | gv
}

/// Compute the actual memory size encoded in a resource page-flags word.
/// Matches CodeWalker's `GetSizeFromFlags` (dexyfex simplified version).
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

// ─── Entry table parsing ──────────────────────────────────────────────────────

fn parse_entries(entries_data: &[u8], names_data: &[u8], count: usize) -> Result<Vec<RpfEntry>> {
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * 16;
        if off + 16 > entries_data.len() { break; }
        let chunk = &entries_data[off..off + 16];
        let h2 = u32::from_le_bytes(chunk[4..8].try_into().unwrap());

        let entry = if h2 == 0x7FFFFF00 {
            parse_directory(chunk, names_data, i)
        } else if (h2 & 0x80000000) == 0 {
            parse_binary_file(chunk, names_data, i)
        } else {
            parse_resource_file(chunk, names_data, i)
        };

        entries.push(entry);
    }

    Ok(entries)
}

fn parse_directory(chunk: &[u8], names: &[u8], idx: usize) -> RpfEntry {
    let name_offset   = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as usize;
    let entries_index = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
    let entries_count = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
    let name = read_cstring(names, name_offset).unwrap_or_else(|| format!("dir_{}", idx));
    let name_lower = name.to_lowercase();
    RpfEntry { name, name_lower, kind: RpfEntryKind::Directory { entries_index, entries_count } }
}

fn parse_binary_file(chunk: &[u8], names: &[u8], idx: usize) -> RpfEntry {
    let name_offset      = u16::from_le_bytes(chunk[0..2].try_into().unwrap()) as usize;
    let file_size        = (chunk[2] as u32) | ((chunk[3] as u32) << 8) | ((chunk[4] as u32) << 16);
    let file_offset      = (chunk[5] as u32) | ((chunk[6] as u32) << 8) | ((chunk[7] as u32) << 16);
    let uncompressed_size= u32::from_le_bytes(chunk[8..12].try_into().unwrap());
    let enc_type         = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
    let is_encrypted     = enc_type == 1;
    let name = read_cstring(names, name_offset).unwrap_or_else(|| format!("binary_{}", idx));
    let name_lower = name.to_lowercase();
    RpfEntry { name, name_lower, kind: RpfEntryKind::BinaryFile { file_offset, file_size, uncompressed_size, is_encrypted } }
}

fn parse_resource_file(chunk: &[u8], names: &[u8], idx: usize) -> RpfEntry {
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

fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() { return None; }
    let end = data[offset..].iter().position(|&b| b == 0).map(|p| offset + p).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

// ─── Decompression ───────────────────────────────────────────────────────────

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
