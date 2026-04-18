use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::archive::{
    RpfEncryption, RpfVersion,
    IMG3_MAGIC, RPF0_MAGIC, RPF2_MAGIC, RPF3_MAGIC, RPF4_MAGIC, RPF6_MAGIC, RPF7_MAGIC, RSC7_MAGIC,
};
use crate::crypto::{encrypt_aes, GtaKeys};

// ─── Internal tree nodes ──────────────────────────────────────────────────────

struct BuildDir {
    name   : String,
    subdirs: Vec<BuildDir>,
    files  : Vec<BuildFile>,
}

struct BuildFile {
    name           : String,
    data           : Vec<u8>,
    is_resource    : bool,
    system_flags   : u32,
    graphics_flags : u32,
}

impl BuildDir {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), subdirs: vec![], files: vec![] }
    }

    fn get_or_create_subdir(&mut self, name: &str) -> &mut BuildDir {
        if self.subdirs.iter().position(|d| d.name == name).is_none() {
            self.subdirs.push(BuildDir::new(name));
        }
        let idx = self.subdirs.iter().position(|d| d.name == name).unwrap();
        &mut self.subdirs[idx]
    }
}

// ─── Flat entry list ─────────────────────────────────────────────────────────

#[derive(Debug)]
enum FlatKind {
    Directory { entries_index: u32, entries_count: u32 },
    Binary    { file_offset: u32, file_size: u32, uncompressed_size: u32 },
    Resource  { file_offset: u32, file_size: u32, system_flags: u32, graphics_flags: u32 },
}

#[derive(Debug)]
struct FlatEntry {
    name       : String,
    name_offset: u32,
    kind       : FlatKind,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Builds an RPF/IMG archive from a list of (path, data) pairs.
///
/// Paths use forward-slash separators: `"x64/foo.ydr"`.
/// Resource files are detected automatically by the RSC7 magic (V7 only).
///
/// Use [`RpfBuilder::new`] for RPF7 (GTA V) or [`RpfBuilder::for_version`]
/// to target RPF0, RPF2, RPF3, RPF4, RPF6, or IMG3.
pub struct RpfBuilder {
    version   : RpfVersion,
    encryption: RpfEncryption,
    root      : BuildDir,
}

impl RpfBuilder {
    /// Create an RPF7 (GTA V) builder with the given encryption mode.
    pub fn new(encryption: RpfEncryption) -> Self {
        Self::for_version(RpfVersion::V7, encryption)
    }

    /// Create a builder targeting any supported write format.
    ///
    /// Supported versions: V0, V2, V3, V4, V6, V7, Img3.
    /// V8 is not supported (requires proprietary TFIT keys and RSA signing).
    pub fn for_version(version: RpfVersion, encryption: RpfEncryption) -> Self {
        Self { version, encryption, root: BuildDir::new("") }
    }

    /// Add a file at `path` (forward-slash separated).
    pub fn add_file(&mut self, path: &str, data: Vec<u8>) {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() { return; }

        let filename  = parts[parts.len() - 1];
        let dir_parts = &parts[..parts.len() - 1];

        let mut dir = &mut self.root;
        for part in dir_parts {
            dir = dir.get_or_create_subdir(part);
        }

        // Resource detection: only meaningful for V7 archives
        let is_resource = self.version == RpfVersion::V7
            && data.len() >= 4
            && u32::from_le_bytes(data[..4].try_into().unwrap()) == RSC7_MAGIC;
        let (system_flags, graphics_flags) = if is_resource && data.len() >= 16 {
            let sys = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let gfx = u32::from_le_bytes(data[12..16].try_into().unwrap());
            (sys, gfx)
        } else {
            (0, 0)
        };

        dir.files.push(BuildFile { name: filename.to_string(), data, is_resource, system_flags, graphics_flags });
    }

    /// Serialize the archive to bytes.
    ///
    /// `keys` is required when `encryption == RpfEncryption::Aes` (V7 only).
    pub fn build(self, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        match self.version {
            RpfVersion::V7   => self.build_v7(keys),
            RpfVersion::V0   => self.build_v0(),
            RpfVersion::V2
            | RpfVersion::V3
            | RpfVersion::V4 => self.build_v2(),
            RpfVersion::V6   => self.build_v6(),
            RpfVersion::Img3 => self.build_img3(),
            RpfVersion::V8   => bail!("RPF8 write not supported (requires TFIT keys + RSA signing)"),
        }
    }

    // ─── RPF7 ─────────────────────────────────────────────────────────────────

    fn build_v7(self, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        if self.encryption == RpfEncryption::Ng {
            bail!("NG encryption write is not yet implemented");
        }
        if self.encryption == RpfEncryption::Aes && keys.is_none() {
            bail!("AES encryption requires crypto keys");
        }

        let mut flat: Vec<FlatEntry> = Vec::new();
        let mut file_data: Vec<Vec<u8>> = Vec::new();

        flat.push(FlatEntry { name: String::new(), name_offset: 0,
            kind: FlatKind::Directory { entries_index: 0, entries_count: 0 } });
        Self::bfs_flatten(&self.root, 0, &mut flat, &mut file_data);

        // Names table (deduplicated)
        let mut names_buf  = Vec::<u8>::new();
        let mut name_map   = HashMap::<String, u32>::new();
        for entry in flat.iter_mut() {
            let off = *name_map.entry(entry.name.clone()).or_insert_with(|| {
                let o = names_buf.len() as u32;
                names_buf.extend_from_slice(entry.name.as_bytes());
                names_buf.push(0);
                o
            });
            entry.name_offset = off;
        }
        let rem = names_buf.len() % 16;
        if rem != 0 { names_buf.resize(names_buf.len() + (16 - rem), 0); }
        let names_length = names_buf.len() as u32;

        // Assign 512-byte block offsets
        let entry_count   = flat.len() as u32;
        let header_bytes  = 16 + entry_count as u64 * 16 + names_length as u64;
        let header_blocks = (header_bytes + 511) / 512;
        let mut current_block = header_blocks as u32;
        let mut file_idx = 0usize;
        for entry in flat.iter_mut() {
            match &mut entry.kind {
                FlatKind::Binary   { file_offset, file_size, .. }
                | FlatKind::Resource { file_offset, file_size, .. } => {
                    let blocks = (file_data[file_idx].len() as u32 + 511) / 512;
                    *file_offset = current_block;
                    *file_size   = file_data[file_idx].len() as u32;
                    current_block += blocks;
                    file_idx += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        // Encode entries
        let mut entries_buf = Vec::<u8>::with_capacity(flat.len() * 16);
        for entry in &flat {
            match &entry.kind {
                FlatKind::Directory { entries_index, entries_count } => {
                    entries_buf.extend_from_slice(&entry.name_offset.to_le_bytes());
                    entries_buf.extend_from_slice(&0x7FFFFF00u32.to_le_bytes());
                    entries_buf.extend_from_slice(&entries_index.to_le_bytes());
                    entries_buf.extend_from_slice(&entries_count.to_le_bytes());
                }
                FlatKind::Binary { file_offset, file_size, uncompressed_size } => {
                    let no = entry.name_offset as u16;
                    entries_buf.extend_from_slice(&no.to_le_bytes());
                    entries_buf.push((file_size & 0xFF) as u8);
                    entries_buf.push(((file_size >> 8)  & 0xFF) as u8);
                    entries_buf.push(((file_size >> 16) & 0xFF) as u8);
                    entries_buf.push((file_offset & 0xFF) as u8);
                    entries_buf.push(((file_offset >> 8)  & 0xFF) as u8);
                    entries_buf.push(((file_offset >> 16) & 0xFF) as u8);
                    entries_buf.extend_from_slice(&uncompressed_size.to_le_bytes());
                    entries_buf.extend_from_slice(&0u32.to_le_bytes());
                }
                FlatKind::Resource { file_offset, file_size, system_flags, graphics_flags } => {
                    let no = entry.name_offset as u16;
                    let fs = (*file_size).min(0xFFFFFF);
                    entries_buf.extend_from_slice(&no.to_le_bytes());
                    entries_buf.push((fs & 0xFF) as u8);
                    entries_buf.push(((fs >> 8)  & 0xFF) as u8);
                    entries_buf.push(((fs >> 16) & 0xFF) as u8);
                    entries_buf.push((file_offset & 0xFF) as u8);
                    entries_buf.push(((file_offset >> 8)  & 0xFF) as u8);
                    entries_buf.push((((file_offset >> 16) & 0xFF) | 0x80) as u8);
                    entries_buf.extend_from_slice(&system_flags.to_le_bytes());
                    entries_buf.extend_from_slice(&graphics_flags.to_le_bytes());
                }
            }
        }

        // Encrypt if needed
        let (entries_buf, names_buf) = if self.encryption == RpfEncryption::Aes {
            let k = &keys.unwrap().aes_key;
            (encrypt_aes(&entries_buf, k), encrypt_aes(&names_buf, k))
        } else {
            (entries_buf, names_buf)
        };

        // Assemble
        let total_header = header_blocks as usize * 512;
        let mut out = Vec::new();
        out.extend_from_slice(&RPF7_MAGIC.to_le_bytes());
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&names_length.to_le_bytes());
        out.extend_from_slice(&self.encryption.as_u32().to_le_bytes());
        out.extend_from_slice(&entries_buf);
        out.extend_from_slice(&names_buf);
        out.resize(total_header, 0);

        for data in &file_data {
            out.extend_from_slice(data);
            let pad = align_up(data.len(), 512) - data.len();
            out.resize(out.len() + pad, 0);
        }

        Ok(out)
    }

    // ─── RPF0 ─────────────────────────────────────────────────────────────────

    fn build_v0(self) -> Result<Vec<u8>> {
        let mut flat: Vec<FlatEntry> = Vec::new();
        let mut file_data: Vec<Vec<u8>> = Vec::new();

        flat.push(FlatEntry { name: String::new(), name_offset: 0,
            kind: FlatKind::Directory { entries_index: 0, entries_count: 0 } });
        Self::bfs_flatten(&self.root, 0, &mut flat, &mut file_data);

        // Sequential names (no dedup needed — one per entry)
        let (names_buf, name_offsets) = build_sequential_names(&flat);

        let entry_count  = flat.len();
        let entries_size = entry_count * 16;
        let header_size  = entries_size + names_buf.len(); // stored in header

        // Files start after TOC at 0x800
        let toc_end = 0x800usize + header_size;
        let data_start = align_up(toc_end, 16);

        // Assign byte offsets
        let mut current = data_start;
        let mut file_idx = 0usize;
        for entry in flat.iter_mut() {
            match &mut entry.kind {
                FlatKind::Binary { file_offset, file_size, .. }
                | FlatKind::Resource { file_offset, file_size, .. } => {
                    *file_offset = current as u32;
                    *file_size   = file_data[file_idx].len() as u32;
                    current += file_data[file_idx].len();
                    file_idx += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        // Encode entries (16 bytes each)
        let mut entries_buf = Vec::<u8>::with_capacity(entry_count * 16);
        for (i, entry) in flat.iter().enumerate() {
            let name_off = name_offsets[i] as u32;
            match &entry.kind {
                FlatKind::Directory { entries_index, entries_count } => {
                    // dword0: IsDir=1 | NameOffset:31
                    entries_buf.extend_from_slice(&(0x80000000u32 | name_off).to_le_bytes());
                    entries_buf.extend_from_slice(&entries_index.to_le_bytes());
                    entries_buf.extend_from_slice(&entries_count.to_le_bytes());
                    entries_buf.extend_from_slice(&entries_count.to_le_bytes());
                }
                FlatKind::Binary { file_offset, file_size, uncompressed_size }
                | FlatKind::Resource { file_offset, file_size,
                    system_flags: uncompressed_size, graphics_flags: _ } => {
                    entries_buf.extend_from_slice(&name_off.to_le_bytes());
                    entries_buf.extend_from_slice(&file_offset.to_le_bytes());
                    entries_buf.extend_from_slice(&file_size.to_le_bytes());
                    entries_buf.extend_from_slice(&uncompressed_size.to_le_bytes());
                }
            }
        }

        // Assemble
        let mut out = Vec::new();
        out.extend_from_slice(&RPF0_MAGIC.to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes());
        out.extend_from_slice(&(entry_count as u32).to_le_bytes());
        out.resize(0x800, 0); // pad to TOC offset

        out.extend_from_slice(&entries_buf);
        out.extend_from_slice(&names_buf);
        out.resize(data_start, 0);

        for data in &file_data {
            out.extend_from_slice(data);
        }

        Ok(out)
    }

    // ─── RPF2 / RPF3 / RPF4 ──────────────────────────────────────────────────

    fn build_v2(self) -> Result<Vec<u8>> {
        let magic = match self.version {
            RpfVersion::V3 => RPF3_MAGIC,
            RpfVersion::V4 => RPF4_MAGIC,
            _              => RPF2_MAGIC,
        };
        let use_hashes = self.version == RpfVersion::V3;
        // V4 stores offsets divided by 8
        let offset_shift = self.version == RpfVersion::V4;

        let mut flat: Vec<FlatEntry> = Vec::new();
        let mut file_data: Vec<Vec<u8>> = Vec::new();

        flat.push(FlatEntry { name: String::new(), name_offset: 0,
            kind: FlatKind::Directory { entries_index: 0, entries_count: 0 } });
        Self::bfs_flatten(&self.root, 0, &mut flat, &mut file_data);

        let entry_count  = flat.len();
        let entries_size = entry_count * 16;

        // Names table (V3 uses hashes only → no name strings needed)
        let (names_buf, name_offsets) = if use_hashes {
            (Vec::new(), vec![0u32; entry_count])
        } else {
            let (buf, offsets) = build_sequential_names(&flat);
            (buf, offsets.iter().map(|&o| o as u32).collect())
        };

        let header_size = entries_size + names_buf.len();

        // Files start after TOC at 0x800
        let data_start = align_up(0x800 + header_size, if offset_shift { 8 } else { 4 });

        // Assign byte offsets
        let mut current = data_start;
        let mut file_idx = 0usize;
        for entry in flat.iter_mut() {
            match &mut entry.kind {
                FlatKind::Binary   { file_offset, file_size, .. }
                | FlatKind::Resource { file_offset, file_size, .. } => {
                    *file_offset = current as u32;
                    *file_size   = file_data[file_idx].len() as u32;
                    let stride = if offset_shift { align_up(file_data[file_idx].len(), 8) } else { file_data[file_idx].len() };
                    current += stride;
                    file_idx += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        // Encode entries (16 bytes each)
        let mut entries_buf = Vec::<u8>::with_capacity(entry_count * 16);
        for (i, entry) in flat.iter().enumerate() {
            let dword0 = if use_hashes {
                rage_joaat(&entry.name.to_lowercase())
            } else {
                name_offsets[i]
            };

            match &entry.kind {
                FlatKind::Directory { entries_index, entries_count } => {
                    // dword0: NameOffset/Hash
                    // dword4: unused (0)
                    // dword8: IsDir:1 | EntryIndex:31
                    // dwordC: EntryCount:30
                    entries_buf.extend_from_slice(&dword0.to_le_bytes());
                    entries_buf.extend_from_slice(&0u32.to_le_bytes());
                    entries_buf.extend_from_slice(&(0x80000000u32 | entries_index).to_le_bytes());
                    entries_buf.extend_from_slice(&entries_count.to_le_bytes());
                }
                FlatKind::Binary { file_offset, file_size: _, uncompressed_size } => {
                    // For stored binary: dword8 = raw_offset (V2/V3) or raw_offset/8 (V4)
                    let stored_offset = if offset_shift { file_offset / 8 } else { *file_offset };
                    entries_buf.extend_from_slice(&dword0.to_le_bytes());
                    entries_buf.extend_from_slice(&uncompressed_size.to_le_bytes()); // Size
                    entries_buf.extend_from_slice(&(stored_offset & 0x7FFFFFFF).to_le_bytes());
                    entries_buf.extend_from_slice(&0u32.to_le_bytes()); // stored, not resource
                }
                FlatKind::Resource { file_offset, file_size, system_flags: _, graphics_flags: _ } => {
                    let stored_offset = if offset_shift { file_offset / 8 } else { *file_offset };
                    let resource_flags = 0u32;
                    let dword8 = stored_offset & 0x7FFFFF00;
                    let dwordc = 0x80000000u32 | resource_flags;
                    entries_buf.extend_from_slice(&dword0.to_le_bytes());
                    entries_buf.extend_from_slice(&(*file_size as u32).to_le_bytes());
                    entries_buf.extend_from_slice(&dword8.to_le_bytes());
                    entries_buf.extend_from_slice(&dwordc.to_le_bytes());
                }
            }
        }

        // Assemble
        // Header: Magic(4) + HeaderSize(4) + EntryCount(4) + unused(4) + HeaderDecryptionTag(4=0) + FileDecryptionTag(4=0)
        let mut out = Vec::new();
        out.extend_from_slice(&magic.to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes());
        out.extend_from_slice(&(entry_count as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // unused
        out.extend_from_slice(&0u32.to_le_bytes()); // HeaderDecryptionTag = 0 (unencrypted)
        out.extend_from_slice(&0u32.to_le_bytes()); // FileDecryptionTag = 0
        out.resize(0x800, 0);

        out.extend_from_slice(&entries_buf);
        out.extend_from_slice(&names_buf);
        out.resize(data_start, 0);

        let mut file_idx = 0usize;
        for entry in &flat {
            match &entry.kind {
                FlatKind::Binary { .. } | FlatKind::Resource { .. } => {
                    let data = &file_data[file_idx];
                    out.extend_from_slice(data);
                    if offset_shift {
                        let pad = align_up(out.len(), 8) - out.len();
                        out.resize(out.len() + pad, 0);
                    }
                    file_idx += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        Ok(out)
    }

    // ─── RPF6 ─────────────────────────────────────────────────────────────────

    fn build_v6(self) -> Result<Vec<u8>> {
        let mut flat: Vec<FlatEntry> = Vec::new();
        let mut file_data: Vec<Vec<u8>> = Vec::new();

        flat.push(FlatEntry { name: String::new(), name_offset: 0,
            kind: FlatKind::Directory { entries_index: 0, entries_count: 0 } });
        Self::bfs_flatten(&self.root, 0, &mut flat, &mut file_data);

        let entry_count   = flat.len();
        // Header (16 bytes big-endian) + entries (20 bytes each) immediately follow
        let entries_end   = 16 + entry_count * 20;
        // File data starts after entries, aligned to 8 bytes (offsets stored as /8)
        let data_start    = align_up(entries_end, 8);

        // Assign byte offsets (multiples of 8)
        let mut current  = data_start;
        let mut file_idx = 0usize;
        for entry in flat.iter_mut() {
            match &mut entry.kind {
                FlatKind::Binary   { file_offset, file_size, .. }
                | FlatKind::Resource { file_offset, file_size, .. } => {
                    *file_offset = current as u32;
                    *file_size   = file_data[file_idx].len() as u32;
                    current      = align_up(current + file_data[file_idx].len(), 8);
                    file_idx    += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        // Debug data (names) follows all file data; DebugDataOffset stored as bytes/8
        let debug_byte_offset = align_up(current, 8);
        let debug_data_offset = (debug_byte_offset / 8) as u32;

        // Build debug data: per-entry 8-byte struct (NameOffset:u32 big-endian, LastModified:u32=0)
        // followed by sequential null-terminated names
        let mut debug_name_bytes = Vec::<u8>::new();
        let mut debug_entry_bytes = Vec::<u8>::with_capacity(entry_count * 8);
        for entry in &flat {
            debug_entry_bytes.extend_from_slice(&(debug_name_bytes.len() as u32).to_be_bytes());
            debug_entry_bytes.extend_from_slice(&0u32.to_be_bytes());
            debug_name_bytes.extend_from_slice(entry.name.as_bytes());
            debug_name_bytes.push(0);
        }

        // Encode entries (20 bytes each, big-endian)
        let mut entries_buf = Vec::<u8>::with_capacity(entry_count * 20);
        for entry in &flat {
            let hash = rage_joaat(&entry.name.to_lowercase());
            match &entry.kind {
                FlatKind::Directory { entries_index, entries_count } => {
                    entries_buf.extend_from_slice(&hash.to_be_bytes());         // dword0 hash
                    entries_buf.extend_from_slice(&0u32.to_be_bytes());         // dword4 OnDiskSize=0
                    entries_buf.extend_from_slice(&(0x80000000u32 | entries_index).to_be_bytes()); // IsDir|Index
                    entries_buf.extend_from_slice(&entries_count.to_be_bytes());// dwordC EntryCount
                    entries_buf.extend_from_slice(&0u32.to_be_bytes());         // dword10
                }
                FlatKind::Binary { file_offset, file_size, uncompressed_size } => {
                    // raw_offset = file_offset / 8 (stored as offset>>3)
                    let raw = (*file_offset / 8) & 0x7FFFFFFF;
                    entries_buf.extend_from_slice(&hash.to_be_bytes());
                    entries_buf.extend_from_slice(&file_size.to_be_bytes());     // OnDiskSize
                    entries_buf.extend_from_slice(&raw.to_be_bytes());           // offset (no IsDir bit)
                    entries_buf.extend_from_slice(&uncompressed_size.to_be_bytes()); // Size (stored = same as disk)
                    entries_buf.extend_from_slice(&0u32.to_be_bytes());
                }
                FlatKind::Resource { file_offset, file_size, system_flags, graphics_flags } => {
                    let raw = (*file_offset / 8) & 0x7FFFFF00; // keep in offset field position
                    entries_buf.extend_from_slice(&hash.to_be_bytes());
                    entries_buf.extend_from_slice(&file_size.to_be_bytes());
                    entries_buf.extend_from_slice(&raw.to_be_bytes());
                    entries_buf.extend_from_slice(&(0x80000000u32).to_be_bytes()); // IsResource
                    entries_buf.extend_from_slice(&0u32.to_be_bytes());
                    // Note: system/graphics flags not encoded here; would need RPF6 flag packing
                    let _ = (system_flags, graphics_flags);
                }
            }
        }

        // Assemble
        let mut out = Vec::new();
        // Header (big-endian): Magic + EntryCount + DebugDataOffset + DecryptionTag(0)
        out.extend_from_slice(&RPF6_MAGIC.to_be_bytes());
        out.extend_from_slice(&(entry_count as u32).to_be_bytes());
        out.extend_from_slice(&debug_data_offset.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // unencrypted

        out.extend_from_slice(&entries_buf);
        out.resize(data_start, 0); // pad to file data start

        let mut file_idx = 0usize;
        for entry in &flat {
            match &entry.kind {
                FlatKind::Binary { file_size: _, .. } | FlatKind::Resource { file_size: _, .. } => {
                    out.extend_from_slice(&file_data[file_idx]);
                    let pad = align_up(out.len(), 8) - out.len();
                    out.resize(out.len() + pad, 0);
                    file_idx += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        // Debug data
        out.resize(debug_byte_offset, 0);
        out.extend_from_slice(&debug_entry_bytes);
        out.extend_from_slice(&debug_name_bytes);

        Ok(out)
    }

    // ─── IMG3 ─────────────────────────────────────────────────────────────────

    fn build_img3(self) -> Result<Vec<u8>> {
        // IMG3 is flat: collect all files recursively, no directory entries
        let mut flat_files: Vec<(String, Vec<u8>)> = Vec::new();
        Self::collect_files_flat(&self.root, "", &mut flat_files);

        let entry_count  = flat_files.len();

        // Sequential names
        let mut names_buf    = Vec::<u8>::new();
        let mut name_offsets = Vec::<usize>::new();
        for (name, _) in &flat_files {
            name_offsets.push(names_buf.len());
            names_buf.extend_from_slice(name.as_bytes());
            names_buf.push(0);
        }

        let entries_size = entry_count * 16;
        let header_size  = entries_size + names_buf.len(); // stored in header

        // File data starts after header at 0x14 + header_size, aligned to 2048
        let data_start = align_up(0x14 + header_size, 2048);

        // Assign byte offsets (multiples of 2048)
        let mut offsets  = Vec::<u32>::with_capacity(entry_count);
        let mut current  = data_start;
        for (_, data) in &flat_files {
            offsets.push(current as u32);
            current = align_up(current + data.len(), 2048);
        }

        // Encode entries (16 bytes each)
        let mut entries_buf = Vec::<u8>::with_capacity(entry_count * 16);
        for (i, (_, data)) in flat_files.iter().enumerate() {
            let file_offset = offsets[i];
            let disk_size   = data.len() as u32;

            // dword8 = file_offset >> 11 (= byte_offset / 2048)
            let dword8 = file_offset >> 11;

            // wordC and wordE encode on-disk size:
            // GetOnDiskSize = (wordC << 11) - (wordE & 0x7FF)
            // Choose wordC = ceil(disk_size / 2048)
            let word_c = ((disk_size + 2047) / 2048) as u16;
            let word_e = ((word_c as u32 * 2048) - disk_size) as u16; // low 11 bits

            entries_buf.extend_from_slice(&0u32.to_le_bytes()); // dword0 (no resource flags)
            entries_buf.extend_from_slice(&0u32.to_le_bytes()); // dword4 resource_type = 0
            entries_buf.extend_from_slice(&dword8.to_le_bytes());
            entries_buf.extend_from_slice(&word_c.to_le_bytes());
            entries_buf.extend_from_slice(&word_e.to_le_bytes());
        }

        // Assemble
        // Header: Magic(4) + Version(4=3) + EntryCount(4) + HeaderSize(4) + EntrySize(2=16) + pad(2)
        let mut out = Vec::new();
        out.extend_from_slice(&IMG3_MAGIC.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes()); // version
        out.extend_from_slice(&(entry_count as u32).to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes()); // entry_size
        out.extend_from_slice(&0u16.to_le_bytes());  // pad

        out.extend_from_slice(&entries_buf);
        out.extend_from_slice(&names_buf);
        out.resize(data_start, 0); // pad to file data area

        for (_, data) in &flat_files {
            out.extend_from_slice(data);
            let pad = align_up(out.len(), 2048) - out.len();
            out.resize(out.len() + pad, 0);
        }

        Ok(out)
    }

    // ─── Shared tree helpers ──────────────────────────────────────────────────

    fn bfs_flatten(
        dir          : &BuildDir,
        self_flat_idx: usize,
        flat         : &mut Vec<FlatEntry>,
        file_data    : &mut Vec<Vec<u8>>,
    ) {
        let mut children_dirs  = dir.subdirs.iter().collect::<Vec<_>>();
        let mut children_files = dir.files.iter().collect::<Vec<_>>();
        children_dirs.sort_by( |a, b| a.name.cmp(&b.name));
        children_files.sort_by(|a, b| a.name.cmp(&b.name));

        let mut all: Vec<(bool, usize)> = (0..children_dirs.len()).map(|i| (true, i))
            .chain((0..children_files.len()).map(|i| (false, i)))
            .collect();
        all.sort_by_key(|&(is_dir, idx)| {
            if is_dir { children_dirs[idx].name.clone() } else { children_files[idx].name.clone() }
        });

        let entries_index = flat.len() as u32;
        let entries_count = all.len() as u32;
        if let FlatKind::Directory { entries_index: ei, entries_count: ec } =
            &mut flat[self_flat_idx].kind
        {
            *ei = entries_index;
            *ec = entries_count;
        }

        let child_start = flat.len();
        for &(is_dir, idx) in &all {
            if is_dir {
                flat.push(FlatEntry {
                    name: children_dirs[idx].name.clone(), name_offset: 0,
                    kind: FlatKind::Directory { entries_index: 0, entries_count: 0 },
                });
            } else {
                let f = children_files[idx];
                if f.is_resource {
                    flat.push(FlatEntry {
                        name: f.name.clone(), name_offset: 0,
                        kind: FlatKind::Resource {
                            file_offset: 0, file_size: 0,
                            system_flags: f.system_flags, graphics_flags: f.graphics_flags,
                        },
                    });
                } else {
                    flat.push(FlatEntry {
                        name: f.name.clone(), name_offset: 0,
                        kind: FlatKind::Binary {
                            file_offset: 0, file_size: 0,
                            uncompressed_size: f.data.len() as u32,
                        },
                    });
                }
                file_data.push(f.data.clone());
            }
        }

        let mut ci = child_start;
        for &(is_dir, idx) in &all {
            if is_dir { Self::bfs_flatten(children_dirs[idx], ci, flat, file_data); }
            ci += 1;
        }
    }

    /// Recursively collect all files (name = full relative path).
    fn collect_files_flat(dir: &BuildDir, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
        for f in &dir.files {
            let name = if prefix.is_empty() {
                f.name.clone()
            } else {
                format!("{}/{}", prefix, f.name)
            };
            out.push((name, f.data.clone()));
        }
        for sub in &dir.subdirs {
            let sub_prefix = if prefix.is_empty() {
                sub.name.clone()
            } else {
                format!("{}/{}", prefix, sub.name)
            };
            Self::collect_files_flat(sub, &sub_prefix, out);
        }
    }
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Build a sequential names buffer where each entry's name follows the previous.
/// Returns (names_buf, per-entry byte offsets into names_buf).
fn build_sequential_names(flat: &[FlatEntry]) -> (Vec<u8>, Vec<usize>) {
    let mut buf     = Vec::<u8>::new();
    let mut offsets = Vec::with_capacity(flat.len());
    for entry in flat {
        offsets.push(buf.len());
        buf.extend_from_slice(entry.name.as_bytes());
        buf.push(0);
    }
    (buf, offsets)
}

/// RAGE Jenkins one-at-a-time hash (atStringHash).
/// Input should already be lowercase.
pub fn rage_joaat(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for b in s.bytes() {
        hash = hash.wrapping_add(b as u32);
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash = hash.wrapping_add(hash << 15);
    hash
}
