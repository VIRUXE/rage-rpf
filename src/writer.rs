use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::archive::{RpfEncryption, RPF7_MAGIC, RSC7_MAGIC};
use crate::crypto::{encrypt_aes, GtaKeys};

// ─── Internal tree nodes ──────────────────────────────────────────────────────

struct BuildDir {
    name: String,
    subdirs: Vec<BuildDir>,
    files: Vec<BuildFile>,
}

struct BuildFile {
    name: String,
    data: Vec<u8>,
    is_resource: bool,
    system_flags: u32,
    graphics_flags: u32,
}

impl BuildDir {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), subdirs: vec![], files: vec![] }
    }

    fn get_or_create_subdir(&mut self, name: &str) -> &mut BuildDir {
        let pos = self.subdirs.iter().position(|d| d.name == name);
        if pos.is_none() {
            self.subdirs.push(BuildDir::new(name));
        }
        let idx = self.subdirs.iter().position(|d| d.name == name).unwrap();
        &mut self.subdirs[idx]
    }
}

// ─── Flat entry list built during BFS ────────────────────────────────────────

#[derive(Debug)]
enum FlatKind {
    Directory { entries_index: u32, entries_count: u32 },
    Binary { file_offset: u32, file_size: u32, uncompressed_size: u32 },
    Resource { file_offset: u32, file_size: u32, system_flags: u32, graphics_flags: u32 },
}

#[derive(Debug)]
struct FlatEntry {
    name: String,
    name_offset: u32,
    kind: FlatKind,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Builds an RPF7 archive from a list of (path, data) pairs.
///
/// Paths use forward-slash separators: `"x64/foo.ydr"`.
/// Resource files are detected automatically by the RSC7 magic (`0x37435352`).
pub struct RpfBuilder {
    encryption: RpfEncryption,
    root: BuildDir,
}

impl RpfBuilder {
    pub fn new(encryption: RpfEncryption) -> Self {
        Self {
            encryption,
            root: BuildDir::new(""),
        }
    }

    /// Add a file. `path` may contain forward-slash directory components.
    pub fn add_file(&mut self, path: &str, data: Vec<u8>) {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return;
        }

        let filename = parts[parts.len() - 1];
        let dir_parts = &parts[..parts.len() - 1];

        let mut dir = &mut self.root;
        for part in dir_parts {
            dir = dir.get_or_create_subdir(part);
        }

        let is_resource = data.len() >= 4
            && u32::from_le_bytes(data[..4].try_into().unwrap()) == RSC7_MAGIC;
        let (system_flags, graphics_flags) = if is_resource && data.len() >= 16 {
            let sys = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let gfx = u32::from_le_bytes(data[12..16].try_into().unwrap());
            (sys, gfx)
        } else {
            (0, 0)
        };

        dir.files.push(BuildFile {
            name: filename.to_string(),
            data,
            is_resource,
            system_flags,
            graphics_flags,
        });
    }

    /// Serialize the archive to bytes.
    ///
    /// Pass `keys` when using `RpfEncryption::Aes` (required for AES encryption).
    pub fn build(self, keys: Option<&GtaKeys>) -> Result<Vec<u8>> {
        if self.encryption == RpfEncryption::Ng {
            bail!("NG encryption write is not yet implemented");
        }
        if self.encryption == RpfEncryption::Aes && keys.is_none() {
            bail!("AES encryption requires crypto keys");
        }

        // ── Step 1: BFS traversal to build flat entry list ─────────────────
        let mut flat: Vec<FlatEntry> = Vec::new();

        // Root directory entry placeholder — we'll fill entries_index/count later
        flat.push(FlatEntry {
            name: String::new(),
            name_offset: 0,
            kind: FlatKind::Directory { entries_index: 0, entries_count: 0 },
        });

        // Collect file data in the same BFS order as files are assigned offsets
        let mut file_data: Vec<Vec<u8>> = Vec::new();

        // BFS queue: (dir_ref, flat_index_of_this_dir)
        // We process the root first by simulating a queue with index tracking.
        // Because we need mutable references we flatten the tree recursively.
        Self::bfs_flatten(&self.root, 0, &mut flat, &mut file_data);

        // ── Step 2: Build names table ──────────────────────────────────────
        let mut names_buf: Vec<u8> = Vec::new();
        let mut name_map: HashMap<String, u32> = HashMap::new();

        for entry in flat.iter_mut() {
            let name = entry.name.as_str();
            if let Some(&off) = name_map.get(name) {
                entry.name_offset = off;
            } else {
                let off = names_buf.len() as u32;
                name_map.insert(name.to_string(), off);
                entry.name_offset = off;
                names_buf.extend_from_slice(name.as_bytes());
                names_buf.push(0); // null terminator
            }
        }
        // Pad names to 16-byte boundary
        let rem = names_buf.len() % 16;
        if rem != 0 {
            names_buf.resize(names_buf.len() + (16 - rem), 0);
        }
        let names_length = names_buf.len() as u32;

        // ── Step 3: Assign file offsets ────────────────────────────────────
        let entry_count = flat.len() as u32;
        let header_bytes: u64 = 16 + entry_count as u64 * 16 + names_length as u64;
        let header_blocks = (header_bytes + 511) / 512;
        let mut current_block = header_blocks as u32;

        let mut file_idx = 0usize;
        for entry in flat.iter_mut() {
            match &mut entry.kind {
                FlatKind::Binary { file_offset, file_size, .. }
                | FlatKind::Resource { file_offset, file_size, .. } => {
                    let data = &file_data[file_idx];
                    let data_blocks = (data.len() as u32 + 511) / 512;
                    *file_offset = current_block;
                    *file_size = data.len() as u32;
                    current_block += data_blocks;
                    file_idx += 1;
                }
                FlatKind::Directory { .. } => {}
            }
        }

        // ── Step 4: Encode entries table ───────────────────────────────────
        let mut entries_buf: Vec<u8> = Vec::with_capacity(flat.len() * 16);
        for entry in &flat {
            match &entry.kind {
                FlatKind::Directory { entries_index, entries_count } => {
                    entries_buf.extend_from_slice(&entry.name_offset.to_le_bytes());
                    entries_buf.extend_from_slice(&0x7FFFFF00u32.to_le_bytes());
                    entries_buf.extend_from_slice(&entries_index.to_le_bytes());
                    entries_buf.extend_from_slice(&entries_count.to_le_bytes());
                }
                FlatKind::Binary { file_offset, file_size, uncompressed_size } => {
                    let name_off = entry.name_offset as u16;
                    entries_buf.extend_from_slice(&name_off.to_le_bytes());
                    entries_buf.push((file_size & 0xFF) as u8);
                    entries_buf.push(((file_size >> 8) & 0xFF) as u8);
                    entries_buf.push(((file_size >> 16) & 0xFF) as u8);
                    entries_buf.push((file_offset & 0xFF) as u8);
                    entries_buf.push(((file_offset >> 8) & 0xFF) as u8);
                    entries_buf.push(((file_offset >> 16) & 0xFF) as u8);
                    entries_buf.extend_from_slice(&uncompressed_size.to_le_bytes());
                    entries_buf.extend_from_slice(&0u32.to_le_bytes()); // not encrypted
                }
                FlatKind::Resource { file_offset, file_size, system_flags, graphics_flags } => {
                    let name_off = entry.name_offset as u16;
                    let fs = (*file_size).min(0xFFFFFF);
                    entries_buf.extend_from_slice(&name_off.to_le_bytes());
                    entries_buf.push((fs & 0xFF) as u8);
                    entries_buf.push(((fs >> 8) & 0xFF) as u8);
                    entries_buf.push(((fs >> 16) & 0xFF) as u8);
                    // bit 23 of file_offset field marks resource entry
                    entries_buf.push((file_offset & 0xFF) as u8);
                    entries_buf.push(((file_offset >> 8) & 0xFF) as u8);
                    entries_buf.push((((file_offset >> 16) & 0xFF) | 0x80) as u8);
                    entries_buf.extend_from_slice(&system_flags.to_le_bytes());
                    entries_buf.extend_from_slice(&graphics_flags.to_le_bytes());
                }
            }
        }

        // ── Step 5: Encrypt if needed ──────────────────────────────────────
        let (entries_buf, names_buf) = if self.encryption == RpfEncryption::Aes {
            let aes_key = &keys.unwrap().aes_key;
            (
                encrypt_aes(&entries_buf, aes_key),
                encrypt_aes(&names_buf, aes_key),
            )
        } else {
            (entries_buf, names_buf)
        };

        // ── Step 6: Write output ───────────────────────────────────────────
        let total_header = header_blocks as usize * 512;
        let total_data: usize = file_data.iter()
            .map(|d| ((d.len() + 511) / 512) * 512)
            .sum();
        let mut out = Vec::with_capacity(total_header + total_data);

        // 16-byte RPF7 header
        out.extend_from_slice(&RPF7_MAGIC.to_le_bytes());
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&names_length.to_le_bytes());
        out.extend_from_slice(&self.encryption.as_u32().to_le_bytes());

        out.extend_from_slice(&entries_buf);
        out.extend_from_slice(&names_buf);

        // Pad header to 512-byte boundary
        let pad = total_header - out.len();
        out.resize(out.len() + pad, 0);

        // File data blocks (each padded to 512-byte boundary)
        for data in &file_data {
            out.extend_from_slice(data);
            let block_pad = ((data.len() + 511) / 512) * 512 - data.len();
            out.resize(out.len() + block_pad, 0);
        }

        Ok(out)
    }

    // Recursively flatten tree via BFS (sorted by name per directory).
    // Returns (entries_index, entries_count) for this dir.
    fn bfs_flatten(
        dir: &BuildDir,
        self_flat_idx: usize,
        flat: &mut Vec<FlatEntry>,
        file_data: &mut Vec<Vec<u8>>,
    ) {
        // Collect and sort children by name
        let mut children_dirs: Vec<&BuildDir> = dir.subdirs.iter().collect();
        let mut children_files: Vec<&BuildFile> = dir.files.iter().collect();
        children_dirs.sort_by(|a, b| a.name.cmp(&b.name));
        children_files.sort_by(|a, b| a.name.cmp(&b.name));

        // All children sorted together by name (dirs + files interleaved)
        let mut all_names: Vec<(bool, usize)> = Vec::new(); // (is_dir, original_index)
        for i in 0..children_dirs.len() {
            all_names.push((true, i));
        }
        for i in 0..children_files.len() {
            all_names.push((false, i));
        }
        all_names.sort_by_key(|&(is_dir, idx)| {
            if is_dir { children_dirs[idx].name.clone() }
            else { children_files[idx].name.clone() }
        });

        let entries_index = flat.len() as u32;
        let entries_count = all_names.len() as u32;

        // Update the directory entry we already inserted
        if let FlatKind::Directory { entries_index: ei, entries_count: ec } =
            &mut flat[self_flat_idx].kind
        {
            *ei = entries_index;
            *ec = entries_count;
        }

        // Push placeholder entries for all children first (preserving order)
        let child_flat_start = flat.len();
        for &(is_dir, idx) in &all_names {
            if is_dir {
                flat.push(FlatEntry {
                    name: children_dirs[idx].name.clone(),
                    name_offset: 0,
                    kind: FlatKind::Directory { entries_index: 0, entries_count: 0 },
                });
            } else {
                let f = children_files[idx];
                if f.is_resource {
                    flat.push(FlatEntry {
                        name: f.name.clone(),
                        name_offset: 0,
                        kind: FlatKind::Resource {
                            file_offset: 0,
                            file_size: 0,
                            system_flags: f.system_flags,
                            graphics_flags: f.graphics_flags,
                        },
                    });
                } else {
                    flat.push(FlatEntry {
                        name: f.name.clone(),
                        name_offset: 0,
                        kind: FlatKind::Binary {
                            file_offset: 0,
                            file_size: 0,
                            uncompressed_size: f.data.len() as u32,
                        },
                    });
                }
                file_data.push(f.data.clone());
            }
        }

        // Recurse into subdirectories
        let mut child_flat_idx = child_flat_start;
        for &(is_dir, idx) in &all_names {
            if is_dir {
                let dir_flat_idx = child_flat_idx;
                Self::bfs_flatten(children_dirs[idx], dir_flat_idx, flat, file_data);
            }
            child_flat_idx += 1;
        }
    }
}
