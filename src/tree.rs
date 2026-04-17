use crate::archive::{RpfEntry, RpfEntryKind};

/// A node in an RPF directory tree. Stores indices into the flat `RpfArchive.entries` slice.
#[derive(Debug, Clone)]
pub struct DirNode {
    pub name  : String,
    pub path  : String,
    pub files : Vec<FileRef>,
    pub subdirs: Vec<DirNode>,
}

/// A reference to a file entry within a `DirNode`, keyed by entry index.
#[derive(Debug, Clone)]
pub struct FileRef {
    pub name        : String,
    pub path        : String,
    pub entry_index : usize,   // index into RpfArchive.entries
    pub size        : u32,     // on-disk / compressed size
    pub mem_size    : u32,     // uncompressed (binary) or resource page size (resource)
    pub is_resource : bool,
}

/// Build a navigable directory tree from a flat `RpfArchive.entries` slice.
pub fn build_directory_tree(entries: &[RpfEntry]) -> DirNode {
    if entries.is_empty() {
        return DirNode { name: String::new(), path: String::new(), files: vec![], subdirs: vec![] };
    }

    // If the first entry is a directory, it is the root.
    let (root_name, start, count) = if let RpfEntryKind::Directory { entries_index, entries_count } = &entries[0].kind {
        (entries[0].name.clone(), *entries_index as usize, *entries_count as usize)
    } else {
        // Flat archive (no directory wrapper) — put everything in a synthetic root.
        return flat_root(entries);
    };

    let mut root = DirNode { name: root_name, path: String::new(), files: vec![], subdirs: vec![] };
    populate(&mut root, entries, start, count, "");
    root
}

/// Returns a flat list of all `FileRef`s in the tree (breadth-first).
pub fn list_all_files(node: &DirNode) -> Vec<&FileRef> {
    let mut out = Vec::new();
    collect(node, &mut out);
    out
}

// ─── Internals ────────────────────────────────────────────────────────────────

fn populate(dir: &mut DirNode, entries: &[RpfEntry], start: usize, count: usize, parent_path: &str) {
    let end = (start + count).min(entries.len());
    for i in start..end {
        let entry = &entries[i];
        match &entry.kind {
            RpfEntryKind::Directory { entries_index, entries_count } => {
                let sub_path = child_path(parent_path, &entry.name_lower);
                let mut sub = DirNode { name: entry.name.clone(), path: sub_path.clone(), files: vec![], subdirs: vec![] };
                populate(&mut sub, entries, *entries_index as usize, *entries_count as usize, &sub_path);
                dir.subdirs.push(sub);
            }
            RpfEntryKind::BinaryFile { file_size, uncompressed_size, .. } => {
                let path = child_path(parent_path, &entry.name_lower);
                dir.files.push(FileRef {
                    name: entry.name.clone(), path, entry_index: i,
                    size: *file_size, mem_size: *uncompressed_size, is_resource: false,
                });
            }
            RpfEntryKind::ResourceFile { file_size, system_flags, .. } => {
                let path = child_path(parent_path, &entry.name_lower);
                let mem_size = crate::archive::resource_size_from_flags(*system_flags) as u32;
                dir.files.push(FileRef {
                    name: entry.name.clone(), path, entry_index: i,
                    size: *file_size, mem_size, is_resource: true,
                });
            }
        }
    }
}

fn flat_root(entries: &[RpfEntry]) -> DirNode {
    let mut root = DirNode { name: String::new(), path: String::new(), files: vec![], subdirs: vec![] };
    for (i, entry) in entries.iter().enumerate() {
        match &entry.kind {
            RpfEntryKind::BinaryFile { file_size, uncompressed_size, .. } => {
                root.files.push(FileRef {
                    name: entry.name.clone(), path: entry.name_lower.clone(), entry_index: i,
                    size: *file_size, mem_size: *uncompressed_size, is_resource: false,
                });
            }
            RpfEntryKind::ResourceFile { file_size, system_flags, .. } => {
                let mem_size = crate::archive::resource_size_from_flags(*system_flags) as u32;
                root.files.push(FileRef {
                    name: entry.name.clone(), path: entry.name_lower.clone(), entry_index: i,
                    size: *file_size, mem_size, is_resource: true,
                });
            }
            _ => {}
        }
    }
    root
}

fn collect<'a>(node: &'a DirNode, out: &mut Vec<&'a FileRef>) {
    out.extend(node.files.iter());
    for sub in &node.subdirs { collect(sub, out); }
}

fn child_path(parent: &str, name: &str) -> String {
    if parent.is_empty() { name.to_string() } else { format!("{}/{}", parent, name) }
}
