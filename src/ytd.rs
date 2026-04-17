/// YTD (Texture Dictionary) parser for GTA V (Gen8 / PC format).
///
/// Accepts the standalone RSC7 bytes as returned by `RpfArchive::extract_entry`.
use anyhow::{bail, Context, Result};
use flate2::read::DeflateDecoder;
use std::io::Read;

use crate::archive::{resource_size_from_flags, RSC7_MAGIC};

// ─── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TextureFormat {
    A8R8G8B8 = 21,
    X8R8G8B8 = 22,
    A1R5G5B5 = 25,
    A8       = 28,
    A8B8G8R8 = 32,
    L8       = 50,
    DXT1     = 0x31545844,
    DXT3     = 0x33545844,
    DXT5     = 0x35545844,
    ATI1     = 0x31495441,
    ATI2     = 0x32495441,
    BC7      = 0x20374342,
    Unknown  = 0,
}

impl TextureFormat {
    pub fn from_u32(v: u32) -> Self {
        match v {
            21          => Self::A8R8G8B8,
            22          => Self::X8R8G8B8,
            25          => Self::A1R5G5B5,
            28          => Self::A8,
            32          => Self::A8B8G8R8,
            50          => Self::L8,
            0x31545844  => Self::DXT1,
            0x33545844  => Self::DXT3,
            0x35545844  => Self::DXT5,
            0x31495441  => Self::ATI1,
            0x32495441  => Self::ATI2,
            0x20374342  => Self::BC7,
            _           => Self::Unknown,
        }
    }

    pub fn is_block_compressed(self) -> bool {
        matches!(self, Self::DXT1 | Self::DXT3 | Self::DXT5 | Self::ATI1 | Self::ATI2 | Self::BC7)
    }
}

impl std::fmt::Display for TextureFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::A8R8G8B8 => "A8R8G8B8",
            Self::X8R8G8B8 => "X8R8G8B8",
            Self::A1R5G5B5 => "A1R5G5B5",
            Self::A8       => "A8",
            Self::A8B8G8R8 => "A8B8G8R8",
            Self::L8       => "L8",
            Self::DXT1     => "DXT1",
            Self::DXT3     => "DXT3",
            Self::DXT5     => "DXT5",
            Self::ATI1     => "ATI1",
            Self::ATI2     => "ATI2",
            Self::BC7      => "BC7",
            Self::Unknown  => "Unknown",
        };
        f.write_str(s)
    }
}

/// One texture entry extracted from a YTD.
#[derive(Debug)]
pub struct YtdTexture {
    pub name: String,
    pub name_hash: u32,
    pub width: u16,
    pub height: u16,
    pub depth: u16,
    pub format: TextureFormat,
    pub levels: u8,
    pub stride: u16,
    pub pixel_data: Vec<u8>,
}

impl YtdTexture {
    /// Serialize this texture to a DDS file.
    pub fn to_dds(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // DDS magic
        out.extend_from_slice(b"DDS ");

        // DDS_HEADER (124 bytes)
        let has_mips = self.levels > 1;
        let is_compressed = self.format.is_block_compressed();

        let mut flags: u32 = 0x1 | 0x2 | 0x4 | 0x1000; // CAPS | HEIGHT | WIDTH | PIXELFORMAT
        if has_mips { flags |= 0x20000; } // MIPMAPCOUNT
        if is_compressed { flags |= 0x80000; } else { flags |= 0x8; } // LINEARSIZE or PITCH

        let pitch_or_linear: u32 = self.stride as u32 * self.height as u32;

        out.extend_from_slice(&124u32.to_le_bytes());            // dwSize
        out.extend_from_slice(&flags.to_le_bytes());             // dwFlags
        out.extend_from_slice(&(self.height as u32).to_le_bytes()); // dwHeight
        out.extend_from_slice(&(self.width as u32).to_le_bytes());  // dwWidth
        out.extend_from_slice(&pitch_or_linear.to_le_bytes());   // dwPitchOrLinearSize
        out.extend_from_slice(&(self.depth as u32).to_le_bytes()); // dwDepth
        out.extend_from_slice(&(self.levels as u32).to_le_bytes()); // dwMipMapCount
        out.extend_from_slice(&[0u8; 44]);                       // dwReserved1[11]

        // DDS_PIXELFORMAT (32 bytes)
        self.write_pixelformat(&mut out);

        let mut caps: u32 = 0x1000; // DDSCAPS_TEXTURE
        if has_mips { caps |= 0x8 | 0x400000; } // COMPLEX | MIPMAP
        out.extend_from_slice(&caps.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]); // Caps2/3/4 + Reserved2

        // Pixel data
        if self.format == TextureFormat::BC7 {
            // Prepend DX10 extension header after pixel format signals DX10
            // Note: the DX10 header is placed before pixel data but after DDS_HEADER
            // The FourCC "DX10" in the pixelformat signals this header follows
            write_dx10_header(&mut out);
        }
        out.extend_from_slice(&self.pixel_data);

        out
    }

    fn write_pixelformat(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&32u32.to_le_bytes()); // dwSize
        match self.format {
            TextureFormat::DXT1 | TextureFormat::DXT3 | TextureFormat::DXT5
            | TextureFormat::ATI1 | TextureFormat::ATI2 => {
                out.extend_from_slice(&0x4u32.to_le_bytes()); // DDPF_FOURCC
                out.extend_from_slice(&(self.format as u32).to_le_bytes()); // FourCC
                out.extend_from_slice(&[0u8; 20]); // RGB counts + masks
            }
            TextureFormat::BC7 => {
                out.extend_from_slice(&0x4u32.to_le_bytes()); // DDPF_FOURCC
                out.extend_from_slice(b"DX10");               // FourCC = DX10
                out.extend_from_slice(&[0u8; 20]);
            }
            TextureFormat::A8R8G8B8 => {
                out.extend_from_slice(&(0x1 | 0x40u32).to_le_bytes()); // ALPHAPIXELS | RGB
                out.extend_from_slice(&0u32.to_le_bytes()); // no FourCC
                out.extend_from_slice(&32u32.to_le_bytes()); // bit count
                out.extend_from_slice(&0x00FF0000u32.to_le_bytes()); // R
                out.extend_from_slice(&0x0000FF00u32.to_le_bytes()); // G
                out.extend_from_slice(&0x000000FFu32.to_le_bytes()); // B
                out.extend_from_slice(&0xFF000000u32.to_le_bytes()); // A
            }
            TextureFormat::X8R8G8B8 => {
                out.extend_from_slice(&0x40u32.to_le_bytes()); // RGB
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&32u32.to_le_bytes());
                out.extend_from_slice(&0x00FF0000u32.to_le_bytes());
                out.extend_from_slice(&0x0000FF00u32.to_le_bytes());
                out.extend_from_slice(&0x000000FFu32.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes()); // no alpha
            }
            TextureFormat::A8B8G8R8 => {
                out.extend_from_slice(&(0x1 | 0x40u32).to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&32u32.to_le_bytes());
                out.extend_from_slice(&0x000000FFu32.to_le_bytes()); // R
                out.extend_from_slice(&0x0000FF00u32.to_le_bytes()); // G
                out.extend_from_slice(&0x00FF0000u32.to_le_bytes()); // B
                out.extend_from_slice(&0xFF000000u32.to_le_bytes()); // A
            }
            TextureFormat::A1R5G5B5 => {
                out.extend_from_slice(&(0x1 | 0x40u32).to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&16u32.to_le_bytes());
                out.extend_from_slice(&0x7C00u32.to_le_bytes()); // R (5 bits)
                out.extend_from_slice(&0x03E0u32.to_le_bytes()); // G (5 bits)
                out.extend_from_slice(&0x001Fu32.to_le_bytes()); // B (5 bits)
                out.extend_from_slice(&0x8000u32.to_le_bytes()); // A (1 bit)
            }
            TextureFormat::A8 => {
                out.extend_from_slice(&0x2u32.to_le_bytes()); // ALPHA
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&8u32.to_le_bytes());
                out.extend_from_slice(&[0u8; 16]);
                // alpha mask is last u32 — overwrite last 4 bytes
                let len = out.len();
                out[len - 4..len].copy_from_slice(&0xFFu32.to_le_bytes());
            }
            TextureFormat::L8 => {
                out.extend_from_slice(&0x20000u32.to_le_bytes()); // LUMINANCE
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&8u32.to_le_bytes());
                out.extend_from_slice(&0xFFu32.to_le_bytes()); // R mask
                out.extend_from_slice(&[0u8; 12]);
            }
            TextureFormat::Unknown => {
                // best-effort fallback: write empty pixelformat
                out.extend_from_slice(&[0u8; 28]);
            }
        }
    }
}

fn write_dx10_header(out: &mut Vec<u8>) {
    out.extend_from_slice(&98u32.to_le_bytes()); // DXGI_FORMAT_BC7_UNORM
    out.extend_from_slice(&3u32.to_le_bytes());  // D3D10_RESOURCE_DIMENSION_TEXTURE2D
    out.extend_from_slice(&0u32.to_le_bytes());  // miscFlag
    out.extend_from_slice(&1u32.to_le_bytes());  // arraySize
    out.extend_from_slice(&0u32.to_le_bytes());  // miscFlags2
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse a YTD file from standalone RSC7 bytes.
///
/// `data` is the output of `RpfArchive::extract_entry` for a `.ytd` entry.
pub fn parse_ytd(data: &[u8]) -> Result<Vec<YtdTexture>> {
    if data.len() < 16 {
        bail!("YTD data too short");
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != RSC7_MAGIC {
        bail!("Not an RSC7 file (magic = 0x{:08X})", magic);
    }

    let system_flags  = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let graphics_flags = u32::from_le_bytes(data[12..16].try_into().unwrap());

    let sys_size  = resource_size_from_flags(system_flags);
    let gfx_size  = resource_size_from_flags(graphics_flags);
    let body      = &data[16..];

    // Decompress
    let decompressed = {
        let mut out = Vec::new();
        if DeflateDecoder::new(body).read_to_end(&mut out).is_ok() && !out.is_empty() {
            out
        } else {
            // Try raw (uncompressed) body
            body.to_vec()
        }
    };

    if decompressed.len() < sys_size {
        bail!(
            "Decompressed size {} < expected system size {}",
            decompressed.len(), sys_size
        );
    }

    let system   = &decompressed[..sys_size];
    let graphics = if decompressed.len() >= sys_size + gfx_size {
        &decompressed[sys_size..sys_size + gfx_size]
    } else {
        &decompressed[sys_size..]
    };

    let reader = ResReader { system, graphics };
    parse_texture_dict(&reader)
}

// ─── Internal virtual-memory reader ──────────────────────────────────────────

struct ResReader<'a> {
    system:   &'a [u8],
    graphics: &'a [u8],
}

impl<'a> ResReader<'a> {
    fn resolve(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        if va == 0 { return None; }
        if (va & 0x50000000) == 0x50000000 && (va & 0x60000000) != 0x60000000 {
            let off = (va - 0x50000000) as usize;
            self.system.get(off..off + len)
        } else if (va & 0x60000000) == 0x60000000 {
            let off = (va - 0x60000000) as usize;
            self.graphics.get(off..off + len)
        } else {
            None
        }
    }

    fn string_at(&self, va: u64) -> Option<String> {
        if (va & 0x50000000) == 0x50000000 && (va & 0x60000000) != 0x60000000 {
            let off = (va - 0x50000000) as usize;
            let slice = self.system.get(off..)?;
            let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            Some(String::from_utf8_lossy(&slice[..end]).into_owned())
        } else {
            None
        }
    }
}

// ─── Struct parsing helpers ───────────────────────────────────────────────────

fn u16_le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

// ─── TextureDictionary ────────────────────────────────────────────────────────

fn parse_texture_dict(reader: &ResReader<'_>) -> Result<Vec<YtdTexture>> {
    let sys = reader.system;
    if sys.len() < 64 {
        bail!("system section too small for TextureDictionary");
    }

    // ResourceFileBase at 0x00 (16 bytes): VFT, FileUnknown, FilePagesInfoPointer
    // TextureDictionary fields at 0x10:
    // 0x10..0x1F: four u32 unknowns
    // 0x20: ResourceSimpleList64_uint (TextureNameHashes) — 16 bytes
    let hash_ptr   = u64_le(sys, 0x20);
    let hash_count = u32_le(sys, 0x28) as usize;
    // capacity at 0x2C

    // 0x30: ResourcePointerList64<Texture> (Textures) — 16 bytes
    let tex_ptr_array = u64_le(sys, 0x30);
    let tex_count     = u32_le(sys, 0x38) as usize;

    // Read name hashes (u32 array in system section)
    let hash_data = if hash_count > 0 {
        reader.resolve(hash_ptr, hash_count * 4)
    } else {
        None
    };

    // Read texture pointer array (u64 per texture, in system section)
    let ptr_bytes = tex_count * 8;
    let ptr_data = if tex_count > 0 {
        reader.resolve(tex_ptr_array, ptr_bytes)
            .with_context(|| format!("texture pointer array out of bounds (va=0x{:X})", tex_ptr_array))?
    } else {
        return Ok(vec![]);
    };

    let mut textures = Vec::with_capacity(tex_count);
    for i in 0..tex_count {
        let tex_va = u64_le(ptr_data, i * 8);
        if tex_va == 0 { continue; }

        let name_hash = hash_data
            .and_then(|h| h.get(i * 4..i * 4 + 4))
            .map(|b| u32_le(b, 0))
            .unwrap_or(0);

        match parse_texture(tex_va, name_hash, reader) {
            Ok(tex) => textures.push(tex),
            Err(e) => eprintln!("[YTD] Warning: texture {} parse error: {}", i, e),
        }
    }

    Ok(textures)
}

fn parse_texture(tex_va: u64, name_hash: u32, reader: &ResReader<'_>) -> Result<YtdTexture> {
    // Texture struct is 144 bytes (0x90) in the system section
    let raw = reader.resolve(tex_va, 0x90)
        .with_context(|| format!("texture struct out of bounds (va=0x{:X})", tex_va))?;

    // TextureBase fields (offset within Texture struct)
    let name_ptr = u64_le(raw, 0x28);

    // Texture-specific fields (starting at 0x50)
    let width  = u16_le(raw, 0x50);
    let height = u16_le(raw, 0x52);
    let depth  = u16_le(raw, 0x54);
    let stride = u16_le(raw, 0x56);
    let fmt    = TextureFormat::from_u32(u32_le(raw, 0x58));
    let levels = raw[0x5D];
    let data_ptr = u64_le(raw, 0x70);

    let name = reader.string_at(name_ptr).unwrap_or_default();

    // Compute pixel data size (same formula as CodeWalker TextureData.Read)
    let pixel_size = calc_pixel_data_size(stride, height, levels);

    let pixel_data = if pixel_size > 0 && data_ptr != 0 {
        reader.resolve(data_ptr, pixel_size)
            .with_context(|| format!("pixel data out of bounds (va=0x{:X}, size={})", data_ptr, pixel_size))?
            .to_vec()
    } else {
        vec![]
    };

    Ok(YtdTexture { name, name_hash, width, height, depth, format: fmt, levels, stride, pixel_data })
}

fn calc_pixel_data_size(stride: u16, height: u16, levels: u8) -> usize {
    let mut total = 0usize;
    let mut length = stride as usize * height as usize;
    for _ in 0..levels {
        total += length;
        length /= 4;
    }
    total
}
