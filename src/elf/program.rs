//! # Program Header Parsing
//!
//! Program headers describe segments loaded at runtime (execution view).
//! Critical for security: PT_LOAD defines memory permissions, PT_GNU_STACK
//! controls executable stack, PT_GNU_RELRO marks read-only regions.

use crate::utils::{ElfClass, Endianness, read_u32, read_u64};

// ============================================================================
// Program Header Type Constants
// ============================================================================

/// Null entry (ignored).
const PT_NULL: u32 = 0;

/// Loadable segment.
const PT_LOAD: u32 = 1;

/// Dynamic linking information.
const PT_DYNAMIC: u32 = 2;

/// Interpreter path.
const PT_INTERP: u32 = 3;

/// Auxiliary information.
const PT_NOTE: u32 = 4;

/// Reserved (unused).
const PT_SHLIB: u32 = 5;

/// Program header table itself.
const PT_PHDR: u32 = 6;

/// Thread-local storage.
const PT_TLS: u32 = 7;

/// GNU extension: stack executability.
/// If this segment is absent or has no PF_X flag, the stack is non-executable.
const PT_GNU_STACK: u32 = 0x6474_e551;

/// GNU extension: read-only after relocation.
/// This segment marks memory that should be made read-only after
/// the dynamic linker has processed relocations.
const PT_GNU_RELRO: u32 = 0x6474_e552;

/// GNU extension: EH frame header.
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

/// GNU property notes.
const PT_GNU_PROPERTY: u32 = 0x6474_e553;

// ============================================================================
// Program Header Flags
// ============================================================================

/// Segment is executable.
pub const PF_X: u32 = 1;

/// Segment is writable.
pub const PF_W: u32 = 2;

/// Segment is readable.
pub const PF_R: u32 = 4;

// ============================================================================
// Dynamic Section Constants (for RELRO detection)
// ============================================================================

/// Marks end of dynamic section.
///
/// The dynamic section is a table of tag-value pairs. When the parser
/// encounters DT_NULL, it knows there are no more entries.
const DT_NULL: u64 = 0;

/// Indicates all relocations must be processed before execution.
///
/// The mere presence of this tag indicates BIND_NOW behavior.
/// The d_val field is ignored. This is the traditional way to request
/// immediate binding (resolving all symbols at load time).
///
/// Reference: ELF specification, System V ABI
const DT_BIND_NOW: u64 = 24;

/// Flags entry containing DF_* flags.
///
/// This is a more modern way to specify various dynamic linking options.
/// The d_val field contains a bitmask of DF_* values.
///
/// Reference: ELF specification, System V ABI
const DT_FLAGS: u64 = 30;

/// Extended flags entry (GNU extension) containing DF_1_* flags.
///
/// This GNU extension provides additional flags beyond what DT_FLAGS offers.
/// The d_val field contains a bitmask of DF_1_* values.
///
/// The value 0x6ffffffb is in the OS-specific range (0x6000000D-0x6fffffff).
///
/// Reference: GNU ld documentation
const DT_FLAGS_1: u64 = 0x6fff_fffb;

/// DF_BIND_NOW flag within DT_FLAGS.
///
/// When this bit is set in the DT_FLAGS entry, all relocations for the
/// object must be processed before returning control to the program.
/// This is equivalent to having a DT_BIND_NOW entry.
///
/// Value: 0x8 (bit 3)
const DF_BIND_NOW: u64 = 0x8;

/// DF_1_NOW flag within DT_FLAGS_1.
///
/// GNU extension equivalent of DF_BIND_NOW. When set, indicates that
/// all relocations should be processed at load time.
///
/// Value: 0x1 (bit 0)
const DF_1_NOW: u64 = 0x1;

// ============================================================================
// Types
// ============================================================================

/// Type of program header segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    /// Unused entry.
    Null,
    /// Loadable segment - will be mapped into memory.
    Load,
    /// Dynamic linking tables.
    Dynamic,
    /// Interpreter path (null-terminated string).
    Interp,
    /// Note segments (auxiliary information).
    Note,
    /// Reserved.
    Shlib,
    /// Program header table.
    Phdr,
    /// Thread-local storage template.
    Tls,
    /// GNU extension: stack executability hint.
    GnuStack,
    /// GNU extension: read-only after relocation.
    GnuRelro,
    /// GNU extension: exception handling frame.
    GnuEhFrame,
    /// GNU extension: property notes.
    GnuProperty,
    /// OS or processor-specific, or unknown.
    Other(u32),
}

impl ProgramType {
    /// Converts a raw p_type value to a ProgramType.
    pub fn from_raw(value: u32) -> Self {
        match value {
            PT_NULL => ProgramType::Null,
            PT_LOAD => ProgramType::Load,
            PT_DYNAMIC => ProgramType::Dynamic,
            PT_INTERP => ProgramType::Interp,
            PT_NOTE => ProgramType::Note,
            PT_SHLIB => ProgramType::Shlib,
            PT_PHDR => ProgramType::Phdr,
            PT_TLS => ProgramType::Tls,
            PT_GNU_STACK => ProgramType::GnuStack,
            PT_GNU_RELRO => ProgramType::GnuRelro,
            PT_GNU_EH_FRAME => ProgramType::GnuEhFrame,
            PT_GNU_PROPERTY => ProgramType::GnuProperty,
            other => ProgramType::Other(other),
        }
    }

    /// Returns a human-readable name for this segment type.
    pub fn name(&self) -> &'static str {
        match self {
            ProgramType::Null => "NULL",
            ProgramType::Load => "LOAD",
            ProgramType::Dynamic => "DYNAMIC",
            ProgramType::Interp => "INTERP",
            ProgramType::Note => "NOTE",
            ProgramType::Shlib => "SHLIB",
            ProgramType::Phdr => "PHDR",
            ProgramType::Tls => "TLS",
            ProgramType::GnuStack => "GNU_STACK",
            ProgramType::GnuRelro => "GNU_RELRO",
            ProgramType::GnuEhFrame => "GNU_EH_FRAME",
            ProgramType::GnuProperty => "GNU_PROPERTY",
            ProgramType::Other(_) => "UNKNOWN",
        }
    }
}

/// A parsed program header.
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    /// Segment type (what this segment is for).
    pub segment_type: ProgramType,

    /// Segment flags (Read, Write, Execute permissions).
    pub flags: u32,

    /// Offset in the file where segment data begins.
    pub offset: u64,

    /// Virtual address where segment should be loaded.
    pub virtual_address: u64,

    /// Physical address (rarely used, often same as virtual).
    pub physical_address: u64,

    /// Size of segment data in the file.
    /// May be less than memory_size (the difference is zero-filled).
    pub file_size: u64,

    /// Size of segment in memory.
    /// If larger than file_size, extra bytes are zero-filled (e.g., .bss).
    pub memory_size: u64,

    /// Alignment requirement for this segment.
    /// The segment is loaded at (virtual_address % align) == (offset % align).
    pub alignment: u64,
}

impl ProgramHeader {
    /// Returns true if this segment is readable.
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    /// Returns true if this segment is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    /// Returns true if this segment is executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    /// Returns a string representation of the flags (like "R E" for read+execute).
    pub fn flags_string(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.is_readable() { 'R' } else { ' ' });
        s.push(if self.is_writable() { 'W' } else { ' ' });
        s.push(if self.is_executable() { 'E' } else { ' ' });
        s
    }

    /// Returns true if segment is both writable and executable (dangerous).
    pub fn is_rwx(&self) -> bool {
        self.is_writable() && self.is_executable()
    }

    /// Parses a 32-bit program header from bytes (32 bytes total).
    pub fn parse_32(data: &[u8], endian: Endianness) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }

        // Note: In 32-bit ELF, flags come AFTER memsz (at offset 24)
        Some(ProgramHeader {
            segment_type: ProgramType::from_raw(read_u32(&data[0..], endian).ok()?),
            offset: u64::from(read_u32(&data[4..], endian).ok()?),
            virtual_address: u64::from(read_u32(&data[8..], endian).ok()?),
            physical_address: u64::from(read_u32(&data[12..], endian).ok()?),
            file_size: u64::from(read_u32(&data[16..], endian).ok()?),
            memory_size: u64::from(read_u32(&data[20..], endian).ok()?),
            flags: read_u32(&data[24..], endian).ok()?,
            alignment: u64::from(read_u32(&data[28..], endian).ok()?),
        })
    }

    /// Parses a 64-bit program header from bytes (56 bytes total).
    /// Note: p_flags at offset 4 (before offset) for alignment.
    pub fn parse_64(data: &[u8], endian: Endianness) -> Option<Self> {
        if data.len() < 56 {
            return None;
        }

        // Note: In 64-bit ELF, flags come BEFORE offset (at byte 4)
        // This is different from 32-bit! It's for alignment purposes.
        Some(ProgramHeader {
            segment_type: ProgramType::from_raw(read_u32(&data[0..], endian).ok()?),
            flags: read_u32(&data[4..], endian).ok()?,
            offset: read_u64(&data[8..], endian).ok()?,
            virtual_address: read_u64(&data[16..], endian).ok()?,
            physical_address: read_u64(&data[24..], endian).ok()?,
            file_size: read_u64(&data[32..], endian).ok()?,
            memory_size: read_u64(&data[40..], endian).ok()?,
            alignment: read_u64(&data[48..], endian).ok()?,
        })
    }
}

/// Iterator over program headers (lazy evaluation, no pre-allocation).
pub struct ProgramHeaderIter<'a> {
    /// Reference to the complete ELF data.
    data: &'a [u8],

    /// Offset of the program header table in the file.
    table_offset: u64,

    /// Total number of entries in the table.
    count: u16,

    /// Size of each entry in bytes.
    entry_size: u16,

    /// Current entry index (0-based).
    current: u16,

    /// Endianness for parsing.
    endian: Endianness,

    /// ELF class (determines struct sizes).
    class: ElfClass,
}

impl<'a> ProgramHeaderIter<'a> {
    /// Creates a new program header iterator.
    pub fn new(
        data: &'a [u8],
        table_offset: u64,
        count: u16,
        entry_size: u16,
        endian: Endianness,
        class: ElfClass,
    ) -> Self {
        Self {
            data,
            table_offset,
            count,
            entry_size,
            current: 0,
            endian,
            class,
        }
    }
}

impl<'a> Iterator for ProgramHeaderIter<'a> {
    type Item = ProgramHeader;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we've exhausted all entries
        if self.current >= self.count {
            return None;
        }

        // Calculate offset of current entry
        // Use u64 to avoid overflow with large tables
        let entry_offset = self
            .table_offset
            .checked_add(u64::from(self.current) * u64::from(self.entry_size))?;

        // Bounds check
        let entry_end = entry_offset.checked_add(u64::from(self.entry_size))?;
        if entry_end > self.data.len() as u64 {
            return None;
        }

        // Get slice for this entry
        let entry_data = &self.data[entry_offset as usize..entry_end as usize];

        // Parse based on class
        let header = match self.class {
            ElfClass::Elf32 => ProgramHeader::parse_32(entry_data, self.endian),
            ElfClass::Elf64 => ProgramHeader::parse_64(entry_data, self.endian),
        };

        // Advance to next entry
        self.current += 1;

        header
    }

    /// Returns size hint (exact count known).
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.current) as usize;
        (remaining, Some(remaining))
    }
}

/// Implement ExactSizeIterator (exact count known).
impl<'a> ExactSizeIterator for ProgramHeaderIter<'a> {}

// ============================================================================
// Dynamic Section Parsing
// ============================================================================

/// Checks if BIND_NOW is set in dynamic section.
/// Checks for DT_BIND_NOW, DT_FLAGS with DF_BIND_NOW, or DT_FLAGS_1 with DF_1_NOW.
pub fn has_bind_now(
    data: &[u8],
    dynamic_phdr: &ProgramHeader,
    endian: Endianness,
    class: ElfClass,
) -> bool {
    let offset = dynamic_phdr.offset as usize;
    let size = dynamic_phdr.file_size as usize;

    // Bounds check to prevent panic
    if offset.saturating_add(size) > data.len() {
        return false;
    }

    let dynamic_data = &data[offset..offset + size];

    // Dynamic entry: 8 bytes (32-bit) or 16 bytes (64-bit)
    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };

    // Iterate through dynamic entries
    let mut pos = 0;
    while pos + entry_size <= dynamic_data.len() {
        let entry = &dynamic_data[pos..];

        // Parse d_tag and d_val
        let (d_tag, d_val) = match class {
            ElfClass::Elf32 => {
                let tag = read_u32(entry, endian).unwrap_or(0) as u64;
                let val = read_u32(&entry[4..], endian).unwrap_or(0) as u64;
                (tag, val)
            }
            ElfClass::Elf64 => {
                let tag = read_u64(entry, endian).unwrap_or(0);
                let val = read_u64(&entry[8..], endian).unwrap_or(0);
                (tag, val)
            }
        };

        // DT_NULL marks end of dynamic section
        if d_tag == DT_NULL {
            break;
        }

        // Check for BIND_NOW indicators
        match d_tag {
            DT_BIND_NOW => return true,
            DT_FLAGS if d_val & DF_BIND_NOW != 0 => return true,
            DT_FLAGS_1 if d_val & DF_1_NOW != 0 => return true,
            _ => {}
        }

        pos += entry_size;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_type_names() {
        assert_eq!(ProgramType::Load.name(), "LOAD");
        assert_eq!(ProgramType::GnuRelro.name(), "GNU_RELRO");
        assert_eq!(ProgramType::Other(0x12345).name(), "UNKNOWN");
    }

    #[test]
    fn test_flags_string() {
        let ph = ProgramHeader {
            segment_type: ProgramType::Load,
            flags: PF_R | PF_X,
            offset: 0,
            virtual_address: 0,
            physical_address: 0,
            file_size: 0,
            memory_size: 0,
            alignment: 0,
        };
        assert_eq!(ph.flags_string(), "R E");
        assert!(!ph.is_rwx());
        assert!(ph.is_executable());
        assert!(!ph.is_writable());
    }

    #[test]
    fn test_rwx_detection() {
        let ph = ProgramHeader {
            segment_type: ProgramType::Load,
            flags: PF_R | PF_W | PF_X,
            offset: 0,
            virtual_address: 0,
            physical_address: 0,
            file_size: 0,
            memory_size: 0,
            alignment: 0,
        };
        assert!(ph.is_rwx());
    }
}
