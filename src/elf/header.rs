//! ELF header parsing.

use crate::errors::{ElfError, Result};
use crate::utils::{ElfClass, Endianness, read_addr, read_u16, read_u32};

// ============================================================================
// ELF Identification Constants (e_ident indices)
// ============================================================================

/// Size of the e_ident array at the start of every ELF file.
/// This is the minimum size an ELF file can be.
const EI_NIDENT: usize = 16;

/// Index of the first byte of the magic number.
const EI_MAG0: usize = 0;

/// Index of the ELF class byte (32-bit vs 64-bit).
const EI_CLASS: usize = 4;

/// Index of the data encoding byte (endianness).
const EI_DATA: usize = 5;

/// Index of the ELF version byte.
const EI_VERSION: usize = 6;

/// Index of the OS/ABI byte.
const EI_OSABI: usize = 7;

// ============================================================================
// ELF Magic Number
// ============================================================================

/// ELF magic number bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

// ============================================================================
// ELF Class Values
// ============================================================================

/// Invalid class (0).
const ELFCLASSNONE: u8 = 0;

/// 32-bit ELF objects.
const ELFCLASS32: u8 = 1;

/// 64-bit ELF objects.
const ELFCLASS64: u8 = 2;

// ============================================================================
// ELF Data Encoding Values
// ============================================================================

/// Invalid data encoding.
const ELFDATANONE: u8 = 0;

/// Little-endian encoding (LSB first).
/// Used by x86, x86-64, ARM (usually), RISC-V.
const ELFDATA2LSB: u8 = 1;

/// Big-endian encoding (MSB first).
/// Used by SPARC, older PowerPC, network protocols.
const ELFDATA2MSB: u8 = 2;

// ============================================================================
// ELF Type Values
// ============================================================================

/// No file type.
const ET_NONE: u16 = 0;

/// Relocatable file (object file, .o).
const ET_REL: u16 = 1;

/// Executable file.
const ET_EXEC: u16 = 2;

/// Shared object file (also used for PIE executables).
const ET_DYN: u16 = 3;

/// Core dump file.
const ET_CORE: u16 = 4;

// ============================================================================
// Types
// ============================================================================

/// ELF file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// No file type.
    None,
    /// Relocatable file (.o).
    Relocatable,
    /// Traditional executable (fixed load address).
    Executable,
    /// Shared object or PIE executable.
    SharedObject,
    /// Core dump.
    Core,
    /// Unknown or OS/processor-specific type.
    Other(u16),
}

impl ElfType {
    /// Converts a raw u16 e_type value to an ElfType.
    fn from_raw(value: u16) -> Self {
        match value {
            ET_NONE => ElfType::None,
            ET_REL => ElfType::Relocatable,
            ET_EXEC => ElfType::Executable,
            ET_DYN => ElfType::SharedObject,
            ET_CORE => ElfType::Core,
            other => ElfType::Other(other),
        }
    }
}

/// Parsed ELF header fields.
#[derive(Debug)]
pub struct ElfHeader {
    /// ELF class (32-bit or 64-bit).
    pub class: ElfClass,

    /// File data encoding (endianness).
    pub endianness: Endianness,

    /// ELF version (should be 1 for current ELF).
    pub version: u8,

    /// OS/ABI identification.
    pub os_abi: u8,

    /// Object file type.
    pub elf_type: ElfType,

    /// Target machine architecture.
    /// Common values: 3 (x86), 62 (x86-64), 183 (AArch64), 243 (RISC-V).
    pub machine: u16,

    /// Entry point virtual address.
    /// This is where execution starts for executables.
    pub entry_point: u64,

    /// Program header table file offset.
    pub program_header_offset: u64,

    /// Section header table file offset.
    pub section_header_offset: u64,

    /// Processor-specific flags.
    pub flags: u32,

    /// ELF header size in bytes.
    pub header_size: u16,

    /// Size of one program header entry.
    pub program_header_entry_size: u16,

    /// Number of program header entries.
    pub program_header_count: u16,

    /// Size of one section header entry.
    pub section_header_entry_size: u16,

    /// Number of section header entries.
    pub section_header_count: u16,

    /// Section name string table index.
    pub section_name_string_table_index: u16,
}

impl ElfHeader {
    /// Parse the ELF header and return (ElfHeader, Endianness, ElfClass).
    pub fn parse(data: &[u8]) -> Result<(Self, Endianness, ElfClass)> {
        // ====================================================================
        // Step 1: Validate minimum size and magic number
        // ====================================================================

        // We need at least the e_ident array to start
        if data.len() < EI_NIDENT {
            return Err(ElfError::FileTooSmall {
                expected: EI_NIDENT,
                actual: data.len(),
            });
        }

        // Check magic number
        let magic: [u8; 4] = data[EI_MAG0..EI_MAG0 + 4].try_into().unwrap();
        if magic != ELF_MAGIC {
            return Err(ElfError::InvalidMagic { found: magic });
        }

        // ====================================================================
        // Step 2: Parse class and endianness
        // ====================================================================

        // These determine how to read everything else
        let class = match data[EI_CLASS] {
            ELFCLASS32 => ElfClass::Elf32,
            ELFCLASS64 => ElfClass::Elf64,
            other => return Err(ElfError::UnsupportedClass(other)),
        };

        let endian = match data[EI_DATA] {
            ELFDATA2LSB => Endianness::Little,
            ELFDATA2MSB => Endianness::Big,
            other => return Err(ElfError::UnsupportedEndianness(other)),
        };

        let version = data[EI_VERSION];
        let os_abi = data[EI_OSABI];

        // ====================================================================
        // Step 3: Validate total header size
        // ====================================================================

        // Now we know the class, we can check if we have enough data
        let expected_header_size = match class {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        };

        if data.len() < expected_header_size {
            return Err(ElfError::FileTooSmall {
                expected: expected_header_size,
                actual: data.len(),
            });
        }

        // ====================================================================
        // Step 4: Parse remaining fields
        // ====================================================================

        // Field positions and sizes depend on class
        // We use a helper to abstract this complexity
        let header = match class {
            ElfClass::Elf32 => Self::parse_32(data, endian, version, os_abi)?,
            ElfClass::Elf64 => Self::parse_64(data, endian, version, os_abi)?,
        };

        Ok((header, endian, class))
    }

    /// Parse a 32-bit ELF header.
    fn parse_32(data: &[u8], endian: Endianness, version: u8, os_abi: u8) -> Result<Self> {
        Ok(ElfHeader {
            class: ElfClass::Elf32,
            endianness: endian,
            version,
            os_abi,
            elf_type: ElfType::from_raw(read_u16(&data[16..], endian)?),
            machine: read_u16(&data[18..], endian)?,
            // e_version is 4 bytes but we only care about first byte
            entry_point: u64::from(read_u32(&data[24..], endian)?),
            program_header_offset: u64::from(read_u32(&data[28..], endian)?),
            section_header_offset: u64::from(read_u32(&data[32..], endian)?),
            flags: read_u32(&data[36..], endian)?,
            header_size: read_u16(&data[40..], endian)?,
            program_header_entry_size: read_u16(&data[42..], endian)?,
            program_header_count: read_u16(&data[44..], endian)?,
            section_header_entry_size: read_u16(&data[46..], endian)?,
            section_header_count: read_u16(&data[48..], endian)?,
            section_name_string_table_index: read_u16(&data[50..], endian)?,
        })
    }

    /// Parse a 64-bit ELF header.
    fn parse_64(data: &[u8], endian: Endianness, version: u8, os_abi: u8) -> Result<Self> {
        Ok(ElfHeader {
            class: ElfClass::Elf64,
            endianness: endian,
            version,
            os_abi,
            elf_type: ElfType::from_raw(read_u16(&data[16..], endian)?),
            machine: read_u16(&data[18..], endian)?,
            entry_point: crate::utils::read_u64(&data[24..], endian)?,
            program_header_offset: crate::utils::read_u64(&data[32..], endian)?,
            section_header_offset: crate::utils::read_u64(&data[40..], endian)?,
            flags: read_u32(&data[48..], endian)?,
            header_size: read_u16(&data[52..], endian)?,
            program_header_entry_size: read_u16(&data[54..], endian)?,
            program_header_count: read_u16(&data[56..], endian)?,
            section_header_entry_size: read_u16(&data[58..], endian)?,
            section_header_count: read_u16(&data[60..], endian)?,
            section_name_string_table_index: read_u16(&data[62..], endian)?,
        })
    }
}

/// Returns a human-readable name for a machine type.
///
/// ## Common Machine Types (from ELF spec)
///
/// - EM_386 (3): Intel 80386
/// - EM_X86_64 (62): AMD x86-64
/// - EM_ARM (40): ARM
/// - EM_AARCH64 (183): ARM 64-bit
/// - EM_RISCV (243): RISC-V
pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        0 => "No machine",
        3 => "Intel 80386",
        40 => "ARM",
        62 => "AMD x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "Unknown",
    }
}
