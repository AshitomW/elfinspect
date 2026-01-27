//! Error types for ELF parsing.

use thiserror::Error;

/// Errors that can occur during ELF parsing.
#[derive(Error, Debug)]
pub enum ElfError {
    /// The file is too small to contain even the basic ELF identification bytes.
    /// ELF files must be at least 16 bytes (the e_ident array size).
    #[error("File too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    /// The magic bytes at the start of the file don't match "\x7fELF".
    /// This means the file is not an ELF binary at all.
    #[error("Invalid ELF magic: expected [0x7f, 'E', 'L', 'F'], got {found:02x?}")]
    InvalidMagic { found: [u8; 4] },

    /// The ELF class (32-bit vs 64-bit) is not recognized.
    /// Valid values are 1 (32-bit) or 2 (64-bit).
    #[error("Unsupported ELF class: {0} (expected 1=32-bit or 2=64-bit)")]
    UnsupportedClass(u8),

    /// The endianness marker is not recognized.
    /// Valid values are 1 (little-endian) or 2 (big-endian).
    #[error("Unsupported data encoding: {0} (expected 1=LSB or 2=MSB)")]
    UnsupportedEndianness(u8),

    /// A field references data outside the bounds of the file.
    /// This often indicates a corrupted or truncated ELF file.
    #[error("Offset {offset} with size {size} exceeds file bounds (file size: {file_size})")]
    OutOfBounds {
        offset: u64,
        size: u64,
        file_size: usize,
    },

    /// The program header table parameters are invalid.
    #[error(
        "Invalid program header table: offset={offset}, count={count}, entry_size={entry_size}"
    )]
    InvalidProgramHeaders {
        offset: u64,
        count: u16,
        entry_size: u16,
    },

    /// The section header table parameters are invalid.
    #[error(
        "Invalid section header table: offset={offset}, count={count}, entry_size={entry_size}"
    )]
    InvalidSectionHeaders {
        offset: u64,
        count: u16,
        entry_size: u16,
    },

    /// A string is not valid UTF-8.
    /// ELF paths (like the interpreter) should be valid UTF-8 in practice,
    /// though the spec technically allows arbitrary bytes.
    #[error("Invalid UTF-8 in string at offset {offset}")]
    InvalidUtf8 { offset: u64 },

    /// Generic I/O error wrapper for file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias using `ElfError`.
pub type Result<T> = std::result::Result<T, ElfError>;
