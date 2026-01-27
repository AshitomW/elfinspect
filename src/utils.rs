//! Utility functions for parsing primitive values from byte slices.

use crate::errors::{ElfError, Result};

/// Endianness of the ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little-endian: least-significant byte first.
    Little,

    /// Big-endian: most-significant byte first.
    Big,
}

/// ELF class (32-bit or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    /// 32-bit ELF: addresses are 4 bytes
    Elf32,
    /// 64-bit ELF: addresses are 8 bytes
    Elf64,
}

impl ElfClass {
    /// Returns the size of an address/offset in bytes for this class.
    #[inline]
    pub const fn addr_size(self) -> usize {
        match self {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        }
    }
}

/// Read a `u16` from `data` using `endian`.
#[inline]
pub fn read_u16(data: &[u8], endian: Endianness) -> Result<u16> {
    // Verify length
    if data.len() < 2 {
        return Err(ElfError::FileTooSmall {
            expected: 2,
            actual: data.len(),
        });
    }

    // Convert to fixed-size array and decode
    let bytes: [u8; 2] = data[..2].try_into().unwrap();

    Ok(match endian {
        Endianness::Little => u16::from_le_bytes(bytes),
        Endianness::Big => u16::from_be_bytes(bytes),
    })
}

/// Read a `u32` from `data` using `endian`.
#[inline]
pub fn read_u32(data: &[u8], endian: Endianness) -> Result<u32> {
    if data.len() < 4 {
        return Err(ElfError::FileTooSmall {
            expected: 4,
            actual: data.len(),
        });
    }

    let bytes: [u8; 4] = data[..4].try_into().unwrap();

    Ok(match endian {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    })
}

/// Read a `u64` from `data` using `endian`.
#[inline]
pub fn read_u64(data: &[u8], endian: Endianness) -> Result<u64> {
    if data.len() < 8 {
        return Err(ElfError::FileTooSmall {
            expected: 8,
            actual: data.len(),
        });
    }

    let bytes: [u8; 8] = data[..8].try_into().unwrap();

    Ok(match endian {
        Endianness::Little => u64::from_le_bytes(bytes),
        Endianness::Big => u64::from_be_bytes(bytes),
    })
}

/// Read an address-sized value based on `class` (returns `u64`).
#[inline]
pub fn read_addr(data: &[u8], endian: Endianness, class: ElfClass) -> Result<u64> {
    match class {
        ElfClass::Elf32 => read_u32(data, endian).map(u64::from),
        ElfClass::Elf64 => read_u64(data, endian),
    }
}

/// Validate that `[offset, offset+size)` is within `data_len`.
#[inline]
pub fn validate_bounds(offset: u64, size: u64, data_len: usize) -> Result<()> {
    // Convert to u64 for consistent arithmetic
    let data_len = data_len as u64;

    // checked_add returns None on overflow
    let end = offset.checked_add(size).ok_or(ElfError::OutOfBounds {
        offset,
        size,
        file_size: data_len as usize,
    })?;

    if end > data_len {
        return Err(ElfError::OutOfBounds {
            offset,
            size,
            file_size: data_len as usize,
        });
    }

    Ok(())
}

/// Return a borrowed subslice after validating bounds.
#[inline]
pub fn get_slice(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    validate_bounds(offset, size, data.len())?;

    // Safe because we just validated bounds
    Ok(&data[offset as usize..(offset + size) as usize])
}

/// Read a null-terminated string from `data` and return as `&str`.
pub fn read_null_terminated_string(data: &[u8]) -> Result<&str> {
    // Find the position of the null terminator
    let null_pos = data.iter().position(|&b| b == 0).unwrap_or(data.len());

    // Extract the string portion (before the null)
    let string_bytes = &data[..null_pos];

    // Convert to UTF-8; ELF strings are usually ASCII
    std::str::from_utf8(string_bytes).map_err(|_| ElfError::InvalidUtf8 { offset: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_little_endian() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16(&data, Endianness::Little).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u16_big_endian() {
        let data = [0x12, 0x34];
        assert_eq!(read_u16(&data, Endianness::Big).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32_little_endian() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32(&data, Endianness::Little).unwrap(), 0x12345678);
    }

    #[test]
    fn test_bounds_check_overflow() {
        // Test that we handle potential overflow correctly
        let result = validate_bounds(u64::MAX, 1, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_null_terminated_string() {
        let data = b"hello\0world";
        assert_eq!(read_null_terminated_string(data).unwrap(), "hello");
    }
}
