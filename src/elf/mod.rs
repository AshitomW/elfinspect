//! # ELF Module Root

pub mod header;
pub mod program;
pub mod security;

pub use header::ElfHeader;
pub use program::{ProgramHeader, ProgramHeaderIter, ProgramType};
pub use security::{RelroStatus, SecurityInfo};

use crate::errors::{ElfError, Result};
use crate::utils::{ElfClass, Endianness, get_slice, read_null_terminated_string};

/// The main ELF parser structure.
#[derive(Debug)]
pub struct Elf<'a> {
    data: &'a [u8],
    pub header: ElfHeader,
    endian: Endianness,
    class: ElfClass,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let (header, endian, class) = ElfHeader::parse(data)?;

        if header.program_header_count > 0 {
            let ph_table_size = u64::from(header.program_header_count)
                .checked_mul(u64::from(header.program_header_entry_size))
                .ok_or(ElfError::InvalidProgramHeaders {
                    offset: header.program_header_offset,
                    count: header.program_header_count,
                    entry_size: header.program_header_entry_size,
                })?;

            get_slice(data, header.program_header_offset, ph_table_size)?;
        }

        Ok(Self {
            data,
            header,
            endian,
            class,
        })
    }

    pub fn program_headers(&self) -> ProgramHeaderIter<'a> {
        ProgramHeaderIter::new(
            self.data,
            self.header.program_header_offset,
            self.header.program_header_count,
            self.header.program_header_entry_size,
            self.endian,
            self.class,
        )
    }

    pub fn interpreter(&self) -> Option<&'a str> {
        self.program_headers()
            .find(|ph| ph.segment_type == ProgramType::Interp)
            .and_then(|ph| get_slice(self.data, ph.offset, ph.file_size).ok())
            .and_then(|data| read_null_terminated_string(data).ok())
    }

    pub fn security_info(&self) -> SecurityInfo {
        security::analyze(self)
    }

    pub fn is_pie(&self) -> bool {
        self.header.elf_type == header::ElfType::SharedObject
    }

    pub fn endianness(&self) -> Endianness {
        self.endian
    }

    pub fn class(&self) -> ElfClass {
        self.class
    }

    /// Returns the raw data slice (needed for dynamic section parsing).
    pub(crate) fn raw_data(&self) -> &'a [u8] {
        self.data
    }
}
