//! # Security Analysis Module
//!
//! Analyzes ELF binaries for security-relevant properties.

use super::program::has_bind_now;
use super::{Elf, ProgramHeader, ProgramType};

/// RELRO (Relocation Read-Only) status.
///
/// ## How RELRO Works
///
/// RELRO protects internal data structures from being overwritten:
///
/// - **None**: GOT and PLT are writable. An attacker who can write
///   arbitrary memory can overwrite GOT entries to hijack control flow.
///
/// - **Partial**: Enabled with `-Wl,-z,relro`. Non-PLT portions of GOT
///   are read-only. The PLT GOT remains writable for lazy binding.
///
/// - **Full**: Enabled with `-Wl,-z,relro,-z,now`. All relocations are
///   resolved at startup, and the entire GOT is made read-only.
///   
/// ## Detection Logic
///
/// - If PT_GNU_RELRO is absent → None
/// - If PT_GNU_RELRO is present but no BIND_NOW → Partial
/// - If PT_GNU_RELRO is present AND BIND_NOW is set → Full
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelroStatus {
    /// No RELRO protection.
    None,
    /// Partial RELRO (PT_GNU_RELRO present but lazy binding enabled).
    Partial,
    /// Full RELRO (PT_GNU_RELRO + BIND_NOW flag).
    Full,
}

impl RelroStatus {
    /// Returns a human-readable description.
    pub fn as_str(&self) -> &'static str {
        match self {
            RelroStatus::None => "None",
            RelroStatus::Partial => "Partial",
            RelroStatus::Full => "Full",
        }
    }

    /// Returns true if this status provides any RELRO protection.
    pub fn has_protection(&self) -> bool {
        *self != RelroStatus::None
    }
}

/// Information about a potentially dangerous RWX segment.
#[derive(Debug, Clone)]
pub struct RwxSegment {
    /// Index of the segment in the program header table.
    pub index: usize,
    /// Virtual address where this segment is loaded.
    pub virtual_address: u64,
    /// Size of the segment in memory.
    pub memory_size: u64,
    /// Type of segment.
    pub segment_type: ProgramType,
}

/// Aggregated security information about an ELF binary.
#[derive(Debug)]
pub struct SecurityInfo {
    /// Whether the binary is position-independent (PIE).
    pub pie: bool,

    /// RELRO protection status.
    pub relro: RelroStatus,

    /// Whether the stack is non-executable (NX enabled).
    pub nx: bool,

    /// List of segments with RWX permissions (should be empty for secure binaries).
    pub rwx_segments: Vec<RwxSegment>,

    /// Interpreter path, if present.
    pub interpreter: Option<String>,

    /// Whether the binary appears to be statically linked.
    pub is_static: bool,
}

impl SecurityInfo {
    /// Returns a simple security score (0-100).
    /// Score: PIE(25) + RELRO(25 full/10 partial) + NX(25) + No RWX(25)
    pub fn score(&self) -> u8 {
        let mut score = 0u8;

        if self.pie {
            score += 25;
        }

        match self.relro {
            RelroStatus::Full => score += 25,
            RelroStatus::Partial => score += 10,
            RelroStatus::None => {}
        }

        if self.nx {
            score += 25;
        }

        if self.rwx_segments.is_empty() {
            score += 25;
        }

        score
    }

    /// Returns true if this binary has all standard security features enabled.
    pub fn is_hardened(&self) -> bool {
        self.pie && self.relro == RelroStatus::Full && self.nx && self.rwx_segments.is_empty()
    }
}

/// Analyzes an ELF binary for security properties.
pub fn analyze(elf: &Elf<'_>) -> SecurityInfo {
    let mut has_gnu_relro = false;
    let mut has_dynamic = false;
    let mut has_interp = false;
    let mut nx_enabled = true; // Assume NX unless we find executable stack
    let mut rwx_segments = Vec::new();
    let mut dynamic_phdr: Option<ProgramHeader> = None;

    // Collect information from program headers
    for (index, ph) in elf.program_headers().enumerate() {
        match ph.segment_type {
            ProgramType::GnuRelro => {
                has_gnu_relro = true;
            }

            ProgramType::GnuStack => {
                // If PT_GNU_STACK has PF_X flag, stack is executable
                // Modern binaries should NOT have this flag
                if ph.is_executable() {
                    nx_enabled = false;
                }
            }

            ProgramType::Dynamic => {
                has_dynamic = true;
                // Clone the program header so we can use it after the loop
                // to parse the dynamic section for BIND_NOW
                dynamic_phdr = Some(ph.clone());
            }

            ProgramType::Interp => {
                has_interp = true;
            }

            ProgramType::Load => {
                // Check for dangerous RWX permissions
                if ph.is_rwx() {
                    rwx_segments.push(RwxSegment {
                        index,
                        virtual_address: ph.virtual_address,
                        memory_size: ph.memory_size,
                        segment_type: ph.segment_type,
                    });
                }
            }

            _ => {}
        }
    }

    // Determine RELRO status
    let relro = if has_gnu_relro {
        // Check for BIND_NOW in the dynamic section
        let bind_now = dynamic_phdr
            .as_ref()
            .map(|dyn_ph| has_bind_now(elf.raw_data(), dyn_ph, elf.endianness(), elf.class()))
            .unwrap_or(false);

        if bind_now {
            RelroStatus::Full
        } else {
            RelroStatus::Partial
        }
    } else {
        RelroStatus::None
    };

    // PIE detection: ET_DYN with an interpreter suggests PIE
    // Pure shared libraries are also ET_DYN but typically don't have PT_INTERP
    let pie = elf.is_pie();

    // Static vs dynamic linking
    // Static binaries have no PT_INTERP and no PT_DYNAMIC
    let is_static = !has_interp && !has_dynamic;

    SecurityInfo {
        pie,
        relro,
        nx: nx_enabled,
        rwx_segments,
        interpreter: elf.interpreter().map(String::from),
        is_static,
    }
}

/// Formats security information for human-readable output.
impl std::fmt::Display for SecurityInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Security Analysis:")?;
        writeln!(
            f,
            "  PIE:           {}",
            if self.pie { "Yes" } else { "No" }
        )?;
        writeln!(f, "  RELRO:         {}", self.relro.as_str())?;
        writeln!(f, "  NX (Stack):    {}", if self.nx { "Yes" } else { "No" })?;
        writeln!(f, "  RWX Segments:  {}", self.rwx_segments.len())?;

        if !self.rwx_segments.is_empty() {
            for seg in &self.rwx_segments {
                writeln!(
                    f,
                    "    [{:2}] {} at {:#x} ({} bytes)",
                    seg.index,
                    seg.segment_type.name(),
                    seg.virtual_address,
                    seg.memory_size,
                )?;
            }
        }

        if let Some(ref interp) = self.interpreter {
            writeln!(f, "  Interpreter:   {}", interp)?;
        } else if self.is_static {
            writeln!(f, "  Type:          Statically linked")?;
        }

        writeln!(f, "  Security Score: {}/100", self.score())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relro_status_str() {
        assert_eq!(RelroStatus::None.as_str(), "None");
        assert_eq!(RelroStatus::Partial.as_str(), "Partial");
        assert_eq!(RelroStatus::Full.as_str(), "Full");
    }

    #[test]
    fn test_relro_has_protection() {
        assert!(!RelroStatus::None.has_protection());
        assert!(RelroStatus::Partial.has_protection());
        assert!(RelroStatus::Full.has_protection());
    }

    #[test]
    fn test_security_score() {
        let info = SecurityInfo {
            pie: true,
            relro: RelroStatus::Full,
            nx: true,
            rwx_segments: vec![],
            interpreter: None,
            is_static: true,
        };
        assert_eq!(info.score(), 100);
        assert!(info.is_hardened());
    }

    #[test]
    fn test_security_score_partial() {
        let info = SecurityInfo {
            pie: true,
            relro: RelroStatus::Partial,
            nx: true,
            rwx_segments: vec![],
            interpreter: None,
            is_static: false,
        };
        assert_eq!(info.score(), 85);
        assert!(!info.is_hardened());
    }

    #[test]
    fn test_security_score_none() {
        let info = SecurityInfo {
            pie: false,
            relro: RelroStatus::None,
            nx: false,
            rwx_segments: vec![RwxSegment {
                index: 0,
                virtual_address: 0,
                memory_size: 0,
                segment_type: ProgramType::Load,
            }],
            interpreter: None,
            is_static: false,
        };
        assert_eq!(info.score(), 0);
    }
}
