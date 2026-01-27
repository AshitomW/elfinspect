//! ELF Inspector - CLI

mod elf;
mod errors;
mod utils;

use std::env;
use std::fs;
use std::process;

use anyhow::{Context, Result};

use elf::Elf;
use elf::header::machine_name;

/// Main entry point.
fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let path = &args[1];
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");

    // Read the file into memory
    let data = fs::read(path).with_context(|| format!("Failed to read file: {}", path))?;

    // Parse the ELF file
    // The Elf struct borrows from `data`, so `data` must outlive `elf`
    let elf = Elf::parse(&data).with_context(|| format!("Failed to parse ELF file: {}", path))?;

    // Print basic information
    println!("ELF Analysis: {}", path);
    println!("{}", "=".repeat(60));
    println!();

    // ELF Header Info
    println!("ELF Header:");
    println!("  Class:         {:?}", elf.header.class);
    println!("  Endianness:    {:?}", elf.header.endianness);
    println!("  Type:          {:?}", elf.header.elf_type);
    println!(
        "  Machine:       {} ({})",
        elf.header.machine,
        machine_name(elf.header.machine)
    );
    println!("  Entry Point:   {:#x}", elf.header.entry_point);
    println!();

    // Program Headers Summary
    let program_headers: Vec<_> = elf.program_headers().collect();
    println!("Program Headers ({} entries):", program_headers.len());

    if verbose {
        println!(
            "  {:2}  {:12}  {:>10}  {:>10}  {:>10}  Flags",
            "#", "Type", "Offset", "VirtAddr", "MemSize"
        );
        println!("  {}", "-".repeat(56));

        for (i, ph) in program_headers.iter().enumerate() {
            println!(
                "  {:2}  {:12}  {:#10x}  {:#10x}  {:#10x}  {}",
                i,
                ph.segment_type.name(),
                ph.offset,
                ph.virtual_address,
                ph.memory_size,
                ph.flags_string(),
            );
        }
    } else {
        // Compact summary
        for (i, ph) in program_headers.iter().enumerate() {
            if matches!(
                ph.segment_type,
                elf::ProgramType::Load
                    | elf::ProgramType::Interp
                    | elf::ProgramType::GnuStack
                    | elf::ProgramType::GnuRelro
            ) {
                println!(
                    "  [{:2}] {:12} @ {:#x} ({} bytes) [{}]",
                    i,
                    ph.segment_type.name(),
                    ph.virtual_address,
                    ph.memory_size,
                    ph.flags_string(),
                );
            }
        }
    }
    println!();

    // Security Analysis
    let security = elf.security_info();
    print!("{}", security);

    // Final assessment
    println!();
    if security.is_hardened() {
        println!("✓ Binary appears to have standard security hardening enabled.");
    } else {
        println!("⚠ Binary is missing some security features:");
        if !security.pie {
            println!("  - Not a PIE (compile with -fPIE -pie)");
        }
        if security.relro != elf::RelroStatus::Full {
            println!("  - Not using Full RELRO (link with -Wl,-z,relro,-z,now)");
        }
        if !security.nx {
            println!("  - Stack is executable (remove -z execstack)");
        }
        if !security.rwx_segments.is_empty() {
            println!("  - Has RWX segments (investigate memory permissions)");
        }
    }

    Ok(())
}

/// Prints usage information.
fn print_usage(program: &str) {
    eprintln!("ELF Inspector - Analyze ELF binary security properties");
    eprintln!();
    eprintln!("Usage: {} <elf-file> [-v|--verbose]", program);
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -v, --verbose    Show detailed program header information");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} /bin/ls", program);
    eprintln!("  {} ./my_binary -v", program);
}
