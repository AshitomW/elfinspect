# ELF Inspector

A Rust-based command-line utility and library for inspecting, analyzing, and examining Executable and Linkable Format (ELF) binaries. This project was created as a learning exercise to explore both the Rust programming language and the internals of the ELF file format, which is the standard binary format used by Linux, BSD, and many other Unix-like operating systems.

## Project Origin and Learning Objectives

This project was created as a starting point for learning Rust while simultaneously exploring the ELF file format. As such, it represents an educational journey rather than a production-grade tool, and this context is important for understanding the codebase's current state and future direction.

The decision to use Rust for ELF parsing was motivated by several factors. Rust's ownership system and borrow checker provide strong guarantees about memory safety without requiring a garbage collector, making it ideal for systems programming tasks like binary analysis. The language's emphasis on zero-cost abstractions means that high-level code can compile down to efficient machine code comparable to C or C++. Additionally, Rust's pattern matching and enum types make it well-suited for parsing tasks where different cases need to be handled differently.

The ELF format was chosen because it is well-documented (the System V ABI specification provides comprehensive coverage), widely used, and complex enough to serve as a meaningful learning exercise. Understanding ELF is also practically useful for anyone working with Linux systems, as virtually every executable and library on such systems is an ELF file.

## Experimental Code and Historical Artifacts

As a learning project, this codebase contains various experimental code paths, abandoned ideas, and historical artifacts that reflect the iterative development process. Many parts may be unused, partially implemented, or abandoned as the project evolved. Some code may have been superseded by better approaches, while other sections reflect ideas that seemed promising at the time but later proved impractical or unnecessary.
This experimental nature is a feature, not a bug. The codebase serves as a record of a learning journey and can be educational for others following a similar path. However, it should be approached with caution in production or security-critical contexts.

## What is ELF Inspector?

ELF Inspector is a tool that allows you to examine the internal structure of ELF files without requiring deep knowledge of the ELF specification. It provides a user-friendly interface to inspect ELF headers, program headers, and various security-related properties that are critical for understanding binary security posture.

The project consists of two main components: a command-line application that serves as an interactive ELF analysis tool, and a Rust library (`elfinspect`) that can be used as a foundation for more complex ELF parsing tasks. The library exposes structured types for representing ELF components, with zero-copy parsing where feasible to minimize memory overhead and improve performance.

The tool can parse both 32-bit and 64-bit ELF files, handle both little-endian and big-endian encodings, and provides detailed information about the binary's security configuration including Position Independent Executable (PIE) status, RELRO protection levels, NX (non-executable stack) status, and the presence of dangerous Read-Write-Execute (RWX) memory segments.

## What is ELF?

The Executable and Linkable Format, commonly known as ELF, is the standard binary format used by Unix-like operating systems for representing executables, object code, shared libraries, and core dumps. Originally developed by AT&T's System V Interface Definition, ELF has become the de facto standard for binary formats on Linux, FreeBSD, Solaris, and many other systems.

Understanding ELF is fundamental for systems programmers, security researchers, reverse engineers, and anyone who needs to understand how software is structured at the binary level. An ELF file contains several key components that work together to define how the program should be loaded into memory and executed.

The ELF header is the starting point of every ELF file and contains essential metadata about the binary, including whether it is a 32-bit or 64-bit file, the target architecture, the entry point where execution should begin, and the locations of other important structures within the file.

Program headers describe how the file should be mapped into memory at runtime. These headers tell the operating system's loader which portions of the file should be loaded, at what virtual addresses, with what memory permissions (read, write, execute), and how they should be aligned. This information is critical for understanding a program's memory layout and security properties.

Section headers provide finer-grained information used primarily during the linking phase of program development. Sections define things like code (.text), read-only data (.rodata), initialized data (.data), uninitialized data (.bss), and various metadata sections used by the linker and debugger.

The dynamic section, present in executables and shared libraries, contains information used by the dynamic linker at runtime. This includes dependencies on shared libraries, relocation entries, and various flags that affect how the binary is loaded and executed.

## Zero-Copy Parsing Architecture

One of the key architectural decisions in ELF Inspector is the use of zero-copy parsing techniques wherever possible. The term "zero-copy" refers to a programming paradigm where data is parsed and accessed without making unnecessary copies of that data in memory. Instead of reading data into new buffers and converting it to native types, the parser works directly with references to the original byte slices.

The `Elf` struct in the library maintains a reference to the original ELF file data (`&[u8]`) rather than owning an owned copy. All parsed structures, including the ELF header, program headers, and other metadata, derive their values from this original data without copying it into separate memory allocations. This approach offers several significant advantages.

Memory efficiency is the primary benefit of zero-copy parsing. For large ELF files, particularly those with extensive debug information or many sections, avoiding copies can significantly reduce memory usage. When analyzing many binaries in sequence or processing large files, this efficiency becomes practically important.

Performance is improved because copying memory is inherently expensive, especially for large structures or when processing many files. By avoiding copies, the parser reduces both CPU cycles spent on memory operations and pressure on the memory allocator and garbage collector (in languages that have one, though Rust's ownership model makes this particularly efficient).

Cache locality is also improved because all the parsed data resides in a single contiguous memory region (the original file data), which is more cache-friendly than scattered allocations. Modern CPUs rely heavily on cache performance, and keeping related data close together in memory can yield measurable performance improvements.

The zero-copy approach is particularly well-suited to ELF parsing because ELF is a self-describing format with a fixed structure. The file layout is designed to be read sequentially and in place, making it ideal for reference-based access rather than copy-based parsing.

In the Rust implementation, this is achieved through the consistent use of references (`&[u8]`, `&str`) throughout the API. The `Elf::parse()` method takes a reference to the file data and returns structures that borrow from this data. The lifetime system in Rust ensures that these references cannot outlive the data they reference, preventing use-after-free bugs and other memory safety issues.

## Security Analysis Capabilities

ELF Inspector includes a comprehensive security analysis module that examines ELF binaries for common security features and potential vulnerabilities. This analysis is particularly useful for security auditors, developers who want to verify their builds are properly hardened, and researchers studying binary security.

Position Independent Executable (PIE) detection determines whether the binary was compiled as a position-independent executable. PIE is a security feature that enables Address Space Layout Randomization (ASLR) at the executable level, making it harder for attackers to predict memory addresses when exploiting memory corruption vulnerabilities. Modern distributions compile most executables as PIE by default.

RELRO (Relocation Read-Only) analysis examines whether the binary uses RELRO and whether it is partial or full RELRO. RELRO is a security feature that makes certain sections of the binary read-only after relocations are processed, protecting the Global Offset Table (GOT) and other data structures from being overwritten by attackers. Full RELRO, enabled with `-Wl,-z,relro,-z,now`, provides the strongest protection by resolving all relocations at load time and making the entire GOT read-only.

NX (non-executable stack) detection checks whether the binary marks its stack as non-executable. When NX is enabled, the stack cannot contain executable code, which prevents many common stack-based buffer overflow exploits. Modern systems have NX enabled by default for security.

RWX segment detection identifies any memory segments with both read, write, and execute permissions. Such segments are generally considered insecure because they provide an ideal location for attackers to place and execute shellcode. Well-designed binaries should have few or no RWX segments, with code in execute-only segments and data in non-executable segments.

The security module produces a composite security score from 0 to 100 based on the presence and strength of these protections, making it easy to quickly assess a binary's security posture at a glance.

## Command-Line Interface Usage

The primary interface to ELF Inspector is the command-line tool, which provides straightforward access to the library's functionality. The tool accepts an ELF file path as its main argument and optional flags for controlling output verbosity.

### Basic Usage

The basic usage pattern is to run `elfinspect <path-to-elf-file>`, which performs a standard analysis of the binary and prints the results to standard output. The output includes the ELF header information (class, endianness, type, machine architecture, and entry point), a summary of program headers, and the security analysis results.

```bash
# Analyze an ELF file
./target/release/elfinspect /bin/ls
```

### Verbose Mode

The verbose mode, activated with the `-v` or `--verbose` flag, provides detailed information about all program headers rather than just a filtered subset. This includes every header type, not just LOAD, INTERP, GNU_STACK, and GNU_RELRO headers, along with complete information about file offsets, virtual addresses, memory sizes, and flags for each entry.

```bash
# Analyze with verbose output
./target/release/elfinspect /bin/ls -v
```

### Exit Codes

The tool's exit code is 0 for successful analysis and non-zero if an error occurs, such as if the specified file does not exist, is not a valid ELF file, or is truncated or corrupted in some way.

### Example Usage Scenarios

Inspect system binaries like `/bin/ls` or `/usr/bin/date` to understand their structure and security properties. Examine your own compiled executables to verify that build flags like `-fPIE -pie` and `-Wl,-z,relro,-z,now` are being applied correctly. Analyze shared libraries to understand their memory mapping and security configuration.

## Docker Usage

The project includes a Dockerfile that serves as a demonstration and testing environment for ELF Inspector. Rather than containerizing the application for deployment, this Docker setup compiles sample C programs with different security hardening levels and demonstrates how ELF Inspector detects and reports these differences.

### How the Docker Setup Works

The Dockerfile performs the following steps:

1. **Build Stage**: Compiles a simple C program (`example.c`) with two different compiler flag configurations:
   - `example_partial`: Built with partial hardening flags (`-fstack-protector -pie -fPIE -O2`)
   - `example_full`: Built with full hardening flags (`-Wl,-z,relro,-z,now -Wl,-z,noexecstack -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -pie -O2`)

2. **Build ELF Inspector**: Compiles the Rust-based `elfinspect` binary in release mode

3. **Final Image**: Copies both sample binaries and the `elfinspect` tool to a minimal Debian base image

4. **Demonstration**: The default command runs `elfinspect` on both sample binaries with verbose output, showing the security differences between partially and fully hardened executables

### Building the Docker Image

Build the Docker image from the project root:

```bash
docker build -t elfinspect-demo .
```

### Running the Docker Demonstration

Run the container to see the demonstration:

```bash
docker run --rm elfinspect-demo
```

This will output the security analysis for both binaries, showing how the tool detects differences in:

- PIE (Position Independent Executable) status
- RELRO (Relocation Read-Only) protection level
- NX (non-executable stack) flag
- Overall security score

## Sample Output

When you run ELF Inspector, it produces a structured output showing various aspects of the analyzed binary. Here are examples of what the output looks like:

### Standard Output

```
ELF Analysis: /bin/ls
============================================================

ELF Header:
  Class:         Elf64
  Endianness:    Little
  Type:          Executable
  Machine:       62 (AMD x86-64)
  Entry Point:   0x404000

Program Headers (13 entries):
  [ 1] LOAD           @ 0x2000 (758592 bytes) [R E]
  [ 2] LOAD           @ 0xbc000 (516896 bytes) [RW ]
  [ 3] INTERP         @ 0x1b2888 (28 bytes) [R  ]
  [ 6] GNU_RELRO      @ 0xbc000 (754432 bytes) [R  ]
  [13] GNU_STACK      @ 0 (0 bytes) [RW ]

Security Analysis:
  PIE:           Yes
  RELRO:         Full
  NX (Stack):    Yes
  RWX Segments:  0
  Interpreter:   /lib64/ld-linux-x86-64.so.2
  Security Score: 100/100

✓ Binary appears to have standard security hardening enabled.
```

### Verbose Output

```
ELF Analysis: /bin/ls -v
============================================================

ELF Header:
  Class:         Elf64
  Endianness:    Little
  Type:          Executable
  Machine:       62 (AMD x86-64)
  Entry Point:   0x404000

Program Headers (13 entries):
    #  Type            Offset      VirtAddr    MemSize      Flags
  ------------------------------------------------------------
   0  NULL            0x0         0x0         0x0
   1  LOAD            0x2000      0x2000      0xb9000      R E
   2  LOAD            0xbc000     0xbc000     0x7e000      R W
   3  INTERP          0x1b2888    0x1b2888    0x1c         R
   4  DYNAMIC         0x1b28a8    0x1b28a8    0x228        R
   5  NOTE            0x22c       0x22c       0x20         R
   6  GNU_RELRO       0xbc000     0xbc000     0xb8000      R
   7  GNU_EH_FRAME    0x18b55c    0x18b55c    0x26b0       R
   8  GNU_STACK       0x0         0x0         0x0          RW
   9  GNU_PROPERTY    0x22c       0x22c       0x20         R
  10  PHDR            0x1b2a30    0x1b2a30    0x2d8        R
  11  GNU_PROPERTY    0x250       0x250       0x14         R
  12  NOTE            0x264       0x264       0x4          R

Security Analysis:
  PIE:           Yes
  RELRO:         Full
  NX (Stack):    Yes
  RWX Segments:  0
  Interpreter:   /lib64/ld-linux-x86-64.so.2
  Security Score: 100/100

✓ Binary appears to have standard security hardening enabled.
```

### Output for Non-Hardened Binary

```
ELF Analysis: ./unhardened_app
============================================================

ELF Header:
  Class:         Elf64
  Endianness:    Little
  Type:          Executable
  Machine:       62 (AMD x86-64)
  Entry Point:   0x400000

Program Headers (9 entries):
  [ 0] LOAD           @ 0x0 (20480 bytes) [R E]
  [ 1] LOAD           @ 0x5000 (4096 bytes) [RW ]

Security Analysis:
  PIE:           No
  RELRO:         None
  NX (Stack):    Yes
  RWX Segments:  0

Security Score: 25/100
⚠ Binary is missing some security features:
  - Not a PIE (compile with -fPIE -pie)
  - Not using Full RELRO (link with -Wl,-z,relro,-z,now)
```

## Library Usage

The `elfinspect` crate can be used as a Rust library for programs that need to inspect ELF files programmatically. The library exposes several key types and functions.

### Basic Library Usage

Add elfinspect to your `Cargo.toml`:

```toml
[dependencies]
elfinspect = { path = "/path/to/elfinspect" }
anyhow = "1.0"
```

Example code:

```rust
use anyhow::Result;
use elfinspect::elf::Elf;
use std::fs;

fn main() -> Result<()> {
    // Read the ELF file
    let data = fs::read("path/to/binary")?;

    // Parse the ELF file
    let elf = Elf::parse(&data)?;

    // Access header information
    println!("Class: {:?}", elf.class());
    println!("Machine: {}", elf.header.machine);
    println!("Entry point: {:#x}", elf.header.entry_point);

    // Iterate over program headers
    for (i, ph) in elf.program_headers().enumerate() {
        println!("Segment {}: {:?}", i, ph.segment_type);
    }

    // Get security information
    let security = elf.security_info();
    println!("Security score: {}", security.score());
    println!("PIE enabled: {}", security.pie);

    Ok(())
}
```

## Building and Installation

To build ELF Inspector, you will need a recent Rust toolchain installed. The recommended way to obtain Rust is through rustup, available from https://rustup.rs.

### Prerequisites

- Rust toolchain (stable or nightly)
- A Unix-like environment (Linux, macOS, BSD)

### Build Commands

For a debug build:

```bash
cargo build
```

This produces an executable at `target/debug/elfinspect` that includes debug symbols and is suitable for development and debugging.

For a release build with optimizations:

```bash
cargo build --release
```

The resulting executable at `target/release/elfinspect` is optimized for performance and is suitable for regular use.

To run the tool directly from the source directory without building a separate binary:

```bash
cargo run -- <elf-file>
```

## Technical Implementation Details

The implementation uses several Rust idioms and patterns worth understanding for anyone reading or modifying the code.

Endianness handling is abstracted through the `Endianness` enum, with helper functions that read multi-byte integers in the correct byte order based on the file's declared endianness. This allows the same parsing code to work correctly on both little-endian files (common on x86 and ARM systems) and big-endian files (used on some older architectures).

The ELF class (32-bit versus 64-bit) similarly determines the size of various fields. The `ElfClass` enum and the associated `addr_size()` method allow the parsing code to handle both formats without duplicating the entire parser.

Lazy evaluation is used for program header iteration through the `ProgramHeaderIter` type. Rather than parsing all headers into a Vec upfront, the iterator parses each header on demand as the consumer requests it. This reduces memory usage for files with many headers and allows work to be done incrementally.

Bounds checking is performed explicitly throughout the parser to handle malformed or truncated files gracefully. The `validate_bounds()` and `get_slice()` functions ensure that all memory accesses are safe and will return appropriate errors rather than panicking.

Error handling uses Rust's `Result` type extensively, with the `thiserror` crate providing convenient derive macros for error enum definitions. Error messages include context about what operation was being performed when the error occurred, making debugging easier.
