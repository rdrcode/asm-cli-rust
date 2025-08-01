# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**RUDI (RUst Debugger Interactive)** is an interactive assembly language instruction simulator and debugger that combines CPU emulation, assembly/disassembly, and advanced debugging features. This version merges modern dependencies from upstream with extended rdr-mods features.

## Build and Development Commands

### Essential Commands
```bash
cargo build                    # Build the project
cargo run                      # Interactive mode (default x86-32)
cargo run -- --help           # Show CLI options
cargo test                     # Run comprehensive test suite (48 tests)
```

### Architecture and Execution Options
```bash
cargo run -- --arch x86-32    # 32-bit x86 mode
cargo run -- --arch x86-64    # 64-bit x86 mode
cargo run -- -b "mov eax, 42; int 0x80"  # Batch execution mode
cargo run -- -c context.json  # Load CPU context from file
cargo run -- -s save.json     # Save CPU context on exit
cargo run -- --ticks 12345    # Fixed timestamp for deterministic execution
```

### Testing Commands
```bash
cargo test                          # Run all 48 tests
cargo test lexer::tests            # Test lexical analysis (6 tests)
cargo test machine::context        # Test context serialization (16 tests)
cargo test machine::cpuarch        # Test CPU architecture (8 tests)
cargo test parser::tests           # Test command parsing (6 tests)
cargo test squeezer::tests         # Test output compression (10 tests)
```

## Architecture Overview

### Core Engine Integration
The project integrates three external engines through a unified interface:
- **Keystone Engine**: Assembly compilation (`git` dependency)
- **Unicorn Engine**: CPU emulation (`git` dependency)  
- **Capstone Engine**: Disassembly (`crates.io`)

### Layered Architecture
```
CLI Interface (main.rs)
    ↓
Command Parser (parser.rs + lexer.rs)
    ↓
Machine Interface (machine/interface.rs)
    ↓
CPU Architecture Layer (machine/cpuarch.rs)
    ↓
Engine Abstraction (Keystone, Unicorn, Capstone)
```

### Key Modules

**`src/machine/`** - Core emulation layer:
- `interface.rs`: Main Machine struct coordinating all engines, lifetime `<'a>`
- `cpuarch.rs`: Architecture definitions, register mappings, syscall handlers
- `context.rs`: CPU state serialization with `#[derive(Clone)]` for context passing
- `macros.rs`: Error handling macros for engine operations

**`src/parser.rs`** - Command processing:
- Separates assembly instructions from debugger commands (.quit, .print, .eval, .define)
- Supports constants, value history, and expression evaluation
- Uses nom parser combinator for robust parsing

**`src/lexer.rs`** - Token-based lexical analysis:
- Handles multiple integer formats (binary, octal, hex, decimal)
- Parses operators, registers, identifiers, and constants

**Output formatting**:
- `hexprint.rs`: Colored hex dumps with ASCII representation
- `squeezer.rs`: Compresses repeated lines in output (similar to `less`)

### Critical Implementation Details

**Engine Access Pattern**: Access unicorn engine directly as `&mut self.unicorn`, not through `.borrow()`

**Context Cloning**: `CpuContext` implements `Clone` - use `cpu_context.clone()` when passing to `Machine::new_from_context()`

**Clap 4.x Integration**: Uses modern derive macros with `#[derive(Parser)]` and `#[derive(ValueEnum)]`

**Lifetime Management**: Machine struct has lifetime parameter `Machine<'a>` with `Unicorn<'a, ()>`

## Dependencies and Build Requirements

### Critical Native Dependencies
- **CMake**: Required for building Keystone/Unicorn from source
- **Build tools**: C compiler toolchain for native library compilation
- **Git dependencies**: Uses specific commits from upstream repositories

### Modern Rust Dependencies
- **Clap 4.x**: CLI parsing with derive macros (no structopt)
- **Unicorn-engine**: CPU emulation with `unicorn_engine::` namespace
- **Serde**: JSON serialization for context persistence
- **Rustyline 9.x**: Interactive readline with Vi-mode support
- **Nom 6**: Parser combinator library

### Known Build Issues
- Macro semicolon warnings (will become errors in future Rust versions)
- Requires manual setup of Keystone/Unicorn engines
- Symlink problems in keystone bindings on some systems

## Interactive Commands

### Debugger Commands (prefix with `.`)
```
.quit                    # Exit the debugger
.print <expression>      # Evaluate and print expression
.eval <expression>       # Evaluate expression
.define <name> <value>   # Define constant
```

### Assembly Instructions
Execute any valid x86/x64 assembly directly:
```
mov eax, 42             # Standard assembly syntax
add eax, ebx            # Register operations
int 0x80                # System calls (emulated)
```

### System Call Emulation
Handles realistic syscall emulation for:
- `write` syscall (stdout output)
- `time` syscall (with optional fixed timestamp)
- `gettimeofday` syscall
- `exit` syscall

## Testing Architecture

The codebase has comprehensive test coverage (48 tests) organized by module:

- **Lexer tests**: Token parsing, integer formats, value history
- **Context tests**: CPU state serialization/deserialization for both x86-32 and x86-64
- **Architecture tests**: Register handling, syscall emulation, time functions
- **Parser tests**: Command parsing, constants, expression resolution
- **Squeezer tests**: Output compression edge cases

All tests use the clone pattern for context creation and direct engine access patterns established in the main codebase.