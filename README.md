# RUDI - RUst Debugger Interactive

🔧 **An interactive assembly language debugger and CPU emulator**

RUDI (RUst Debugger Interactive) is a powerful command-line tool that lets you write, execute, and debug assembly code interactively. It combines the power of three major engines - Keystone (assembler), Unicorn (CPU emulator), and Capstone (disassembler) - to provide a comprehensive assembly development environment.

## ✨ Features

- **Interactive REPL** with Vi-mode editing and command history
- **Multi-architecture support** (x86-32 and x86-64)
- **Real-time CPU state visualization** with colored output
- **System call emulation** (write, time, gettimeofday, exit)
- **CPU context persistence** - save and restore debugging sessions
- **Batch execution mode** for scripting
- **Advanced expression evaluation** with constants and memory references
- **Memory inspection** with hex dumps and ASCII visualization
- **Register tracking** with change highlighting

## 📸 Preview

![x64](images/x64.png)

## 🛠️ Installation

### Prerequisites

- Rust toolchain (1.70 or later)
- CMake (for building native dependencies)
- C compiler (gcc/clang)
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/asm-cli-rust.git
cd asm-cli-rust

# Build the project (this will automatically fetch and build dependencies)
cargo build --release

# Run the debugger
cargo run --release
```

The build process will automatically download and compile the required versions of Keystone and Unicorn engines.

### Troubleshooting Build Issues

If you encounter build errors:

```bash
# Clear cargo cache
cargo clean

# Update dependencies
cargo update

# Try building with verbose output
cargo build -vv
```

## 🚀 Quick Start

### Interactive Mode (Default)

```bash
# Start RUDI in x86-32 mode (default)
cargo run

# Start in x86-64 mode
cargo run -- --arch x86-64
```

### Basic Assembly Examples

```asm
# Move values into registers
> mov eax, 42
> mov ebx, 58
> add eax, ebx
> .print %eax
100

# Working with memory
> mov eax, 0x2000
> mov dword [eax], 0xdeadbeef
> mov ebx, [eax]
> .print %ebx
0xdeadbeef
```

## 📚 Usage Examples

### Example 1: Time Calculation

Calculate hours, minutes, and seconds from Unix timestamp:

```asm
# Get current time
> mov eax, 13
> int 0x80
> .print %eax
1735661234

# Calculate seconds in a day
> .eval 60 * 60 * 24
> .define ticksday 86400

# Get time of day
> mov ebx, $ticksday
> div ebx
> mov eax, edx     # remainder = seconds today

# Calculate hours
> xor edx, edx
> mov ebx, 3600
> div ebx
> .define hours 0x2004
> mov [$hours], al
> .print %al
14  # 14:xx:xx

# Calculate minutes
> mov eax, edx
> xor edx, edx
> mov ebx, 60
> div ebx
> .define minutes 0x2005
> mov [$minutes], al
> .print %al
25  # 14:25:xx

# Remaining seconds
> .define seconds 0x2006
> mov [$seconds], dl
> .print %dl
34  # 14:25:34
```

### Example 2: CPUID Information

Extract CPU vendor string:

```asm
# Execute CPUID
> mov eax, 0
> cpuid

# Store vendor string
> mov [0x2000], ebx
> mov [0x2004], edx
> mov [0x2008], ecx

# Display memory
> .d
┌────────┬─────────────────────────────────────────────────┬──────────────────┐
│ ADDR   │ 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F│ 0123456789ABCDEF │
├────────┼─────────────────────────────────────────────────┼──────────────────┤
│ 0x2000 │ 47 65 6e 75 69 6e 65 49 6e 74 65 6c 00 00 00 00│ GenuineIntel.... │
└────────┴─────────────────────────────────────────────────┴──────────────────┘
```

### Example 3: String Manipulation

Work with ASCII strings in memory:

```asm
# Store string "Hello"
> mov byte [0x2000], 'H'
> mov byte [0x2001], 'e'
> mov byte [0x2002], 'l'
> mov byte [0x2003], 'l'
> mov byte [0x2004], 'o'
> mov byte [0x2005], 0

# Write to stdout using syscall
> mov eax, 4       # sys_write
> mov ebx, 1       # stdout
> mov ecx, 0x2000  # buffer
> mov edx, 5       # length
> int 0x80
Hello
```

### Example 4: Mathematical Operations

Perform calculations with overflow detection:

```asm
# Test overflow with unsigned addition
> mov cl, 255
> inc cl
> jc overflow_detected    # Carry flag set
> .print %cl
0

# Division by zero handling
> xor eax, eax
> dec eax          # eax = 0xFFFFFFFF
> mov ebx, 5
> div ebx
> .print %eax      # quotient
0x33333333
> .print %edx      # remainder
0
```

### Example 5: Context Save/Restore

Save your debugging session:

```bash
# Start with saved context
cargo run -- -c debug_session.json

# In RUDI:
> mov eax, 0x1337
> mov ebx, 0xdead
> .define important_var 0x2000
> mov [$important_var], 0xbeef
> .quit

# Save context on exit
cargo run -- -s debug_session.json
```

## 🎮 Advanced Features

### Batch Mode

Execute assembly from command line:

```bash
# Single instruction
cargo run -- -b "mov eax, 42; int 0x80"

# Multiple instructions
cargo run -- -b "xor eax, eax; cpuid; mov [0x2000], ebx"
```

### Fixed Timestamp Mode

For deterministic debugging:

```bash
# Always return same time value
cargo run -- --ticks 1234567890
```

### Memory Inspection

```asm
# Define memory region
> .define buffer 0x3000
> mov [$buffer], 0x41424344

# Hex dump
> .d
┌────────┬─────────────────────────────────────────────────┬──────────────────┐
│ ADDR   │ 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F│ 0123456789ABCDEF │
├────────┼─────────────────────────────────────────────────┼──────────────────┤
│ 0x3000 │ 44 43 42 41 00 00 00 00 00 00 00 00 00 00 00 00│ DCBA............ │
└────────┴─────────────────────────────────────────────────┴──────────────────┘
```

### Expression Evaluation

```asm
# Complex calculations
> .eval (0x100 + 0x200) * 4
0xC00

# Use in instructions
> mov eax, (1 << 8) | 0xFF
> .print %eax
0x1FF
```

## ⌨️ Commands Reference

### Assembly Instructions
- Standard x86/x64 assembly syntax
- Intel syntax by default
- Memory operations: `mov [addr], value`
- All general-purpose registers available

### Debugger Commands
- `.quit` / `.exit` - Exit RUDI
- `.print <expr>` - Evaluate and print expression
- `.eval <expr>` - Evaluate expression
- `.define <name> <value>` - Define constant
- `.d` - Display memory dump
- Register references: `%eax`, `%ebx`, etc.
- Constant references: `$name`

## 🧪 Testing

Run the comprehensive test suite:

```bash
# All tests
cargo test

# Specific test categories
cargo test lexer        # Lexer tests
cargo test context      # Context serialization
cargo test cpuarch      # Architecture tests
cargo test parser       # Parser tests
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🔀 Fork History

This project is a fork of [cch123/asm-cli-rust](https://github.com/cch123/asm-cli-rust), with significant enhancements in the `rdr-mods` branch.

### Key Enhancements Made

1. **Advanced Parser and Lexer**
   - Implemented a complete parser using nom parser combinators
   - Added support for expressions, constants, and value history
   - Token-based lexical analysis for robust command parsing

2. **CPU Context Persistence**
   - Save and restore complete CPU state to/from JSON files
   - Enables debugging session continuity across runs
   - Comprehensive serialization of registers, memory, and flags

3. **Enhanced Debugging Features**
   - `.print`, `.eval`, `.define` commands for interactive debugging
   - Memory inspection with colored hex dumps
   - Output compression for repeated lines (squeezer)

4. **System Call Emulation**
   - Implemented write, time, gettimeofday, and exit syscalls
   - Fixed timestamp mode for deterministic debugging
   - Realistic program execution environment

5. **Comprehensive Test Suite**
   - Added 48 tests covering all major components
   - Test coverage for lexer, parser, context, and architecture modules
   - Ensures reliability and prevents regressions

6. **Modernized Dependencies**
   - Updated to Clap 4.x with derive macros
   - Migrated from local path dependencies to Git dependencies
   - Improved compatibility with modern Rust toolchain

## 🔗 Related Projects

- Original Rust implementation: [cch123/asm-cli-rust](https://github.com/cch123/asm-cli-rust)
- Original inspiration: [asmshell](https://github.com/poppycompass/asmshell)
- Go version by same author: [asm-cli](https://github.com/cch123/asm-cli)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [cch123](https://github.com/cch123) for the original asm-cli-rust implementation
- Keystone Engine for assembly compilation
- Unicorn Engine for CPU emulation
- Capstone Engine for disassembly
- The Rust community for excellent crates