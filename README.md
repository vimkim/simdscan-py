# simdscan.py

A command-line tool for analyzing SIMD instruction usage in compiled binaries. Inspects x86-64 binaries (ELF, Mach-O, PE) and provides detailed statistics on SIMD operations by ISA extension.

## Features

- **SIMD Detection**: Automatically identifies and counts SIMD instructions in binary files
- **ISA Classification**: Categorizes instructions by extension (SSE, SSE2, SSE4, AVX, AVX2, etc.)
- **Multiple Output Formats**: Support for JSON and YAML output
- **Detailed Breakdown**: Optional per-ISA instruction analysis with occurrence counts
- **Cross-Platform**: Works with ELF, Mach-O, and PE binary formats

## Requirements

- Linux system with `objdump` installed
- Python 3.6+
- Optional: PyYAML for YAML output format

## Installation

```bash
# Clone or download simdscan.py
chmod +x simdscan.py
```

## Usage

### Basic Usage

```bash
./simdscan.py <binary_file>
```

### Options

- `-f, --format {json,yaml}`: Output format (default: json)
- `--show-insts`: Include detailed per-ISA instruction breakdown
- `-h, --help`: Show help message

### Examples

**Analyze a library file:**

```bash
./simdscan.py libfaiss.a
```

**Output with instruction details:**

```bash
./simdscan.py --show-insts libmath.so
```

**YAML format output:**

```bash
./simdscan.py -f yaml binary_file
```

## Sample Output

### Basic Analysis

```json
{
  "binary": "libfaiss.a",
  "has_simd": true,
  "isa_summary": {
    "SSE": 96629,
    "SSE2": 26378
  },
  "total_simd_insts": 123007
}
```

### With AVX Instructions

```json
{
  "binary": "libfaiss_avx2.a",
  "has_simd": true,
  "isa_summary": {
    "AVX": 58825,
    "SSE4": 4078
  },
  "total_simd_insts": 62903
}
```

### Detailed Breakdown (with --show-insts)

```json
{
  "binary": "example.so",
  "has_simd": true,
  "isa_summary": {
    "SSE": 1024,
    "AVX": 512
  },
  "total_simd_insts": 1536,
  "isa_details": {
    "SSE": {
      "unique_mnemonics": 15,
      "occurrences": {
        "movaps": 256,
        "addps": 128,
        "mulps": 64
      }
    },
    "AVX": {
      "unique_mnemonics": 12,
      "occurrences": {
        "vmovaps": 128,
        "vaddps": 96,
        "vmulps": 48
      }
    }
  }
}
```

## How It Works

1. **Disassembly**: Uses `objdump` to disassemble the target binary
2. **Pattern Matching**: Identifies SIMD instructions using mnemonic patterns
3. **Classification**: Categorizes instructions by their corresponding ISA extensions
4. **Aggregation**: Counts occurrences and provides summary statistics

## Supported ISA Extensions

- SSE (Streaming SIMD Extensions)
- SSE2, SSE3, SSSE3, SSE4.1, SSE4.2
- AVX (Advanced Vector Extensions)
- AVX2, AVX-512
- And other x86-64 SIMD instruction sets

## Use Cases

- **Performance Analysis**: Identify SIMD utilization in optimized code
- **Compiler Verification**: Verify that auto-vectorization is working
- **Library Comparison**: Compare SIMD usage between different builds
- **Architecture Targeting**: Ensure binaries use appropriate instruction sets

## Limitations

- Requires `objdump` to be available in PATH
- Only supports x86-64 architecture
- Static analysis only (doesn't consider runtime execution frequency)

## License

Apache License 2.0

## Contributing

As you wish!
