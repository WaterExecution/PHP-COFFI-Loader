# PHP-COFFI-Loader

A **Windows x64 COFF loader** written in PHP. It loads Beacon-style object files (`.o`), resolves **AMD64** relocations and imports, provides **Beacon API stubs** (`BeaconOutput`, `BeaconDataParse`, and related helpers), and runs the BOF entrypoint (`go` / `_go`) in a **dedicated stack** via an FFI call shim.

Use this for **local research, testing, and tooling** around BOF object files. Loading and executing arbitrary native code is inherently risky—only run objects you trust, in environments you control.

## Requirements

- **Windows** (x64), **PHP 8+** with the **FFI** extension enabled (`ffi.enabled=true` in `php.ini`, subject to your distro’s policy).
- **MinGW-w64** (or similar) if you compile the included sample BOF from WSL—see `scripts/build_portscan_wsl.sh`.

## Command-line usage

From the repository root:

```text
php coffi.php <file.o> [args...]
```

The loader expects an **AMD64 COFF** object. It looks for a **`go`** or **`_go`** symbol; if none is found, it loads the image and exits without executing.

### Argument packing (`args`)

Arguments are encoded into a buffer compatible with typical **Beacon / bof_pack** conventions:

| Form | Meaning |
|------|--------|
| Plain token | Narrow (UTF-8) string: length prefix + bytes + NUL. |
| `str:...` | Same as plain; quotes optional; `/` normalized to `\` on Windows. |
| `wstr:...` | Wide (UTF-16LE) string with length prefix. |
| `int:N` | 32-bit signed integer. |
| `short:N` | 16-bit unsigned. |
| `bin:BASE64` | Binary blob with length prefix. |
| Single token of even hex (e.g. `010203`) | Raw packed bytes (legacy). |

No arguments produces a minimal empty pack (`\0\0\0\0`).

## Programmatic usage

```php
<?php
require 'coffi.php';

$loader = new CoffLoader();
$img = $loader->load('path\to\bof.x64.o', []); // optional $externs: symbol => virtual address (int)

// $img keys: 'base', 'size', 'go' (callable FFI cast), 'goVa' (int|null)

$pack = "\0\0\0\0"; // or build same layout as bofCliBuildArgpack
$len = strlen($pack);
$buf = FFI::new("char[{$len}]");
FFI::memcpy($buf, $pack, $len);
$loader->runGoInWorkerThread((int) $img['goVa'], $buf, $len);
```

`load()` maps the image with `VirtualAlloc` (**RWX**), applies relocations, resolves `extern` symbols against `kernel32` / `msvcrt` as needed, and wires Beacon stubs. `runGoInWorkerThread()` allocates a private stack and invokes the entry through a small machine-code trampoline so the BOF does not run on PHP’s own stack.

## Repository layout

| Path | Role |
|------|------|
| `coffi.php` | Loader, CLI, and `CoffLoader` implementation. |
| `bofs/` | Built `.o` files for testing (if present). |
| `src/portscan/portscan_simple.c` | Example BOF source. |
| `scripts/build_portscan_wsl.sh` | Fetch Beacon headers and compile the portscan object with MinGW from WSL. |
| `third_party/beacon/` | `beacon.h` / `bofdefs.h` (from TrustedSec CS-Situational-Awareness-BOF when using the script). |
| `test_bofs.py` | Runs PHP against each `bofs/*.o` with per-file argument presets. |

### Running `test_bofs.py`

From the repo root (with `coffi.php` present):

```text
python test_bofs.py
python test_bofs.py --php "C:\path\to\php.exe" --verbose
```

## Limitations / notes

- **x64 COFF only** (machine `0x8664`).
- **Variadic** `BeaconPrintf` is stubbed; BOFs that rely heavily on formatted printing may be fragile—prefer `BeaconOutput` / `sprintf` patterns where the sample comments mention this.
- Memory for the loaded image is executable; treat this as **unsafe** for untrusted input.

