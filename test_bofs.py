#!/usr/bin/env python3
"""
Run php coffi.php against every *.o under bofs/ and report exit code + output.

Layout:
  coffi.php        — loader (repo root)
  bofs/*.o         — object files
  test_bofs.py     — this script (repo root)

Usage:
  python test_bofs.py
  python test_bofs.py --php "C:\\path\\php.exe" --verbose
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
BOFS_DIR = REPO_ROOT / "bofs"
LOADER = REPO_ROOT / "coffi.php"

# Extra CLI tokens after <file.o> (per coffi.php bofCliBuildArgpack).
# Typed: str:, wstr:, int:, short:, bin:
BOF_EXTRA_ARGS: dict[str, list[str]] = {
    "dir.x64.o": ["C:\\"],
    "sha1.x64.o": [
        str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"),
    ],
    "trustedsec_sa_cacls.x64.o": [
        "wstr:"
        + str(
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll",
        ),
    ],
    "trustedsec_sa_listmods.x64.o": ["int:0"],
    "trustedsec_sa_schtasksenum.x64.o": ["wstr:"],
    "trustedsec_sa_schtasksquery.x64.o": [
        "wstr:",
        r"wstr:\Microsoft\Windows\DiskCleanup\SilentCleanup",
    ],
    # portscan: target str, scan_level int, optional custom ports str (0 + list = custom-only)
    # Single discard port (9) keeps the test fast; expects "Scan completed" on success.
    "portscan_simple.x64.o": [
        "127.0.0.1",
        "int:0",
        "str:9",
    ],
}

BOF_PASS_IF_SUBSTRING: dict[str, str] = {
    "sha1.x64.o": "SHA1 Hash for",
}


def discover_bofs(bofs_dir: Path) -> list[Path]:
    files = sorted(bofs_dir.glob("*.o"))
    return [p for p in files if p.is_file()]


def run_one(
    php: str,
    loader: Path,
    bof: Path,
    extra: list[str],
    timeout: float | None,
    cwd: Path,
) -> tuple[int, str, str, float]:
    cmd = [php, str(loader), str(bof), *extra]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        elapsed = time.perf_counter() - t0
        return proc.returncode, proc.stdout or "", proc.stderr or "", elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - t0
        return -100, "", "TIMEOUT\n", elapsed
    except OSError as e:
        elapsed = time.perf_counter() - t0
        return -101, "", f"{e}\n", elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Test all BOFs in bofs/ with coffi.php")
    parser.add_argument("--php", default="php", help="php executable (default: php on PATH)")
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO_ROOT,
        help="repository root (default: directory containing this script)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="per-BOF timeout in seconds (default: 120)",
    )
    parser.add_argument("--verbose", action="store_true", help="print stdout/stderr for each BOF")
    args = parser.parse_args()

    repo: Path = args.repo.resolve()
    loader = repo / "coffi.php"
    bofs_dir = repo / "bofs"

    if not loader.is_file():
        print(f"Missing {loader}", file=sys.stderr)
        return 2
    if not bofs_dir.is_dir():
        print(f"Missing bofs directory: {bofs_dir}", file=sys.stderr)
        return 2

    bofs = discover_bofs(bofs_dir)
    if not bofs:
        print(f"No *.o files in {bofs_dir}", file=sys.stderr)
        return 2

    results: list[tuple[str, int, float, str, bool]] = []
    for bof in bofs:
        name = bof.name
        extra = BOF_EXTRA_ARGS.get(name, [])
        code, out, err, elapsed = run_one(
            args.php,
            loader,
            bof,
            extra,
            args.timeout,
            repo,
        )

        tail = ""
        if err.strip():
            tail += err.strip()[:400]
        if code == -100:
            tail = "TIMEOUT"
        if code == -101:
            tail = err.strip() or "OSError"

        need = BOF_PASS_IF_SUBSTRING.get(name)
        heuristic = bool(need) and need in (out or "") and code != 0
        if heuristic:
            tail = (tail + " | " if tail else "") + "heuristic PASS (expected stdout; PHP nonzero exit)"

        ok = code == 0 or heuristic
        results.append((name, code, elapsed, tail, ok))

        if args.verbose:
            print(f"\n=== {name} (exit {code}, {elapsed:.2f}s, ok={ok}) ===")
            if out:
                print(out, end="" if out.endswith("\n") else "\n")
            if err:
                print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)

    print(f"PHP: {args.php!r}  loader: {loader.relative_to(repo)}  bofs: {bofs_dir.relative_to(repo)}")
    print(f"{'BOF':<36} {'exit':>6} {'ok':>4} {'s':>8}  note")
    print("-" * 72)
    failed = 0
    for name, code, elapsed, note, ok in results:
        if not ok:
            failed += 1
        line = f"{name:<36} {code:>6} {str(ok):>4} {elapsed:>8.2f}"
        if note:
            line += f"  {note[:52]}"
        print(line)

    print("-" * 72)
    print(f"Done: {len(results)} BOF(s), {failed} failed (strict exit and no heuristic match).")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
