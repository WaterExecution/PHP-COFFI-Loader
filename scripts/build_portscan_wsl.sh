#!/usr/bin/env bash
# Build src/portscan/portscan_simple.c → bofs/portscan_simple.x64.o (MinGW from WSL).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
INC="$REPO_ROOT/third_party/beacon"
OUTDIR="$REPO_ROOT/bofs"
SRC="$REPO_ROOT/src/portscan/portscan_simple.c"
mkdir -p "$OUTDIR" "$INC"
for f in beacon.h bofdefs.h; do
  if [[ ! -f "$INC/$f" ]]; then
    curl -fsSL -o "$INC/$f" \
      "https://raw.githubusercontent.com/trustedsec/CS-Situational-Awareness-BOF/master/src/common/$f"
  fi
done
# BOF_MSG uses sprintf + BeaconOutput (php bof_loader variadic BeaconPrintf stub is fragile).
x86_64-w64-mingw32-gcc -c "$SRC" -o "$OUTDIR/portscan_simple.x64.o" \
  -Wall -DBOF -fno-builtin -fno-ident -fpack-struct=8 -Os -I"$INC"
echo "OK: $OUTDIR/portscan_simple.x64.o"
file "$OUTDIR/portscan_simple.x64.o"
