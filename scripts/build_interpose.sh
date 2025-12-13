#!/usr/bin/env bash
set -euo pipefail

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$THIS_DIR/libcerod_interpose.dylib"
SRC_C="$THIS_DIR/cerod_interpose.c"
SRC_OBJC="$THIS_DIR/cerod_objc.m"
clang -dynamiclib -o "$OUT" "$SRC_C" "$SRC_OBJC" -O2 -arch x86_64 -arch arm64 -framework CoreServices -framework CoreFoundation -framework Foundation -ObjC -Wall -Wextra -fPIC
ls -l "$OUT"
echo "Built $OUT"