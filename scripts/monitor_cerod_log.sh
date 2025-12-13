#!/usr/bin/env bash
set -euo pipefail

LOG=/tmp/cerod_trace.log
OUT=outputs/cerod_filenames.txt
mkdir -p outputs

# print and append unique matches to outputs file
# match lines with :cerod: or activation key or KeyKey.db

grep -oE "[^ ]*(?::cerod:|7bb07b8d471d642e|KeyKey.db)[^ ]*" "$LOG" 2>/dev/null | sort -u | while read -r p; do
  if ! grep -Fxq "$p" "$OUT" 2>/dev/null; then
    echo "$p" | tee -a "$OUT"
  fi
done

# tail mode
exec tail -n +1 -F "$LOG" | sed -nE "s/.* (?:open|fopen|creat|sqlite3_open): ([^ ]+).*/\1/p" | while read -r p; do
  if echo "$p" | grep -qE ":cerod:|7bb07b8d471d642e|KeyKey.db"; then
    if ! grep -Fxq "$p" "$OUT" 2>/dev/null; then
      echo "$p" | tee -a "$OUT"
    fi
  fi
done