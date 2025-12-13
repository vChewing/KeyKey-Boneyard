#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_cerod_inject.sh /path/to/keykey-executable [args...]
if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/executable [args...]"
  exit 2
fi

# expect lib either at repo root or in scripts/
if [ -e "$(pwd)/libcerod_interpose.dylib" ]; then
  LIB=$(pwd)/libcerod_interpose.dylib
elif [ -e "$(dirname "$0")/libcerod_interpose.dylib" ]; then
  LIB=$(cd "$(dirname "$0")" && pwd)/libcerod_interpose.dylib
else
  echo "Missing libcerod_interpose.dylib. Run scripts/build_interpose.sh first." >&2
  exit 2
fi
EXE=$1
shift

if [ ! -e "$LIB" ]; then
  echo "Missing $LIB. Run scripts/build_interpose.sh first." >&2
  exit 2
fi

# clean previous log
rm -f /tmp/cerod_trace.log

# Launch under DYLD insertion (foreground)
env DYLD_INSERT_LIBRARIES="$LIB" "$EXE" "$@" &
PID=$!
echo "Launched PID=$PID; logs -> /tmp/cerod_trace.log"

# helper: wait and tail log
sleep 1
if [ -e /tmp/cerod_trace.log ]; then
  echo "Initial log entries:"; tail -n +1 /tmp/cerod_trace.log
else
  echo "No log yet. Use 'tail -f /tmp/cerod_trace.log' to watch.";
fi

echo "To stop: kill $PID"