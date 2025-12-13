#!/usr/bin/env python3
"""Search candidate filename strings in CEROD decrypted outputs (combined and per-chunk)."""
import sys
from pathlib import Path

OUT_DIR = Path('cerod_out')
if not OUT_DIR.exists():
    print('cerod_out directory not found; run cerod_decrypt.py first')
    sys.exit(1)

cands = list()
# read from generator if available
try:
    import subprocess
    p = subprocess.run(['python3', 'scripts/generate_cerod_filenames.py'], check=True, capture_output=True, text=True)
    for l in p.stdout.strip().splitlines():
        if l:
            cands.append(l)
except Exception:
    # fallback: minimal set
    cands = [':cerod:', '7bb07b8d471d642e', '7bb07b8d471d642e:cerod:', ':cerod:KeyKey.db', 'KeyKey.db']

# Add some high-priority hypothesized patterns
ACT = '7bb07b8d471d642e'
extra = [
    f":cerod:{ACT}/KeyKey.db",
    f"{ACT}:cerod:KeyKey.db",
    f":cerod:{ACT}.db",
    f"{ACT}/:cerod:/KeyKey.db",
    f":cerod:{ACT}:KeyKey.db",
    f"/Library/Application Support/KeyKey/{ACT}/KeyKey.db",
    f"{ACT}/KeyKey.db",
]
for e in extra:
    if e not in cands:
        cands.insert(0, e)

files = list(OUT_DIR.glob('*'))
if not files:
    print('no files in cerod_out')
    sys.exit(1)

found = []
for f in files:
    data = f.read_bytes()
    for s in cands:
        idx = data.find(s.encode('utf-8'))
        if idx != -1:
            found.append((f.name, s, idx))

if found:
    for f, s, idx in found:
        print(f'FOUND in {f}: "{s}" at {idx}')
else:
    print('no candidates found in cerod_out files')
