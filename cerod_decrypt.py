#!/usr/bin/env python3
"""
CEROD preliminary decrypter/prober

- Parses CEROD header (big-endian): page_size (4), n_chunks (4), then n_offsets (4*n)
- For each chunk: expects layout where IV sits at bytes [12:28], encrypted payload at [28:]
- Uses AES-128-OFB with key = first 16 bytes of passphrase (caller must provide)
- Writes per-chunk decrypted payloads and a combined decrypted payload file.
- Attempts to detect and progressively decompress zlib streams found in the combined stream.

This is a probing tool intended to reproduce CEROD decryption steps enough
for manual analysis and later port of full CEROD behavior. It is not a
full replacement of the official CEROD library.
"""

import sys
import struct
from pathlib import Path
from Crypto.Cipher import AES
import zlib


def parse_header(buf):
    if len(buf) < 8:
        raise ValueError('buffer too small')
    page_size = struct.unpack('>I', buf[0:4])[0]
    n = struct.unpack('>I', buf[4:8])[0]
    offsets = []
    off_start = 8
    for i in range(n):
        idx = off_start + 4 * i
        if idx + 4 > len(buf):
            break
        offsets.append(struct.unpack('>I', buf[idx:idx+4])[0])
    return page_size, n, offsets


def decrypt_chunk(chunk_bytes, key_bytes):
    # minimal probing: assume iv is at bytes 12..28, encrypted payload thereafter
    if len(chunk_bytes) < 28:
        return None, None
    iv = chunk_bytes[12:28]
    enc = chunk_bytes[28:]
    cipher = AES.new(key_bytes, AES.MODE_OFB, iv=iv)
    dec = cipher.decrypt(enc)
    return iv, dec


def try_inflate_stream(stream_bytes, out_path):
    # attempt to find a zlib stream and inflate from there.
    zpos = stream_bytes.find(b"\x78\x9c")
    if zpos == -1:
        return False, 'no zlib header found'
    try:
        # try whole-stream decompress
        out = zlib.decompress(stream_bytes[zpos:])
        Path(out_path).write_bytes(out)
        return True, f'decompressed len={len(out)} from pos={zpos}'
    except Exception as e:
        # try streaming/incremental and report progress
        d = zlib.decompressobj()
        out = bytearray()
        try:
            out.extend(d.decompress(stream_bytes[zpos:]))
            out.extend(d.flush())
            Path(out_path).write_bytes(out)
            return True, f'incremental decompressed len={len(out)} from pos={zpos}'
        except Exception as e2:
            return False, f'decompress failed: {e} / {e2}'


def try_inflate_chunk(dec_bytes, idx, out_dir, max_window=65536, step=1024):
    """Try to locate a zlib stream inside a single decrypted chunk and inflate
    using a limited look-ahead window to avoid expensive brute-force scans.
    If successful, write an output file `chunk_<idx>.infl`.
    """
    zpos = dec_bytes.find(b"\x78\x9c")
    if zpos == -1:
        return False, 'no zlib header in chunk'

    # Try small growing windows up to max_window bytes
    max_end = min(len(dec_bytes), zpos + max_window)
    for end in range(zpos + 64, max_end + 1, step):
        try:
            out = zlib.decompress(dec_bytes[zpos:end])
            out_path = Path(out_dir) / f'chunk_{idx:05d}.infl'
            out_path.write_bytes(out)
            return True, f'decompressed len={len(out)} using end={end} (zpos={zpos})'
        except Exception:
            continue

    # Try incremental streaming but limited size
    try:
        d = zlib.decompressobj()
        out = bytearray()
        feed_end = min(len(dec_bytes), zpos + max_window)
        out.extend(d.decompress(dec_bytes[zpos:feed_end]))
        out.extend(d.flush())
        if out:
            out_path = Path(out_dir) / f'chunk_{idx:05d}.infl'
            out_path.write_bytes(out)
            return True, f'incremental decompressed len={len(out)} from zpos={zpos}'
    except Exception:
        pass

    return False, 'no viable zlib stream found within window'


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: cerod_decrypt.py <cerod-file> <passphrase>')
        sys.exit(1)

    fpath = Path(sys.argv[1])
    passphrase = sys.argv[2].encode('utf-8')

    if not fpath.exists():
        print('file not found:', fpath)
        sys.exit(1)

    key = passphrase[:16]
    data = fpath.read_bytes()

    page_size, n, offsets = parse_header(data)
    print(f'parsed header: page_size={page_size}, n={n}, offsets_read={len(offsets)}')

    # ensure we have offsets for all chunks
    if len(offsets) < 2:
        print('insufficient offsets parsed, aborting')
        sys.exit(1)

    out_dir = Path('cerod_out')
    out_dir.mkdir(exist_ok=True)

    combined = bytearray()
    # decrypt each chunk, save decrypted to disk
    for i in range(len(offsets)-1):
        start = offsets[i]
        end = offsets[i+1]
        chunk = data[start:end]
        iv, dec = decrypt_chunk(chunk, key)
        if dec is None:
            print(f'chunk {i} too small, skipping')
            continue
        Path(out_dir / f'chunk_{i:05d}.dec').write_bytes(dec)
        combined.extend(dec)

        # Try to decompress locally in a safe, limited way
        ok, msg = try_inflate_chunk(dec, i, out_dir)
        if ok:
            print(f'chunk {i}: inflated -> {msg}')
        else:
            # keep brief status to avoid huge logs
            if i < 20 or i % 500 == 0:
                print(f'chunk {i}: no local inflate ({msg})')
        if i % 1000 == 0 and i:
            print(f'processed {i} chunks...')

    Path(out_dir / 'combined.dec').write_bytes(combined)
    print('wrote combined.dec size', len(combined))

    ok, msg = try_inflate_stream(bytes(combined), out_dir / 'cerod_inflated.db')
    print('inflate attempt:', ok, msg)

    print('done. check', out_dir)
