#!/usr/bin/env python3
"""
Extract user database key from development source code using RSA decryption.

Based on:
- DevUserDBKeyPhrase.c: RSA encrypted data + masks  
- DevPublicKey.c: VendorMotcle (PEM public key)
- SQLiteCryptoInit.cpp: ObtenirUserDonneCle() uses Minos::GetBack with same pubkey
"""

import re
import subprocess
import tempfile
import os

# Masks from DevUserDBKeyPhrase.c:
UserDonneCleSizeMask1 = 0x7e84656f
UserDonneCleSizeMask2 = 0x81599bc5
UserDonneCleOffsetMask1 = 0x215d8743
UserDonneCleOffsetMask2 = 0x8b8073c5

# Macros from SQLiteCryptoInit.cpp
def real_offset(p, q):
    return (q ^ (p ^ 0xaaddffff)) & 0xffffffff

def real_size(p, q):
    return (q ^ (p ^ 0xffddffaa)) & 0xffffffff


def parse_c_array(filepath, var_name):
    """Parse C array from source file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    pattern = rf'char {var_name}\[\d+\]\s*=\s*\{{([^}}]+)\}};'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return None
    
    array_content = match.group(1)
    bytes_list = []
    for val in re.findall(r'0x([0-9a-fA-F]+)', array_content):
        bytes_list.append(int(val, 16))
    
    return bytes(bytes_list)


def rsa_public_decrypt(pubkey_pem: bytes, encrypted_data: bytes) -> bytes:
    """
    Perform RSA public decrypt (decrypt data encrypted with private key).
    This is signature verification mode - data was "signed" with private key.
    """
    # Write PEM key to temp file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
        f.write(pubkey_pem)
        pubkey_file = f.name
    
    # Write encrypted data to temp file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
        f.write(encrypted_data)
        enc_file = f.name
    
    output_file = tempfile.mktemp(suffix='.bin')
    
    try:
        # Use openssl rsautl to decrypt with public key
        # -pubin: input is public key
        # -inkey: key file
        # -in: encrypted input
        # -out: decrypted output
        result = subprocess.run([
            'openssl', 'rsautl', 
            '-verify',  # verify = decrypt with public key
            '-pubin',
            '-inkey', pubkey_file,
            '-in', enc_file,
            '-out', output_file,
            '-raw'  # No padding (or try without this)
        ], capture_output=True)
        
        if result.returncode != 0:
            # Try with PKCS#1 padding
            result = subprocess.run([
                'openssl', 'rsautl', 
                '-verify',
                '-pubin',
                '-inkey', pubkey_file,
                '-in', enc_file,
                '-out', output_file
            ], capture_output=True)
        
        if result.returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'rb') as f:
                return f.read()
        else:
            print(f"OpenSSL error: {result.stderr.decode()}")
            return None
            
    finally:
        for f in [pubkey_file, enc_file]:
            if os.path.exists(f):
                os.unlink(f)
        if os.path.exists(output_file):
            os.unlink(output_file)


def main():
    base_path = '/Users/shikisuen/Repos/KeyKey-Boneyard/YahooKeyKey-Source-1.1.2528/Distributions/Takao/Keyring/'
    
    # Calculate offset and size
    offset = real_offset(UserDonneCleOffsetMask1, UserDonneCleOffsetMask2)
    size = real_size(UserDonneCleSizeMask1, UserDonneCleSizeMask2)
    
    print(f"=== User Database Key Extraction ===")
    print(f"Calculated offset: {offset}")
    print(f"Calculated size: {size}")
    
    # Parse encrypted data
    encrypted_data = parse_c_array(base_path + 'DevUserDBKeyPhrase.c', 'UserDonneCle')
    if not encrypted_data:
        print("ERROR: Failed to parse UserDonneCle")
        return
    
    print(f"Total encrypted data: {len(encrypted_data)} bytes")
    
    # Extract RSA blob
    rsa_blob = encrypted_data[offset:offset+size]
    print(f"RSA blob: {len(rsa_blob)} bytes")
    print(f"First 32 bytes: {rsa_blob[:32].hex()}")
    
    # Get public key
    pubkey = parse_c_array(base_path + 'DevPublicKey.c', 'VendorMotcle')
    if not pubkey:
        print("ERROR: Failed to parse VendorMotcle")
        return
    
    print(f"\nPublic key (PEM):")
    print(pubkey.decode('ascii'))
    
    # RSA decrypt
    print("\nAttempting RSA public decrypt...")
    decrypted = rsa_public_decrypt(pubkey, rsa_blob)
    
    if decrypted:
        print(f"\n=== SUCCESS ===")
        print(f"Decrypted data ({len(decrypted)} bytes):")
        
        # Try to interpret as string
        try:
            passphrase = decrypted.rstrip(b'\x00').decode('utf-8')
            print(f"  As UTF-8 string: '{passphrase}'")
        except:
            print(f"  As hex: {decrypted.hex()}")
            # Find printable portion
            printable = bytes(b for b in decrypted if 32 <= b < 127)
            if printable:
                print(f"  Printable chars: '{printable.decode('ascii')}'")
    else:
        print("RSA decryption failed")
        
        # Try alternative: maybe the data needs to be reversed or padded differently
        print("\nTrying with reversed data...")
        decrypted = rsa_public_decrypt(pubkey, rsa_blob[::-1])
        if decrypted:
            print(f"Reversed worked: {decrypted.hex()}")


if __name__ == '__main__':
    main()
