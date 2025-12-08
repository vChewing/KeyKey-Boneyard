#!/usr/bin/env python3
"""
解析 KimoOfficialOutputDataText.txt 匯出檔案

此工具可以解析 Yahoo! 奇摩輸入法 (KeyKey) 匯出的使用者詞庫檔案。

檔案格式：
- Header: "MJSR version 1.0.0"
- 使用者單字詞: 每行一筆 (word\treading\tprobability\tbackoff)
- 註解行: 以 # 開頭
- <database> block: 加密的 SQLite 資料庫 (user_bigram_cache + user_candidate_override_cache)

加密方式：
- SQLite SEE AES-128-CCM
- 密鑰: "mjsrexportmjsrex" (重複填充到16 bytes)
"""

import sqlite3
import tempfile
import os
import sys
from pathlib import Path
from Crypto.Cipher import AES

# 從 decrypt_userdb_final 匯入注音解碼功能
from decrypt_userdb_final import decode_query_string

# 常量
PAGE_SIZE = 1024
RESERVED_BYTES = 32  # 16 nonce + 16 MAC
DATA_AREA_SIZE = PAGE_SIZE - RESERVED_BYTES
EXPORT_KEY = b'mjsrexportmjsrex'  # 重複填充到 16 bytes


def decrypt_page(page: bytes, key: bytes = EXPORT_KEY, page_number: int = 0) -> bytes:
    """解密單個頁面
    
    page_number: 頁碼 (0-based)。Page 1 (index 0) 有特殊處理：
    - bytes 0-15: 加密 (SQLite format 3\0)
    - bytes 16-23: 明文 (SQLite header 格式資訊)
    - bytes 24-991: 加密
    """
    if len(page) != PAGE_SIZE:
        raise ValueError(f"Invalid page size: {len(page)}")
    
    # 最後 16 bytes 是 nonce
    nonce = page[-16:]
    
    # 建立 AES ECB cipher
    cipher = AES.new(key, AES.MODE_ECB)
    
    # 對於 page 1，bytes 16-23 是明文
    if page_number == 0:
        decrypted = bytearray(page[:DATA_AREA_SIZE])
        base_counter = int.from_bytes(nonce[4:8], 'little')
        
        for block_idx in range(DATA_AREA_SIZE // 16):
            counter = base_counter + block_idx
            counter_bytes = bytearray(nonce)
            counter_bytes[4:8] = (counter & 0xFFFFFFFF).to_bytes(4, 'little')
            keystream = cipher.encrypt(bytes(counter_bytes))
            
            if block_idx == 0:
                # Block 0: 全部解密
                for i in range(16):
                    decrypted[i] = page[i] ^ keystream[i]
            elif block_idx == 1:
                # Block 1: bytes 16-23 保持明文，bytes 24-31 解密
                for i in range(8, 16):
                    decrypted[16 + i] = page[16 + i] ^ keystream[i]
            else:
                # 其他 blocks: 全部解密
                start = block_idx * 16
                for i in range(16):
                    decrypted[start + i] = page[start + i] ^ keystream[i]
        
        decrypted.extend(b'\x00' * RESERVED_BYTES)
        return bytes(decrypted)
    else:
        # 其他頁面：全部解密
        decrypted = bytearray()
        base_counter = int.from_bytes(nonce[4:8], 'little')
        
        for block_idx in range(DATA_AREA_SIZE // 16):
            counter = base_counter + block_idx
            counter_bytes = bytearray(nonce)
            counter_bytes[4:8] = (counter & 0xFFFFFFFF).to_bytes(4, 'little')
            keystream = cipher.encrypt(bytes(counter_bytes))
            
            encrypted_block = page[block_idx * 16:(block_idx + 1) * 16]
            decrypted_block = bytes(a ^ b for a, b in zip(encrypted_block, keystream))
            decrypted.extend(decrypted_block)
        
        decrypted.extend(b'\x00' * RESERVED_BYTES)
        return bytes(decrypted)


def decrypt_database(encrypted_data: bytes) -> bytes:
    """解密整個資料庫"""
    num_pages = len(encrypted_data) // PAGE_SIZE
    decrypted = bytearray()
    
    for page_idx in range(num_pages):
        page = encrypted_data[page_idx * PAGE_SIZE:(page_idx + 1) * PAGE_SIZE]
        decrypted.extend(decrypt_page(page, page_number=page_idx))
    
    # 清除 SQLite header 中的 reserved bytes 設定 (offset 20)
    decrypted[20] = 0
    
    return bytes(decrypted)


def parse_export_file(filepath: str, verbose: bool = False):
    """解析 KeyKey 匯出檔案"""
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    
    # 檢查 header
    if not lines[0].startswith('MJSR version'):
        print(f'警告：檔案不是標準 MJSR 格式')
    else:
        print(f'✓ 檔案格式: {lines[0]}')
    
    # 解析使用者單字詞
    unigrams = []
    for line in lines[1:]:
        if line.startswith('#') or line.startswith('<'):
            break
        if '\t' in line:
            parts = line.split('\t')
            if len(parts) >= 4:
                word, reading, prob, backoff = parts[0], parts[1], parts[2], parts[3]
                unigrams.append((word, reading, prob, backoff))
    
    print(f'\n=== 使用者單字詞 (user_unigrams) ===')
    print(f'共 {len(unigrams)} 筆')
    if verbose and unigrams:
        for word, reading, prob, _ in unigrams[:20]:
            print(f'  {word}\t{reading}\t{prob}')
        if len(unigrams) > 20:
            print(f'  ... (還有 {len(unigrams) - 20} 筆)')
    
    # 解析 database block
    start = content.find('<database>')
    if start == -1:
        print('\n沒有找到 <database> block')
        return
    
    start = start + len('<database>')
    end = content.find('</database>')
    hex_data = content[start:end].strip().replace('\n', '')
    
    if not hex_data:
        print('\n<database> block 是空的')
        return
    
    encrypted_data = bytes.fromhex(hex_data)
    print(f'\n=== 自動學習資料庫 (database block) ===')
    print(f'加密資料: {len(encrypted_data)} bytes ({len(encrypted_data) // PAGE_SIZE} pages)')
    print(f'密鑰: {EXPORT_KEY.decode()}')
    
    # 解密
    decrypted_data = decrypt_database(encrypted_data)
    
    # 驗證 header
    if decrypted_data[:16] != b'SQLite format 3\x00':
        print(f'✗ SQLite header 驗證失敗')
        return
    
    print(f'✓ SQLite header 驗證成功')
    
    # 寫入臨時檔案並讀取
    temp_db = tempfile.mktemp(suffix='.db')
    try:
        with open(temp_db, 'wb') as f:
            f.write(decrypted_data)
        
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        # 讀取 user_bigram_cache
        print('\n=== 使用者雙字詞快取 (user_bigram_cache) ===')
        try:
            cursor.execute('SELECT COUNT(*) FROM user_bigram_cache')
            count = cursor.fetchone()[0]
            print(f'共 {count} 筆')
            
            if verbose:
                cursor.execute('SELECT qstring, previous, current, probability FROM user_bigram_cache')
                for row in cursor.fetchall():
                    qstring, previous, current, prob = row
                    # bigram 的 qstring 格式是 "{前字注音} {當前字注音}"
                    # 需要加上 ~ 前綴讓 decode_query_string 識別為 bigram 格式
                    if ' ' in qstring:
                        bopomofo = decode_query_string('~' + qstring)
                    else:
                        bopomofo = decode_query_string(qstring)
                    print(f'  {previous}→{current}\t{bopomofo}\t{prob}')
        except sqlite3.DatabaseError as e:
            print(f'  讀取錯誤: {e}')
        
        # 讀取 user_candidate_override_cache
        print('\n=== 使用者候選詞覆蓋快取 (user_candidate_override_cache) ===')
        try:
            cursor.execute('SELECT COUNT(*) FROM user_candidate_override_cache')
            count = cursor.fetchone()[0]
            print(f'共 {count} 筆')
            
            if verbose:
                cursor.execute('SELECT qstring, current FROM user_candidate_override_cache')
                for row in cursor.fetchall():
                    qstring, current = row
                    bopomofo = decode_query_string(qstring)
                    print(f'  {current}\t{bopomofo}')
        except sqlite3.DatabaseError as e:
            print(f'  讀取錯誤: {e}')
        
        conn.close()
    finally:
        if os.path.exists(temp_db):
            os.unlink(temp_db)


def main():
    if len(sys.argv) < 2:
        # 預設使用 KimoOfficialOutputDataText.txt
        filepath = 'KimoOfficialOutputDataText.txt'
        if not Path(filepath).exists():
            print(f'用法: {sys.argv[0]} <export_file.txt> [-v]')
            print()
            print('範例:')
            print(f'  {sys.argv[0]} KimoOfficialOutputDataText.txt')
            print(f'  {sys.argv[0]} KimoOfficialOutputDataText.txt -v  # 詳細輸出')
            sys.exit(1)
    else:
        filepath = sys.argv[1]
    
    verbose = '-v' in sys.argv or '--verbose' in sys.argv
    
    if not Path(filepath).exists():
        print(f'錯誤：找不到檔案 {filepath}')
        sys.exit(1)
    
    parse_export_file(filepath, verbose)


if __name__ == '__main__':
    main()
