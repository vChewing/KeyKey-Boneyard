#!/usr/bin/env python3
"""
Yahoo! 奇摩輸入法 (KeyKey) 使用者資料庫解密工具

此工具可解密 SmartMandarinUserData.db 等使用 SQLite SEE AES-128 加密的資料庫。

加密方式分析：
- 使用 SQLite SEE (SQLite Encryption Extension) with AES-128
- 檔案名稱：sqlite3-cerod-see-aes128-ccm-combined.c
- Page size: 1024 bytes
- Reserved bytes per page: 32 bytes (16 bytes nonce + 16 bytes MAC)
- 加密範圍：每頁的前 992 bytes (data area)
- Page 1 的 bytes 16-23 是未加密的 (SQLite header 格式資訊)

Keystream 產生方式：
- AES-128-ECB(key, counter_block)
- counter_block 結構：nonce 的副本，但 bytes 4-7 是 4-byte little-endian counter
- Counter 從 nonce[4:8] 的原始值開始，每個 16-byte block 遞增 1

密碼：yahookeykeyuserd (17 bytes 的前 16 bytes)
"""

import sys
import struct
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("錯誤：需要安裝 pycryptodome")
    print("請執行：pip3 install pycryptodome")
    sys.exit(1)


# AES-128 key (前 16 bytes of "yahookeykeyuserdb")
KEY = b'yahookeykeyuserd'

PAGE_SIZE = 1024
RESERVED_BYTES = 32
DATA_AREA_SIZE = PAGE_SIZE - RESERVED_BYTES  # 992 bytes


# ============================================================================
# BPMF (注音符號) 解碼器
# 基於 Formosa/Mandarin.cpp 的 BopomofoSyllable 類別
# ============================================================================

class BPMF:
    """注音符號 (Bopomofo) 音節類別"""
    
    # Masks
    ConsonantMask = 0x001f     # 0000 0000 0001 1111, 21 consonants
    MiddleVowelMask = 0x0060   # 0000 0000 0110 0000, 3 middle vowels
    VowelMask = 0x0780         # 0000 0111 1000 0000, 13 vowels
    ToneMarkerMask = 0x3800    # 0011 1000 0000 0000, 5 tones
    
    # Consonants (聲母)
    B = 0x0001; P = 0x0002; M = 0x0003; F = 0x0004
    D = 0x0005; T = 0x0006; N = 0x0007; L = 0x0008
    G = 0x0009; K = 0x000a; H = 0x000b
    J = 0x000c; Q = 0x000d; X = 0x000e
    ZH = 0x000f; CH = 0x0010; SH = 0x0011; R = 0x0012
    Z = 0x0013; C = 0x0014; S = 0x0015
    
    # Middle vowels (介音)
    I = 0x0020; U = 0x0040; UE = 0x0060
    
    # Vowels (韻母)
    A = 0x0080; O = 0x0100; ER = 0x0180; E = 0x0200
    AI = 0x0280; EI = 0x0300; AO = 0x0380; OU = 0x0400
    AN = 0x0480; EN = 0x0500; ANG = 0x0580; ENG = 0x0600
    ERR = 0x0680
    
    # Tones (聲調)
    Tone1 = 0x0000; Tone2 = 0x0800; Tone3 = 0x1000; Tone4 = 0x1800; Tone5 = 0x2000
    
    # Component to Unicode character mapping
    COMPONENT_TO_CHAR = {
        0x0001: 'ㄅ', 0x0002: 'ㄆ', 0x0003: 'ㄇ', 0x0004: 'ㄈ',
        0x0005: 'ㄉ', 0x0006: 'ㄊ', 0x0007: 'ㄋ', 0x0008: 'ㄌ',
        0x0009: 'ㄍ', 0x000a: 'ㄎ', 0x000b: 'ㄏ',
        0x000c: 'ㄐ', 0x000d: 'ㄑ', 0x000e: 'ㄒ',
        0x000f: 'ㄓ', 0x0010: 'ㄔ', 0x0011: 'ㄕ', 0x0012: 'ㄖ',
        0x0013: 'ㄗ', 0x0014: 'ㄘ', 0x0015: 'ㄙ',
        0x0020: 'ㄧ', 0x0040: 'ㄨ', 0x0060: 'ㄩ',
        0x0080: 'ㄚ', 0x0100: 'ㄛ', 0x0180: 'ㄜ', 0x0200: 'ㄝ',
        0x0280: 'ㄞ', 0x0300: 'ㄟ', 0x0380: 'ㄠ', 0x0400: 'ㄡ',
        0x0480: 'ㄢ', 0x0500: 'ㄣ', 0x0580: 'ㄤ', 0x0600: 'ㄥ',
        0x0680: 'ㄦ',
        0x0800: 'ˊ', 0x1000: 'ˇ', 0x1800: 'ˋ', 0x2000: '˙',
    }
    
    def __init__(self, syllable: int = 0):
        self.syllable = syllable
    
    @classmethod
    def from_absolute_order(cls, order: int) -> 'BPMF':
        """從 absolute order 值重建 BPMF 音節"""
        syllable = (
            (order % 22) |                          # Consonant
            ((order // 22) % 4) << 5 |              # Middle vowel
            ((order // (22 * 4)) % 14) << 7 |       # Vowel
            ((order // (22 * 4 * 14)) % 5) << 11    # Tone
        )
        return cls(syllable)
    
    @classmethod
    def from_absolute_order_string(cls, s: str) -> 'BPMF':
        """從 2-char absolute order 字串重建 BPMF 音節
        
        編碼方式: 79 進位制，用 ASCII 48-126 表示
        order = (high - 48) * 79 + (low - 48)
        """
        if len(s) != 2:
            return cls()
        order = (ord(s[1]) - 48) * 79 + (ord(s[0]) - 48)
        return cls.from_absolute_order(order)
    
    def composed_string(self) -> str:
        """將 BPMF 音節轉換為 Unicode 注音符號字串"""
        result = ''
        
        # Consonant
        consonant = self.syllable & self.ConsonantMask
        if consonant in self.COMPONENT_TO_CHAR:
            result += self.COMPONENT_TO_CHAR[consonant]
        
        # Middle vowel
        middle = self.syllable & self.MiddleVowelMask
        if middle in self.COMPONENT_TO_CHAR:
            result += self.COMPONENT_TO_CHAR[middle]
        
        # Vowel
        vowel = self.syllable & self.VowelMask
        if vowel in self.COMPONENT_TO_CHAR:
            result += self.COMPONENT_TO_CHAR[vowel]
        
        # Tone (只輸出 2-5 聲，一聲不標)
        tone = self.syllable & self.ToneMarkerMask
        if tone in self.COMPONENT_TO_CHAR:
            result += self.COMPONENT_TO_CHAR[tone]
        
        return result


def decode_qstring(qstring: str) -> str:
    """將資料庫中的 qstring 解碼為注音符號
    
    格式1 (unigram): 連續的 2-char absolute order 字串，每 2 個字元代表一個注音音節
    格式2 (bigram):  "~{前字注音2char} {當前字注音2char}"，用空格分隔
    """
    def decode_syllables(s: str) -> list:
        """解碼連續的 2-char 音節"""
        result = []
        for i in range(0, len(s), 2):
            if i + 2 <= len(s):
                abs_str = s[i:i+2]
                bpmf = BPMF.from_absolute_order_string(abs_str)
                composed = bpmf.composed_string()
                if composed:
                    result.append(composed)
        return result
    
    # 處理 bigram 格式: "~{abs2} {abs2}"
    if qstring.startswith('~'):
        parts = qstring[1:].split(' ')
        decoded_parts = []
        for p in parts:
            syllables = decode_syllables(p)
            if syllables:
                decoded_parts.append(''.join(syllables))
        return ' → '.join(decoded_parts)
    
    # 處理 unigram 格式
    if len(qstring) % 2 != 0:
        return qstring  # 無法解碼
    
    syllables = decode_syllables(qstring)
    return ','.join(syllables) if syllables else qstring


# ============================================================================
# 資料庫解密功能
# ============================================================================

def decrypt_page(page: bytes, page_num: int) -> bytes:
    """
    解密單一頁面
    
    Args:
        page: 1024 bytes 的加密頁面
        page_num: 頁面編號 (0-based)
    
    Returns:
        992 bytes 的解密資料
    """
    if len(page) != PAGE_SIZE:
        raise ValueError(f"Page size must be {PAGE_SIZE}, got {len(page)}")
    
    # Nonce 是頁面的最後 16 bytes
    nonce = page[-16:]
    
    cipher = AES.new(KEY, AES.MODE_ECB)
    
    decrypted = bytearray()
    num_blocks = (DATA_AREA_SIZE + 15) // 16  # 62 blocks
    
    # Counter 是 4 bytes，little-endian，位於 nonce 的 bytes 4-7
    base_counter = int.from_bytes(nonce[4:8], 'little')
    
    for block_idx in range(num_blocks):
        # 建構 counter block
        counter_block = bytearray(nonce)
        new_counter = (base_counter + block_idx) & 0xFFFFFFFF
        counter_block[4:8] = new_counter.to_bytes(4, 'little')
        
        # 產生 keystream
        keystream = cipher.encrypt(bytes(counter_block))
        
        # XOR 解密
        start = block_idx * 16
        end = min(start + 16, DATA_AREA_SIZE)
        enc_block = page[start:end]
        
        dec_block = bytes(a ^ b for a, b in zip(enc_block, keystream[:len(enc_block)]))
        decrypted.extend(dec_block)
    
    return bytes(decrypted[:DATA_AREA_SIZE])


def decrypt_database(input_path: Path, output_path: Path) -> None:
    """
    解密整個 SQLite 資料庫
    
    Args:
        input_path: 加密資料庫路徑
        output_path: 輸出解密資料庫路徑
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    
    if len(data) % PAGE_SIZE != 0:
        raise ValueError(f"Database size ({len(data)}) is not a multiple of page size ({PAGE_SIZE})")
    
    num_pages = len(data) // PAGE_SIZE
    print(f"解密 {input_path}")
    print(f"  檔案大小: {len(data)} bytes")
    print(f"  頁面數量: {num_pages}")
    
    output = bytearray()
    
    for page_num in range(num_pages):
        page = data[page_num * PAGE_SIZE:(page_num + 1) * PAGE_SIZE]
        dec_data = decrypt_page(page, page_num)
        
        if page_num == 0:
            # Page 0 特殊處理：bytes 16-23 是未加密的
            output.extend(dec_data[:16])           # 解密的 SQLite header
            output.extend(page[16:24])             # 未加密的格式資訊
            output.extend(dec_data[24:])           # 解密的其餘資料
        else:
            output.extend(dec_data)
        
        # Reserved area 填充零
        output.extend(bytes(RESERVED_BYTES))
    
    with open(output_path, 'wb') as f:
        f.write(output)
    
    print(f"  輸出: {output_path}")
    print("  完成！")


def show_decoded_data(db_path: Path) -> None:
    """顯示解密資料庫中的資料（含注音解碼）"""
    try:
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        print("\n=== 使用者單字詞 (user_unigrams) ===")
        cursor.execute("SELECT qstring, current, probability FROM user_unigrams")
        for row in cursor.fetchall():
            qstring, current, probability = row
            bopomofo = decode_qstring(qstring)
            print(f"  {current}\t{bopomofo}\t({probability})")
        
        print("\n=== 使用者雙字詞快取 (user_bigram_cache) ===")
        cursor.execute("SELECT qstring, previous, current FROM user_bigram_cache LIMIT 10")
        for row in cursor.fetchall():
            qstring, previous, current = row
            bopomofo = decode_qstring(qstring)
            print(f"  {previous}→{current}\t{bopomofo}")
        
        conn.close()
    except Exception as e:
        print(f"無法讀取資料: {e}")


def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <encrypted_db> [output_db]")
        print()
        print("範例:")
        print(f"  {sys.argv[0]} SmartMandarinUserData.db decrypted.db")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"錯誤：找不到檔案 {input_path}")
        sys.exit(1)
    
    if len(sys.argv) >= 3:
        output_path = Path(sys.argv[2])
    else:
        output_path = input_path.with_suffix('.decrypted.db')
    
    decrypt_database(input_path, output_path)
    
    # 顯示解密後的資料（含注音解碼）
    show_decoded_data(output_path)


if __name__ == '__main__':
    main()
