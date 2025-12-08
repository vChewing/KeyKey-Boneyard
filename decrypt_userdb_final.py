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
# PhonaSet (注音符號) 解碼器
# 基於 KeyKeyUserDBKit/PhonaSet.swift
# ============================================================================

class PhonaSet:
    """注音符號 (Phonabet) 音節類別"""
    
    # Bit Masks (PhonaType)
    CONSONANT_MASK = 0x001F
    SEMIVOWEL_MASK = 0x0060
    VOWEL_MASK = 0x0780
    INTONATION_MASK = 0x3800
    
    # Consonant (聲母) - 21 個
    # ㄅ=0x0001, ㄆ=0x0002, ..., ㄙ=0x0015
    CONSONANT_SYMBOLS = {
        0x0001: 'ㄅ', 0x0002: 'ㄆ', 0x0003: 'ㄇ', 0x0004: 'ㄈ',
        0x0005: 'ㄉ', 0x0006: 'ㄊ', 0x0007: 'ㄋ', 0x0008: 'ㄌ',
        0x0009: 'ㄍ', 0x000A: 'ㄎ', 0x000B: 'ㄏ',
        0x000C: 'ㄐ', 0x000D: 'ㄑ', 0x000E: 'ㄒ',
        0x000F: 'ㄓ', 0x0010: 'ㄔ', 0x0011: 'ㄕ', 0x0012: 'ㄖ',
        0x0013: 'ㄗ', 0x0014: 'ㄘ', 0x0015: 'ㄙ',
    }
    
    # Semivowel (介音) - 3 個
    SEMIVOWEL_SYMBOLS = {
        0x0020: 'ㄧ',
        0x0040: 'ㄨ',
        0x0060: 'ㄩ',
    }
    
    # Vowel (韻母) - 13 個
    VOWEL_SYMBOLS = {
        0x0080: 'ㄚ',
        0x0100: 'ㄛ',
        0x0180: 'ㄜ',
        0x0200: 'ㄝ',
        0x0280: 'ㄞ',
        0x0300: 'ㄟ',
        0x0380: 'ㄠ',
        0x0400: 'ㄡ',
        0x0480: 'ㄢ',
        0x0500: 'ㄣ',
        0x0580: 'ㄤ',
        0x0600: 'ㄥ',
        0x0680: 'ㄦ',
    }
    
    # Intonation (聲調) - 5 種
    # 一聲 (ˉ) 不顯示
    INTONATION_SYMBOLS = {
        0x0000: None,   # 一聲（陰平）不標
        0x0800: 'ˊ',    # 二聲（陽平）
        0x1000: 'ˇ',    # 三聲（上聲）
        0x1800: 'ˋ',    # 四聲（去聲）
        0x2000: '˙',    # 輕聲
    }
    
    def __init__(self, syllable: int = 0):
        self.syllable = syllable
    
    @classmethod
    def from_absolute_order(cls, order: int) -> 'PhonaSet':
        """從 absolute order 值重建 PhonaSet 音節"""
        consonant = order % 22
        semivowel = ((order // 22) % 4) << 5
        vowel = ((order // (22 * 4)) % 14) << 7
        intonation = ((order // (22 * 4 * 14)) % 5) << 11
        return cls(consonant | semivowel | vowel | intonation)
    
    @classmethod
    def from_absolute_order_string(cls, s: str) -> 'PhonaSet':
        """從 2-char absolute order 字串重建 PhonaSet 音節
        
        編碼方式: 79 進位制，用 ASCII 48-126 表示
        order = (high - 48) * 79 + (low - 48)
        """
        if len(s) != 2:
            return cls()
        low = ord(s[0]) - 48
        high = ord(s[1]) - 48
        if not (0 <= low < 79 and 0 <= high < 79):
            return cls()
        order = high * 79 + low
        return cls.from_absolute_order(order)
    
    @property
    def raw_consonant(self) -> int:
        """取得聲母原始值"""
        return self.syllable & self.CONSONANT_MASK
    
    @property
    def raw_semivowel(self) -> int:
        """取得介音原始值"""
        return self.syllable & self.SEMIVOWEL_MASK
    
    @property
    def raw_vowel(self) -> int:
        """取得韻母原始值"""
        return self.syllable & self.VOWEL_MASK
    
    @property
    def raw_intonation(self) -> int:
        """取得聲調原始值"""
        return self.syllable & self.INTONATION_MASK
    
    def __str__(self) -> str:
        """將 PhonaSet 音節轉換為 Unicode 注音符號字串"""
        result = ''
        
        # Consonant (聲母)
        if self.raw_consonant in self.CONSONANT_SYMBOLS:
            result += self.CONSONANT_SYMBOLS[self.raw_consonant]
        
        # Semivowel (介音)
        if self.raw_semivowel in self.SEMIVOWEL_SYMBOLS:
            result += self.SEMIVOWEL_SYMBOLS[self.raw_semivowel]
        
        # Vowel (韻母)
        if self.raw_vowel in self.VOWEL_SYMBOLS:
            result += self.VOWEL_SYMBOLS[self.raw_vowel]
        
        # Intonation (聲調) - 一聲不標
        intonation_symbol = self.INTONATION_SYMBOLS.get(self.raw_intonation)
        if intonation_symbol:
            result += intonation_symbol
        
        return result


def decode_query_string(qstring: str) -> str:
    """將資料庫中的 qstring 解碼為注音符號
    
    格式1 (unigram): 連續的 2-char absolute order 字串，每 2 個字元代表一個注音音節
    格式2 (bigram):  "~{前字注音2char} {當前字注音2char}"，用空格分隔（必須包含空格）
    """
    def decode_syllables(s: str) -> list:
        """解碼連續的 2-char 音節"""
        if len(s) % 2 != 0:
            return []
        result = []
        for i in range(0, len(s), 2):
            abs_str = s[i:i+2]
            phona = PhonaSet.from_absolute_order_string(abs_str)
            composed = str(phona)
            if composed:
                result.append(composed)
        return result
    
    # 處理 bigram 格式: "~{abs2} {abs2}"（必須包含空格才算 bigram）
    if qstring.startswith('~') and ' ' in qstring:
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


# 為了向後相容，保留舊的函式名稱
def decode_qstring(qstring: str) -> str:
    """向後相容的別名"""
    return decode_query_string(qstring)


# 為了向後相容，保留舊的類別名稱
BPMF = PhonaSet


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
    import sqlite3
    
    abs_path = str(db_path.absolute())
    
    try:
        # 嘗試開啟資料庫
        conn = sqlite3.connect(abs_path)
        cursor = conn.cursor()
        
        # 顯示所有資料表
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"\n發現 {len(tables)} 個資料表: {', '.join(tables)}")
        
        # user_unigrams
        if 'user_unigrams' in tables:
            print("\n=== 使用者單字詞 (user_unigrams) ===")
            try:
                # 嘗試逐筆讀取以獲得準確數量
                cursor.execute("SELECT qstring, current, probability FROM user_unigrams")
                rows = []
                actual_count = 0
                while True:
                    try:
                        row = cursor.fetchone()
                        if row is None:
                            break
                        rows.append(row)
                        actual_count += 1
                    except sqlite3.DatabaseError:
                        break
                
                print(f"共 {actual_count} 筆資料")
                for row in rows[:20]:
                    qstring, current, probability = row
                    bopomofo = decode_qstring(qstring)
                    print(f"  {current}\t{bopomofo}\t({probability})")
                if actual_count > 20:
                    print(f"  ... (還有 {actual_count - 20} 筆)")
            except sqlite3.DatabaseError as e:
                print(f"  讀取 user_unigrams 時發生錯誤: {e}")
        
        # user_bigram_cache
        if 'user_bigram_cache' in tables:
            print("\n=== 使用者雙字詞快取 (user_bigram_cache) ===")
            try:
                cursor.execute("SELECT COUNT(*) FROM user_bigram_cache")
                count = cursor.fetchone()[0]
                print(f"共 {count} 筆資料")
                cursor.execute("SELECT qstring, previous, current FROM user_bigram_cache LIMIT 10")
                for row in cursor.fetchall():
                    qstring, previous, current = row
                    bopomofo = decode_qstring(qstring)
                    print(f"  {previous}→{current}\t{bopomofo}")
            except sqlite3.DatabaseError as e:
                print(f"  讀取 user_bigram_cache 時發生錯誤: {e}")
        
        # user_candidate_override_cache
        if 'user_candidate_override_cache' in tables:
            print("\n=== 使用者候選詞覆蓋快取 (user_candidate_override_cache) ===")
            try:
                cursor.execute("SELECT COUNT(*) FROM user_candidate_override_cache")
                count = cursor.fetchone()[0]
                print(f"共 {count} 筆資料")
                cursor.execute("SELECT * FROM user_candidate_override_cache LIMIT 10")
                for row in cursor.fetchall():
                    print(f"  {row}")
            except sqlite3.DatabaseError as e:
                print(f"  讀取 user_candidate_override_cache 時發生錯誤: {e}")
        
        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"資料庫可能有完整性問題，嘗試使用恢復模式...")
        try:
            # 使用 recover 模式（Python 3.11+）
            import subprocess
            result = subprocess.run(
                ['sqlite3', abs_path, '.mode column', 
                 'SELECT qstring, current, probability FROM user_unigrams LIMIT 20;'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                print("\n=== 使用者單字詞 (user_unigrams, 透過 sqlite3 CLI) ===")
                print(result.stdout)
            else:
                print(f"sqlite3 CLI 也無法讀取: {result.stderr}")
        except Exception as fallback_e:
            print(f"恢復模式也失敗: {fallback_e}")
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
