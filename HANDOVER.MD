# Handover Report — CEROD / SmartMandarinUserData.db Investigation

日期: 2025-12-07

維護者/承接者: 新 AI / 開發者

> 該專案因 CEROD 開始收費的原因而在2012年被官方停止開發、產品取消。目前最後一個公版 Executable 對 macOS 的支援僅限 Intel (Universal Binary Gen 1)。而 2026 年底 macOS 27 會徹底放棄對 Universal Binary Gen 2 的支援，屆時 macOS 系統下的奇摩輸入法使用者們將再無機會取出自己的使用者片語（奇摩輸入法的使用者辭典程式從 macOS 10.9 Mavericks 開始就罷工了）。
>
> 目前的考量：對最後一個公版 Executable 做逆向工程、以圖取出對 SmartMandarinUserData.db 的解讀部分。

---

## 1) 任務簡述
目標：從最後一個公版 macOS Executable（`KeyKey-Executable-Darwin.exe`，Universal Binary Gen 1）尋找 CEROD/SQLite 的金鑰/加解密流程，並嘗試解密 `SmartMandarinUserData.db`。該 DB 用 DB Browser for SQLite 開啟時被提示為「已加密」。

此 repo 包含 OpenVanilla/Takao 專案的原始碼，顯示有 CEROD/SEE（sqlite-cerod-see）支援、`DevUserDBKeyPhrase.c`（dev key）以及 `Minos::GetBack()` 用於從嵌入的資料生成 passphrase 的邏輯。

---

## 2) 目前狀態與主要發現（摘要）
- 你已將 `KeyKey-Executable-Darwin.exe` 複製到 repo 根目錄並使用 `lipo -thin` 把 x86_64 slice 輸出為 `KeyKey-Executable-Darwin-x86_64.exe`。
	- 為了節約空間，原始的 fat binary 已經移除。接下來的工作僅需要 `KeyKey-Executable-Darwin-x86_64.exe` 這一個 Executable 作為分析對象。該檔案存放在 `./EXE-And-FactoryDB/` 目錄下。
- 靜態檢查（`otool -L`）顯示 binary 連結了 `/usr/lib/libcrypto.0.9.7.dylib`（OpenSSL），因此 openssl 函式如 `PEM_read_bio_RSA_PUBKEY`、`RSA_public_decrypt` 可用於抽取/解密操作。
- 使用 `strings` 找到以下重要關鍵字：`KeyKey.db`, `:cerod:`, `cerod`, 以及 `-----BEGIN PUBLIC KEY-----`（PEM header），表示 binary 中包含 PEM 格式的公鑰。
- Repo 原始碼中 `Distributions/Takao/Keyring/SQLiteCryptoInit.cpp` 與 `Frameworks/Minotaur/Source/Minotaur.cpp` 顯示 `Minos::GetBack()` 使用 RSA public decrypt (OpenSSL) 邏輯來從 `VendorDonneCle` / `UserDonneCle` 裡恢復 passphrase，此 passphrase 在 loader 中用於 `:cerod:` 字串（`FetchSQLiteCERODKey`）或 `sqlite3_key`/`sqlite3_rekey` 調用。
- `Frameworks/Manjusri/Source/BPMFUserPhraseHelper.cpp` 和 `ModulePackages/OVIMMandarin/OVIMSmartMandarin.cpp` 中存在 `sqlite3_key` 調用（一些處理在 `#ifdef OVIMSMARTMANDARIN_USE_SQLITE_CRYPTO` 區塊），代表 user DB 的加密/解密邏輯在 source 內存在並可啟用。

---

## 3) 我已執行且可複現的命令（記錄）
> ***重要***：以下命令都是靜態/讀取型分析（非破壞）

1) 切出 x86_64 slice：
```bash
lipo -thin x86_64 KeyKey-Executable-Darwin.exe -output ./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe
```
該步驟已經完成。詳情請洽 `./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe`。

2) 檢查 binary 的動態連結庫：
```bash
otool -L ./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe
```
- 在輸出中看到 `/usr/lib/libcrypto.0.9.7.dylib`，表示 OpenSSL 存在，能用 openssl 對 PEM/encoded block 做處理。

3) 搜尋 strings：
```bash
strings -a ./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe | egrep -i 'cerod|:cerod:|BEGIN PUBLIC KEY|BEGIN RSA PUBLIC KEY'
```
- 輸出包含 `KeyKey.db`, `:cerod:`, `cerod` 以及 `-----BEGIN PUBLIC KEY-----`。

4) 若要查 offsets（可使用此流程）、導出 PEM 與 encoded block：
```bash
strings -a -t x ./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe | egrep -i 'BEGIN PUBLIC KEY|END PUBLIC KEY' -n
# 使用 dd 將公鑰段以 offset 與 count 導出
# (將下面的 $start_dec $count 換為實際數值)
dd if=./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe of=pub.pem bs=1 skip=$start_dec count=$count
file pub.pem
```

5) 如果你能找到 encodedBlock 的 start/length：
```bash
# 將 encoded block 導出
dd if=./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe of=encoded.bin bs=1 skip=$encoded_start count=$encoded_len

# 使用 openssl 公鑰解密 (verify)
openssl rsautl -verify -inkey pub.pem -pubin -in encoded.bin -out decrypted.bin
cat decrypted.bin # 若為 passphrase 應可直接顯示或呈現明文字串
```

6) 如果得到 passphrase，你可以用 `sqlite3-cerod-see` 打開 DB：
```bash
./PrecompiledTools/sqlite3-cerod-see ":cerod:THE_PASSPHRASE:SmartMandarinUserData.db" ".tables"
```

---

## 4) 建議的接續工作（優先順序）
1) **靜態萃取** — 最先由 binary 中抽出所有 PEM/encoded bytes：
   - 用 `strings -a -t x` 找出 `BEGIN PUBLIC KEY` 的 hex offsets，並用 `dd` 導出 PEM。
   - 在 Hopper 或 Ghidra 中找 `Minos::GetBack`（或 `GetBack` 的呼叫），尋找 callers，記錄 encodedBlock pointer & size，並導出 encoded bytes。

2) **測試解密** — 用導出的 pub.pem 和 encoded.bin 用 openssl 進行公開解密（`rsautl -verify` / `pkeyutl`），檢查是否得到 passphrase。若得到請勿公開該 passphrase。

3) **用 passphrase 嘗試打開 DB** — 若 `sqlite3-cerod-see` 可用，嘗試 `:cerod:pass:SmartMandarinUserData.db` 看能否列出 tables 或讀出 user data。

4) **若靜態無法直接復原** — 進行動態調試（`lldb`）抓 `GetBack` 或 `sqlite3_key` 呼叫時的參數（只在有合法權限或所有權的情況下執行）：
   - set breakpoint at `GetBack`, `sqlite3_key` or `InitSQLiteCrypto`.
   - dump memory & registers to find passphrases.

5) **編譯/製作測試工具** — 建議建立一個小工具（Python + openssl 或快速 C++ 使用 OpenSSL lib）來反覆測試 decrypted outputs 與 CEROD DB。此工具應與 repo 中 `Minos::GetBack` 的輸出等價。

6) **如果你必須長期支援 Apple Silicon** — 盡可能從原始碼編譯 arm64 binary（或在 arm64 上 build libraries & tools），而非試圖「永久轉譯」Intel-only binary（自動 AOT 轉譯毫無可靠低成本方案）。

---

## 5) 如果你要交給其他 AI: 必需提供給接手者的資源
- Binary: thin `./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe`。
- DB: `SmartMandarinUserData.db`（原始加密版本）。
	- Sinica Corpus 資產 `./EXE-And-FactoryDB/KeyKey.db`（CEROD主DB）。
- Source: `YahooKeyKey-Source-1.1.2528`，關鍵檔案列表：
  - `Distributions/Takao/Keyring/SQLiteCryptoInit.cpp`
  - `Distributions/Takao/Keyring/DevUserDBKeyPhrase.c`
  - `Frameworks/Minotaur/Source/Minotaur.cpp`
  - `Frameworks/Manjusri/Source/BPMFUserPhraseHelper.cpp`
  - `ModulePackages/OVIMMandarin/OVIMSmartMandarin.cpp`
  - `Loaders/OSX-IMK/OpenVanillaLoader.mm`
  - `Loaders/OSX-IMK/OpenVanillaConfig.h` (檢查 `OPENVANILLA_CEROD_DATABASE_FILE`)
- Build tools: `PrecompiledTools/sqlite3-cerod-see` （若你要測試 CEROD），或 source for `cerod_build`。

---

## 6) 法遵與安全提醒（再次強調）
1) 請**確保你對該 DB 擁有合法權限**（歸你或已獲授權）。
2) 若發現 vendor 的 production key / private key（若被定位出來），切勿公開或分享；在處理這類私密資訊時請遵守當地法律與 EULA。
3) 若需要進行動態 attach/調試（可能會觸及 code signing 或 SIP），請在受控 VM/測試環境進行或先備份系統並確認法律授權。

---

## 7) 要我 / 新 AI 接手做的具體任務建議（可直接 pick 1 or more）
- A) 自動化：在此 repo 下撰寫自動化腳本 (Bash/Python) 做 static scan -> PEM extraction -> encodedBlock extraction -> openssl decryption -> sqlite open 流程。
- B) Hopper 指引：用 Hopper/Ghidra 深入追蹤 `Minos::GetBack` 的 call site，導出 data pointer，dump encoded block，並把步驟寫成一份交接文檔。
- C) 嘗試在一台 macOS x86_64（或 Rosetta 2）環境動態 attach binary 以抓取 passphrase（必須確認權限）。
- D) 嘗試用 repo 中 `DevUserDBKeyPhrase.c` 來 build測試版本，看看能否用 dev key 去解開 DB（如果 DB 為 dev key 加密）。

---

## 8) 聯絡 / 提問清單（提供給接手者）
- 你是否允許我或後續 AI 做動態 attach / debugging？（若否，請不要動態 attach）
- 是否準備好把被分析 binary 的薄片（x86_64）給我 (我已經在 repo root)?
- 是否希望會優先嘗試用 `DevUserDBKeyPhrase.c`？（有時 DB 可能使用 dev key 而非 vendor production key）

---

## 9) 我們目前尚未解密的事項（需後續確認）
- passphrase 是否可由 binary 直接（靜態）復原（取出 PEM + encoded block 解出 passphrase）？
- 若靜態解密失敗，是否授權用動態 attach + run-time memory dump？

---

## 10) 資料來源與參考文件
- `Distributions/Takao/DatabaseCooker/Makefile.SmartMandarin` — 生成 CEROD 数据庫 `KeyKey.db`
- `Distributions/Takao/Keyring/SQLiteCryptoInit.cpp` — `FetchSQLiteCERODKey()`, `InitSQLiteCrypto()` 和 `Minos::GetBack()` 调用
- `Frameworks/Minotaur/Source/Minotaur.cpp` — `GetBack`的 OpenSSL 邏輯
- `ModulePackages/OVIMMandarin/OVIMSmartMandarin.cpp` — user DB 尚有 rekey/attach KEY 的呼叫
- `Frameworks/Manjusri/Source/BPMFUserPhraseHelper.cpp` — 查看 `OpenUserPhraseDB()` 的資訊

---

如果你／接手 AI 想我直接幫忙執行下一步 （例如自動化腳本把 PEM 與 encoded 取出並嘗試解密），請回覆：
- "執行 A" (自動化脚本) 或
- "執行 B" (Hopper 路徑並抓 offset) 或
- "執行 C" (動態 attach for debug)，並事先確認你有權限（且已允許動態 attach）。

謝謝。 — 已完成 `HANDOVER.MD`。

---

## 11) 2025-12-07 新發現：Dev Key 解密邏輯完整分析

### 關鍵原始碼位置
- **公鑰**: `Distributions/Takao/Keyring/DevPublicKey.c` — `VendorMotcle[451]`（PEM 格式 RSA 公鑰）
- **加密的 User DB Key**: `Distributions/Takao/Keyring/DevUserDBKeyPhrase.c` — `UserDonneCle[4684]`

### Mask 計算公式（來自 SQLiteCryptoInit.cpp）
```c
#define REAL_OFFSET(p, q) (q ^ (p ^ 0xaaddffff))
#define REAL_SIZE(p, q) (q ^ (p ^ 0xffddffaa))
```

### DevUserDBKeyPhrase.c 中的 Mask 值
```c
UserDonneCleSizeMask1   = 0x7e84656f
UserDonneCleSizeMask2   = 0x81599bc5
UserDonneCleOffsetMask1 = 0x215d8743
UserDonneCleOffsetMask2 = 0x8b8073c5
```

### 計算實際 Offset 與 Size
```
REAL_OFFSET = 0x8b8073c5 ^ (0x215d8743 ^ 0xaaddffff)
            = 0x8b8073c5 ^ 0x8b8078bc
            = 0x00000b79  (十進制: 2937)

REAL_SIZE   = 0x81599bc5 ^ (0x7e84656f ^ 0xffddffaa)
            = 0x81599bc5 ^ 0x81599ac5
            = 0x00000100  (十進制: 256)
```

### 解密流程
1. 從 `UserDonneCle` 陣列的 offset 2937 開始，取 256 bytes
2. 用 `VendorMotcle`（PEM 公鑰）進行 RSA public decrypt
3. 解出的結果即為 `SmartMandarinUserData.db` 的 sqlite3_key

### 下一步
執行 Python 腳本：
1. 將 `VendorMotcle` 轉為 PEM 檔案
2. 從 `UserDonneCle[2937..2937+256]` 取出 encoded block
3. 使用 `openssl rsautl -verify -pubin` 或 Python cryptography 進行解密

---

## 12) 2025-12-07 解密成功！

### User DB Passphrase（已確認！）
```
yahookeykeyuserdb
```

### 驗證結果
從 Production 二進位檔 `./EXE-And-FactoryDB/KeyKey-Executable-Darwin-x86_64.exe` 中提取並驗證：
- 在二進位檔 offset `0x1aa879` 找到與 Dev 源碼相同的加密塊
- 使用 RSA public decrypt 成功解密得到 `yahookeykeyuserdb`
- **Production 版本使用與 Dev 相同的 passphrase！**

### 加密方式
User DB 使用 **SQLite SEE (Sqlite Encryption Extension)** 的 `sqlite3_key()` API。

### CEROD 激活碼
```
7bb07b8d471d642e
```

### 如何開啟 SmartMandarinUserData.db

#### 選項 1：使用支援 SEE 的 sqlite3（需商業授權）
```c
sqlite3_activate_cerod("7bb07b8d471d642e");
// 或
sqlite3_activate_see("7bb07b8d471d642e");

sqlite3 *db;
sqlite3_open("SmartMandarinUserData.db", &db);
sqlite3_key(db, "yahookeykeyuserdb", 17);
// 現在可以正常查詢
```

#### 選項 2：動態調試匯出資料
```bash
# 使用 lldb 在 sqlite3_key 設置斷點，等 KeyKey 開啟 DB 後匯出資料
arch -x86_64 lldb /Library/Input\ Methods/Yahoo!\ KeyKey.app/Contents/MacOS/...
```

#### 選項 3：從 KeyKey UI 匯出
如果 KeyKey.app 還能運行，可以從偏好設定中匯出使用者詞庫。

### ⚠️ 重要注意事項
- DB Browser for SQLite **不支援** SQLite SEE/CEROD（它只支援 SQLCipher）
- 標準 Python sqlite3 模組也**不支援** SEE
- 需要官方 SQLite SEE 商業版本或使用動態調試方式

---

## 13) 工具腳本

| 腳本 | 用途 |
|------|------|
| `decrypt_userdb_final.py` | **主要工具** - 解密 SmartMandarinUserData.db |
| `extract_user_key_v2.py` | 從原始碼提取 passphrase（參考用） |

---

## 14) 最終結論

### SmartMandarinUserData.db 的加密 KEY

| 項目 | 值 |
|------|-----|
| **Passphrase** | `yahookeykeyuserdb` |
| **長度** | 17 bytes |
| **CEROD/SEE 激活碼** | `7bb07b8d471d642e` |
| **加密類型** | SQLite SEE (商業版) |

### 解密原理
1. 二進位檔中包含 RSA 簽名過的 passphrase blob（UserDonneCle）
2. 同時包含 RSA 公鑰（VendorMotcle）
3. 使用 `RSA_public_decrypt()` 從簽名塊恢復原始 passphrase
4. 此 passphrase 傳遞給 `sqlite3_key()` 開啟加密資料庫

---

## 15) 2025-12-07 完整解密成功！

### 加密算法逆向工程成果

經過深入分析，成功逆向工程了 SQLite SEE 的加密實現：

#### 加密模式
- **算法**: AES-128 (來自 `sqlite3-cerod-see-aes128-ccm-combined.c`)
- **模式**: 類 CTR 模式 (不是標準 CCM)
- **Page size**: 1024 bytes
- **Reserved bytes**: 32 bytes per page (16 bytes nonce + 16 bytes MAC)

#### 頁面結構
```
Offset    Size    Description
0         992     加密的資料區域
992       16      MAC (Message Authentication Code)
1008      16      Nonce (用於生成 keystream)
```

**注意**: Page 0 的 bytes 16-23 是**未加密的** (SQLite header 格式資訊)

#### Keystream 生成
```
keystream_block[i] = AES_ECB(key, counter_block)

counter_block 結構:
- bytes 0-3:   nonce[0:4]（不變）
- bytes 4-7:   4-byte little-endian counter（從 nonce[4:8] 開始，每 block +1）
- bytes 8-15:  nonce[8:16]（不變）
```

#### AES Key
- **Passphrase** (User DB): `yahookeykeyuserdb` (17 bytes)
- **AES Key**: 取前 16 bytes = `yahookeykeyuserd`
- **Hex**: `7961686f6f6b65796b65797573657264`

> 原廠的 Vendor passphrase：B359D6FE-BEB4-411B-82F8-31E347B6C438（可視為 CEROD phrase）。

### 解密腳本

已建立完整的解密工具：

```bash
python3 decrypt_userdb_final.py SmartMandarinUserData.db output.db
```

### 解密結果驗證

```
$ sqlite3 output.db "SELECT * FROM user_unigrams;"
fakM6CQ;=M|過融合音程|-1.174761|0.0
O_yf|複調|-1.174761|0.0
MiWBKP|萬國碼|-1.174761|0.0
```

### 資料庫 Schema

```sql
CREATE TABLE IF NOT EXISTS 'user_unigrams' (qstring, current, probability, backoff);
CREATE TABLE IF NOT EXISTS 'user_bigram_cache' (qstring, previous, current, probability);
CREATE TABLE IF NOT EXISTS 'user_candidate_override_cache' (qstring, current);
CREATE INDEX 'user_unigrams_index' on 'user_unigrams' (qstring);
CREATE INDEX 'user_bigram_cache_index' on 'user_bigram_cache' (qstring);
CREATE INDEX 'user_candidate_override_cache_index' on 'user_candidate_override_cache' (qstring);
```

### 工具腳本

| 腳本 | 用途 |
|------|------|
| `decrypt_userdb_final.py` | **主要解密工具** - 解密 SmartMandarinUserData.db |
| `extract_user_key_v2.py` | 從原始碼提取 passphrase（參考用） |

### 任務完成！

使用者現在可以：
1. 執行 `python3 decrypt_userdb_final.py SmartMandarinUserData.db decrypted.db`
2. 用任何 SQLite 工具開啟 `decrypted.db`
3. 匯出使用者自訂詞彙

此解決方案**不需要**：
- SQLite SEE 商業授權
- Rosetta 2 或 Intel Mac
- 動態調試

---

## 16) 待完成工作

### 注音串 (qstring) 解碼

目前解密後的資料庫中，`qstring` 欄位是編碼過的注音符號：

| qstring | current | 說明 |
|---------|---------|------|
| `fakM6CQ;=M` | 過融合音程 | 需解碼為注音 |
| `O_yf` | 複調 | 需解碼為注音 |
| `MiWBKP` | 萬國碼 | 需解碼為注音 |

這些是 BPMF (Bopomofo) 編碼的注音輸入序列。需要找出對應的解碼邏輯。

可能的參考位置：
- `Frameworks/Manjusri/` - BPMF 相關處理
- `ModulePackages/OVIMMandarin/` - 輸入法模組

---

