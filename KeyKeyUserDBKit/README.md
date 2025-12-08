# KeyKeyUserDBKit

Swift: [![Swift](https://github.com/vChewing/KeyKeyUserDBKit/actions/workflows/ci.yml/badge.svg)](https://github.com/vChewing/KeyKeyUserDBKit/actions/workflows/ci.yml) [![Swift 6.1](https://img.shields.io/badge/Swift-6.1-orange.svg)](https://swift.org) [![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

Yahoo! 奇摩輸入法 (KeyKey) 使用者資料庫解密 Swift Package。

> **💻 C# 版**: `WinNT/` 目錄下含有 .NET 實作版本，詳見其自身的 [README.md](WinNT/README.md)。
>
> C#: [![.NET](https://github.com/vChewing/KeyKeyUserDBKit/actions/workflows/ci.yml/badge.svg)](https://github.com/vChewing/KeyKeyUserDBKit/actions/workflows/ci.yml) [![NuGet](https://img.shields.io/nuget/v/vChewing.Utils.KeyKeyUserDBKit)](https://www.nuget.org/packages/vChewing.Utils.KeyKeyUserDBKit) [![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

## 目的

奇摩輸入法在 2012 年停止開發，最終官方支援的 macOS 系統版本是 macOS 10.8 Mountain Lion。從 macOS 10.9 Mavericks 開始，該輸入法原廠的片語編輯器徹底罷工。雖然官方釋出的最終原始碼（僅限 Yahoo 奇摩被允許授權公開的部分，不包含 SQLite CEROD）小修小補之後仍舊可以將片語編輯器重新建置，但因為 CEROD 原始碼的缺失、導致輸入法本體無法建置成「可以無縫讀取既有使用者片語資料」的樣子。

於是呢，從 macOS 10.9 Mavericks 至 macOS 26 Tahoe 的這些年間，唯一可以抽取到使用者片語的方法便是利用 NSConnection 跨程通訊的方式向奇摩輸入法的 Process 請求使用者片語資料、且只能請求到 Unigram。該輸入法內建的片語編輯器就是這樣與輸入法通訊的。但這要求奇摩輸入法必須正在運行。而 macOS 27 開始不再有 Rosetta 2 可用、會導致奇摩輸入法再無可能運作使用。

這樣一來，就不能用同樣的方法救出使用者片語了。對既有的那些與奇摩輸入法互相陪伴了十幾年、積累了成千上萬筆使用者片語的資深使用者群體而言，這是空前的災難。

為了因應這個需求，唯音專案新開發了 KeyKeyUserDBKit 這款開發套件，可以做到在不運行奇摩輸入法的前提下從使用者資料庫  `SmartMandarinUserData.db` 救出使用者片語（Unigram、Bigram-Cache、Candidate-Override）資料。

唯音專案推出此套件餽贈社會，也希望能得到一些捐助。詳細資訊可洽[唯音輸入法的軟體主頁](https://vchewing.github.io/README.html)。也[歡迎各位 macOS 奇摩輸入法難民們嘗試唯音輸入法](https://vchewing.github.io/manual/onboarding_kimo.html)。

## 功能

- 🔓 解密 SQLite SEE AES-128 加密的使用者資料庫 (`SmartMandarinUserData.db`)
- 📝 解析 MJSR（Manjusri 文殊）匯出文字檔案（奇摩輸入法匯出格式）
- 🔤 解碼注音符號 (Bopomofo) qstring 欄位
- 📖 讀取使用者詞彙資料（單元圖 (Unigram)、雙元圖 (Bigram)、候選字覆蓋）
- 🔄 支援 `Sequence` 與 `AsyncSequence` 迭代

## 專案結構

```
KeyKeyUserDBKit/
├── Package.swift                  # Swift Package 定義
├── CSQLite3/                      # SQLite3 C 模組
│   └── Sources/CSQLite3/
│       ├── sqlite3.c
│       └── include/
│           └── sqlite3.h
├── Sources/
│   ├── KeyKeyUserDBKit/           # 主要函式庫
│   │   ├── Gram.swift             # 語料結構體
│   │   ├── PhonaSet.swift         # 注音符號處理
│   │   ├── SEEDecryptor.swift     # SQLite SEE AES-128 解密器
│   │   ├── UserDatabase.swift     # 使用者資料庫讀取器
│   │   ├── UserPhraseDataSource.swift   # 資料來源協定
│   │   └── UserPhraseTextFileObj.swift  # MJSR 匯出檔案解析器
│   └── KeyKeyDecryptCLI/          # 命令列工具 (kkdecrypt)
│       └── main.swift
└── Tests/
    └── KeyKeyUserDBKitTests/      # 單元測試 (Swift Testing)
        ├── GramTests.swift
        ├── PhonaSetTests.swift
        ├── SEEDecryptorTests.swift
        └── UserDatabaseTests.swift
```

## 系統需求

- Swift 6.1 或更新版本
- macOS 10.13+ / Linux

## 安裝

### Swift Package Manager

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/vChewing/KeyKeyUserDBKit.git", from: "1.0.0")
]
```

```swift
// 在 target 中加入依賴
.target(
    name: "YourTarget",
    dependencies: ["KeyKeyUserDBKit"]
)
```

## 建置

```bash
swift build
```

## 測試

```bash
swift test
```

## 使用方式

### 作為函式庫

```swift
import KeyKeyUserDBKit

// 解密資料庫
let decryptor = KeyKeyUserDBKit.SEEDecryptor()
try decryptor.decryptFile(
    at: URL(fileURLWithPath: "SmartMandarinUserData.db"),
    to: URL(fileURLWithPath: "decrypted.db")
)

// 讀取資料
let db = try KeyKeyUserDBKit.UserDatabase(path: "decrypted.db")

// 取得所有語料資料
let allGrams = try db.fetchAllGrams()

for gram in allGrams {
    print("\(gram.current) → \(gram.keyArray.joined(separator: "-"))")
}

// 或分別讀取各類型資料
let unigrams = try db.fetchUnigrams()           // 單元圖
let bigrams = try db.fetchBigrams()             // 雙元圖
let bigrams5 = try db.fetchBigrams(limit: 5)    // 限制筆數
let overrides = try db.fetchCandidateOverrides() // 候選字覆蓋

// 使用 Sequence 迭代器逐筆讀取
for gram in db {
    print(gram.describe())
}

// 使用 AsyncSequence 非同步迭代
for await gram in db.async {
    print(gram.current)
}
```

### 解析 MJSR 匯出檔案

奇摩輸入法的匯出功能會產生 MJSR（Manjusri 文殊）格式的文字檔案，其中包含使用者單字詞及加密的 database block：

```swift
import KeyKeyUserDBKit

// 從檔案載入 MJSR 匯出檔
let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(path: "export.txt")

// 或從 URL 載入
let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: fileURL)

// 取得所有語料資料（與 UserDatabase 相同的 API）
let allGrams = try textFile.fetchAllGrams()

for gram in allGrams {
    print("\(gram.current) → \(gram.keyArray.joined(separator: "-"))")
}

// UserDatabase 與 UserPhraseTextFileObj 都實作 UserPhraseDataSource 協定
// 可以統一處理不同資料來源
func processDataSource(_ source: some KeyKeyUserDBKit.UserPhraseDataSource) throws {
    for gram in source {
        print(gram.describe())
    }
}

// 使用資料庫
let db = try KeyKeyUserDBKit.UserDatabase(path: "decrypted.db")
try processDataSource(db)

// 使用匯出檔案
let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(path: "export.txt")
try processDataSource(textFile)
```

### 注音解碼

```swift
// 解碼 qstring 為注音符號字串
let phonabet = KeyKeyUserDBKit.PhonaSet.decodeQueryString("0M")
// 結果: "ㄍㄨㄛˋ"

// 解碼為陣列
let keyArray = KeyKeyUserDBKit.PhonaSet.decodeQueryStringAsKeyArray("0M6C")
// 結果: ["ㄍㄨㄛˋ", "ㄖㄨㄥˊ"]

// 使用 PhonaSet 結構
let phona = KeyKeyUserDBKit.PhonaSet(
    consonant: .ㄍ,
    semivowel: .ㄨ,
    vowel: .ㄛ,
    intonation: .ˋ
)
print(phona.description) // "ㄍㄨㄛˋ"
```

### 命令列工具

```bash
# 編譯
swift build -c release

# 解密資料庫
.build/release/kkdecrypt SmartMandarinUserData.db [output.db]

# 或使用 swift run
swift run kkdecrypt SmartMandarinUserData.db decrypted.db
```

## API 對照

| Swift                               | C#                                |
|-------------------------------------|-----------------------------------|
| `KeyKeyUserDBKit.Gram`              | `Gram`                            |
| `KeyKeyUserDBKit.PhonaSet`          | `PhonaSet`                        |
| `KeyKeyUserDBKit.SEEDecryptor`      | `SEEDecryptor`                    |
| `KeyKeyUserDBKit.UserDatabase`      | `UserDatabase`                    |
| `KeyKeyUserDBKit.UserPhraseTextFileObj` | `UserPhraseTextFileObj`       |
| `KeyKeyUserDBKit.UserPhraseDataSource` | `IUserPhraseDataSource`        |
| `fetchUnigrams()`                   | `FetchUnigrams()`                 |
| `fetchBigrams(limit:)`              | `FetchBigrams(int? limit)`        |
| `fetchCandidateOverrides()`         | `FetchCandidateOverrides()`       |
| `fetchAllGrams()`                   | `FetchAllGrams()`                 |
| `makeIterator()`                    | `GetEnumerator()`                 |
| `for gram in db { }`                | `foreach (var gram in db) { }`   |
| `for await gram in db.async { }`    | `await foreach (var gram in db)` |

## 加密分析

此工具解密 Yahoo! 奇摩輸入法使用 SQLite SEE (SQLite Encryption Extension) 加密的資料庫：

- **加密演算法**: AES-128
- **模式**: 自訂 CTR-like (非標準 CCM)
- **頁面大小**: 1024 bytes
- **保留區域**: 32 bytes (16 bytes nonce + 16 bytes MAC)
- **密鑰**: `yahookeykeyuserd` (17 字元密碼的前 16 bytes)

### Keystream 產生

密鑰流（Keystream）的生成方式如下：

1. 複製 Nonce 作為 Counter Block 的初始值
2. 將 Counter Block 的第 4-7 位元組設為計數器（4-byte little-endian 格式）
3. 對 Counter Block 執行 AES-ECB 加密，產生 16 bytes 的密鑰流
4. 每處理 16 bytes 資料後，計數器遞增 1，重複步驟 2-3

## 注音編碼

qstring 欄位使用 79 進位編碼：

```
order = (high_char - 48) * 79 + (low_char - 48)

syllable = consonant | (middle << 5) | (vowel << 7) | (tone << 11)
```

## MJSR 匯出格式

MJSR（Manjusri 文殊）是奇摩輸入法的匯出檔案格式：

- **Header**: `MJSR version 1.0.0`
- **使用者單字詞**: Tab 分隔格式 (`word\treading\tprobability\tbackoff`)
- **`<database>` block**: 十六進位編碼的加密 SQLite 資料庫
  - 包含 `user_bigram_cache` 和 `user_candidate_override_cache` 表格
  - 加密密鑰: `mjsrexportmjsrex`（16 bytes）

## 授權

本專案採用 [LGPL-3.0-or-later](LICENSES/preferred/LGPL-3.0-or-later) 授權。

```
(c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.
```
