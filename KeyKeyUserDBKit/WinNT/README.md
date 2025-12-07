# WinNT - KeyKeyUserDBKit for .NET

[![.NET](https://github.com/vChewing/KeyKeyUserDBKit/actions/workflows/ci.yml/badge.svg)](https://github.com/vChewing/KeyKeyUserDBKit/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/vChewing.Utils.KeyKeyUserDBKit)](https://www.nuget.org/packages/vChewing.Utils.KeyKeyUserDBKit)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

這是 KeyKeyUserDBKit Swift Package 的 .NET 10 移植版本，可用於 Windows & Linux & macOS 等所有受 .NET 10 支援的平台系統版本。

## 目的

奇摩輸入法在 2012 年停止開發，最終官方支援的 macOS 系統版本是 macOS 10.8 Mountain Lion。從 macOS 10.9 Mavericks 開始，該輸入法原廠的片語編輯器徹底罷工。雖然官方釋出的最終原始碼（僅限 Yahoo 奇摩被允許授權公開的部分，不包含 SQLite CEROD）小修小補之後仍舊可以將片語編輯器重新建置，但因為 CEROD 原始碼的缺失、導致輸入法本體無法建置成「可以無縫讀取既有使用者片語資料」的樣子。

於是呢，從 macOS 10.9 Mavericks 至 macOS 26 Tahoe 的這些年間，唯一可以抽取到使用者片語的方法便是利用 NSConnection 跨程通訊的方式向奇摩輸入法的 Process 請求使用者片語資料、且只能請求到 Unigram。該輸入法內建的片語編輯器就是這樣與輸入法通訊的。但這要求奇摩輸入法必須正在運行。而 macOS 27 開始不再有 Rosetta 2 可用、會導致奇摩輸入法再無可能運作使用。

這樣一來，就不能用同樣的方法救出使用者片語了。對既有的那些與奇摩輸入法互相陪伴了十幾年、積累了成千上萬筆使用者片語的資深使用者群體而言，這是空前的災難。

為了因應這個需求，唯音專案新開發了 KeyKeyUserDBKit 這款開發套件，可以做到在不運行奇摩輸入法的前提下從使用者資料庫  `SmartMandarinUserData.db` 救出使用者片語（Unigram、Bigram-Cache、Candidate-Override）資料。

唯音專案推出此套件餽贈社會，也希望能得到一些捐助。詳細資訊可洽[唯音輸入法的軟體主頁](https://vchewing.github.io/README.html)。也[歡迎各位 macOS 奇摩輸入法難民們嘗試唯音輸入法](https://vchewing.github.io/manual/onboarding_kimo.html)。

## 功能

- 🔓 解密 SQLite SEE AES-128 加密的使用者資料庫 (`SmartMandarinUserData.db`)
- 🔤 解碼注音符號 (Bopomofo) qstring 欄位
- 📖 讀取使用者詞彙資料（單元圖、雙元圖、候選字覆蓋）
- 🔄 支援 `IEnumerable<Gram>` 與 `IAsyncEnumerable<Gram>` 迭代

## 專案結構

```
WinNT/
├── KeyKeyUserDBKit.sln          # Visual Studio 解決方案檔
├── KeyKeyUserDBKit/             # 主要函式庫 (NuGet: vChewing.Utils.KeyKeyUserDBKit)
│   ├── Gram.cs                  # 語料結構體
│   ├── PhonaSet.cs              # 注音符號處理
│   ├── SEEDecryptor.cs          # SQLite SEE AES-128 解密器
│   └── UserDatabase.cs          # 使用者資料庫讀取器
├── KeyKeyUserDBKit.Tests/       # 單元測試 (xUnit)
│   ├── GramTests.cs
│   ├── PhonaSetTests.cs
│   ├── SEEDecryptorTests.cs
│   └── UserDatabaseTests.cs
└── KeyKeyDecryptCLI/            # 命令列工具 (kkdecrypt)
    └── Program.cs
```

## 系統需求

- .NET 10.0 SDK 或更新版本
- Windows / Linux / macOS

## 安裝

### NuGet

```bash
dotnet add package vChewing.Utils.KeyKeyUserDBKit
```

### 專案參考

```xml
<PackageReference Include="vChewing.Utils.KeyKeyUserDBKit" Version="1.0.0" />
```

## 建置

```bash
cd WinNT
dotnet build
```

## 測試

```bash
dotnet test
```

## 使用方式

### 作為函式庫

```csharp
using KeyKeyUserDBKit;

// 解密資料庫
using var decryptor = new SEEDecryptor();
await decryptor.DecryptFileAsync("SmartMandarinUserData.db", "decrypted.db");

// 讀取資料
using var db = new UserDatabase("decrypted.db");

// 取得所有語料資料
var allGrams = db.FetchAllGrams();

foreach (var gram in allGrams)
{
    Console.WriteLine($"{gram.Current} → {string.Join("-", gram.KeyArray)}");
}

// 或分別讀取各類型資料
var unigrams = db.FetchUnigrams();           // 單元圖
var bigrams = db.FetchBigrams();             // 雙元圖
var bigrams5 = db.FetchBigrams(5);           // 限制筆數
var overrides = db.FetchCandidateOverrides(); // 候選字覆蓋

// 使用 IEnumerable 迭代器逐筆讀取
foreach (var gram in db)
{
    Console.WriteLine(gram.Describe("-"));
}

// 使用 IAsyncEnumerable 非同步迭代器
await foreach (var gram in db)
{
    Console.WriteLine(gram.Current);
}
```

### 注音解碼

```csharp
// 解碼 qstring 為注音符號字串
var phonabet = PhonaSet.DecodeQueryString("0M");
// 結果: "ㄍㄨㄛˋ"

// 解碼為陣列
var keyArray = PhonaSet.DecodeQueryStringAsKeyArray("0M6C");
// 結果: ["ㄍㄨㄛˋ", "ㄖㄨㄥˊ"]

// 使用 PhonaSet 結構
var phona = new PhonaSet(
    consonant: PhonaSet.Consonant.ㄍ,
    semivowel: PhonaSet.Semivowel.ㄨ,
    vowel: PhonaSet.Vowel.ㄛ,
    intonation: PhonaSet.Intonation.Tone4
);
Console.WriteLine(phona.ToString()); // "ㄍㄨㄛˋ"
```

### 命令列工具

```bash
# 解密資料庫
kkdecrypt decrypt SmartMandarinUserData.db decrypted.db

# 傾印所有資料
kkdecrypt dump decrypted.db

# 或使用 dotnet run
dotnet run --project KeyKeyDecryptCLI -- decrypt SmartMandarinUserData.db decrypted.db
dotnet run --project KeyKeyDecryptCLI -- dump decrypted.db
```

## API 對照

| Swift                               | C#                                |
|-------------------------------------|-----------------------------------|
| `KeyKeyUserDBKit.Gram`              | `Gram`                            |
| `KeyKeyUserDBKit.PhonaSet`          | `PhonaSet`                        |
| `KeyKeyUserDBKit.SEEDecryptor`      | `SEEDecryptor`                    |
| `KeyKeyUserDBKit.UserDatabase`      | `UserDatabase`                    |
| `fetchUnigrams()`                   | `FetchUnigrams()`                 |
| `fetchBigrams(limit:)`              | `FetchBigrams(int? limit)`        |
| `fetchCandidateOverrides()`         | `FetchCandidateOverrides()`       |
| `fetchAllGrams()`                   | `FetchAllGrams()`                 |
| `makeIterator()`                    | `GetEnumerator()`                 |
| `for gram in db { }`                | `foreach (var gram in db) { }`   |
| `for await gram in db.async { }`    | `await foreach (var gram in db)` |

## 授權

本專案採用 [LGPL-3.0-or-later](../LICENSES/preferred/LGPL-3.0-or-later) 授權。

```
(c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.
```
