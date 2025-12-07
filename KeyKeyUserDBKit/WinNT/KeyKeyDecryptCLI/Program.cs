// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using KeyKeyUserDBKit;

if (args.Length < 1) {
  PrintUsage();
  return 1;
}

try {
  switch (args[0].ToLowerInvariant()) {
    case "decrypt":
      return await HandleDecrypt(args);
    case "dump":
      return await HandleDump(args);
    case "--help":
    case "-h":
      PrintUsage();
      return 0;
    default:
      Console.Error.WriteLine($"未知的指令: {args[0]}");
      PrintUsage();
      return 1;
  }
} catch (Exception ex) {
  Console.Error.WriteLine($"錯誤：{ex.Message}");
  return 1;
}

static void PrintUsage() {
  var programName = Path.GetFileName(Environment.ProcessPath) ?? "kkdecrypt";
  Console.WriteLine($"""
        Yahoo! 奇摩輸入法 (KeyKey) 使用者資料庫工具

        用法: {programName} <指令> [選項]

        指令:
          decrypt <輸入檔> [輸出檔]   解密 KeyKey 使用者資料庫
          dump <資料庫路徑>           顯示資料庫中的所有詞彙

        選項:
          -h, --help                  顯示此說明

        範例:
          {programName} decrypt SmartMandarinUserData.db
          {programName} decrypt SmartMandarinUserData.db decrypted.db
          {programName} dump SmartMandarinUserData.db
        """);
}

static async Task<int> HandleDecrypt(string[] args) {
  if (args.Length < 2) {
    Console.Error.WriteLine("用法: kkdecrypt decrypt <輸入檔> [輸出檔]");
    return 1;
  }

  var inputPath = args[1];

  if (!File.Exists(inputPath)) {
    Console.Error.WriteLine($"錯誤：找不到檔案 {inputPath}");
    return 1;
  }

  // 如果沒有指定輸出檔，使用預設名稱
  string outputPath;
  if (args.Length >= 3) {
    outputPath = args[2];
  } else {
    var baseName = Path.GetFileNameWithoutExtension(inputPath);
    var directory = Path.GetDirectoryName(inputPath) ?? ".";
    outputPath = Path.Combine(directory, $"{baseName}.decrypted.db");
  }

  var fileInfo = new FileInfo(inputPath);
  Console.WriteLine($"解密 {inputPath}");
  Console.WriteLine($"  檔案大小: {fileInfo.Length} bytes");
  Console.WriteLine($"  頁面數量: {fileInfo.Length / SEEDecryptor.PageSize}");

  using var decryptor = new SEEDecryptor();
  await decryptor.DecryptFileAsync(inputPath, outputPath);

  Console.WriteLine($"  輸出: {outputPath}");
  Console.WriteLine("  完成！");

  // 顯示解密後的資料
  await ShowDecodedData(outputPath);

  return 0;
}

static async Task<int> HandleDump(string[] args) {
  if (args.Length < 2) {
    Console.Error.WriteLine("用法: kkdecrypt dump <資料庫路徑>");
    return 1;
  }

  var dbPath = args[1];

  if (!File.Exists(dbPath)) {
    Console.Error.WriteLine($"錯誤：找不到檔案 {dbPath}");
    return 1;
  }

  // 檢查是否為加密資料庫，如果是則先解密到臨時檔案
  string actualDbPath = dbPath;
  string? tempFile = null;

  if (SEEDecryptor.IsEncryptedDatabase(dbPath)) {
    Console.WriteLine("偵測到加密資料庫，正在解密...");
    tempFile = Path.GetTempFileName();
    using var decryptor = new SEEDecryptor();
    await decryptor.DecryptFileAsync(dbPath, tempFile);
    actualDbPath = tempFile;
  }

  try {
    await ShowDecodedData(actualDbPath);
    return 0;
  } finally {
    // 清理臨時檔案
    if (tempFile != null && File.Exists(tempFile)) {
      File.Delete(tempFile);
    }
  }
}

static Task ShowDecodedData(string dbPath) {
  using var db = new UserDatabase(dbPath);

  Console.WriteLine("\n=== 使用者單元圖 (user_unigrams) ===");
  var unigrams = db.FetchUnigrams();
  foreach (var gram in unigrams) {
    var reading = string.Join(",", gram.KeyArray);
    Console.WriteLine($"  {gram.Current}\t{reading}\t({gram.Probability})");
  }

  Console.WriteLine("\n=== 使用者雙元圖快取 (user_bigram_cache) ===");
  var bigrams = db.FetchBigrams(limit: 10);
  foreach (var gram in bigrams) {
    var reading = string.Join(",", gram.KeyArray);
    Console.WriteLine($"  {gram.Previous}→{gram.Current}\t{reading}");
  }

  Console.WriteLine("\n=== 候選字覆蓋快取 (user_candidate_override_cache) ===");
  var overrides = db.FetchCandidateOverrides();
  if (overrides.Count == 0) {
    Console.WriteLine("  (空)");
  } else {
    foreach (var gram in overrides) {
      var reading = string.Join(",", gram.KeyArray);
      Console.WriteLine($"  {gram.Current}\t{reading}");
    }
  }

  return Task.CompletedTask;
}
