// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using System.Collections;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Data.Sqlite;

namespace KeyKeyUserDBKit;

/// <summary>
/// MJSR 匯出檔案解析器
/// </summary>
/// <remarks>
/// <para>
/// 此類別可解析 Yahoo! 奇摩輸入法 (KeyKey) 匯出的使用者詞庫文字檔案。
/// </para>
/// <para>
/// <strong>檔案格式</strong>
/// <list type="bullet">
/// <item>Header: "MJSR version 1.0.0"</item>
/// <item>使用者單字詞: 每行一筆 (word\treading\tprobability\tbackoff)</item>
/// <item>註解行: 以 # 開頭</item>
/// <item>&lt;database&gt; block: 加密的 SQLite 資料庫 (user_bigram_cache + user_candidate_override_cache)</item>
/// </list>
/// </para>
/// <para>
/// <strong>加密方式</strong>
/// <list type="bullet">
/// <item>SQLite SEE AES-128-CCM</item>
/// <item>密鑰: "mjsrexportmjsrex" (重複填充到 16 bytes)</item>
/// </list>
/// </para>
/// </remarks>
public sealed class UserPhraseTextFileObj : IUserPhraseDataSource, IDisposable {
  // MARK: - Constants

  /// <summary>
  /// 候選字覆蓋記錄的預設權重
  /// </summary>
  public const double CandidateOverrideProbability = 114.514;

  /// <summary>
  /// Export 密鑰（"mjsrexport" 重複填充到 16 bytes）
  /// </summary>
  public static readonly byte[] ExportKey = Encoding.UTF8.GetBytes("mjsrexportmjsrex");

  // 解密常數
  private const int PageSize = 1024;
  private const int ReservedBytes = 32;
  private const int DataAreaSize = PageSize - ReservedBytes;

  // MARK: - Properties

  /// <summary>
  /// MJSR 版本字串
  /// </summary>
  public string Version { get; }

  /// <summary>
  /// 使用者單元圖
  /// </summary>
  public IReadOnlyList<Gram> Unigrams { get; }

  /// <summary>
  /// 使用者雙元圖（來自 database block）
  /// </summary>
  public IReadOnlyList<Gram> Bigrams { get; }

  /// <summary>
  /// 候選字覆蓋（來自 database block）
  /// </summary>
  public IReadOnlyList<Gram> CandidateOverrides { get; }

  private bool _disposed;

  // MARK: - Constructors

  /// <summary>
  /// 從檔案路徑載入
  /// </summary>
  /// <param name="path">MJSR 匯出檔案路徑</param>
  /// <returns>UserPhraseTextFileObj 實例</returns>
  /// <exception cref="TextFileException">檔案讀取或解析錯誤</exception>
  public static UserPhraseTextFileObj FromPath(string path) {
    var content = File.ReadAllText(path, Encoding.UTF8);
    return new UserPhraseTextFileObj(content);
  }

  /// <summary>
  /// 從文字內容初始化
  /// </summary>
  /// <param name="content">MJSR 匯出檔案的文字內容</param>
  /// <exception cref="TextFileException">解析錯誤</exception>
  public UserPhraseTextFileObj(string content) {
    var lines = content.Split('\n', '\r')
        .Where(line => !string.IsNullOrEmpty(line))
        .ToList();

    // 檢查 header
    if (lines.Count == 0 || !lines[0].StartsWith("MJSR version")) {
      throw new TextFileException("Missing MJSR header", TextFileErrorType.InvalidFormat);
    }
    Version = lines[0];

    // 解析 unigrams（逐行解析到 # 或 < 開頭為止）
    var unigrams = new List<Gram>();
    foreach (var line in lines.Skip(1)) {
      if (line.StartsWith("#") || line.StartsWith("<")) {
        break;
      }
      if (string.IsNullOrWhiteSpace(line)) continue;

      var parts = line.Split('\t');
      if (parts.Length < 4) continue;

      var word = parts[0];
      var reading = parts[1];
      var probability = double.TryParse(parts[2], out var prob) ? prob : 0;
      // backoff 目前不使用

      // reading 格式是逗號分隔的注音字串，如 "ㄔㄨㄣ,ㄒㄧ"
      var keyArray = reading.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
      unigrams.Add(Gram.CreateUnigram(keyArray, word, probability));
    }
    Unigrams = unigrams.AsReadOnly();

    // 解析 database block
    var (bigrams, candidateOverrides) = ParseDatabaseBlock(content);
    Bigrams = bigrams.AsReadOnly();
    CandidateOverrides = candidateOverrides.AsReadOnly();
  }

  // MARK: - IUserPhraseDataSource

  /// <inheritdoc/>
  public List<Gram> FetchUnigrams() {
    ThrowIfDisposed();
    return Unigrams.ToList();
  }

  /// <inheritdoc/>
  public List<Gram> FetchBigrams(int? limit = null) {
    ThrowIfDisposed();
    return limit.HasValue
        ? Bigrams.Take(limit.Value).ToList()
        : Bigrams.ToList();
  }

  /// <inheritdoc/>
  public List<Gram> FetchCandidateOverrides() {
    ThrowIfDisposed();
    return CandidateOverrides.ToList();
  }

  /// <inheritdoc/>
  public List<Gram> FetchAllGrams() {
    ThrowIfDisposed();
    var allGrams = new List<Gram>();
    allGrams.AddRange(Unigrams);
    allGrams.AddRange(Bigrams);
    allGrams.AddRange(CandidateOverrides);
    return allGrams;
  }

  // MARK: - IEnumerable<Gram>

  /// <inheritdoc/>
  public IEnumerator<Gram> GetEnumerator() {
    ThrowIfDisposed();
    foreach (var gram in Unigrams)
      yield return gram;
    foreach (var gram in Bigrams)
      yield return gram;
    foreach (var gram in CandidateOverrides)
      yield return gram;
  }

  /// <inheritdoc/>
  IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

  // MARK: - IDisposable

  private void ThrowIfDisposed() {
    ObjectDisposedException.ThrowIf(_disposed, this);
  }

  /// <inheritdoc/>
  public void Dispose() {
    _disposed = true;
  }

  // MARK: - Database Block Parsing

  private static (List<Gram> bigrams, List<Gram> candidateOverrides) ParseDatabaseBlock(string content) {
    // 找到 <database> block
    var startTag = "<database>";
    var endTag = "</database>";
    var startIdx = content.IndexOf(startTag, StringComparison.Ordinal);
    var endIdx = content.IndexOf(endTag, StringComparison.Ordinal);

    if (startIdx < 0 || endIdx < 0) {
      // 沒有 database block，回傳空列表
      return (new List<Gram>(), new List<Gram>());
    }

    var hexDataStart = startIdx + startTag.Length;
    var hexString = content[hexDataStart..endIdx]
        .Replace("\n", "")
        .Replace("\r", "")
        .Trim();

    if (string.IsNullOrEmpty(hexString)) {
      return (new List<Gram>(), new List<Gram>());
    }

    // 將 hex 字串轉換為 bytes
    var encryptedData = HexStringToBytes(hexString)
        ?? throw new TextFileException("Invalid hex data", TextFileErrorType.InvalidDatabaseBlock);

    // 解密資料庫
    var decryptedData = DecryptDatabaseBlock(encryptedData);

    // 使用臨時檔案讀取 SQLite 資料
    var tempPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.db");

    try {
      File.WriteAllBytes(tempPath, decryptedData);
      return ReadGramsFromDecryptedDatabase(tempPath);
    } finally {
      try {
        File.Delete(tempPath);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  private static byte[] DecryptDatabaseBlock(byte[] encryptedData) {
    if (encryptedData.Length % PageSize != 0) {
      throw new TextFileException(
          $"Invalid size: {encryptedData.Length} is not a multiple of {PageSize}",
          TextFileErrorType.InvalidDatabaseBlock);
    }

    var numPages = encryptedData.Length / PageSize;
    var decrypted = new List<byte>();

    for (var pageIdx = 0; pageIdx < numPages; pageIdx++) {
      var pageData = new byte[PageSize];
      Array.Copy(encryptedData, pageIdx * PageSize, pageData, 0, PageSize);

      var decryptedPage = DecryptPage(pageData, pageIdx, ExportKey);
      decrypted.AddRange(decryptedPage);
    }

    // 清除 SQLite header 中的 reserved bytes 設定 (offset 20)
    if (decrypted.Count > 20) {
      decrypted[20] = 0;
    }

    return decrypted.ToArray();
  }

  private static byte[] DecryptPage(byte[] pageData, int pageNumber, byte[] key) {
    if (pageData.Length != PageSize) {
      throw new TextFileException("Invalid page size", TextFileErrorType.InvalidDatabaseBlock);
    }

    var nonce = new byte[16];
    Array.Copy(pageData, PageSize - 16, nonce, 0, 16);

    // 建立 AES cipher
    using var aes = Aes.Create();
    aes.Key = key;
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.None;

    var decrypted = new byte[DataAreaSize];
    var baseCounter = BitConverter.ToUInt32(nonce, 4);

    using var encryptor = aes.CreateEncryptor();

    for (var blockIdx = 0; blockIdx < DataAreaSize / 16; blockIdx++) {
      var counter = baseCounter + (uint)blockIdx;
      var counterBytes = (byte[])nonce.Clone();
      BitConverter.GetBytes(counter).CopyTo(counterBytes, 4);

      // AES-ECB 加密 counter block 產生 keystream
      var keystream = new byte[16];
      encryptor.TransformBlock(counterBytes, 0, 16, keystream, 0);

      // XOR 解密
      var blockStart = blockIdx * 16;
      if (pageNumber == 0) {
        // Page 1 特殊處理：bytes 16-23 是明文
        if (blockIdx == 0) {
          // Block 0: 全部解密
          for (var i = 0; i < 16; i++) {
            decrypted[i] = (byte)(pageData[i] ^ keystream[i]);
          }
        } else if (blockIdx == 1) {
          // Block 1: bytes 16-23 保持明文，bytes 24-31 解密
          for (var i = 0; i < 8; i++) {
            decrypted[16 + i] = pageData[16 + i];
          }
          for (var i = 8; i < 16; i++) {
            decrypted[16 + i] = (byte)(pageData[16 + i] ^ keystream[i]);
          }
        } else {
          // 其他 blocks: 全部解密
          for (var i = 0; i < 16; i++) {
            decrypted[blockStart + i] = (byte)(pageData[blockStart + i] ^ keystream[i]);
          }
        }
      } else {
        // 其他頁面：全部解密
        for (var i = 0; i < 16; i++) {
          decrypted[blockStart + i] = (byte)(pageData[blockStart + i] ^ keystream[i]);
        }
      }
    }

    // 填充 reserved bytes 為零
    var result = new byte[PageSize];
    Array.Copy(decrypted, result, DataAreaSize);
    return result;
  }

  private static (List<Gram> bigrams, List<Gram> candidateOverrides) ReadGramsFromDecryptedDatabase(string path) {
    var connectionString = new SqliteConnectionStringBuilder {
      DataSource = path,
      Mode = SqliteOpenMode.ReadOnly
    }.ToString();

    using var connection = new SqliteConnection(connectionString);
    connection.Open();

    var bigrams = new List<Gram>();
    var candidateOverrides = new List<Gram>();

    // 讀取 user_bigram_cache
    const string bigramSQL = "SELECT qstring, previous, current, probability FROM user_bigram_cache";
    using (var command = new SqliteCommand(bigramSQL, connection)) {
      using var reader = command.ExecuteReader();
      while (reader.Read()) {
        var qstring = reader.GetString(0);
        var previous = reader.GetString(1);
        var current = reader.GetString(2);
        var probability = reader.GetDouble(3);

        // bigram 的 qstring 格式是 "{前字注音2char} {當前字注音2char}"
        var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
        bigrams.Add(Gram.CreateBigram(keyArray, current, previous, probability));
      }
    }

    // 讀取 user_candidate_override_cache
    const string overrideSQL = "SELECT qstring, current FROM user_candidate_override_cache";
    using (var command = new SqliteCommand(overrideSQL, connection)) {
      using var reader = command.ExecuteReader();
      while (reader.Read()) {
        var qstring = reader.GetString(0);
        var current = reader.GetString(1);

        var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
        candidateOverrides.Add(Gram.CreateCandidateOverride(keyArray, current, CandidateOverrideProbability));
      }
    }

    return (bigrams, candidateOverrides);
  }

  // MARK: - Helper Methods

  private static byte[]? HexStringToBytes(string hex) {
    if (hex.Length % 2 != 0)
      return null;

    var bytes = new byte[hex.Length / 2];
    for (var i = 0; i < bytes.Length; i++) {
      if (!byte.TryParse(hex.AsSpan(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out bytes[i])) {
        return null;
      }
    }
    return bytes;
  }
}

// MARK: - TextFileException

/// <summary>
/// 文字檔案解析錯誤類型
/// </summary>
public enum TextFileErrorType {
  /// <summary>無效的檔案格式</summary>
  InvalidFormat,
  /// <summary>無效的資料庫區塊</summary>
  InvalidDatabaseBlock,
  /// <summary>解密失敗</summary>
  DecryptionFailed,
  /// <summary>資料庫讀取失敗</summary>
  DatabaseReadFailed
}

/// <summary>
/// 文字檔案解析錯誤
/// </summary>
public class TextFileException : Exception {
  /// <summary>
  /// 錯誤類型
  /// </summary>
  public TextFileErrorType ErrorType { get; }

  /// <summary>
  /// 以指定訊息和錯誤類型初始化文字檔案錯誤
  /// </summary>
  /// <param name="message">錯誤訊息</param>
  /// <param name="errorType">錯誤類型</param>
  public TextFileException(string message, TextFileErrorType errorType)
      : base($"{errorType}: {message}") {
    ErrorType = errorType;
  }

  /// <summary>
  /// 以指定訊息、錯誤類型和內部例外初始化文字檔案錯誤
  /// </summary>
  /// <param name="message">錯誤訊息</param>
  /// <param name="errorType">錯誤類型</param>
  /// <param name="innerException">造成此錯誤的內部例外</param>
  public TextFileException(string message, TextFileErrorType errorType, Exception innerException)
      : base($"{errorType}: {message}", innerException) {
    ErrorType = errorType;
  }
}
