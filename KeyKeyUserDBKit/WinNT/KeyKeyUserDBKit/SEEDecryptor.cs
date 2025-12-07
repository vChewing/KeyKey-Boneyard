// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using System.Security.Cryptography;

namespace KeyKeyUserDBKit;

/// <summary>
/// Yahoo! 奇摩輸入法 (KeyKey) 使用者資料庫解密器
///
/// 此解密器可解密 SmartMandarinUserData.db 等使用 SQLite SEE AES-128 加密的資料庫。
///
/// ## 加密方式分析
/// - 使用 SQLite SEE (SQLite Encryption Extension) with AES-128
/// - Page size: 1024 bytes
/// - Reserved bytes per page: 32 bytes (16 bytes nonce + 16 bytes MAC)
/// - 加密範圍：每頁的前 992 bytes (data area)
/// - Page 1 的 bytes 16-23 是未加密的 (SQLite header 格式資訊)
///
/// ## Keystream 產生方式
/// - AES-128-ECB(key, counter_block)
/// - counter_block 結構：nonce 的副本，但 bytes 4-7 是 4-byte little-endian counter
/// - Counter 從 nonce[4:8] 的原始值開始，每個 16-byte block 遞增 1
/// </summary>
public sealed class SEEDecryptor : IDisposable {
  // MARK: - Constants

  /// <summary>
  /// AES-128 密鑰長度
  /// </summary>
  public const int KeySize = 16;

  /// <summary>
  /// 頁面大小
  /// </summary>
  public const int PageSize = 1024;

  /// <summary>
  /// 保留區域大小 (nonce + MAC)
  /// </summary>
  public const int ReservedBytes = 32;

  /// <summary>
  /// 資料區域大小
  /// </summary>
  public const int DataAreaSize = PageSize - ReservedBytes; // 992 bytes

  /// <summary>
  /// 預設密鑰 (前 16 bytes of "yahookeykeyuserdb")
  /// </summary>
  public static readonly byte[] DefaultKey = "yahookeykeyuserdb"u8.ToArray()[..KeySize];

  /// <summary>
  /// SQLite 資料庫魔術數字
  /// </summary>
  private static readonly byte[] SqliteMagic = "SQLite format 3\0"u8.ToArray();

  private readonly byte[] _key;
  private readonly Aes _aes;
  private bool _disposed;

  // MARK: - Constructors

  /// <summary>
  /// 使用預設密鑰初始化解密器
  /// </summary>
  public SEEDecryptor() : this(DefaultKey) {
  }

  /// <summary>
  /// 使用自訂密鑰初始化解密器
  /// </summary>
  /// <param name="key">16 bytes AES-128 密鑰</param>
  public SEEDecryptor(byte[] key) {
    if (key.Length != KeySize)
      throw new ArgumentException($"Key must be {KeySize} bytes for AES-128", nameof(key));

    _key = key;
    _aes = Aes.Create();
    _aes.Key = _key;
    _aes.Mode = CipherMode.ECB;
    _aes.Padding = PaddingMode.None;
  }

  // MARK: - Static Methods

  /// <summary>
  /// 檢查資料庫檔案是否為加密的（非標準 SQLite 格式）
  /// </summary>
  /// <param name="filePath">資料庫檔案路徑</param>
  /// <returns>如果檔案是加密的回傳 true，否則回傳 false</returns>
  public static bool IsEncryptedDatabase(string filePath) {
    if (!File.Exists(filePath))
      return false;

    try {
      using var fs = File.OpenRead(filePath);
      var header = new byte[SqliteMagic.Length];
      var bytesRead = fs.Read(header, 0, header.Length);

      if (bytesRead < SqliteMagic.Length)
        return true; // 檔案太小，可能是加密的

      // 如果開頭不是 SQLite 魔術數字，則是加密的
      return !header.AsSpan().SequenceEqual(SqliteMagic);
    } catch {
      return true; // 無法讀取，假設是加密的
    }
  }

  // MARK: - Public Methods

  /// <summary>
  /// 解密整個資料庫檔案
  /// </summary>
  /// <param name="encryptedData">加密的資料庫二進位資料</param>
  /// <returns>解密後的資料庫二進位資料</returns>
  /// <exception cref="DecryptionException">如果解密失敗</exception>
  public byte[] Decrypt(byte[] encryptedData) {
    ObjectDisposedException.ThrowIf(_disposed, this);

    if (encryptedData.Length % PageSize != 0)
      throw new DecryptionException(
          $"Invalid database size: expected multiple of {PageSize}, got {encryptedData.Length} bytes");

    var numPages = encryptedData.Length / PageSize;
    var output = new MemoryStream(encryptedData.Length);

    for (var pageNum = 0; pageNum < numPages; pageNum++) {
      var pageStart = pageNum * PageSize;
      var pageData = encryptedData.AsSpan(pageStart, PageSize);

      var decryptedData = DecryptPage(pageData);

      if (pageNum == 0) {
        // Page 0 特殊處理：bytes 16-23 是未加密的
        output.Write(decryptedData.AsSpan(0, 16));
        output.Write(pageData.Slice(16, 8));
        output.Write(decryptedData.AsSpan(24));
      } else {
        output.Write(decryptedData);
      }

      // Reserved area 填充零
      output.Write(new byte[ReservedBytes]);
    }

    return output.ToArray();
  }

  /// <summary>
  /// 從檔案解密資料庫
  /// </summary>
  /// <param name="inputPath">加密資料庫檔案路徑</param>
  /// <param name="outputPath">輸出解密資料庫檔案路徑</param>
  public void DecryptFile(string inputPath, string outputPath) {
    var encryptedData = File.ReadAllBytes(inputPath);
    var decryptedData = Decrypt(encryptedData);
    File.WriteAllBytes(outputPath, decryptedData);
  }

  /// <summary>
  /// 非同步從檔案解密資料庫
  /// </summary>
  public async Task DecryptFileAsync(string inputPath, string outputPath,
      CancellationToken cancellationToken = default) {
    var encryptedData = await File.ReadAllBytesAsync(inputPath, cancellationToken);
    var decryptedData = Decrypt(encryptedData);
    await File.WriteAllBytesAsync(outputPath, decryptedData, cancellationToken);
  }

  // MARK: - Private Methods

  /// <summary>
  /// 解密單一頁面
  /// </summary>
  private byte[] DecryptPage(ReadOnlySpan<byte> page) {
    if (page.Length != PageSize)
      throw new DecryptionException($"Invalid page size: expected {PageSize}, got {page.Length}");

    // Nonce 是頁面的最後 16 bytes
    var nonce = page.Slice(PageSize - 16, 16).ToArray();

    // Counter 是 4 bytes，little-endian，位於 nonce 的 bytes 4-7
    var baseCounter = BitConverter.ToUInt32(nonce, 4);

    var decrypted = new byte[DataAreaSize];
    var numBlocks = (DataAreaSize + 15) / 16; // 62 blocks

    using var encryptor = _aes.CreateEncryptor();
    var counterBlock = new byte[16];
    var keystream = new byte[16];

    for (var blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
      // 建構 counter block
      Array.Copy(nonce, counterBlock, 16);
      var newCounter = baseCounter + (uint)blockIdx;
      BitConverter.TryWriteBytes(counterBlock.AsSpan(4), newCounter);

      // 產生 keystream (AES-ECB encrypt counter block)
      encryptor.TransformBlock(counterBlock, 0, 16, keystream, 0);

      // XOR 解密
      var start = blockIdx * 16;
      var end = Math.Min(start + 16, DataAreaSize);

      for (var i = start; i < end; i++) {
        decrypted[i] = (byte)(page[i] ^ keystream[i - start]);
      }
    }

    return decrypted;
  }

  /// <inheritdoc/>
  public void Dispose() {
    if (_disposed) return;
    _aes.Dispose();
    _disposed = true;
  }
}

/// <summary>
/// 解密錯誤
/// </summary>
public class DecryptionException : Exception {
  /// <summary>
  /// 以指定訊息初始化解密錯誤
  /// </summary>
  /// <param name="message">錯誤訊息</param>
  public DecryptionException(string message) : base(message) {
  }

  /// <summary>
  /// 以指定訊息和內部例外初始化解密錯誤
  /// </summary>
  /// <param name="message">錯誤訊息</param>
  /// <param name="innerException">造成此錯誤的內部例外</param>
  public DecryptionException(string message, Exception innerException)
      : base(message, innerException) {
  }
}
