// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using Xunit;

namespace KeyKeyUserDBKit.Tests;

public class SEEDecryptorTests {
  // MARK: - Swift 對齊測試

  /// <summary>
  /// 測試預設密鑰是 "yahookeykeyuserd" (16 字元)
  /// Swift 對應: testDefaultKey
  /// </summary>
  [Fact]
  public void TestDefaultKey() {
    Assert.Equal(16, SEEDecryptor.DefaultKey.Length);
    var expectedKey = "yahookeykeyuserdb"u8.ToArray()[..16];
    Assert.Equal(expectedKey, SEEDecryptor.DefaultKey);
  }

  /// <summary>
  /// 測試常數
  /// Swift 對應: testConstants
  /// </summary>
  [Fact]
  public void TestConstants() {
    Assert.Equal(16, SEEDecryptor.KeySize);
    Assert.Equal(1024, SEEDecryptor.PageSize);
    Assert.Equal(32, SEEDecryptor.ReservedBytes);
    Assert.Equal(992, SEEDecryptor.DataAreaSize);
  }

  /// <summary>
  /// 測試無效的資料（不是 pageSize 的倍數）
  /// Swift 對應: testInvalidSize
  /// </summary>
  [Fact]
  public void TestInvalidSize() {
    using var decryptor = new SEEDecryptor();
    var invalidData = new byte[100]; // 不是 1024 的倍數

    Assert.Throws<DecryptionException>(() => decryptor.Decrypt(invalidData));
  }

  /// <summary>
  /// 測試空資料
  /// Swift 對應: testEmptyData
  /// </summary>
  [Fact]
  public void TestEmptyData() {
    using var decryptor = new SEEDecryptor();
    var result = decryptor.Decrypt([]);

    Assert.Empty(result);
  }

  // MARK: - C# 額外測試

  [Fact]
  public void Constructor_WithDefaultKey_ShouldSucceed() {
    using var decryptor = new SEEDecryptor();
    Assert.NotNull(decryptor);
  }

  [Fact]
  public void Constructor_WithValidKey_ShouldSucceed() {
    var key = new byte[16];
    using var decryptor = new SEEDecryptor(key);
    Assert.NotNull(decryptor);
  }

  [Fact]
  public void Constructor_WithInvalidKeyLength_ShouldThrow() {
    var key = new byte[8]; // 錯誤長度
    Assert.Throws<ArgumentException>(() => new SEEDecryptor(key));
  }

  [Fact]
  public void Decrypt_SinglePage_ShouldReturnCorrectSize() {
    using var decryptor = new SEEDecryptor();
    var singlePage = new byte[SEEDecryptor.PageSize];

    var result = decryptor.Decrypt(singlePage);

    Assert.Equal(SEEDecryptor.PageSize, result.Length);
  }

  [Fact]
  public void Dispose_MultipleTimes_ShouldNotThrow() {
    var decryptor = new SEEDecryptor();
    decryptor.Dispose();
    decryptor.Dispose(); // 不應拋出例外
  }

  [Fact]
  public void Decrypt_AfterDispose_ShouldThrow() {
    var decryptor = new SEEDecryptor();
    decryptor.Dispose();

    Assert.Throws<ObjectDisposedException>(() => decryptor.Decrypt(new byte[SEEDecryptor.PageSize]));
  }
}
