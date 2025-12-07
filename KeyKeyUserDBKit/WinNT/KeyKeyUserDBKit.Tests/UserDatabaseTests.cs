// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using Xunit;

namespace KeyKeyUserDBKit.Tests;

public class UserDatabaseTests : IDisposable {
  private readonly string _decryptedDbPath;

  public UserDatabaseTests() {
    var encryptedPath = Path.Combine(AppContext.BaseDirectory, "TestAssets", "SmartMandarinUserData.db");

    // 解密到臨時目錄
    var tempPath = Path.Combine(Path.GetTempPath(), $"decrypted_test_{Guid.NewGuid()}.db");

    using var decryptor = new SEEDecryptor();
    decryptor.DecryptFile(encryptedPath, tempPath);

    _decryptedDbPath = tempPath;
  }

  public void Dispose() {
    // 在 Windows 上，SQLite 連線可能需要一點時間才能完全釋放檔案鎖定
    // 嘗試多次刪除，失敗則忽略
    for (var i = 0; i < 3; i++) {
      try {
        if (File.Exists(_decryptedDbPath)) {
          File.Delete(_decryptedDbPath);
        }
        break;
      } catch (IOException) {
        if (i < 2) {
          Thread.Sleep(100); // 等待 100ms 後重試
        }
        // 最後一次失敗則忽略，留給系統清理臨時檔案
      }
    }
  }

  [Fact]
  public void TestDatabaseOpen() {
    using var db = new UserDatabase(_decryptedDbPath);
    Assert.NotNull(db);
  }

  [Fact]
  public void TestFetchUnigrams() {
    using var db = new UserDatabase(_decryptedDbPath);
    var unigrams = db.FetchUnigrams();

    // 驗證回傳的是 Unigram
    Assert.All(unigrams, gram => {
      Assert.True(gram.IsUnigram);
      Assert.NotEmpty(gram.KeyArray);
      Assert.NotEmpty(gram.Current);
      Assert.Null(gram.Previous);
      Assert.False(gram.IsCandidateOverride);
    });
  }

  [Fact]
  public void TestFetchBigrams() {
    using var db = new UserDatabase(_decryptedDbPath);
    var bigrams = db.FetchBigrams();

    // 驗證 Bigram 有 Previous
    Assert.All(bigrams, gram => {
      Assert.NotEmpty(gram.KeyArray);
      Assert.NotEmpty(gram.Current);
      Assert.NotNull(gram.Previous);
      Assert.False(gram.IsCandidateOverride);
    });
  }

  [Fact]
  public void TestFetchBigramsWithLimit() {
    using var db = new UserDatabase(_decryptedDbPath);
    var allBigrams = db.FetchBigrams();
    var limitedBigrams = db.FetchBigrams(5);

    if (allBigrams.Count > 5) {
      Assert.Equal(5, limitedBigrams.Count);
    } else {
      Assert.Equal(allBigrams.Count, limitedBigrams.Count);
    }
  }

  [Fact]
  public void TestFetchCandidateOverrides() {
    using var db = new UserDatabase(_decryptedDbPath);
    var overrides = db.FetchCandidateOverrides();

    // 驗證 CandidateOverride 的特性
    Assert.All(overrides, gram => {
      Assert.NotEmpty(gram.KeyArray);
      Assert.NotEmpty(gram.Current);
      Assert.True(gram.IsCandidateOverride);
      Assert.Equal(UserDatabase.CandidateOverrideProbability, gram.Probability);
    });
  }

  [Fact]
  public void TestFetchAllGrams() {
    using var db = new UserDatabase(_decryptedDbPath);

    var unigrams = db.FetchUnigrams();
    var bigrams = db.FetchBigrams();
    var overrides = db.FetchCandidateOverrides();
    var allGrams = db.FetchAllGrams();

    // 驗證總數
    var expectedCount = unigrams.Count + bigrams.Count + overrides.Count;
    Assert.Equal(expectedCount, allGrams.Count);
  }

  [Fact]
  public void TestGramKeyArrayDecoding() {
    using var db = new UserDatabase(_decryptedDbPath);
    var unigrams = db.FetchUnigrams();

    // 驗證 keyArray 中的注音符號格式正確
    foreach (var gram in unigrams.Take(10)) {
      foreach (var key in gram.KeyArray) {
        // 注音符號應包含 ㄅ-ㄩ 範圍的字元
        var containsBopomofo = key.Any(c =>
            (c >= '\u3105' && c <= '\u3129') || // 注音符號 ㄅ-ㄩ
            (c >= '\u02CA' && c <= '\u02CB') || // 聲調符號 ˊˋ
            c == '\u02C7' || // ˇ
            c == '\u02D9'    // ˙
        );
        Assert.True(containsBopomofo, $"keyArray 應包含注音符號：{key}");
      }
    }
  }

  [Fact]
  public void TestCandidateOverrideProbabilityValue() {
    Assert.Equal(114.514, UserDatabase.CandidateOverrideProbability);
  }

  [Fact]
  public void TestDatabaseOpenFailure() {
    Assert.Throws<DatabaseException>(() => new UserDatabase("/nonexistent/path/to/database.db"));
  }

  // MARK: - Sequence Iterator Tests

  [Fact]
  public void TestSequenceIteration() {
    using var db = new UserDatabase(_decryptedDbPath);

    var iteratedGrams = new List<Gram>();
    foreach (var gram in db) {
      iteratedGrams.Add(gram);
    }

    var allGrams = db.FetchAllGrams();
    Assert.Equal(allGrams.Count, iteratedGrams.Count);
  }

  [Fact]
  public void TestSequenceForEach() {
    using var db = new UserDatabase(_decryptedDbPath);

    var count = 0;
    var unigramCount = 0;
    var bigramCount = 0;
    var candidateOverrideCount = 0;

    foreach (var gram in db) {
      count++;
      if (gram.IsCandidateOverride) {
        candidateOverrideCount++;
      } else if (gram.Previous != null) {
        bigramCount++;
      } else {
        unigramCount++;
      }
    }

    Assert.True(count > 0, "應至少有一筆資料");
    Assert.Equal(count, unigramCount + bigramCount + candidateOverrideCount);
  }

  [Fact]
  public void TestSequenceIteratorMultipleTimes() {
    using var db = new UserDatabase(_decryptedDbPath);

    // 第一次迭代
    var firstCount = db.Count();

    // 第二次迭代
    var secondCount = db.Count();

    Assert.Equal(firstCount, secondCount);
  }

  [Fact]
  public void TestSequenceIteratorGramTypes() {
    using var db = new UserDatabase(_decryptedDbPath);

    var unigramCount = 0;
    var bigramCount = 0;
    var candidateOverrideCount = 0;

    foreach (var gram in db) {
      if (gram.IsCandidateOverride) {
        candidateOverrideCount++;
        Assert.Equal(UserDatabase.CandidateOverrideProbability, gram.Probability);
      } else if (gram.Previous != null) {
        bigramCount++;
      } else {
        unigramCount++;
      }
    }

    var unigrams = db.FetchUnigrams();
    var bigrams = db.FetchBigrams();
    var overrides = db.FetchCandidateOverrides();

    Assert.Equal(unigrams.Count, unigramCount);
    Assert.Equal(bigrams.Count, bigramCount);
    Assert.Equal(overrides.Count, candidateOverrideCount);
  }

  // MARK: - AsyncSequence Iterator Tests

  [Fact]
  public async Task TestAsyncSequenceIteration() {
    using var db = new UserDatabase(_decryptedDbPath);

    var iteratedGrams = new List<Gram>();
    await foreach (var gram in db) {
      iteratedGrams.Add(gram);
    }

    var allGrams = db.FetchAllGrams();
    Assert.Equal(allGrams.Count, iteratedGrams.Count);
  }

  [Fact]
  public async Task TestAsyncSequenceGramTypes() {
    using var db = new UserDatabase(_decryptedDbPath);

    var unigramCount = 0;
    var bigramCount = 0;
    var candidateOverrideCount = 0;

    await foreach (var gram in db) {
      if (gram.IsCandidateOverride) {
        candidateOverrideCount++;
        Assert.Equal(UserDatabase.CandidateOverrideProbability, gram.Probability);
      } else if (gram.Previous != null) {
        bigramCount++;
      } else {
        unigramCount++;
      }
    }

    var unigrams = db.FetchUnigrams();
    var bigrams = db.FetchBigrams();
    var overrides = db.FetchCandidateOverrides();

    Assert.Equal(unigrams.Count, unigramCount);
    Assert.Equal(bigrams.Count, bigramCount);
    Assert.Equal(overrides.Count, candidateOverrideCount);
  }

  [Fact]
  public async Task TestAsyncSequenceMultipleIterations() {
    using var db = new UserDatabase(_decryptedDbPath);

    // 第一次非同步迭代
    var firstCount = 0;
    await foreach (var _ in db) {
      firstCount++;
    }

    // 第二次非同步迭代
    var secondCount = 0;
    await foreach (var _ in db) {
      secondCount++;
    }

    Assert.Equal(firstCount, secondCount);
  }

  [Fact]
  public async Task TestAsyncAndSyncIteratorConsistency() {
    using var db = new UserDatabase(_decryptedDbPath);

    // 同步迭代
    var syncGrams = db.ToList();

    // 非同步迭代
    var asyncGrams = new List<Gram>();
    await foreach (var gram in db) {
      asyncGrams.Add(gram);
    }

    Assert.Equal(syncGrams.Count, asyncGrams.Count);

    // 驗證內容一致（比較前幾筆）
    var compareCount = Math.Min(10, syncGrams.Count);
    for (var i = 0; i < compareCount; i++) {
      Assert.Equal(syncGrams[i].KeyArray, asyncGrams[i].KeyArray);
      Assert.Equal(syncGrams[i].Current, asyncGrams[i].Current);
      Assert.Equal(syncGrams[i].Previous, asyncGrams[i].Previous);
      Assert.Equal(syncGrams[i].IsCandidateOverride, asyncGrams[i].IsCandidateOverride);
    }
  }
}

