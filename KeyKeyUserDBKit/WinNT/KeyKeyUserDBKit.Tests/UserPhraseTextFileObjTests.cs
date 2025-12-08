// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using Xunit;

namespace KeyKeyUserDBKit.Tests;

public class UserPhraseTextFileObjTests : IDisposable {
  // 基於 parse_database_block.py 的預期結果
  private const int ExpectedUnigramCount = 104;
  private const int ExpectedBigramCount = 4;
  private const int ExpectedCandidateOverrideCount = 3;

  // 預期的 bigrams（來自 Python 解析結果）
  private static readonly (string[] KeyArray, string Previous, string Current)[] ExpectedBigrams = [
    (["ㄉㄧㄥ"], "給", "盯"),
    (["ㄒㄧㄢ"], "那", "先"),
    (["ㄗˋ"], "用", "字"),
    (["ㄐㄧㄡˋ"], "用", "就"),
  ];

  // 預期的 candidate overrides
  private static readonly (string[] KeyArray, string Current)[] ExpectedCandidateOverrides = [
    (["ㄧㄡˋ"], "又"),
    (["ㄙㄨㄥˋ"], "送"),
    (["ㄐㄧㄥˇ"], "井"),
  ];

  private readonly string _textFilePath;
  private UserPhraseTextFileObj? _textFile;

  public UserPhraseTextFileObjTests() {
    _textFilePath = Path.Combine(AppContext.BaseDirectory, "TestAssets", "KimoOfficialOutputDataText.txt");
  }

  public void Dispose() {
    _textFile?.Dispose();
  }

  [Fact]
  public void ShouldParseMjsrFileHeader() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    Assert.StartsWith("MJSR version", textFile.Version);
  }

  [Fact]
  public void ShouldParseUnigramsCorrectly() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    var unigrams = textFile.FetchUnigrams();

    Assert.Equal(ExpectedUnigramCount, unigrams.Count);

    // 檢查所有 unigrams 都是 Unigram 類型
    foreach (var gram in unigrams) {
      Assert.True(gram.IsUnigram);
      Assert.False(gram.IsCandidateOverride);
    }
  }

  [Fact]
  public void ShouldParseBigramsCorrectly() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    var bigrams = textFile.FetchBigrams();

    Assert.Equal(ExpectedBigramCount, bigrams.Count);

    // 驗證 bigrams 的內容
    for (var idx = 0; idx < ExpectedBigrams.Length; idx++) {
      var expected = ExpectedBigrams[idx];
      Assert.Equal(expected.KeyArray, bigrams[idx].KeyArray);
      Assert.Equal(expected.Previous, bigrams[idx].Previous);
      Assert.Equal(expected.Current, bigrams[idx].Current);
      Assert.False(bigrams[idx].IsUnigram);
    }
  }

  [Fact]
  public void ShouldParseCandidateOverridesCorrectly() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    var overrides = textFile.FetchCandidateOverrides();

    Assert.Equal(ExpectedCandidateOverrideCount, overrides.Count);

    // 驗證 candidate overrides 的內容
    for (var idx = 0; idx < ExpectedCandidateOverrides.Length; idx++) {
      var expected = ExpectedCandidateOverrides[idx];
      Assert.Equal(expected.KeyArray, overrides[idx].KeyArray);
      Assert.Equal(expected.Current, overrides[idx].Current);
      Assert.True(overrides[idx].IsCandidateOverride);
      Assert.Equal(UserPhraseTextFileObj.CandidateOverrideProbability, overrides[idx].Probability);
    }
  }

  [Fact]
  public void FetchAllGramsShouldReturnAllGrams() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    var allGrams = textFile.FetchAllGrams();

    var expectedTotal = ExpectedUnigramCount + ExpectedBigramCount + ExpectedCandidateOverrideCount;
    Assert.Equal(expectedTotal, allGrams.Count);
  }

  [Fact]
  public void FetchBigramsWithLimitShouldRespectLimit() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    var bigrams = textFile.FetchBigrams(limit: 2);

    Assert.Equal(2, bigrams.Count);
  }

  [Fact]
  public void ShouldBeIterableAsEnumerable() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    var count = 0;
    foreach (var _ in textFile) {
      count++;
    }

    var expectedTotal = ExpectedUnigramCount + ExpectedBigramCount + ExpectedCandidateOverrideCount;
    Assert.Equal(expectedTotal, count);
  }

  [Fact]
  public void ShouldConformToIUserPhraseDataSource() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    // 驗證可以作為 IUserPhraseDataSource 使用
    IUserPhraseDataSource source = textFile;
    var count = source.FetchAllGrams().Count;

    var expectedTotal = ExpectedUnigramCount + ExpectedBigramCount + ExpectedCandidateOverrideCount;
    Assert.Equal(expectedTotal, count);
  }

  [Fact]
  public void ShouldWorkWithLinq() {
    var textFile = UserPhraseTextFileObj.FromPath(_textFilePath);
    _textFile = textFile;

    // 先收集所有 Gram 以避免多次列舉
    var allGrams = textFile.ToList();

    // 使用 LINQ 查詢
    var unigramCount = allGrams.Count(g => g.IsUnigram && !g.IsCandidateOverride);
    var bigramCount = allGrams.Count(g => !g.IsUnigram && !g.IsCandidateOverride);
    var overrideCount = allGrams.Count(g => g.IsCandidateOverride);

    Assert.Equal(ExpectedUnigramCount, unigramCount);
    Assert.Equal(ExpectedBigramCount, bigramCount);
    Assert.Equal(ExpectedCandidateOverrideCount, overrideCount);
  }
}
