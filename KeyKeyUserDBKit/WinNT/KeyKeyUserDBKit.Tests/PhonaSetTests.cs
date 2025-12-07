// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using Xunit;

namespace KeyKeyUserDBKit.Tests;

public class PhonaSetTests {
  [Theory]
  [InlineData("fa", "ㄍㄨㄛˋ")] // 過
  [InlineData("kM", "ㄖㄨㄥˊ")] // 融
  [InlineData("6C", "ㄏㄜˊ")] // 合
  [InlineData("Q;", "ㄧㄣ")] // 音
  [InlineData("=M", "ㄔㄥˊ")] // 程
  public void TestAbsoluteOrderString(string input, string expected) {
    var phonaSet = PhonaSet.FromAbsoluteOrderString(input);
    Assert.NotNull(phonaSet);
    Assert.Equal(expected, phonaSet!.Value.ToString());
  }

  [Fact]
  public void TestDecodeQString_Unigram() {
    // 測試 unigram 格式
    var qstring = "fakM6CQ;=M"; // 過融合音程
    var result = PhonaSet.DecodeQueryString(qstring);
    Assert.Equal("ㄍㄨㄛˋ,ㄖㄨㄥˊ,ㄏㄜˊ,ㄧㄣ,ㄔㄥˊ", result);
  }

  [Fact]
  public void TestDecodeQString_ShortUnigram() {
    // 測試 4 字元的 unigram (2 個音節)
    // "複調" 的 qstring 是 "O_yf" (ㄈㄨˋ,ㄉㄧㄠˋ)
    var qstring = "O_yf";
    var result = PhonaSet.DecodeQueryString(qstring);
    Assert.Equal("ㄈㄨˋ,ㄉㄧㄠˋ", result);
  }

  [Fact]
  public void TestComponentToChar() {
    // 測試基本的聲母
    var phonaSet = new PhonaSet(PhonaSet.Consonant.ㄅ, null, PhonaSet.Vowel.ㄚ, PhonaSet.Intonation.First);
    Assert.Equal("ㄅㄚ", phonaSet.ToString()); // 八 (陰平不標)

    // 測試二聲
    var phonaSet2 = new PhonaSet(PhonaSet.Consonant.ㄇ, null, PhonaSet.Vowel.ㄚ, PhonaSet.Intonation.Second);
    Assert.Equal("ㄇㄚˊ", phonaSet2.ToString()); // 麻

    // 測試含介音
    var phonaSet3 = new PhonaSet(PhonaSet.Consonant.ㄍ, PhonaSet.Semivowel.ㄨ, PhonaSet.Vowel.ㄛ, PhonaSet.Intonation.Fourth);
    Assert.Equal("ㄍㄨㄛˋ", phonaSet3.ToString()); // 過
  }

  [Fact]
  public void TestInvalidInput() {
    // 測試無效輸入
    Assert.Null(PhonaSet.FromAbsoluteOrderString("a")); // 太短
    Assert.Null(PhonaSet.FromAbsoluteOrderString("abc")); // 太長

    // 奇數長度的 qstring 應該回傳原字串
    var oddString = "abc";
    Assert.Equal(oddString, PhonaSet.DecodeQueryString(oddString));
  }

  [Fact]
  public void FromAbsoluteOrderString_InvalidLength_ShouldReturnNull() {
    Assert.Null(PhonaSet.FromAbsoluteOrderString(""));
    Assert.Null(PhonaSet.FromAbsoluteOrderString("a"));
    Assert.Null(PhonaSet.FromAbsoluteOrderString("abc"));
  }

  [Fact]
  public void FromAbsoluteOrderString_ValidString_ShouldReturnPhonaSet() {
    var result = PhonaSet.FromAbsoluteOrderString("00");
    Assert.NotNull(result);
  }

  [Fact]
  public void DecodeQueryStringAsKeyArray_BigramFormat_ShouldDecodeLastPart() {
    // 測試 bigram 格式（以 ~ 開頭且含空格）
    var result = PhonaSet.DecodeQueryStringAsKeyArray("~00 00");
    Assert.NotEmpty(result);
  }

  [Fact]
  public void DecodeQueryStringAsKeyArray_UnigramFormat_ShouldReturnArray() {
    var result = PhonaSet.DecodeQueryStringAsKeyArray("0000");
    Assert.NotNull(result);
  }

  // ~ 開頭的 Unigram 測試
  // 這些 qstring 恰好以 ~ (ASCII 126) 作為第一個字元的低位元組，
  // 但它們不是 bigram 格式（沒有空格分隔符）
  [Theory]
  [InlineData("~_]O", new[] { "ㄋㄚˋ", "ㄌㄧˇ" })] // 那裡
  [InlineData("~_3_", new[] { "ㄋㄚˋ", "ㄘˋ" })] // 那次
  [InlineData("~_XO", new[] { "ㄋㄚˋ", "ㄇㄧˇ" })] // 納米
  [InlineData("~@U:", new[] { "ㄧㄚˊ", "ㄑㄧㄢ" })] // 牙籤
  [InlineData("~\\cH", new[] { "ㄐㄧㄥˇ", "ㄏㄡˊ" })] // 儆猴
  [InlineData("~=KP6CJ1", new[] { "ㄉㄨㄥ", "ㄇㄚˇ", "ㄏㄜˊ", "ㄕㄚ" })] // 冬馬和紗
  [InlineData("~=ZX01", new[] { "ㄉㄨㄥ", "ㄐㄧㄡˇ", "ㄑㄩ" })] // 東九區
  [InlineData("~7]K", new[] { "ㄓㄠ", "ㄩㄣˊ" })] // 朝雲
  [InlineData("~Ip4", new[] { "ㄋㄧㄢˊ", "ㄊㄧㄝ" })] // 粘貼
  [InlineData("~Jc=", new[] { "ㄘㄣˊ", "ㄧㄥ" })] // 岑纓
  public void DecodeUnigramStartingWithTilde_ShouldDecodeCorrectly(string input, string[] expected) {
    var result = PhonaSet.DecodeQueryStringAsKeyArray(input);
    Assert.Equal(expected, result);
  }

  // CandidateOverride Tests
  // user_candidate_override_cache 表中的 qstring 是純 2 字元編碼，無前綴
  [Theory]
  [InlineData("}g", new[] { "ㄧㄡˋ" })] // 又
  [InlineData("}l", new[] { "ㄙㄨㄥˋ" })] // 送
  [InlineData("~\\", new[] { "ㄐㄧㄥˇ" })] // 井
  public void DecodeCandidateOverrideQstring_ShouldDecodeCorrectly(string input, string[] expected) {
    var result = PhonaSet.DecodeQueryStringAsKeyArray(input);
    Assert.Equal(expected, result);
  }

  [Theory]
  [InlineData(PhonaSet.Consonant.ㄅ, '\u3105')]
  [InlineData(PhonaSet.Consonant.ㄆ, '\u3106')]
  [InlineData(PhonaSet.Consonant.ㄇ, '\u3107')]
  public void Consonant_ShouldMapToCorrectUnicode(PhonaSet.Consonant consonant, char expectedChar) {
    var phonaSet = new PhonaSet(consonant);
    var result = phonaSet.ToString();
    Assert.Contains(expectedChar, result);
  }

  [Fact]
  public void Equality_SameValues_ShouldBeEqual() {
    var a = new PhonaSet(100);
    var b = new PhonaSet(100);

    Assert.Equal(a, b);
    Assert.True(a == b);
    Assert.False(a != b);
    Assert.Equal(a.GetHashCode(), b.GetHashCode());
  }

  [Fact]
  public void Equality_DifferentValues_ShouldNotBeEqual() {
    var a = new PhonaSet(100);
    var b = new PhonaSet(200);

    Assert.NotEqual(a, b);
    Assert.False(a == b);
    Assert.True(a != b);
  }
}
