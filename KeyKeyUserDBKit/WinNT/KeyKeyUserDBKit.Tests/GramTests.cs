// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using Xunit;

namespace KeyKeyUserDBKit.Tests;

public class GramTests {
  [Fact]
  public void CreateUnigram_ShouldSetCorrectProperties() {
    var keyArray = new[] { "ㄋㄧˇ", "ㄏㄠˇ" };
    var current = "你好";
    var probability = 0.5;

    var gram = Gram.CreateUnigram(keyArray, current, probability);

    Assert.Equal(keyArray, gram.KeyArray);
    Assert.Equal(current, gram.Current);
    Assert.Null(gram.Previous);
    Assert.Equal(probability, gram.Probability);
    Assert.False(gram.IsCandidateOverride);
    Assert.True(gram.IsUnigram);
  }

  [Fact]
  public void CreateBigram_ShouldSetCorrectProperties() {
    var keyArray = new[] { "ㄏㄠˇ" };
    var current = "好";
    var previous = "你";

    var gram = Gram.CreateBigram(keyArray, current, previous);

    Assert.Equal(keyArray, gram.KeyArray);
    Assert.Equal(current, gram.Current);
    Assert.Equal(previous, gram.Previous);
    Assert.Equal(0, gram.Probability);
    Assert.False(gram.IsCandidateOverride);
    Assert.False(gram.IsUnigram);
  }

  [Fact]
  public void CreateBigram_WithEmptyPrevious_ShouldSetPreviousToNull() {
    var gram = Gram.CreateBigram(["ㄏㄠˇ"], "好", "");
    Assert.Null(gram.Previous);
    Assert.True(gram.IsUnigram);
  }

  [Fact]
  public void CreateCandidateOverride_ShouldSetCorrectProperties() {
    var keyArray = new[] { "ㄋㄧˇ" };
    var current = "妳";
    var probability = 114.514;

    var gram = Gram.CreateCandidateOverride(keyArray, current, probability);

    Assert.Equal(keyArray, gram.KeyArray);
    Assert.Equal(current, gram.Current);
    Assert.Null(gram.Previous);
    Assert.Equal(probability, gram.Probability);
    Assert.True(gram.IsCandidateOverride);
  }

  [Fact]
  public void IsReadingMismatched_WhenLengthsDiffer_ShouldReturnTrue() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ", "ㄏㄠˇ"], "你好嗎"); // 2 keys, 3 chars
    Assert.True(gram.IsReadingMismatched);
  }

  [Fact]
  public void IsReadingMismatched_WhenLengthsMatch_ShouldReturnFalse() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ", "ㄏㄠˇ"], "你好"); // 2 keys, 2 chars
    Assert.False(gram.IsReadingMismatched);
  }

  [Fact]
  public void SegLength_ShouldReturnKeyArrayLength() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ", "ㄏㄠˇ", "ㄇㄚ"], "你好嗎");
    Assert.Equal(3, gram.SegLength);
  }

  [Fact]
  public void AsTuple_ShouldReturnCorrectTuple() {
    var gram = Gram.CreateBigram(["ㄏㄠˇ"], "好", "你");
    var tuple = gram.AsTuple;

    Assert.Equal(["ㄏㄠˇ"], tuple.KeyArray);
    Assert.Equal("好", tuple.Value);
    Assert.Equal(0, tuple.Probability);
    Assert.Equal("你", tuple.Previous);
  }

  [Fact]
  public void DescriptionSansReading_Unigram_ShouldFormatCorrectly() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);
    Assert.Equal("P(你)=0.5", gram.DescriptionSansReading);
  }

  [Fact]
  public void DescriptionSansReading_Bigram_ShouldFormatCorrectly() {
    var gram = Gram.CreateBigram(["ㄏㄠˇ"], "好", "你");
    Assert.Equal("P(好|你)=0", gram.DescriptionSansReading);
  }

  [Fact]
  public void DescriptionSansReading_CandidateOverride_ShouldFormatCorrectly() {
    var gram = Gram.CreateCandidateOverride(["ㄋㄧˇ"], "妳", 114.514);
    Assert.Equal("P(妳)", gram.DescriptionSansReading);
  }

  [Fact]
  public void Describe_ShouldIncludeHeaderAndBody() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);
    var description = gram.Describe();

    Assert.Contains("[Unigram]", description);
    Assert.Contains("ㄋㄧˇ", description);
    Assert.Contains("P(你)=0.5", description);
  }

  [Fact]
  public void ToString_ShouldCallDescribe() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);
    Assert.Equal(gram.Describe(), gram.ToString());
  }

  [Fact]
  public void Equality_SameValues_ShouldBeEqual() {
    var gram1 = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);
    var gram2 = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);

    Assert.True(gram1.Equals(gram2));
    Assert.Equal(gram1.GetHashCode(), gram2.GetHashCode());
  }

  [Fact]
  public void Equality_DifferentValues_ShouldNotBeEqual() {
    var gram1 = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);
    var gram2 = Gram.CreateUnigram(["ㄋㄧˇ"], "妳", 0.5);

    Assert.False(gram1.Equals(gram2));
  }

  [Fact]
  public void Equality_WithNull_ShouldNotBeEqual() {
    var gram = Gram.CreateUnigram(["ㄋㄧˇ"], "你", 0.5);
    Assert.False(gram.Equals(null));
  }
}
