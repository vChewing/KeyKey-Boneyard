// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using System.Text.Json.Serialization;

namespace KeyKeyUserDBKit;

/// <summary>
/// This is the basic Gram type extracted from our Homa Assembler with no backoff support.
/// </summary>
public sealed record Gram : IEquatable<Gram> {
  /// <summary>
  /// 元圖識別碼。
  /// </summary>
  [JsonPropertyName("keys")]
  public required string[] KeyArray { get; init; }

  /// <summary>
  /// 當前候選字
  /// </summary>
  [JsonPropertyName("curr")]
  public required string Current { get; init; }

  /// <summary>
  /// 前一個候選字（雙元圖時使用）
  /// </summary>
  [JsonPropertyName("prev")]
  public string? Previous { get; init; }

  /// <summary>
  /// 機率權重
  /// </summary>
  [JsonPropertyName("prob")]
  public double Probability { get; init; }

  /// <summary>
  /// 是否為候選字覆蓋
  /// </summary>
  [JsonPropertyName("ovrw")]
  public bool IsCandidateOverride { get; init; }

  /// <summary>
  /// 是否為單元圖 (Unigram)
  /// </summary>
  [JsonIgnore]
  public bool IsUnigram => Previous is null;

  /// <summary>
  /// 檢查是否「讀音字長與候選字字長不一致」。
  /// </summary>
  [JsonIgnore]
  public bool IsReadingMismatched => KeyArray.Length != Current.Length;

  /// <summary>
  /// 幅長。
  /// </summary>
  [JsonIgnore]
  public int SegLength => KeyArray.Length;

  /// <summary>
  /// Raw Tuple 表示形式
  /// </summary>
  public (string[] KeyArray, string Value, double Probability, string? Previous) AsTuple =>
      (KeyArray, Current, Probability, Previous);

  /// <summary>
  /// 不含讀音的描述
  /// </summary>
  [JsonIgnore]
  public string DescriptionSansReading {
    get {
      if (IsCandidateOverride)
        return $"P({Current})"; // 候選覆蓋
      if (Previous is null)
        return $"P({Current})={Probability}"; // 單元圖
      return $"P({Current}|{Previous})={Probability}"; // 雙元圖
    }
  }

  /// <summary>
  /// 描述 Gram 的完整資訊
  /// </summary>
  /// <param name="keySeparator">鍵陣列分隔符號</param>
  /// <returns>格式化的描述字串</returns>
  public string Describe(string keySeparator = "-") {
    var header = IsCandidateOverride ? "[CndOvrw]" : $"[{(IsUnigram ? "Unigram" : "Bigram")}]";
    var body = $"'{string.Join(keySeparator, KeyArray)}', {DescriptionSansReading}";
    return $"{header} {body}";
  }

  /// <inheritdoc/>
  public override string ToString() => Describe();

  /// <inheritdoc/>
  public override int GetHashCode() =>
      HashCode.Combine(
          KeyArray.Aggregate(0, HashCode.Combine),
          Current,
          Previous,
          Probability,
          IsCandidateOverride
      );

  /// <inheritdoc/>
  public bool Equals(Gram? other) {
    if (other is null) return false;
    if (ReferenceEquals(this, other)) return true;
    return KeyArray.SequenceEqual(other.KeyArray)
        && Current == other.Current
        && Previous == other.Previous
        && Probability.Equals(other.Probability)
        && IsCandidateOverride == other.IsCandidateOverride;
  }

  // Factory methods

  /// <summary>
  /// 建立單元圖 (Unigram)
  /// </summary>
  /// <param name="keyArray">注音鍵陣列</param>
  /// <param name="current">當前候選字</param>
  /// <param name="probability">機率權重</param>
  /// <returns>新的 Gram 實例</returns>
  public static Gram CreateUnigram(IEnumerable<string> keyArray, string current, double probability = 0) =>
      new() {
        KeyArray = keyArray.ToArray(),
        Current = current,
        Probability = probability,
        IsCandidateOverride = false
      };

  /// <summary>
  /// 建立雙元圖 (Bigram)
  /// </summary>
  /// <param name="keyArray">注音鍵陣列</param>
  /// <param name="current">當前候選字</param>
  /// <param name="previous">前一個候選字</param>
  /// <param name="probability">機率權重</param>
  /// <returns>新的 Gram 實例</returns>
  public static Gram CreateBigram(IEnumerable<string> keyArray, string current, string previous, double probability = 0) =>
      new() {
        KeyArray = keyArray.ToArray(),
        Current = current,
        Previous = string.IsNullOrEmpty(previous) ? null : previous,
        Probability = probability,
        IsCandidateOverride = false
      };

  /// <summary>
  /// 建立候選字覆蓋記錄 (CandidateOverride)
  /// </summary>
  /// <param name="keyArray">注音鍵陣列</param>
  /// <param name="current">當前候選字</param>
  /// <param name="probability">機率權重</param>
  /// <returns>新的 Gram 實例</returns>
  public static Gram CreateCandidateOverride(IEnumerable<string> keyArray, string current, double probability) =>
      new() {
        KeyArray = keyArray.ToArray(),
        Current = current,
        Probability = probability,
        IsCandidateOverride = true
      };
}
