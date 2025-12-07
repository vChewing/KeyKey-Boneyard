// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using System.Text;

namespace KeyKeyUserDBKit;

/// <summary>
/// 注音符號 (Phonabet) 的完整漢字讀音結構（PhonaSet）。
/// 該結構體類型僅用於解密奇摩輸入法的讀音字串。
/// </summary>
public readonly struct PhonaSet : IEquatable<PhonaSet> {
  // MARK: - Bit Masks

  /// <summary>
  /// 注音符號組件類型的位元遮罩
  /// </summary>
  public enum PhonaType : ushort {
    /// <summary>聲母位元遮罩</summary>
    Consonant = 0x001F,
    /// <summary>介音位元遮罩</summary>
    Semivowel = 0x0060,
    /// <summary>韻母位元遮罩</summary>
    Vowel = 0x0780,
    /// <summary>聲調位元遮罩</summary>
    Intonation = 0x3800
  }

  // MARK: - Component Definitions

  /// <summary>
  /// 聲母 (21 個)
  /// </summary>
  public enum Consonant : ushort {
    /// <summary>ㄅ (U+3105)</summary>
    ㄅ = 0x0001,
    /// <summary>ㄆ (U+3106)</summary>
    ㄆ = 0x0002,
    /// <summary>ㄇ (U+3107)</summary>
    ㄇ = 0x0003,
    /// <summary>ㄈ (U+3108)</summary>
    ㄈ = 0x0004,
    /// <summary>ㄉ (U+3109)</summary>
    ㄉ = 0x0005,
    /// <summary>ㄊ (U+310A)</summary>
    ㄊ = 0x0006,
    /// <summary>ㄋ (U+310B)</summary>
    ㄋ = 0x0007,
    /// <summary>ㄌ (U+310C)</summary>
    ㄌ = 0x0008,
    /// <summary>ㄍ (U+310D)</summary>
    ㄍ = 0x0009,
    /// <summary>ㄎ (U+310E)</summary>
    ㄎ = 0x000A,
    /// <summary>ㄏ (U+310F)</summary>
    ㄏ = 0x000B,
    /// <summary>ㄐ (U+3110)</summary>
    ㄐ = 0x000C,
    /// <summary>ㄑ (U+3111)</summary>
    ㄑ = 0x000D,
    /// <summary>ㄒ (U+3112)</summary>
    ㄒ = 0x000E,
    /// <summary>ㄓ (U+3113)</summary>
    ㄓ = 0x000F,
    /// <summary>ㄔ (U+3114)</summary>
    ㄔ = 0x0010,
    /// <summary>ㄕ (U+3115)</summary>
    ㄕ = 0x0011,
    /// <summary>ㄖ (U+3116)</summary>
    ㄖ = 0x0012,
    /// <summary>ㄗ (U+3117)</summary>
    ㄗ = 0x0013,
    /// <summary>ㄘ (U+3118)</summary>
    ㄘ = 0x0014,
    /// <summary>ㄙ (U+3119)</summary>
    ㄙ = 0x0015
  }

  /// <summary>
  /// 介音 (3 個)
  /// </summary>
  public enum Semivowel : ushort {
    /// <summary>ㄧ (U+3127)</summary>
    ㄧ = 0x0020,
    /// <summary>ㄨ (U+3128)</summary>
    ㄨ = 0x0040,
    /// <summary>ㄩ (U+3129)</summary>
    ㄩ = 0x0060
  }

  /// <summary>
  /// 韻母 (13 個)
  /// </summary>
  public enum Vowel : ushort {
    /// <summary>ㄚ (U+311A)</summary>
    ㄚ = 0x0080,
    /// <summary>ㄛ (U+311B)</summary>
    ㄛ = 0x0100,
    /// <summary>ㄜ (U+311C)</summary>
    ㄜ = 0x0180,
    /// <summary>ㄝ (U+311D)</summary>
    ㄝ = 0x0200,
    /// <summary>ㄞ (U+311E)</summary>
    ㄞ = 0x0280,
    /// <summary>ㄟ (U+311F)</summary>
    ㄟ = 0x0300,
    /// <summary>ㄠ (U+3120)</summary>
    ㄠ = 0x0380,
    /// <summary>ㄡ (U+3121)</summary>
    ㄡ = 0x0400,
    /// <summary>ㄢ (U+3122)</summary>
    ㄢ = 0x0480,
    /// <summary>ㄣ (U+3123)</summary>
    ㄣ = 0x0500,
    /// <summary>ㄤ (U+3124)</summary>
    ㄤ = 0x0580,
    /// <summary>ㄥ (U+3125)</summary>
    ㄥ = 0x0600,
    /// <summary>ㄦ (U+3126)</summary>
    ㄦ = 0x0680
  }

  /// <summary>
  /// 聲調 (5 個)
  /// </summary>
  public enum Intonation : ushort {
    /// <summary>一聲（陰平）- 不標記</summary>
    First = 0x0000,
    /// <summary>二聲（陽平）- ˊ (U+02CA)</summary>
    Second = 0x0800,
    /// <summary>三聲（上聲）- ˇ (U+02C7)</summary>
    Third = 0x1000,
    /// <summary>四聲（去聲）- ˋ (U+02CB)</summary>
    Fourth = 0x1800,
    /// <summary>輕聲 - ˙ (U+02D9)</summary>
    Neutral = 0x2000
  }

  /// <summary>
  /// 注音音節的原始位元表示
  /// </summary>
  public ushort Syllable { get; }

  // MARK: - Constructors

  /// <summary>
  /// 從原始音節值建立 PhonaSet
  /// </summary>
  /// <param name="syllable">音節的位元表示</param>
  public PhonaSet(ushort syllable = 0) {
    Syllable = syllable;
  }

  /// <summary>
  /// 從 absolute order 值重建 PhonaSet 音節
  /// </summary>
  public PhonaSet(int absoluteOrder) {
    var consonant = (ushort)(absoluteOrder % 22);
    var semi = (ushort)(((absoluteOrder / 22) % 4) << 5);
    var vowel = (ushort)(((absoluteOrder / (22 * 4)) % 14) << 7);
    var tone = (ushort)(((absoluteOrder / (22 * 4 * 14)) % 5) << 11);
    Syllable = (ushort)(consonant | semi | vowel | tone);
  }

  /// <summary>
  /// 以組件建立 PhonaSet 音節
  /// </summary>
  public PhonaSet(Consonant? consonant = null, Semivowel? semivowel = null,
                  Vowel? vowel = null, Intonation intonation = Intonation.First) {
    var consRaw = consonant.HasValue ? (ushort)consonant.Value : (ushort)0;
    var semiRaw = semivowel.HasValue ? (ushort)semivowel.Value : (ushort)0;
    var vowelRaw = vowel.HasValue ? (ushort)vowel.Value : (ushort)0;
    Syllable = (ushort)(consRaw | semiRaw | vowelRaw | (ushort)intonation);
  }

  /// <summary>
  /// 從 2-char absolute order 字串重建 PhonaSet 音節
  /// 編碼方式: 79 進位制，用 ASCII 48-126 表示
  /// order = (high - 48) * 79 + (low - 48)
  /// </summary>
  public static PhonaSet? FromAbsoluteOrderString(string s) {
    if (s.Length != 2) return null;

    var low = s[0] - 48;
    var high = s[1] - 48;
    if (low is < 0 or >= 79 || high is < 0 or >= 79) return null;

    return new PhonaSet(high * 79 + low);
  }

  // MARK: - Component Accessors

  /// <summary>聲母的原始值</summary>
  public ushort RawConsonant => (ushort)(Syllable & (ushort)PhonaType.Consonant);
  /// <summary>介音的原始值</summary>
  public ushort RawSemivowel => (ushort)(Syllable & (ushort)PhonaType.Semivowel);
  /// <summary>韻母的原始值</summary>
  public ushort RawVowel => (ushort)(Syllable & (ushort)PhonaType.Vowel);
  /// <summary>聲調的原始值</summary>
  public ushort RawIntonation => (ushort)(Syllable & (ushort)PhonaType.Intonation);

  // MARK: - Symbol Mappings

  private static readonly Dictionary<Consonant, char> ConsonantSymbols = new() {
    [Consonant.ㄅ] = '\u3105',
    [Consonant.ㄆ] = '\u3106',
    [Consonant.ㄇ] = '\u3107',
    [Consonant.ㄈ] = '\u3108',
    [Consonant.ㄉ] = '\u3109',
    [Consonant.ㄊ] = '\u310A',
    [Consonant.ㄋ] = '\u310B',
    [Consonant.ㄌ] = '\u310C',
    [Consonant.ㄍ] = '\u310D',
    [Consonant.ㄎ] = '\u310E',
    [Consonant.ㄏ] = '\u310F',
    [Consonant.ㄐ] = '\u3110',
    [Consonant.ㄑ] = '\u3111',
    [Consonant.ㄒ] = '\u3112',
    [Consonant.ㄓ] = '\u3113',
    [Consonant.ㄔ] = '\u3114',
    [Consonant.ㄕ] = '\u3115',
    [Consonant.ㄖ] = '\u3116',
    [Consonant.ㄗ] = '\u3117',
    [Consonant.ㄘ] = '\u3118',
    [Consonant.ㄙ] = '\u3119'
  };

  private static readonly Dictionary<Semivowel, char> SemivowelSymbols = new() {
    [Semivowel.ㄧ] = '\u3127',
    [Semivowel.ㄨ] = '\u3128',
    [Semivowel.ㄩ] = '\u3129'
  };

  private static readonly Dictionary<Vowel, char> VowelSymbols = new() {
    [Vowel.ㄚ] = '\u311A',
    [Vowel.ㄛ] = '\u311B',
    [Vowel.ㄜ] = '\u311C',
    [Vowel.ㄝ] = '\u311D',
    [Vowel.ㄞ] = '\u311E',
    [Vowel.ㄟ] = '\u311F',
    [Vowel.ㄠ] = '\u3120',
    [Vowel.ㄡ] = '\u3121',
    [Vowel.ㄢ] = '\u3122',
    [Vowel.ㄣ] = '\u3123',
    [Vowel.ㄤ] = '\u3124',
    [Vowel.ㄥ] = '\u3125',
    [Vowel.ㄦ] = '\u3126'
  };

  private static readonly Dictionary<Intonation, char?> IntonationSymbols = new() {
    [Intonation.First] = null,
    [Intonation.Second] = '\u02CA',
    [Intonation.Third] = '\u02C7',
    [Intonation.Fourth] = '\u02CB',
    [Intonation.Neutral] = '\u02D9'
  };

  private char? GetConsonantSymbol() {
    if (Enum.IsDefined(typeof(Consonant), RawConsonant) &&
        ConsonantSymbols.TryGetValue((Consonant)RawConsonant, out var symbol))
      return symbol;
    return null;
  }

  private char? GetSemivowelSymbol() {
    if (Enum.IsDefined(typeof(Semivowel), RawSemivowel) &&
        SemivowelSymbols.TryGetValue((Semivowel)RawSemivowel, out var symbol))
      return symbol;
    return null;
  }

  private char? GetVowelSymbol() {
    if (Enum.IsDefined(typeof(Vowel), RawVowel) &&
        VowelSymbols.TryGetValue((Vowel)RawVowel, out var symbol))
      return symbol;
    return null;
  }

  private char? GetIntonationSymbol() {
    if (Enum.IsDefined(typeof(Intonation), RawIntonation) &&
        IntonationSymbols.TryGetValue((Intonation)RawIntonation, out var symbol))
      return symbol;
    return null;
  }

  /// <summary>
  /// 將 PhonaSet 音節轉換為 Unicode 注音符號字串
  /// </summary>
  public override string ToString() {
    var sb = new StringBuilder();

    if (GetConsonantSymbol() is { } c) sb.Append(c);
    if (GetSemivowelSymbol() is { } s) sb.Append(s);
    if (GetVowelSymbol() is { } v) sb.Append(v);
    if (GetIntonationSymbol() is { } i) sb.Append(i);

    return sb.ToString();
  }

  // MARK: - QString Decoder

  /// <summary>
  /// 將資料庫中的 qstring 解碼為注音符號
  /// - 格式1 (unigram): 連續的 2-char absolute order 字串，每 2 個字元代表一個注音音節
  /// - 格式2 (bigram):  "~{前字注音2char} {當前字注音2char}"，用空格分隔
  /// 
  /// 注意: ~ (ASCII 126) 可能是有效的編碼字元（order % 79 = 78），
  /// 只有當 ~ 後面有空格時才是真正的 bigram 格式
  /// </summary>
  public static string DecodeQueryString(string queryString) {
    // 只有當 ~ 後面有空格時才是 bigram 格式
    if (queryString.StartsWith('~') && queryString[1..].Contains(' '))
      return DecodeBigram(queryString);

    if (queryString.Length % 2 != 0)
      return queryString;

    var syllables = DecodeSyllables(queryString);
    return syllables.Count == 0 ? queryString : string.Join(",", syllables);
  }

  /// <summary>
  /// 將資料庫中的 qstring 解碼為注音符號陣列（用於 Gram 的 keyArray）
  /// 
  /// 注意: ~ (ASCII 126) 可能是有效的編碼字元（order % 79 = 78），
  /// 只有當 ~ 後面有空格時才是真正的 bigram 格式
  /// </summary>
  public static string[] DecodeQueryStringAsKeyArray(string queryString) {
    // 只有當 ~ 後面有空格時才是 bigram 格式
    if (queryString.StartsWith('~') && queryString[1..].Contains(' '))
      return DecodeBigramAsKeyArray(queryString);

    if (queryString.Length % 2 != 0)
      return [queryString];

    var syllables = DecodeSyllables(queryString);
    return syllables.Count == 0 ? [queryString] : syllables.ToArray();
  }

  private static string DecodeBigram(string queryString) {
    var content = queryString[1..];
    var parts = content.Split(' ');

    var decodedParts = parts
        .Select(part => DecodeSyllables(part))
        .Where(syllables => syllables.Count > 0)
        .Select(syllables => string.Join("", syllables))
        .ToList();

    return string.Join(" → ", decodedParts);
  }

  private static string[] DecodeBigramAsKeyArray(string queryString) {
    var content = queryString[1..];
    var parts = content.Split(' ');

    // 只取最後一個部分的音節（當前字的注音）
    if (parts.Length == 0) return [queryString];

    var lastPart = parts[^1];
    var syllables = DecodeSyllables(lastPart);
    return syllables.Count == 0 ? [queryString] : syllables.ToArray();
  }

  /// <summary>
  /// 解碼連續的 2-char 音節。若字串長度為奇數，只解碼前面偶數個字元。
  /// </summary>
  private static List<string> DecodeSyllables(string stringToDecode) {
    var decodableLength = stringToDecode.Length - (stringToDecode.Length % 2);
    if (decodableLength < 2)
      return [];

    var result = new List<string>();

    for (var i = 0; i < decodableLength; i += 2) {
      var absStr = stringToDecode.Substring(i, 2);
      var phonaSet = FromAbsoluteOrderString(absStr);
      if (phonaSet is null) continue;

      var composed = phonaSet.Value.ToString();
      if (!string.IsNullOrEmpty(composed))
        result.Add(composed);
    }

    return result;
  }

  // MARK: - IEquatable

  /// <inheritdoc/>
  public bool Equals(PhonaSet other) => Syllable == other.Syllable;
  /// <inheritdoc/>
  public override bool Equals(object? obj) => obj is PhonaSet other && Equals(other);
  /// <inheritdoc/>
  public override int GetHashCode() => Syllable.GetHashCode();
  /// <summary>判斷兩個 PhonaSet 是否相等</summary>
  public static bool operator ==(PhonaSet left, PhonaSet right) => left.Equals(right);
  /// <summary>判斷兩個 PhonaSet 是否不相等</summary>
  public static bool operator !=(PhonaSet left, PhonaSet right) => !left.Equals(right);
}
