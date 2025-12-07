// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

import Testing

@testable import KeyKeyUserDBKit

@Suite("PhonaSet Tests")
struct PhonaSetTests {
  @Test(
    "Absolute order string decoding",
    arguments: [
      ("fa", "ㄍㄨㄛˋ"),
      ("kM", "ㄖㄨㄥˊ"),
      ("6C", "ㄏㄜˊ"),
      ("Q;", "ㄧㄣ"),
      ("=M", "ㄔㄥˊ"),
    ]
  )
  func absoluteOrderString(input: String, expected: String) {
    let phonaSet = KeyKeyUserDBKit.PhonaSet(absoluteOrderString: input)
    #expect(phonaSet != nil, "Failed to parse '\(input)'")
    #expect(phonaSet?.description == expected, "Input '\(input)' should decode to '\(expected)'")
  }

  @Test("Decode QString Unigram format")
  func decodeQString_Unigram() {
    let qstring = "fakM6CQ;=M" // 過融合音程
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryString(qstring)
    #expect(result == "ㄍㄨㄛˋ,ㄖㄨㄥˊ,ㄏㄜˊ,ㄧㄣ,ㄔㄥˊ")
  }

  @Test("Decode QString short Unigram")
  func decodeQString_ShortUnigram() {
    // 測試 4 字元的 unigram (2 個音節)
    // "複調" 的 qstring 是 "O_yf" (ㄈㄨˋ,ㄉㄧㄠˋ)
    let qstring = "O_yf"
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryString(qstring)
    #expect(result == "ㄈㄨˋ,ㄉㄧㄠˋ")
  }

  @Test("Component to char mapping")
  func componentToChar() {
    // 測試基本的聲母
    let phonaSet = KeyKeyUserDBKit.PhonaSet(consonant: .ㄅ, vowel: .ㄚ, intonation: .ˉ)
    #expect(phonaSet.description == "ㄅㄚ") // 八 (陰平不標)

    // 測試二聲
    let phonaSet2 = KeyKeyUserDBKit.PhonaSet(consonant: .ㄇ, vowel: .ㄚ, intonation: .ˊ)
    #expect(phonaSet2.description == "ㄇㄚˊ") // 麻

    // 測試含介音
    let phonaSet3 = KeyKeyUserDBKit.PhonaSet(
      consonant: .ㄍ, semivowel: .ㄨ, vowel: .ㄛ, intonation: .ˋ
    )
    #expect(phonaSet3.description == "ㄍㄨㄛˋ") // 過
  }

  @Test("Invalid input handling")
  func invalidInput() {
    // 測試無效輸入
    #expect(KeyKeyUserDBKit.PhonaSet(absoluteOrderString: "a") == nil) // 太短
    #expect(KeyKeyUserDBKit.PhonaSet(absoluteOrderString: "abc") == nil) // 太長

    // 奇數長度的 qstring 應該回傳原字串
    let oddString = "abc"
    #expect(KeyKeyUserDBKit.PhonaSet.decodeQueryString(oddString) == oddString)
  }

  // MARK: - Equality Tests

  @Test("Equality with same values should be equal")
  func equality_SameValues_ShouldBeEqual() {
    let a = KeyKeyUserDBKit.PhonaSet(absoluteOrder: 100)
    let b = KeyKeyUserDBKit.PhonaSet(absoluteOrder: 100)

    #expect(a == b)
    #expect(a.hashValue == b.hashValue)
  }

  @Test("Equality with different values should not be equal")
  func equality_DifferentValues_ShouldNotBeEqual() {
    let a = KeyKeyUserDBKit.PhonaSet(absoluteOrder: 100)
    let b = KeyKeyUserDBKit.PhonaSet(absoluteOrder: 200)

    #expect(a != b)
  }

  // MARK: - Consonant Mapping Tests

  @Test(
    "Consonant should map to correct Unicode",
    arguments: [
      (KeyKeyUserDBKit.PhonaSet.Consonant.ㄅ, "ㄅ"),
      (KeyKeyUserDBKit.PhonaSet.Consonant.ㄆ, "ㄆ"),
      (KeyKeyUserDBKit.PhonaSet.Consonant.ㄇ, "ㄇ")
    ]
  )
  func consonant_ShouldMapToCorrectUnicode(
    consonant: KeyKeyUserDBKit.PhonaSet.Consonant, expected: String
  ) {
    let phonaSet = KeyKeyUserDBKit.PhonaSet(consonant: consonant)
    #expect(phonaSet.description.contains(expected))
  }

  // MARK: - DecodeQueryStringAsKeyArray Tests

  @Test("Decode query string as key array for Bigram format")
  func decodeQueryStringAsKeyArray_BigramFormat_ShouldDecodeLastPart() {
    // 測試 bigram 格式（以 ~ 開頭）
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryStringAsKeyArray("~00 00")
    #expect(!result.isEmpty)
  }

  @Test("Decode query string as key array for Unigram format")
  func decodeQueryStringAsKeyArray_UnigramFormat_ShouldReturnArray() {
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryStringAsKeyArray("0000")
    #expect(!result.isEmpty)
  }

  // MARK: - ~ 開頭的 Unigram 測試

  // 這些 qstring 恰好以 ~ (ASCII 126) 作為第一個字元的低位元組，
  // 但它們不是 bigram 格式（沒有空格分隔符）

  @Test(
    "Decode Unigram starting with tilde character",
    arguments: [
      // ~ 可能是有效編碼字元（order % 79 = 78）
      // 只有當 ~ 後面有空格時才是 bigram 格式
      ("~_]O", ["ㄋㄚˋ", "ㄌㄧˇ"]), // 那裡
      ("~_3_", ["ㄋㄚˋ", "ㄘˋ"]), // 那次
      ("~_XO", ["ㄋㄚˋ", "ㄇㄧˇ"]), // 納米
      ("~@U:", ["ㄧㄚˊ", "ㄑㄧㄢ"]), // 牙籤
      ("~\\cH", ["ㄐㄧㄥˇ", "ㄏㄡˊ"]), // 儆猴
      ("~=KP6CJ1", ["ㄉㄨㄥ", "ㄇㄚˇ", "ㄏㄜˊ", "ㄕㄚ"]), // 冬馬和紗
      ("~=ZX01", ["ㄉㄨㄥ", "ㄐㄧㄡˇ", "ㄑㄩ"]), // 東九區
      ("~7]K", ["ㄓㄠ", "ㄩㄣˊ"]), // 朝雲
      ("~Ip4", ["ㄋㄧㄢˊ", "ㄊㄧㄝ"]), // 粘貼
      ("~Jc=", ["ㄘㄣˊ", "ㄧㄥ"]) // 岑纓
    ]
  )
  func decodeUnigramStartingWithTilde(input: String, expected: [String]) {
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryStringAsKeyArray(input)
    #expect(result == expected, "Input '\(input)' should decode to \(expected), got \(result)")
  }

  // MARK: - CandidateOverride Tests

  // user_candidate_override_cache 表中的 qstring 是純 2 字元編碼，無前綴

  @Test(
    "Decode CandidateOverride qstring",
    arguments: [
      ("}g", ["ㄧㄡˋ"]), // 又
      ("}l", ["ㄙㄨㄥˋ"]), // 送
      ("~\\", ["ㄐㄧㄥˇ"]) // 井
    ]
  )
  func decodeCandidateOverrideQstring(input: String, expected: [String]) {
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryStringAsKeyArray(input)
    #expect(result == expected, "Input '\(input)' should decode to \(expected), got \(result)")
  }

  // MARK: - Empty String Tests

  @Test("From absolute order string with empty string should return nil")
  func fromAbsoluteOrderString_EmptyString_ShouldReturnNil() {
    #expect(KeyKeyUserDBKit.PhonaSet(absoluteOrderString: "") == nil)
  }

  @Test("Decode query string with empty string should return empty")
  func decodeQueryString_EmptyString_ShouldReturnEmpty() {
    let result = KeyKeyUserDBKit.PhonaSet.decodeQueryString("")
    #expect(result == "")
  }
}
