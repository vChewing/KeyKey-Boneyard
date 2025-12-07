// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

import Foundation
import Testing

@testable import KeyKeyUserDBKit

@Suite("Gram Tests")
struct GramTests {
  // MARK: - Creation Tests

  @Test("Create Unigram should set correct properties")
  func createUnigram_ShouldSetCorrectProperties() {
    let keyArray = ["ㄋㄧˇ", "ㄏㄠˇ"]
    let current = "你好"
    let probability = 0.5

    let gram = KeyKeyUserDBKit.Gram(
      keyArray: keyArray,
      current: current,
      probability: probability
    )

    #expect(gram.keyArray == keyArray)
    #expect(gram.current == current)
    #expect(gram.previous == nil)
    #expect(gram.probability == probability)
    #expect(gram.isCandidateOverride == false)
    #expect(gram.isUnigram == true)
  }

  @Test("Create Bigram should set correct properties")
  func createBigram_ShouldSetCorrectProperties() {
    let keyArray = ["ㄏㄠˇ"]
    let current = "好"
    let previous = "你"

    let gram = KeyKeyUserDBKit.Gram(
      keyArray: keyArray,
      current: current,
      previous: previous
    )

    #expect(gram.keyArray == keyArray)
    #expect(gram.current == current)
    #expect(gram.previous == previous)
    #expect(gram.probability == 0)
    #expect(gram.isCandidateOverride == false)
    #expect(gram.isUnigram == false)
  }

  @Test("Create Bigram with empty previous should set previous to nil")
  func createBigram_WithEmptyPrevious_ShouldSetPreviousToNil() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄏㄠˇ"],
      current: "好",
      previous: ""
    )
    #expect(gram.previous == nil)
    #expect(gram.isUnigram == true)
  }

  @Test("Create CandidateOverride should set correct properties")
  func createCandidateOverride_ShouldSetCorrectProperties() {
    let keyArray = ["ㄋㄧˇ"]
    let current = "妳"
    let probability = 114.514

    let gram = KeyKeyUserDBKit.Gram(
      keyArray: keyArray,
      current: current,
      probability: probability,
      isCandidateOverride: true
    )

    #expect(gram.keyArray == keyArray)
    #expect(gram.current == current)
    #expect(gram.previous == nil)
    #expect(gram.probability == probability)
    #expect(gram.isCandidateOverride == true)
  }

  // MARK: - Property Tests

  @Test("isReadingMismatched should return true when lengths differ")
  func isReadingMismatched_WhenLengthsDiffer_ShouldReturnTrue() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ", "ㄏㄠˇ"],
      current: "你好嗎" // 2 keys, 3 chars
    )
    #expect(gram.isReadingMismatched == true)
  }

  @Test("isReadingMismatched should return false when lengths match")
  func isReadingMismatched_WhenLengthsMatch_ShouldReturnFalse() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ", "ㄏㄠˇ"],
      current: "你好" // 2 keys, 2 chars
    )
    #expect(gram.isReadingMismatched == false)
  }

  @Test("segLength should return keyArray length")
  func segLength_ShouldReturnKeyArrayLength() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ", "ㄏㄠˇ", "ㄇㄚ"],
      current: "你好嗎"
    )
    #expect(gram.segLength == 3)
  }

  @Test("asTuple should return correct tuple")
  func asTuple_ShouldReturnCorrectTuple() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄏㄠˇ"],
      current: "好",
      previous: "你"
    )
    let tuple = gram.asTuple

    #expect(tuple.keyArray == ["ㄏㄠˇ"])
    #expect(tuple.value == "好")
    #expect(tuple.probability == 0)
    #expect(tuple.previous == "你")
  }

  // MARK: - Description Tests

  @Test("descriptionSansReading for Unigram should format correctly")
  func descriptionSansReading_Unigram_ShouldFormatCorrectly() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "你",
      probability: 0.5
    )
    #expect(gram.descriptionSansReading == "P(你)=0.5")
  }

  @Test("descriptionSansReading for Bigram should format correctly")
  func descriptionSansReading_Bigram_ShouldFormatCorrectly() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄏㄠˇ"],
      current: "好",
      previous: "你"
    )
    #expect(gram.descriptionSansReading == "P(好|你)=0.0")
  }

  @Test("descriptionSansReading for CandidateOverride should format correctly")
  func descriptionSansReading_CandidateOverride_ShouldFormatCorrectly() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "妳",
      probability: 114.514,
      isCandidateOverride: true
    )
    #expect(gram.descriptionSansReading == "P(妳)")
  }

  @Test("describe should include header and body")
  func describe_ShouldIncludeHeaderAndBody() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "你",
      probability: 0.5
    )
    let description = gram.describe(keySeparator: "-")

    #expect(description.contains("[Unigram]"))
    #expect(description.contains("ㄋㄧˇ"))
    #expect(description.contains("P(你)=0.5"))
  }

  @Test("description should call describe")
  func description_ShouldCallDescribe() {
    let gram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "你",
      probability: 0.5
    )
    #expect(gram.description == gram.describe(keySeparator: "-"))
  }

  // MARK: - Equality Tests

  @Test("Equality with same values should be equal")
  func equality_SameValues_ShouldBeEqual() {
    let gram1 = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "你",
      probability: 0.5
    )
    let gram2 = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "你",
      probability: 0.5
    )

    #expect(gram1 == gram2)
    #expect(gram1.hashValue == gram2.hashValue)
  }

  @Test("Equality with different values should not be equal")
  func equality_DifferentValues_ShouldNotBeEqual() {
    let gram1 = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "你",
      probability: 0.5
    )
    let gram2 = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "妳",
      probability: 0.5
    )

    #expect(gram1 != gram2)
  }

  // MARK: - Codable Tests

  @Test("Codable encode/decode should preserve values")
  func codable_EncodeDecode_ShouldPreserveValues() throws {
    let originalGram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ", "ㄏㄠˇ"],
      current: "你好",
      previous: "大家",
      probability: 0.75,
      isCandidateOverride: false
    )

    let encoder = JSONEncoder()
    let data = try encoder.encode(originalGram)

    let decoder = JSONDecoder()
    let decodedGram = try decoder.decode(KeyKeyUserDBKit.Gram.self, from: data)

    #expect(originalGram == decodedGram)
    #expect(originalGram.isCandidateOverride == decodedGram.isCandidateOverride)
  }

  @Test("Codable for CandidateOverride should preserve flag")
  func codable_CandidateOverride_ShouldPreserveFlag() throws {
    let originalGram = KeyKeyUserDBKit.Gram(
      keyArray: ["ㄋㄧˇ"],
      current: "妳",
      probability: 114.514,
      isCandidateOverride: true
    )

    let encoder = JSONEncoder()
    let data = try encoder.encode(originalGram)

    let decoder = JSONDecoder()
    let decodedGram = try decoder.decode(KeyKeyUserDBKit.Gram.self, from: data)

    #expect(decodedGram.isCandidateOverride == true)
  }

  // MARK: - Raw Tuple Constructor Tests

  @Test("Raw tuple constructor should set correct properties")
  func rawTupleConstructor_ShouldSetCorrectProperties() {
    let rawTuple: KeyKeyUserDBKit.Gram.GramRAW = (
      keyArray: ["ㄋㄧˇ"],
      value: "你",
      probability: 0.5,
      previous: "我"
    )

    let gram = KeyKeyUserDBKit.Gram(rawTuple)

    #expect(gram.keyArray == ["ㄋㄧˇ"])
    #expect(gram.current == "你")
    #expect(gram.previous == "我")
    #expect(gram.probability == 0.5)
    #expect(gram.isCandidateOverride == false)
  }

  @Test("Raw tuple constructor with CandidateOverride should set flag")
  func rawTupleConstructor_WithCandidateOverride_ShouldSetFlag() {
    let rawTuple: KeyKeyUserDBKit.Gram.GramRAW = (
      keyArray: ["ㄋㄧˇ"],
      value: "妳",
      probability: 114.514,
      previous: nil
    )

    let gram = KeyKeyUserDBKit.Gram(rawTuple, isCandidateOverride: true)

    #expect(gram.isCandidateOverride == true)
  }
}
