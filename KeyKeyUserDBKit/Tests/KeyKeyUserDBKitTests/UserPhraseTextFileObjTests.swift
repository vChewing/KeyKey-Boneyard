// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

import Foundation
import Testing
import UnitTestAssets4KeyKeyUserDBKit

@testable import KeyKeyUserDBKit

// MARK: - UserPhraseTextFileObjTests

@Suite("UserPhraseTextFileObj Tests", .serialized)
struct UserPhraseTextFileObjTests {
  // MARK: Internal

  // MARK: - Test Data

  // 基於 parse_database_block.py 的預期結果
  static let expectedUnigramCount = 104
  static let expectedBigramCount = 4
  static let expectedCandidateOverrideCount = 3

  // 預期的 bigrams（來自 Python 解析結果）
  static let expectedBigrams: [(keyArray: [String], previous: String, current: String)] = [
    (["ㄉㄧㄥ"], "給", "盯"),
    (["ㄒㄧㄢ"], "那", "先"),
    (["ㄗˋ"], "用", "字"),
    (["ㄐㄧㄡˋ"], "用", "就"),
  ]

  // 預期的 candidate overrides
  static let expectedCandidateOverrides: [(keyArray: [String], current: String)] = [
    (["ㄧㄡˋ"], "又"),
    (["ㄙㄨㄥˋ"], "送"),
    (["ㄐㄧㄥˇ"], "井"),
  ]

  // MARK: - Tests

  @Test("Should parse MJSR file header")
  func parseHeader() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)

    #expect(textFile.version.hasPrefix("MJSR version"))
  }

  @Test("Should parse unigrams correctly")
  func parseUnigrams() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)
    let unigrams = try textFile.fetchUnigrams()

    #expect(unigrams.count == Self.expectedUnigramCount)

    // 檢查所有 unigrams 都是 Unigram 類型
    for gram in unigrams {
      #expect(gram.isUnigram)
      #expect(!gram.isCandidateOverride)
    }
  }

  @Test("Should parse bigrams correctly")
  func parseBigrams() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)
    let bigrams = try textFile.fetchBigrams()

    #expect(bigrams.count == Self.expectedBigramCount)

    // 驗證 bigrams 的內容
    for (idx, expected) in Self.expectedBigrams.enumerated() {
      #expect(bigrams[idx].keyArray == expected.keyArray)
      #expect(bigrams[idx].previous == expected.previous)
      #expect(bigrams[idx].current == expected.current)
      #expect(!bigrams[idx].isUnigram)
    }
  }

  @Test("Should parse candidate overrides correctly")
  func parseCandidateOverrides() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)
    let overrides = try textFile.fetchCandidateOverrides()

    #expect(overrides.count == Self.expectedCandidateOverrideCount)

    // 驗證 candidate overrides 的內容
    for (idx, expected) in Self.expectedCandidateOverrides.enumerated() {
      #expect(overrides[idx].keyArray == expected.keyArray)
      #expect(overrides[idx].current == expected.current)
      #expect(overrides[idx].isCandidateOverride)
      #expect(
        overrides[idx].probability
          == KeyKeyUserDBKit.UserPhraseTextFileObj.candidateOverrideProbability
      )
    }
  }

  @Test("fetchAllGrams should return all grams")
  func fetchAllGrams() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)
    let allGrams = try textFile.fetchAllGrams()

    let expectedTotal =
      Self.expectedUnigramCount + Self.expectedBigramCount + Self.expectedCandidateOverrideCount

    #expect(allGrams.count == expectedTotal)
  }

  @Test("fetchBigrams with limit should respect limit")
  func fetchBigramsWithLimit() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)
    let bigrams = try textFile.fetchBigrams(limit: 2)

    #expect(bigrams.count == 2)
  }

  @Test("Should be iterable as Sequence")
  func iterateAsSequence() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)

    var count = 0
    for _ in textFile {
      count += 1
    }

    let expectedTotal =
      Self.expectedUnigramCount + Self.expectedBigramCount + Self.expectedCandidateOverrideCount

    #expect(count == expectedTotal)
  }

  @Test("Should conform to UserPhraseDataSource protocol")
  func conformToProtocol() throws {
    try skipIfNoTextFile()
    guard let url = UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL else { return }

    let textFile = try KeyKeyUserDBKit.UserPhraseTextFileObj(url: url)

    // 驗證可以作為 UserPhraseDataSource 使用
    func useAsDataSource(_ source: some KeyKeyUserDBKit.UserPhraseDataSource) throws -> Int {
      try source.fetchAllGrams().count
    }

    let count = try useAsDataSource(textFile)
    let expectedTotal =
      Self.expectedUnigramCount + Self.expectedBigramCount + Self.expectedCandidateOverrideCount

    #expect(count == expectedTotal)
  }

  // MARK: Private

  // MARK: - Helper Methods

  private func skipIfNoTextFile() throws {
    guard UnitTestAssets4KeyKeyUserDBKit.mjsrTextFileURL != nil else {
      throw TestSkipReason.testAssetNotAvailable
    }
  }
}

// MARK: - TestSkipReason

private enum TestSkipReason: Error, CustomStringConvertible {
  case testAssetNotAvailable

  // MARK: Internal

  var description: String {
    switch self {
    case .testAssetNotAvailable:
      "Test asset file not available"
    }
  }
}
