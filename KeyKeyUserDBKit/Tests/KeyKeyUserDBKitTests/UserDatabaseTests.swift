// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

import Foundation
import Testing
import UnitTestAssets4KeyKeyUserDBKit

@testable import KeyKeyUserDBKit

@Suite("UserDatabase Tests", .serialized)
struct UserDatabaseTests {
  // MARK: Lifecycle

  // MARK: - Init (replaces setUp)

  init() throws {
    // 取得加密的資料庫檔案
    guard let encryptedURL = UnitTestAssets4KeyKeyUserDBKit.assetURL else {
      self.decryptedDBPath = nil
      return
    }

    // 解密到臨時目錄
    let tempDir = FileManager.default.temporaryDirectory
    let decryptedURL = tempDir.appendingPathComponent("decrypted_test_\(UUID().uuidString).db")

    let decryptor = KeyKeyUserDBKit.SEEDecryptor()
    try decryptor.decryptFile(at: encryptedURL, to: decryptedURL)

    self.decryptedDBPath = decryptedURL
  }

  // MARK: Internal

  let decryptedDBPath: URL?

  // MARK: - Tests

  @Test("Database should open successfully")
  func databaseOpen() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    // 測試可以成功開啟資料庫
    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)
    // 如果能執行到這裡，代表開啟成功
    _ = db
    cleanupDatabase(at: dbPath)
  }

  @Test("Fetch Unigrams should return valid Gram objects")
  func fetchUnigrams() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)
    let unigrams = try db.fetchUnigrams()

    // 驗證回傳的是 Gram 型別
    #expect(unigrams.allSatisfy { $0.isUnigram })

    // 驗證每個 Gram 都有 keyArray 和 current
    for gram in unigrams {
      #expect(!gram.keyArray.isEmpty, "keyArray 不應為空")
      #expect(!gram.current.isEmpty, "current 不應為空")
      #expect(gram.previous == nil, "Unigram 的 previous 應為 nil")
      #expect(!gram.isCandidateOverride, "Unigram 不應是 candidateOverride")
    }

    print("共讀取到 \(unigrams.count) 筆 Unigram")
    unigrams.forEach { print($0) }
    cleanupDatabase(at: dbPath)
  }

  @Test("Fetch Bigrams should return valid Gram objects with previous")
  func fetchBigrams() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)
    let bigrams = try db.fetchBigrams()

    // 驗證回傳的是 Bigram (有 previous)
    for gram in bigrams {
      #expect(!gram.keyArray.isEmpty, "keyArray 不應為空")
      #expect(!gram.current.isEmpty, "current 不應為空")
      #expect(gram.previous != nil, "Bigram 的 previous 應存在")
      #expect(!gram.isCandidateOverride, "Bigram 不應是 candidateOverride")
    }

    print("共讀取到 \(bigrams.count) 筆 Bigram")
    bigrams.forEach { print($0) }
    cleanupDatabase(at: dbPath)
  }

  @Test("Fetch Bigrams with limit should respect limit parameter")
  func fetchBigramsWithLimit() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)
    let allBigrams = try db.fetchBigrams()
    let limitedBigrams = try db.fetchBigrams(limit: 5)

    if allBigrams.count > 5 {
      #expect(limitedBigrams.count == 5, "限制筆數應正確")
    } else {
      #expect(limitedBigrams.count == allBigrams.count)
    }
    limitedBigrams.forEach { print($0) }
    cleanupDatabase(at: dbPath)
  }

  @Test("Fetch Candidate Overrides should return correct probability")
  func fetchCandidateOverrides() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)
    let overrides = try db.fetchCandidateOverrides()

    // 驗證 CandidateOverride 的特性
    for gram in overrides {
      #expect(!gram.keyArray.isEmpty, "keyArray 不應為空")
      #expect(!gram.current.isEmpty, "current 不應為空")
      #expect(gram.isCandidateOverride, "應是 candidateOverride")
      #expect(
        gram.probability == KeyKeyUserDBKit.UserDatabase.candidateOverrideProbability,
        "權重應為 114514.0"
      )
    }

    print("共讀取到 \(overrides.count) 筆 CandidateOverride")
    overrides.forEach { print($0) }
    cleanupDatabase(at: dbPath)
  }

  @Test("Fetch All Grams should return combined count of all types")
  func fetchAllGrams() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    // 分別取得各類型的資料
    let unigrams = try db.fetchUnigrams()
    let bigrams = try db.fetchBigrams()
    let overrides = try db.fetchCandidateOverrides()

    // 取得全部資料
    let allGrams = try db.fetchAllGrams()

    // 驗證總數
    let expectedCount = unigrams.count + bigrams.count + overrides.count
    #expect(allGrams.count == expectedCount, "fetchAllGrams 應回傳所有類型的 Gram")

    print("fetchAllGrams 共讀取到 \(allGrams.count) 筆資料")
    print("  - Unigrams: \(unigrams.count)")
    print("  - Bigrams: \(bigrams.count)")
    print("  - CandidateOverrides: \(overrides.count)")
    cleanupDatabase(at: dbPath)
  }

  @Test("Gram keyArray should contain valid Bopomofo characters")
  func gramKeyArrayDecoding() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)
    let unigrams = try db.fetchUnigrams()

    // 驗證 keyArray 中的注音符號格式正確
    for gram in unigrams.prefix(10) {
      for key in gram.keyArray {
        // 注音符號應包含 ㄅ-ㄩ 範圍的字元
        let containsBopomofo = key.unicodeScalars.contains { scalar in
          (0x3105 ... 0x3129).contains(scalar.value) // 注音符號 ㄅ-ㄩ
            || (0x02CA ... 0x02CB).contains(scalar.value) // 聲調符號 ˊˋ
            || scalar.value == 0x02C7 // ˇ
            || scalar.value == 0x02D9 // ˙
        }
        #expect(containsBopomofo, "keyArray 應包含注音符號：\(key)")
      }
    }
    cleanupDatabase(at: dbPath)
  }

  @Test("Candidate Override probability constant should be correct")
  func candidateOverrideProbabilityValue() {
    // 驗證常數值
    #expect(KeyKeyUserDBKit.UserDatabase.candidateOverrideProbability == 114.514)
  }

  @Test("Database open with invalid path should throw openFailed error")
  func databaseOpenFailure() {
    // 測試開啟不存在的檔案應拋出錯誤
    #expect(throws: KeyKeyUserDBKit.DatabaseError.self) {
      try KeyKeyUserDBKit.UserDatabase(path: "/nonexistent/path/to/database.db")
    }
  }

  // MARK: - Sequence Iterator Tests

  @Test("Sequence iteration should return same count as fetchAllGrams")
  func sequenceIteration() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    // 使用 Sequence 協定迭代
    var iteratedGrams: [KeyKeyUserDBKit.Gram] = []
    for gram in db {
      iteratedGrams.append(gram)
    }

    // 使用 fetchAllGrams 取得所有資料作為對照
    let allGrams = try db.fetchAllGrams()

    // 驗證數量相同
    #expect(iteratedGrams.count == allGrams.count, "迭代器應回傳與 fetchAllGrams 相同數量的資料")

    print("Sequence 迭代共取得 \(iteratedGrams.count) 筆資料")
    cleanupDatabase(at: dbPath)
  }

  @Test("Sequence forEach should work correctly")
  func sequenceForEach() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    var count = 0
    var hasUnigram = false
    var hasBigram = false
    var hasCandidateOverride = false

    db.forEach { gram in
      count += 1
      if gram.isUnigram { hasUnigram = true }
      if gram.previous != nil, !gram.isCandidateOverride { hasBigram = true }
      if gram.isCandidateOverride { hasCandidateOverride = true }
    }

    #expect(count > 0, "應至少有一筆資料")
    print("forEach 迭代共取得 \(count) 筆資料")
    print("  - 包含 Unigram: \(hasUnigram)")
    print("  - 包含 Bigram: \(hasBigram)")
    print("  - 包含 CandidateOverride: \(hasCandidateOverride)")
    cleanupDatabase(at: dbPath)
  }

  @Test("Sequence iterator multiple times should return consistent results")
  func sequenceIteratorMultipleTimes() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    // 第一次迭代
    let firstCount = db.reduce(0) { acc, _ in acc + 1 }

    // 第二次迭代（應該可以重新迭代）
    let secondCount = db.reduce(0) { acc, _ in acc + 1 }

    #expect(firstCount == secondCount, "多次迭代應取得相同數量的資料")
    print("多次 Sequence 迭代結果一致：\(firstCount) 筆")
    cleanupDatabase(at: dbPath)
  }

  @Test("Sequence iterator should categorize gram types correctly")
  func sequenceIteratorGramTypes() throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    var unigramCount = 0
    var bigramCount = 0
    var candidateOverrideCount = 0

    for gram in db {
      if gram.isCandidateOverride {
        candidateOverrideCount += 1
        #expect(
          gram.probability == KeyKeyUserDBKit.UserDatabase.candidateOverrideProbability,
          "CandidateOverride 權重應正確"
        )
      } else if gram.previous != nil {
        bigramCount += 1
      } else {
        unigramCount += 1
      }
    }

    // 驗證與 fetch 方法結果一致
    let unigrams = try db.fetchUnigrams()
    let bigrams = try db.fetchBigrams()
    let overrides = try db.fetchCandidateOverrides()

    #expect(unigramCount == unigrams.count, "Unigram 數量應一致")
    #expect(bigramCount == bigrams.count, "Bigram 數量應一致")
    #expect(candidateOverrideCount == overrides.count, "CandidateOverride 數量應一致")

    print("Sequence 迭代分類統計：")
    print("  - Unigrams: \(unigramCount)")
    print("  - Bigrams: \(bigramCount)")
    print("  - CandidateOverrides: \(candidateOverrideCount)")
    cleanupDatabase(at: dbPath)
  }

  // MARK: - AsyncSequence Iterator Tests

  @Test("AsyncSequence iteration should return same count as fetchAllGrams")
  func asyncSequenceIteration() async throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    // 使用 AsyncSequence 協定迭代
    var iteratedGrams: [KeyKeyUserDBKit.Gram] = []
    for await gram in db.async {
      iteratedGrams.append(gram)
    }

    // 使用 fetchAllGrams 取得所有資料作為對照
    let allGrams = try db.fetchAllGrams()

    // 驗證數量相同
    #expect(iteratedGrams.count == allGrams.count, "非同步迭代器應回傳與 fetchAllGrams 相同數量的資料")

    print("AsyncSequence 迭代共取得 \(iteratedGrams.count) 筆資料")
    cleanupDatabase(at: dbPath)
  }

  @Test("AsyncSequence should categorize gram types correctly")
  func asyncSequenceGramTypes() async throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    var unigramCount = 0
    var bigramCount = 0
    var candidateOverrideCount = 0

    for await gram in db.async {
      if gram.isCandidateOverride {
        candidateOverrideCount += 1
        #expect(
          gram.probability == KeyKeyUserDBKit.UserDatabase.candidateOverrideProbability,
          "CandidateOverride 權重應正確"
        )
      } else if gram.previous != nil {
        bigramCount += 1
      } else {
        unigramCount += 1
      }
    }

    // 驗證與 fetch 方法結果一致
    let unigrams = try db.fetchUnigrams()
    let bigrams = try db.fetchBigrams()
    let overrides = try db.fetchCandidateOverrides()

    #expect(unigramCount == unigrams.count, "Unigram 數量應一致")
    #expect(bigramCount == bigrams.count, "Bigram 數量應一致")
    #expect(candidateOverrideCount == overrides.count, "CandidateOverride 數量應一致")

    print("AsyncSequence 迭代分類統計：")
    print("  - Unigrams: \(unigramCount)")
    print("  - Bigrams: \(bigramCount)")
    print("  - CandidateOverrides: \(candidateOverrideCount)")
    cleanupDatabase(at: dbPath)
  }

  @Test("AsyncSequence multiple iterations should return consistent results")
  func asyncSequenceMultipleIterations() async throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    // 第一次非同步迭代
    var firstCount = 0
    for await _ in db.async {
      firstCount += 1
    }

    // 第二次非同步迭代
    var secondCount = 0
    for await _ in db.async {
      secondCount += 1
    }

    #expect(firstCount == secondCount, "多次非同步迭代應取得相同數量的資料")
    print("多次 AsyncSequence 迭代結果一致：\(firstCount) 筆")
    cleanupDatabase(at: dbPath)
  }

  @Test("Async and Sync iterators should return consistent results")
  func asyncAndSyncIteratorConsistency() async throws {
    try skipIfNoDatabase()
    guard let dbPath = decryptedDBPath else { return }

    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath.path)

    // 同步迭代
    var syncGrams: [KeyKeyUserDBKit.Gram] = []
    for gram in db {
      syncGrams.append(gram)
    }

    // 非同步迭代
    var asyncGrams: [KeyKeyUserDBKit.Gram] = []
    for await gram in db.async {
      asyncGrams.append(gram)
    }

    // 驗證數量一致
    #expect(syncGrams.count == asyncGrams.count, "同步與非同步迭代器應回傳相同數量的資料")

    // 驗證內容一致（比較前幾筆）
    let compareCount = min(10, syncGrams.count)
    for i in 0 ..< compareCount {
      #expect(syncGrams[i].keyArray == asyncGrams[i].keyArray, "第 \(i) 筆 keyArray 應一致")
      #expect(syncGrams[i].current == asyncGrams[i].current, "第 \(i) 筆 current 應一致")
      #expect(syncGrams[i].previous == asyncGrams[i].previous, "第 \(i) 筆 previous 應一致")
      #expect(
        syncGrams[i].isCandidateOverride == asyncGrams[i].isCandidateOverride,
        "第 \(i) 筆 isCandidateOverride 應一致"
      )
    }

    print("同步與非同步迭代器結果一致：\(syncGrams.count) 筆")
    cleanupDatabase(at: dbPath)
  }

  // MARK: Private

  private struct Error: Swift.Error, CustomStringConvertible {
    // MARK: Lifecycle

    init(_ description: String) {
      self.description = description
    }

    // MARK: Internal

    let description: String
  }

  // MARK: - Private Helpers

  private func skipIfNoDatabase() throws {
    guard decryptedDBPath != nil else {
      throw Error("測試資料庫檔案不存在")
    }
  }

  private func cleanupDatabase(at url: URL) {
    try? FileManager.default.removeItem(at: url)
  }
}
