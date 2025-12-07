// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

import Foundation
import Testing

@testable import KeyKeyUserDBKit

@Suite("SEEDecryptor Tests")
struct SEEDecryptorTests {
  @Test("Default key should be correct")
  func defaultKey() {
    // 驗證預設密鑰
    #expect(KeyKeyUserDBKit.SEEDecryptor.defaultKey.count == 16)
    #expect(
      String(bytes: KeyKeyUserDBKit.SEEDecryptor.defaultKey, encoding: .utf8) == "yahookeykeyuserd"
    )
  }

  @Test("Constants should be correct")
  func constants() {
    #expect(KeyKeyUserDBKit.SEEDecryptor.pageSize == 1_024)
    #expect(KeyKeyUserDBKit.SEEDecryptor.reservedBytes == 32)
    #expect(KeyKeyUserDBKit.SEEDecryptor.dataAreaSize == 992)
  }

  @Test("Invalid size should throw error")
  func invalidSize() {
    let decryptor = KeyKeyUserDBKit.SEEDecryptor()

    // 資料大小不是 page size 的倍數應該拋出錯誤
    let invalidData = Data(repeating: 0, count: 1_000)
    #expect(throws: KeyKeyUserDBKit.DecryptionError.self) {
      try decryptor.decrypt(encryptedData: invalidData)
    }
  }

  @Test("Empty data should return empty result")
  func emptyData() throws {
    let decryptor = KeyKeyUserDBKit.SEEDecryptor()

    // 空資料應該回傳空結果
    let emptyData = Data()
    let result = try decryptor.decrypt(encryptedData: emptyData)
    #expect(result.isEmpty)
  }

  // MARK: - Constructor Tests

  @Test("Constructor with default key should succeed")
  func constructor_WithDefaultKey_ShouldSucceed() {
    let decryptor = KeyKeyUserDBKit.SEEDecryptor()
    // 驗證可以成功初始化（如果能執行到這裡，代表成功）
    _ = decryptor
  }

  @Test("Constructor with valid key should succeed")
  func constructor_WithValidKey_ShouldSucceed() {
    let key: [UInt8] = Array(repeating: 0, count: 16)
    let decryptor = KeyKeyUserDBKit.SEEDecryptor(key: key)
    // 驗證可以成功初始化（如果能執行到這裡，代表成功）
    _ = decryptor
  }

  // MARK: - Single Page Tests

  @Test("Decrypt single page should return correct size")
  func decrypt_SinglePage_ShouldReturnCorrectSize() throws {
    let decryptor = KeyKeyUserDBKit.SEEDecryptor()
    let singlePage = Data(repeating: 0, count: KeyKeyUserDBKit.SEEDecryptor.pageSize)

    let result = try decryptor.decrypt(encryptedData: singlePage)

    #expect(result.count == KeyKeyUserDBKit.SEEDecryptor.pageSize)
  }

  // MARK: - Multiple Pages Tests

  @Test("Decrypt multiple pages should return correct size")
  func decrypt_MultiplePages_ShouldReturnCorrectSize() throws {
    let decryptor = KeyKeyUserDBKit.SEEDecryptor()
    let twoPages = Data(repeating: 0, count: KeyKeyUserDBKit.SEEDecryptor.pageSize * 2)

    let result = try decryptor.decrypt(encryptedData: twoPages)

    #expect(result.count == KeyKeyUserDBKit.SEEDecryptor.pageSize * 2)
  }
}
