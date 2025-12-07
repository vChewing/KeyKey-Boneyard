// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

import Foundation
import KeyKeyUserDBKit

// MARK: - CLI Implementation

func printUsage() {
  let programName = (CommandLine.arguments[0] as NSString).lastPathComponent
  print(
    """
    Yahoo! 奇摩輸入法 (KeyKey) 使用者資料庫工具

    用法: \(programName) <指令> [選項]

    指令:
      decrypt <輸入檔> [輸出檔]   解密 KeyKey 使用者資料庫
      dump <資料庫路徑>           顯示資料庫中的所有詞彙

    選項:
      -h, --help                  顯示此說明

    範例:
      \(programName) decrypt SmartMandarinUserData.db
      \(programName) decrypt SmartMandarinUserData.db decrypted.db
      \(programName) dump SmartMandarinUserData.db
    """
  )
}

func showDecodedData(dbPath: String) {
  do {
    let db = try KeyKeyUserDBKit.UserDatabase(path: dbPath)

    print("\n=== 使用者單元圖 (user_unigrams) ===")
    let unigrams = try db.fetchUnigrams()
    for gram in unigrams {
      let reading = gram.keyArray.joined(separator: ",")
      print("  \(gram.current)\t\(reading)\t(\(gram.probability))")
    }

    print("\n=== 使用者雙元圖快取 (user_bigram_cache) ===")
    let bigrams = try db.fetchBigrams(limit: 10)
    for gram in bigrams {
      let reading = gram.keyArray.joined(separator: ",")
      print("  \(gram.previous ?? "")→\(gram.current)\t\(reading)")
    }

    print("\n=== 候選字覆蓋快取 (user_candidate_override_cache) ===")
    let overrides = try db.fetchCandidateOverrides()
    if overrides.isEmpty {
      print("  (空)")
    } else {
      for gram in overrides {
        let reading = gram.keyArray.joined(separator: ",")
        print("  \(gram.current)\t\(reading)")
      }
    }
  } catch {
    print("無法讀取資料: \(error.localizedDescription)")
  }
}

func handleDecrypt(args: [String]) -> Int32 {
  guard args.count >= 2 else {
    print("用法: \((args[0] as NSString).lastPathComponent) decrypt <輸入檔> [輸出檔]")
    return 1
  }

  let inputPath = args[1]
  let inputURL = URL(fileURLWithPath: inputPath)

  guard FileManager.default.fileExists(atPath: inputPath) else {
    print("錯誤：找不到檔案 \(inputPath)")
    return 1
  }

  let outputPath: String
  if args.count >= 3 {
    outputPath = args[2]
  } else {
    let baseName = inputURL.deletingPathExtension().lastPathComponent
    let directory = inputURL.deletingLastPathComponent()
    outputPath = directory.appendingPathComponent("\(baseName).decrypted.db").path
  }

  let outputURL = URL(fileURLWithPath: outputPath)

  do {
    let encryptedData = try Data(contentsOf: inputURL)
    print("解密 \(inputPath)")
    print("  檔案大小: \(encryptedData.count) bytes")
    print("  頁面數量: \(encryptedData.count / KeyKeyUserDBKit.SEEDecryptor.pageSize)")

    let decryptor = KeyKeyUserDBKit.SEEDecryptor()
    try decryptor.decryptFile(at: inputURL, to: outputURL)

    print("  輸出: \(outputPath)")
    print("  完成！")

    showDecodedData(dbPath: outputPath)
    return 0

  } catch {
    print("錯誤：\(error.localizedDescription)")
    return 1
  }
}

func handleDump(args: [String]) -> Int32 {
  guard args.count >= 2 else {
    print("用法: \((args[0] as NSString).lastPathComponent) dump <資料庫路徑>")
    return 1
  }

  let dbPath = args[1]

  guard FileManager.default.fileExists(atPath: dbPath) else {
    print("錯誤：找不到檔案 \(dbPath)")
    return 1
  }

  // 檢查是否為加密資料庫
  var actualDbPath = dbPath
  var tempURL: URL?

  if KeyKeyUserDBKit.SEEDecryptor.isEncryptedDatabase(at: URL(fileURLWithPath: dbPath)) {
    print("偵測到加密資料庫，正在解密...")
    tempURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(
      UUID().uuidString + ".db"
    )
    do {
      let decryptor = KeyKeyUserDBKit.SEEDecryptor()
      try decryptor.decryptFile(at: URL(fileURLWithPath: dbPath), to: tempURL!)
      actualDbPath = tempURL!.path
    } catch {
      print("錯誤：\(error.localizedDescription)")
      return 1
    }
  }

  defer {
    // 清理臨時檔案
    if let tempURL {
      try? FileManager.default.removeItem(at: tempURL)
    }
  }

  showDecodedData(dbPath: actualDbPath)
  return 0
}

func main() -> Int32 {
  let args = CommandLine.arguments

  guard args.count >= 2 else {
    printUsage()
    return 1
  }

  switch args[1].lowercased() {
  case "decrypt":
    return handleDecrypt(args: Array(args.dropFirst()))
  case "dump":
    return handleDump(args: Array(args.dropFirst()))
  case "--help", "-h":
    printUsage()
    return 0
  default:
    print("未知的指令: \(args[1])")
    printUsage()
    return 1
  }
}

exit(main())
