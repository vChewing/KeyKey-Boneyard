// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using System.Collections;

namespace KeyKeyUserDBKit;

/// <summary>
/// 使用者詞庫資料來源介面
/// </summary>
/// <remarks>
/// 此介面定義了讀取使用者詞庫資料的通用 API，
/// 可由資料庫 (<see cref="UserDatabase"/>) 或文字檔案 (<see cref="UserPhraseTextFileObj"/>) 實作。
/// </remarks>
public interface IUserPhraseDataSource : IEnumerable<Gram> {
  /// <summary>
  /// 候選字覆蓋記錄的預設權重
  /// </summary>
  public static double CandidateOverrideProbability => 114.514;

  /// <summary>
  /// 讀取所有使用者單元圖
  /// </summary>
  /// <returns>單元圖列表</returns>
  public List<Gram> FetchUnigrams();

  /// <summary>
  /// 讀取使用者雙元圖快取
  /// </summary>
  /// <param name="limit">限制回傳筆數 (null 表示全部)</param>
  /// <returns>雙元圖列表</returns>
  public List<Gram> FetchBigrams(int? limit = null);

  /// <summary>
  /// 讀取候選字覆蓋快取
  /// </summary>
  /// <returns>候選字覆蓋列表</returns>
  public List<Gram> FetchCandidateOverrides();

  /// <summary>
  /// 讀取所有使用者資料，回傳包含所有 Unigram、Bigram 和 CandidateOverride 的列表
  /// </summary>
  /// <returns>包含所有結果的 <see cref="Gram"/> 列表</returns>
  public List<Gram> FetchAllGrams() {
    var allGrams = new List<Gram>();
    allGrams.AddRange(FetchUnigrams());
    allGrams.AddRange(FetchBigrams());
    allGrams.AddRange(FetchCandidateOverrides());
    return allGrams;
  }
}
