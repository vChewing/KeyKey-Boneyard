// (c) 2025 and onwards The vChewing Project (LGPL v3.0 License or later).
// ====================
// This code is released under the SPDX-License-Identifier: `LGPL-3.0-or-later`.

using System.Collections;

using Microsoft.Data.Sqlite;

namespace KeyKeyUserDBKit;

/// <summary>
/// 使用者資料庫讀取器
/// </summary>
public sealed class UserDatabase : IDisposable, IEnumerable<Gram>, IAsyncEnumerable<Gram> {
  /// <summary>
  /// 候選字覆蓋記錄的預設權重
  /// </summary>
  public const double CandidateOverrideProbability = 114.514;

  private readonly string _path;
  private readonly SqliteConnection _connection;
  private readonly System.Threading.Lock _lock = new();
  private bool _disposed;

  // MARK: - Constructors

  /// <summary>
  /// 開啟解密後的資料庫
  /// </summary>
  /// <param name="path">解密後的資料庫檔案路徑</param>
  public UserDatabase(string path) {
    _path = path;

    var connectionString = new SqliteConnectionStringBuilder {
      DataSource = path,
      Mode = SqliteOpenMode.ReadOnly
    }.ToString();

    _connection = new SqliteConnection(connectionString);

    try {
      _connection.Open();
    } catch (SqliteException ex) {
      throw new DatabaseException($"Failed to open database: {ex.Message}", ex);
    }
  }

  // MARK: - Public Methods

  /// <summary>
  /// 讀取所有使用者單元圖
  /// </summary>
  public List<Gram> FetchUnigrams() {
    lock (_lock) {
      ThrowIfDisposed();

      const string sql = "SELECT qstring, current, probability FROM user_unigrams";
      var results = new List<Gram>();

      using var command = new SqliteCommand(sql, _connection);
      using var reader = command.ExecuteReader();

      while (reader.Read()) {
        var qstring = reader.GetString(0);
        var current = reader.GetString(1);
        var probability = reader.GetDouble(2);

        var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
        results.Add(Gram.CreateUnigram(keyArray, current, probability));
      }

      return results;
    }
  }

  /// <summary>
  /// 讀取使用者雙元圖快取
  /// </summary>
  /// <param name="limit">限制回傳筆數 (null 表示全部)</param>
  public List<Gram> FetchBigrams(int? limit = null) {
    lock (_lock) {
      ThrowIfDisposed();

      var sql = "SELECT qstring, previous, current FROM user_bigram_cache";
      if (limit.HasValue)
        sql += $" LIMIT {limit.Value}";

      var results = new List<Gram>();

      using var command = new SqliteCommand(sql, _connection);
      using var reader = command.ExecuteReader();

      while (reader.Read()) {
        var qstring = reader.GetString(0);
        var previous = reader.GetString(1);
        var current = reader.GetString(2);

        var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
        results.Add(Gram.CreateBigram(keyArray, current, previous));
      }

      return results;
    }
  }

  /// <summary>
  /// 讀取候選字覆蓋快取
  /// </summary>
  public List<Gram> FetchCandidateOverrides() {
    lock (_lock) {
      ThrowIfDisposed();

      const string sql = "SELECT qstring, current FROM user_candidate_override_cache";
      var results = new List<Gram>();

      using var command = new SqliteCommand(sql, _connection);
      using var reader = command.ExecuteReader();

      while (reader.Read()) {
        var qstring = reader.GetString(0);
        var current = reader.GetString(1);

        var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
        results.Add(Gram.CreateCandidateOverride(keyArray, current, CandidateOverrideProbability));
      }

      return results;
    }
  }

  /// <summary>
  /// 讀取所有使用者資料，回傳包含所有 Unigram、Bigram 和 CandidateOverride 的陣列
  /// </summary>
  public List<Gram> FetchAllGrams() {
    var allGrams = new List<Gram>();
    allGrams.AddRange(FetchUnigrams());
    allGrams.AddRange(FetchBigrams());
    allGrams.AddRange(FetchCandidateOverrides());
    return allGrams;
  }

  // MARK: - IEnumerable<Gram>

  /// <summary>
  /// 建立一個迭代器，逐行讀取所有使用者資料（Unigram、Bigram、CandidateOverride）
  /// </summary>
  public IEnumerator<Gram> GetEnumerator() {
    return new GramEnumerator(this);
  }

  /// <inheritdoc/>
  IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

  // MARK: - IAsyncEnumerable<Gram>

  /// <summary>
  /// 建立一個非同步迭代器，逐行讀取所有使用者資料
  /// </summary>
  public async IAsyncEnumerator<Gram> GetAsyncEnumerator(CancellationToken cancellationToken = default) {
    await foreach (var gram in IterateGramsAsync(cancellationToken)) {
      yield return gram;
    }
  }

  private async IAsyncEnumerable<Gram> IterateGramsAsync(
      [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default) {
    // Unigrams
    await foreach (var gram in IterateTableAsync(
        "SELECT qstring, current, probability FROM user_unigrams",
        reader => {
          var qstring = reader.GetString(0);
          var current = reader.GetString(1);
          var probability = reader.GetDouble(2);
          var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
          return Gram.CreateUnigram(keyArray, current, probability);
        },
        cancellationToken)) {
      yield return gram;
    }

    // Bigrams
    await foreach (var gram in IterateTableAsync(
        "SELECT qstring, previous, current FROM user_bigram_cache",
        reader => {
          var qstring = reader.GetString(0);
          var previous = reader.GetString(1);
          var current = reader.GetString(2);
          var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
          return Gram.CreateBigram(keyArray, current, previous);
        },
        cancellationToken)) {
      yield return gram;
    }

    // Candidate Overrides
    await foreach (var gram in IterateTableAsync(
        "SELECT qstring, current FROM user_candidate_override_cache",
        reader => {
          var qstring = reader.GetString(0);
          var current = reader.GetString(1);
          var keyArray = PhonaSet.DecodeQueryStringAsKeyArray(qstring);
          return Gram.CreateCandidateOverride(keyArray, current, CandidateOverrideProbability);
        },
        cancellationToken)) {
      yield return gram;
    }
  }

  private async IAsyncEnumerable<Gram> IterateTableAsync(
      string sql,
      Func<SqliteDataReader, Gram> mapper,
      [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default) {
    await using var command = new SqliteCommand(sql, _connection);
    await using var reader = await command.ExecuteReaderAsync(cancellationToken);

    while (await reader.ReadAsync(cancellationToken)) {
      yield return mapper(reader);
    }
  }

  // MARK: - Internal Methods for Iterator

  internal SqliteDataReader ExecuteReader(string sql) {
    lock (_lock) {
      ThrowIfDisposed();
      var command = new SqliteCommand(sql, _connection);
      return command.ExecuteReader();
    }
  }

  // MARK: - IDisposable

  private void ThrowIfDisposed() {
    ObjectDisposedException.ThrowIf(_disposed, this);
  }

  /// <inheritdoc/>
  public void Dispose() {
    if (_disposed) return;

    lock (_lock) {
      _connection.Dispose();
      _disposed = true;
    }
  }

  // MARK: - GramEnumerator

  private sealed class GramEnumerator : IEnumerator<Gram> {
    private readonly UserDatabase _database;
    private Phase _phase = Phase.Unigrams;
    private SqliteDataReader? _currentReader;
    private Gram? _current;

    private enum Phase {
      Unigrams,
      Bigrams,
      CandidateOverrides,
      Done
    }

    public GramEnumerator(UserDatabase database) {
      _database = database;
    }

    public Gram Current => _current ?? throw new InvalidOperationException("No current element");

    object IEnumerator.Current => Current;

    public bool MoveNext() {
      while (true) {
        if (_currentReader is null) {
          if (!PrepareNextPhase())
            return false;
        }

        if (_currentReader!.Read()) {
          _current = MapCurrentRow();
          return true;
        }

        _currentReader.Dispose();
        _currentReader = null;
        AdvancePhase();
      }
    }

    private bool PrepareNextPhase() {
      var sql = _phase switch {
        Phase.Unigrams => "SELECT qstring, current, probability FROM user_unigrams",
        Phase.Bigrams => "SELECT qstring, previous, current FROM user_bigram_cache",
        Phase.CandidateOverrides => "SELECT qstring, current FROM user_candidate_override_cache",
        Phase.Done => null,
        _ => null
      };

      if (sql is null)
        return false;

      _currentReader = _database.ExecuteReader(sql);
      return true;
    }

    private Gram MapCurrentRow() {
      var reader = _currentReader!;

      return _phase switch {
        Phase.Unigrams =>
            Gram.CreateUnigram(
                PhonaSet.DecodeQueryStringAsKeyArray(reader.GetString(0)),
                reader.GetString(1),
                reader.GetDouble(2)),

        Phase.Bigrams =>
            Gram.CreateBigram(
                PhonaSet.DecodeQueryStringAsKeyArray(reader.GetString(0)),
                reader.GetString(2),
                reader.GetString(1)),

        Phase.CandidateOverrides =>
            Gram.CreateCandidateOverride(
                PhonaSet.DecodeQueryStringAsKeyArray(reader.GetString(0)),
                reader.GetString(1),
                CandidateOverrideProbability),

        _ => throw new InvalidOperationException("Invalid phase")
      };
    }

    private void AdvancePhase() {
      _phase = _phase switch {
        Phase.Unigrams => Phase.Bigrams,
        Phase.Bigrams => Phase.CandidateOverrides,
        Phase.CandidateOverrides => Phase.Done,
        _ => Phase.Done
      };
    }

    public void Reset() {
      _currentReader?.Dispose();
      _currentReader = null;
      _phase = Phase.Unigrams;
      _current = null;
    }

    public void Dispose() {
      _currentReader?.Dispose();
      _currentReader = null;
    }
  }
}

/// <summary>
/// 資料庫錯誤
/// </summary>
public class DatabaseException : Exception {
  /// <summary>
  /// 以指定訊息初始化資料庫錯誤
  /// </summary>
  /// <param name="message">錯誤訊息</param>
  public DatabaseException(string message) : base(message) {
  }

  /// <summary>
  /// 以指定訊息和內部例外初始化資料庫錯誤
  /// </summary>
  /// <param name="message">錯誤訊息</param>
  /// <param name="innerException">造成此錯誤的內部例外</param>
  public DatabaseException(string message, Exception innerException)
      : base(message, innerException) {
  }
}
