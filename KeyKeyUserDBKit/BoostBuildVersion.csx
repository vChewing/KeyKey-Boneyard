#!/usr/bin/env dotnet-script

#nullable enable
// BoostBuildVersion.csx
// 用途:
//  1. 自動將主專案 WinNT/KeyKeyUserDBKit/KeyKeyUserDBKit.csproj 的 <Version> 之 semver patch 自動 +1。
//  2. 或若第一個非旗標參數是合法 semver (X.Y.Z) 則直接使用該版本號。
//  3. 同步更新以下檔案中的版本字串：
//       - WinNT/KeyKeyUserDBKit/KeyKeyUserDBKit.csproj: Version
//       - WinNT/KeyKeyDecryptCLI/KeyKeyDecryptCLI.csproj: Version
//       - WinNT/KeyKeyUserDBKit.Tests/KeyKeyUserDBKit.Tests.csproj: Version
//       - Sources/KeyKeyUserDBKit/KeyKeyUserDBKit.swift: version 常數
//  4. 保留原始 UTF-8 BOM（若存在）與換行格式。
// 使用方式:
//   dotnet script BoostBuildVersion.csx --             (自動 patch +1)
//   dotnet script BoostBuildVersion.csx -- --dry-run   (僅顯示不寫回)
//   dotnet script BoostBuildVersion.csx -- 5.1.0       (指定版本)
//   dotnet script BoostBuildVersion.csx -- 5.1.0 --dry-run
// 備註: 若自動計算版本與舊版本相同則視為錯誤；成功後會嘗試 git add 被更動的檔案。

using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;
using System.Collections.Generic;

// dotnet-script 使用 Args 變數傳遞參數
bool dryRun = Args.Contains("--dry-run");
var rawArgs = Args.Where(a => a != "--dry-run").ToList();

string root = Directory.GetCurrentDirectory();
string mainProj = Path.Combine(root, "WinNT", "KeyKeyUserDBKit", "KeyKeyUserDBKit.csproj");
if (!File.Exists(mainProj)) {
    Console.Error.WriteLine($"找不到主專案檔: {mainProj}");
    Environment.Exit(1);
}

string ReadAllPreserve(string path, out bool hadBom, out bool usedCRLF) {
    byte[] raw = File.ReadAllBytes(path);
    hadBom = raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF;
    string text = hadBom ? Encoding.UTF8.GetString(raw, 3, raw.Length - 3) : Encoding.UTF8.GetString(raw);
    usedCRLF = text.Contains("\r\n");
    return text;
}

void WriteAllPreserve(string path, string text, bool hadBom, bool usedCRLF) {
    if (usedCRLF) {
        text = Regex.Replace(text, "\r?\n", "\r\n");
    } else {
        text = text.Replace("\r\n", "\n");
    }
    byte[] body = Encoding.UTF8.GetBytes(text);
    if (hadBom) {
        var withBom = new byte[body.Length + 3];
        withBom[0] = 0xEF; withBom[1] = 0xBB; withBom[2] = 0xBF;
        Buffer.BlockCopy(body, 0, withBom, 3, body.Length);
        body = withBom;
    }
    File.WriteAllBytes(path, body);
}

string projText = ReadAllPreserve(mainProj, out _, out _);
var verMatch = Regex.Match(projText, "<Version>([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)</Version>");
if (!verMatch.Success) {
    Console.Error.WriteLine("無法在 KeyKeyUserDBKit.csproj 找到 <Version> 標籤。");
    Environment.Exit(1);
}

string oldVersion = verMatch.Groups[1].Value;
string autoNew;
var parts = oldVersion.Split('.');
if (parts.Length >= 3 && int.TryParse(parts[2], out int patch)) {
    autoNew = $"{parts[0]}.{parts[1]}.{patch + 1}";
} else if (parts.Length == 2) {
    autoNew = $"{parts[0]}.{parts[1]}.1";
} else {
    Console.Error.WriteLine($"不支援的版本格式: {oldVersion}");
    Environment.Exit(1);
    return; // 避免編譯器警告
}

string? manual = null;
if (rawArgs.Count > 0) {
    var cand = rawArgs[0];
    if (Regex.IsMatch(cand, "^[0-9]+\\.[0-9]+\\.[0-9]+$")) {
        manual = cand;
    }
}
string newVersion = manual ?? autoNew;
bool manualOverride = manual != null;

if (!manualOverride && newVersion == oldVersion) {
    Console.Error.WriteLine("自動推算的新版本與舊版本相同，未進行變更。");
    Environment.Exit(1);
}

Console.WriteLine($"Old version: {oldVersion} -> New version: {newVersion}{(manualOverride ? " (manual override)" : "")}{(dryRun ? " (dry-run)" : "")}");

// 定義要更新的 .csproj 檔案
var csprojFiles = new[] {
    Path.Combine(root, "WinNT", "KeyKeyUserDBKit", "KeyKeyUserDBKit.csproj"),
    Path.Combine(root, "WinNT", "KeyKeyDecryptCLI", "KeyKeyDecryptCLI.csproj"),
    Path.Combine(root, "WinNT", "KeyKeyUserDBKit.Tests", "KeyKeyUserDBKit.Tests.csproj")
};

string swiftFile = Path.Combine(root, "Sources", "KeyKeyUserDBKit", "KeyKeyUserDBKit.swift");

// 用於替換 XML 版本標籤的正則
var xmlTagPattern = new Regex(
    "<(ReleaseVersion|AssemblyVersion|FileVersion|Version)>" + Regex.Escape(oldVersion) + "</\\1>"
);

// 用於替換 Swift 版本常數的正則
var swiftVersionPattern = new Regex(
    @"(public\s+static\s+let\s+version\s*=\s*"")" + Regex.Escape(oldVersion) + @"("")"
);

int changedCount = 0;
var changedFiles = new List<string>();

// 處理 .csproj 檔案
foreach (var file in csprojFiles) {
    if (!File.Exists(file)) {
        Console.WriteLine($"跳過 (不存在): {Path.GetRelativePath(root, file)}");
        continue;
    }
    string text = ReadAllPreserve(file, out bool hadBom, out bool usedCRLF);
    string original = text;

    text = xmlTagPattern.Replace(text, m => {
        var tagName = m.Groups[1].Value;
        return $"<{tagName}>{newVersion}</{tagName}>";
    });

    bool changed = text != original;
    if (changed) {
        if (dryRun) {
            Console.WriteLine($"Would update: {Path.GetRelativePath(root, file)}");
        } else {
            WriteAllPreserve(file, text, hadBom, usedCRLF);
            Console.WriteLine($"Updated: {Path.GetRelativePath(root, file)}");
        }
        changedCount++;
        changedFiles.Add(file);
    } else {
        Console.WriteLine($"No change needed: {Path.GetRelativePath(root, file)}");
    }
}

// 處理 Swift 檔案
if (File.Exists(swiftFile)) {
    string text = ReadAllPreserve(swiftFile, out bool hadBom, out bool usedCRLF);
    string original = text;

    text = swiftVersionPattern.Replace(text, m => $"{m.Groups[1].Value}{newVersion}{m.Groups[2].Value}");

    bool changed = text != original;
    if (changed) {
        if (dryRun) {
            Console.WriteLine($"Would update: {Path.GetRelativePath(root, swiftFile)}");
        } else {
            WriteAllPreserve(swiftFile, text, hadBom, usedCRLF);
            Console.WriteLine($"Updated: {Path.GetRelativePath(root, swiftFile)}");
        }
        changedCount++;
        changedFiles.Add(swiftFile);
    } else {
        Console.WriteLine($"No change needed: {Path.GetRelativePath(root, swiftFile)}");
    }
} else {
    Console.WriteLine($"跳過 (不存在): {Path.GetRelativePath(root, swiftFile)}");
}

Console.WriteLine($"Done. Files changed: {changedCount}. New version: {newVersion}");

if (!dryRun && changedFiles.Count > 0) {
    try {
        var psi = new System.Diagnostics.ProcessStartInfo {
            FileName = "git",
            Arguments = "rev-parse --is-inside-work-tree",
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        var checkProcess = System.Diagnostics.Process.Start(psi);
        checkProcess?.WaitForExit();
        
        if (checkProcess?.ExitCode == 0) {
            // 在 git 倉庫中，添加更改的文件
            var relativePaths = changedFiles.Select(f => Path.GetRelativePath(root, f));
            var addPsi = new System.Diagnostics.ProcessStartInfo {
                FileName = "git",
                Arguments = $"add {string.Join(" ", relativePaths.Select(p => $"\"{p}\""))}",
                UseShellExecute = false,
                WorkingDirectory = root
            };
            System.Diagnostics.Process.Start(addPsi)?.WaitForExit();
            Console.WriteLine("(Staged changes in git.)");
        }
    } catch {
        // 忽略 git 相關錯誤
    }
}
