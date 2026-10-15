using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetWatch.Core.Qos;

/// <summary>一条由当前 NetWatch 会话创建的临时上传限速规则。</summary>
public sealed record UploadLimitEntry(
    string PolicyName,
    string AppPath,
    long BytesPerSecond,
    DateTime CreatedUtc,
    bool Enabled)
{
    public ulong BitsPerSecond => checked((ulong)BytesPerSecond * 8UL);
}

/// <summary>
/// 管理按 exe 路径匹配的 Windows QoS 出站节流策略。
/// 规则不写入 NetWatch 配置；正常退出显式删除，异常终止后下次启动按 owner 标记清理。
/// </summary>
public sealed class UploadLimitManager : IDisposable
{
    private const string PolicyPrefix = "NetWatch.Upload.";
    private const string PolicyStore = "ActiveStore";
    private readonly object _gate = new();
    private readonly List<UploadLimitEntry> _entries = new();
    private readonly string _sessionId = Guid.NewGuid().ToString("N");
    private readonly int _ownerPid = Environment.ProcessId;
    private readonly DateTime _ownerStartedUtc = DateTime.UtcNow;
    private readonly string _ownerFile;
    private bool _loaded;
    private bool _disposed;

    public UploadLimitManager()
    {
        _ownerFile = Path.Combine(Path.GetTempPath(), $"{PolicyPrefix}{_sessionId}.owner.json");
    }

    public string? LastError { get; private set; }

    public IReadOnlyList<UploadLimitEntry> Entries
    {
        get { lock (_gate) return _entries.ToList(); }
    }

    public int ActiveCount
    {
        get { lock (_gate) return _entries.Count(e => e.Enabled); }
    }

    /// <summary>清理 NetWatch 自己遗留的策略，并登记本次会话 owner。</summary>
    public void Load()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_loaded) return;
            try
            {
                CleanupOrphansLocked();
                File.WriteAllText(_ownerFile, JsonSerializer.Serialize(new OwnerMarker(_ownerPid, _ownerStartedUtc)));
                _loaded = true;
                LastError = null;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Log.Error("上传限速初始化失败：" + ex.Message);
            }
        }
    }

    public UploadLimitEntry? Find(string appPath)
    {
        var normalized = NormalizeAppPath(appPath);
        lock (_gate)
            return _entries.FirstOrDefault(e => e.AppPath.Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>按已有规范化路径查询，不访问文件系统，供 UI 刷新使用。</summary>
    public UploadLimitEntry? FindKnown(string? appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath)) return null;
        lock (_gate)
            return _entries.FirstOrDefault(e => e.AppPath.Equals(appPath, StringComparison.OrdinalIgnoreCase));
    }

    public UploadLimitEntry Add(string appPath, long bytesPerSecond)
    {
        var normalized = NormalizeAppPath(appPath);
        var bits = ToBitsPerSecond(bytesPerSecond);
        lock (_gate)
        {
            ThrowIfDisposed();
            EnsureLoadedLocked();
            if (_entries.Any(e => e.AppPath.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("该程序已经存在上传限速规则，请使用修改或取消限速。");

            var name = PolicyName(normalized);
            ApplyPolicy(name, normalized, bits);
            var entry = new UploadLimitEntry(name, normalized, bytesPerSecond, DateTime.UtcNow, true);
            _entries.Add(entry);
            return entry;
        }
    }

    public void Update(UploadLimitEntry entry, long bytesPerSecond)
    {
        var bits = ToBitsPerSecond(bytesPerSecond);
        lock (_gate)
        {
            ThrowIfDisposed();
            EnsureLoadedLocked();
            var index = IndexOfLocked(entry);
            if (index < 0) return;
            var current = _entries[index];
            if (current.Enabled)
            {
                RemovePolicy(current.PolicyName);
                try
                {
                    ApplyPolicy(current.PolicyName, current.AppPath, bits);
                }
                catch
                {
                    try { ApplyPolicy(current.PolicyName, current.AppPath, current.BitsPerSecond); }
                    catch (Exception restore) { Log.Error("恢复原上传限速失败：" + restore.Message); }
                    throw;
                }
            }
            _entries[index] = current with { BytesPerSecond = bytesPerSecond };
        }
    }

    public void SetEnabled(UploadLimitEntry entry, bool enabled)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            EnsureLoadedLocked();
            var index = IndexOfLocked(entry);
            if (index < 0) return;
            var current = _entries[index];
            if (current.Enabled == enabled) return;
            if (enabled) ApplyPolicy(current.PolicyName, current.AppPath, current.BitsPerSecond);
            else RemovePolicy(current.PolicyName);
            _entries[index] = current with { Enabled = enabled };
        }
    }

    public void Remove(UploadLimitEntry entry)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var index = IndexOfLocked(entry);
            if (index < 0) return;
            var current = _entries[index];
            if (current.Enabled) RemovePolicy(current.PolicyName);
            _entries.RemoveAt(index);
        }
    }

    /// <summary>显式撤销本会话创建的全部策略；可重复调用。</summary>
    public void RemoveAll()
    {
        lock (_gate)
        {
            if (_disposed) return;
            RemoveAllLocked();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            try { RemoveAllLocked(); }
            finally
            {
                try { if (File.Exists(_ownerFile)) File.Delete(_ownerFile); } catch { }
                _disposed = true;
            }
        }
    }

    private void RemoveAllLocked()
    {
        foreach (var entry in _entries.ToList())
        {
            if (!entry.Enabled) continue;
            try { RemovePolicy(entry.PolicyName); }
            catch (Exception ex) { LastError = ex.Message; Log.Error("清理上传限速失败：" + ex.Message); }
        }
        _entries.Clear();
    }

    private void CleanupOrphansLocked()
    {
        foreach (var name in ListOwnedPolicyNames())
        {
            if (!TryParseOwner(name, out var pid, out var sessionId)) continue;
            if (IsOwnerAlive(pid, sessionId)) continue;
            try { RemovePolicy(name); }
            catch (Exception ex) { Log.Error("清理遗留上传限速失败：" + ex.Message); }
        }
    }

    private static bool IsOwnerAlive(int pid, string sessionId)
    {
        var marker = Path.Combine(Path.GetTempPath(), $"{PolicyPrefix}{sessionId}.owner.json");
        try
        {
            if (!File.Exists(marker)) return false;
            var owner = JsonSerializer.Deserialize<OwnerMarker>(File.ReadAllText(marker));
            if (owner is null || owner.Pid != pid) return false;
            using var process = Process.GetProcessById(pid);
            var started = process.StartTime.ToUniversalTime();
            return Math.Abs((started - owner.StartedUtc).TotalSeconds) < 5;
        }
        catch { return false; }
    }

    private List<string> ListOwnedPolicyNames()
    {
        const string script = """
$ErrorActionPreference = 'Stop'
$items = @(Get-NetQosPolicy -PolicyStore $env:NW_QOS_STORE -ErrorAction Stop |
    Where-Object { $_.Name -like 'NetWatch.Upload.*' } |
    ForEach-Object { $_.Name })
ConvertTo-Json -InputObject $items -Compress
""";
        var output = RunPowerShell(script, new Dictionary<string, string>
        {
            ["NW_QOS_STORE"] = PolicyStore,
        });
        if (string.IsNullOrWhiteSpace(output)) return new List<string>();
        using var doc = JsonDocument.Parse(output.Trim());
        if (doc.RootElement.ValueKind == JsonValueKind.String)
            return new List<string> { doc.RootElement.GetString()! };
        return doc.RootElement.ValueKind == JsonValueKind.Array
            ? doc.RootElement.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList()
            : new List<string>();
    }

    private static void ApplyPolicy(string name, string appPath, ulong bitsPerSecond)
    {
        const string script = """
$ErrorActionPreference = 'Stop'
$rate = [UInt64]::Parse($env:NW_QOS_RATE)
New-NetQosPolicy -Name $env:NW_QOS_NAME -AppPathNameMatchCondition $env:NW_QOS_PATH -ThrottleRateActionBitsPerSecond $rate -PolicyStore $env:NW_QOS_STORE -ErrorAction Stop | Out-Null
""";
        RunPowerShell(script, new Dictionary<string, string>
        {
            ["NW_QOS_NAME"] = name,
            ["NW_QOS_PATH"] = appPath,
            ["NW_QOS_RATE"] = bitsPerSecond.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["NW_QOS_STORE"] = PolicyStore,
        });
    }

    private static void RemovePolicy(string name)
    {
        const string script = """
$ErrorActionPreference = 'Stop'
Remove-NetQosPolicy -Name $env:NW_QOS_NAME -PolicyStore $env:NW_QOS_STORE -Confirm:$false -ErrorAction Stop | Out-Null
""";
        RunPowerShell(script, new Dictionary<string, string>
        {
            ["NW_QOS_NAME"] = name,
            ["NW_QOS_STORE"] = PolicyStore,
        });
    }

    private static string RunPowerShell(string script, IReadOnlyDictionary<string, string> variables)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("-NoLogo");
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(encoded);
        foreach (var pair in variables) psi.Environment[pair.Key] = pair.Value;

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("无法启动 Windows QoS 管理组件 powershell.exe。");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30000))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("Windows QoS 操作超时。");
        }
        if (process.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
            throw new InvalidOperationException(SimplifyPowerShellError(detail));
        }
        return stdout;
    }

    private static string SimplifyPowerShellError(string detail)
    {
        if (detail.Contains("拒绝访问", StringComparison.Ordinal)
            || detail.Contains("Access is denied", StringComparison.OrdinalIgnoreCase))
            return "Windows QoS 拒绝访问。请确认 NetWatch 是以管理员身份运行，且 QoS Packet Scheduler 服务已启用。";
        if (detail.Contains("找不到", StringComparison.Ordinal)
            || detail.Contains("not found", StringComparison.OrdinalIgnoreCase))
            return "系统未找到 Windows QoS 组件。请确认系统启用了 QoS Packet Scheduler。";
        if (detail.Contains("超出", StringComparison.Ordinal)
            || detail.Contains("invalid", StringComparison.OrdinalIgnoreCase))
            return "Windows QoS 不接受当前限速参数，请换一个更大的正数重试。";

        var compact = detail.Replace("\r", " ").Replace("\n", " ").Trim();
        return compact.Length > 600 ? compact[..600] + "…" : compact;
    }

    private int IndexOfLocked(UploadLimitEntry entry)
        => _entries.FindIndex(e => e.PolicyName.Equals(entry.PolicyName, StringComparison.OrdinalIgnoreCase));

    private string PolicyName(string appPath)
    {
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(appPath))).ToLowerInvariant()[..10];
        return $"{PolicyPrefix}{_ownerPid}.{_sessionId}.{digest}";
    }

    private static bool TryParseOwner(string name, out int pid, out string sessionId)
    {
        pid = 0;
        sessionId = "";
        var parts = name.Split('.');
        if (parts.Length != 5 || parts[0] != "NetWatch" || parts[1] != "Upload") return false;
        if (!int.TryParse(parts[2], out pid) || !Guid.TryParseExact(parts[3], "N", out _)) return false;
        sessionId = parts[3];
        return sessionId.Length == 32;
    }

    private static string NormalizeAppPath(string appPath)
    {
        if (string.IsNullOrWhiteSpace(appPath)) throw new ArgumentException("程序路径不能为空。", nameof(appPath));
        var full = Path.GetFullPath(appPath.Trim());
        if (!full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("上传限速只能应用于 exe 程序。");
        if (!File.Exists(full)) throw new InvalidOperationException($"程序不存在：{full}");
        return full;
    }

    private static ulong ToBitsPerSecond(long bytesPerSecond)
    {
        if (bytesPerSecond <= 0) throw new InvalidOperationException("上传速度必须大于 0。");
        return checked((ulong)bytesPerSecond * 8UL);
    }

    private void EnsureLoadedLocked()
    {
        if (!_loaded) Load();
        if (!_loaded) throw new InvalidOperationException(LastError ?? "上传限速管理器尚未初始化。");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(UploadLimitManager));
    }

    private sealed record OwnerMarker(int Pid, DateTime StartedUtc);
}
