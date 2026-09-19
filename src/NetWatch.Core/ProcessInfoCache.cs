using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetWatch.Core;

public sealed record ProcessInfo(int Pid, string Name, string? Path, bool Alive);

/// <summary>PID → 进程名/路径 的带缓存查询（ETW 只给 PID，名称查询有开销）。</summary>
public sealed class ProcessInfoCache
{
    private readonly ConcurrentDictionary<int, ProcessInfo> _cache = new();

    public ProcessInfo Get(int pid)
        => _cache.GetOrAdd(pid, p =>
        {
            try
            {
                using var proc = Process.GetProcessById(p);
                string? path = null;
                try { path = proc.MainModule?.FileName; }
                catch { /* 系统或受保护进程读不到路径 */ }
                return new ProcessInfo(p, proc.ProcessName, path, true);
            }
            catch
            {
                return new ProcessInfo(p, $"PID {p}", null, false);
            }
        });

    public bool IsAlive(int pid)
    {
        try { using var proc = Process.GetProcessById(pid); return true; }
        catch { return false; }
    }
}
