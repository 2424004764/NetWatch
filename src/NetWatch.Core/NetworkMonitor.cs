using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetWatch.Core;

/// <summary>单个进程在一次刷新周期内的增量与累计流量。</summary>
public sealed record PidSnapshot(int Pid, long TickSent, long TickRecv, long TotalSent, long TotalRecv);

/// <summary>单个远程 IP 在一次刷新周期内的增量与累计流量，以及与之通信的进程。</summary>
public sealed record RemoteSnapshot(string Ip, long TickSent, long TickRecv, long TotalSent, long TotalRecv, List<int> Pids);

/// <summary>
/// 基于 ETW（Windows 内核网络跟踪）的按进程流量采集器。
/// 需要管理员权限：内核提供程序（NetworkTCPIP 关键字）会推送每个 TCP/UDP 收发事件，
/// 我们按 PID 累加字节数，界面每秒取一次增量得到速率。
/// 同时按“对端 IP”聚合一份（send 事件的对端是 daddr，recv 事件的对端是 saddr），
/// 供“目标 IP”视图回答“数据都发给了谁”。
/// </summary>
public sealed class NetworkMonitor : IDisposable
{
    private sealed class Stats
    {
        public long TickSent, TickRecv, TotalSent, TotalRecv;
        public DateTime LastActiveUtc = DateTime.UtcNow;
    }

    private sealed class RemoteStats
    {
        public long TickSent, TickRecv, TotalSent, TotalRecv;
        public readonly HashSet<int> Pids = new();
        public DateTime LastActiveUtc = DateTime.UtcNow;
    }

    private readonly TraceEventSession _session;
    private readonly Dictionary<int, Stats> _stats = new();
    private readonly Dictionary<string, RemoteStats> _remotes = new();
    private readonly object _gate = new();
    private long _events;
    private bool _disposed;

    public long EventCount => Interlocked.Read(ref _events);
    public DateTime StartedUtc { get; } = DateTime.UtcNow;

    private NetworkMonitor(TraceEventSession session) => _session = session;

    public static NetworkMonitor Start()
    {
        var session = new TraceEventSession("NetWatchLiveSession")
        {
            StopOnDispose = true,
        };
        try
        {
            bool ok = session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
            if (!ok)
                throw new InvalidOperationException("创建内核网络跟踪会话失败（可能被其他内核跟踪程序占用）。");
        }
        catch (Exception ex)
        {
            session.Dispose();
            throw new InvalidOperationException(
                "启动内核网络跟踪失败：NetWatch 需要管理员权限，请右键选择“以管理员身份运行”。（" + ex.Message + "）", ex);
        }

        var monitor = new NetworkMonitor(session);
        monitor.Hook(session.Source.Kernel);

        var pump = new Thread(() =>
        {
            try { session.Source.Process(); }
            catch (Exception ex) { Log.Error("ETW 事件泵异常退出：" + ex.Message); }
        })
        { IsBackground = true, Name = "NetWatch-ETW" };
        pump.Start();
        Log.Info("ETW 内核网络监控已启动。");
        return monitor;
    }

    private void Hook(KernelTraceEventParser k)
    {
        // TCP（IPv4 / IPv6）：send/recv 的对端都在 daddr（recv 的 saddr 是本机地址，实测如此）
        k.TcpIpSend += d => Count(d.ProcessID, d.size, 0, d.daddr);
        k.TcpIpRecv += d => Count(d.ProcessID, 0, d.size, d.daddr);
        k.TcpIpSendIPV6 += d => Count(d.ProcessID, d.size, 0, d.daddr);
        k.TcpIpRecvIPV6 += d => Count(d.ProcessID, 0, d.size, d.daddr);
        // UDP（部分 Windows 版本不提供接收方向事件）
        k.UdpIpSend += d => Count(d.ProcessID, d.size, 0, d.daddr);
        k.UdpIpRecv += d => Count(d.ProcessID, 0, d.size, d.saddr);
    }

    private void Count(int pid, int sent, int recv, System.Net.IPAddress? remote)
    {
        Interlocked.Increment(ref _events);
        lock (_gate)
        {
            if (!_stats.TryGetValue(pid, out var s))
                _stats[pid] = s = new Stats();
            if (sent != 0) { s.TickSent += sent; s.TotalSent += sent; }
            if (recv != 0) { s.TickRecv += recv; s.TotalRecv += recv; }
            s.LastActiveUtc = DateTime.UtcNow;

            if (remote != null)
            {
                if (!_remotes.TryGetValue(remote.ToString(), out var rs))
                {
                    if (_remotes.Count >= 4096) PruneRemotesLocked(force: true);
                    _remotes[remote.ToString()] = rs = new RemoteStats();
                }
                if (sent != 0) { rs.TickSent += sent; rs.TotalSent += sent; }
                if (recv != 0) { rs.TickRecv += recv; rs.TotalRecv += recv; }
                if (rs.Pids.Count < 16) rs.Pids.Add(pid);
                rs.LastActiveUtc = DateTime.UtcNow;
            }
        }
    }

    /// <summary>取走自上次调用以来的增量（并把增量清零），同时返回累计值。</summary>
    public List<PidSnapshot> Snapshot(bool resetTick = true)
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            var result = new List<PidSnapshot>(_stats.Count);
            List<int>? stale = null;
            foreach (var kv in _stats)
            {
                var s = kv.Value;
                result.Add(new PidSnapshot(kv.Key, s.TickSent, s.TickRecv, s.TotalSent, s.TotalRecv));
                if (resetTick) { s.TickSent = 0; s.TickRecv = 0; }
                if (now - s.LastActiveUtc > TimeSpan.FromMinutes(5))
                    (stale ??= new List<int>()).Add(kv.Key);
            }
            if (stale != null)
                foreach (var pid in stale) _stats.Remove(pid);
            return result;
        }
    }

    /// <summary>按远程 IP 聚合的增量与累计流量（并清零增量）。</summary>
    public List<RemoteSnapshot> SnapshotRemotes(bool resetTick = true)
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            var result = new List<RemoteSnapshot>(_remotes.Count);
            List<string>? stale = null;
            foreach (var kv in _remotes)
            {
                var s = kv.Value;
                result.Add(new RemoteSnapshot(kv.Key, s.TickSent, s.TickRecv, s.TotalSent, s.TotalRecv, s.Pids.ToList()));
                if (resetTick) { s.TickSent = 0; s.TickRecv = 0; }
                if (now - s.LastActiveUtc > TimeSpan.FromMinutes(5))
                    (stale ??= new List<string>()).Add(kv.Key);
            }
            if (stale != null)
                foreach (var ip in stale) _remotes.Remove(ip);
            return result;
        }
    }

    private void PruneRemotesLocked(bool force)
    {
        var now = DateTime.UtcNow;
        string? oldestKey = null;
        var oldest = TimeSpan.MaxValue;
        List<string>? toRemove = null;
        foreach (var kv in _remotes)
        {
            var idle = now - kv.Value.LastActiveUtc;
            if (idle > TimeSpan.FromMinutes(5)) (toRemove ??= new List<string>()).Add(kv.Key);
            else if (idle < oldest) { oldest = idle; oldestKey = kv.Key; }
        }
        if (toRemove != null)
            foreach (var ip in toRemove) _remotes.Remove(ip);
        if (_remotes.Count >= 4096 && force && oldestKey != null)
            _remotes.Remove(oldestKey);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _session.Dispose(); } catch { }
    }
}
