using System.Reflection;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using NetWatch.Core;

// netwatch-cli --events   : 列出内核解析器上可用的 Tcp/Udp 事件（诊断用）
// netwatch-cli [秒数]     : 监控指定秒数，每 2 秒打印一次有流量的进程

if (args.Contains("--events"))
{
    DumpEvents();
    return 0;
}

// 屏蔽管理：--block <ip|网段> [--app <exe路径>] / --unblock <ip|网段> [--app <exe路径>] / --blocks
if (args.Contains("--blocks") || args.Contains("--block") || args.Contains("--unblock"))
{
    return RunBlockCommand(args);
}

// 目标 IP 视图：--remotes [秒数] —— 输出每个远程 IP 的收发流量
if (args.Contains("--remotes"))
{
    return RunRemotesView(args);
}

// 抓包视图：--sniff <ip|网段> [秒数] —— 打印发往/来自该 IP 的数据包内容预览
if (args.Contains("--sniff"))
{
    return RunSniffView(args);
}

int seconds = args.Length > 0 && int.TryParse(args[0], out var s) ? s : 15;
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine($"NetWatch CLI — 监听 {seconds} 秒（需要管理员权限）");

NetworkMonitor monitor;
try
{
    monitor = NetworkMonitor.Start();
}
catch (Exception ex)
{
    Console.WriteLine("启动失败：" + ex.Message);
    return 1;
}

using var mon = monitor;
var procs = new ProcessInfoCache();
Console.WriteLine("监控中…（每 2 秒输出一次有流量的进程）\n");

var sw = System.Diagnostics.Stopwatch.StartNew();
var lastElapsed = 0.0;
while (sw.Elapsed.TotalSeconds < seconds)
{
    System.Threading.Thread.Sleep(2000);
    double elapsed = sw.Elapsed.TotalSeconds - lastElapsed;
    lastElapsed = sw.Elapsed.TotalSeconds;
    if (elapsed <= 0) elapsed = 2;

    var snap = mon.Snapshot();
    long up = snap.Sum(p => p.TickSent), down = snap.Sum(p => p.TickRecv);
    Console.WriteLine($"── {DateTime.Now:HH:mm:ss}  整机 ↑{Fmt.Bytes(up / elapsed)}/s  ↓{Fmt.Bytes(down / elapsed)}/s   事件总数 {mon.EventCount:N0}");
    foreach (var p in snap.Where(p => p.TickSent + p.TickRecv > 0)
                          .OrderByDescending(p => p.TickSent + p.TickRecv)
                          .Take(12))
    {
        var info = procs.Get(p.Pid);
        Console.WriteLine($"   {Cut(info.Name, 28),-28} PID {p.Pid,-8} ↑ {Fmt.Bytes(p.TickSent / elapsed),9}/s   ↓ {Fmt.Bytes(p.TickRecv / elapsed),9}/s");
    }
}

Console.WriteLine("\n══ 会话累计流量（前 15 名）══");
foreach (var p in mon.Snapshot(false).OrderByDescending(p => p.TotalSent + p.TotalRecv).Take(15))
{
    var info = procs.Get(p.Pid);
    Console.WriteLine($"   {Cut(info.Name, 28),-28} PID {p.Pid,-8} 累计 ↑ {Fmt.Bytes(p.TotalSent),10}   ↓ {Fmt.Bytes(p.TotalRecv),10}");
}
return 0;

static string Cut(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";

static int RunBlockCommand(string[] args)
{
    using var blocks = new NetWatch.Core.Wfp.BlockManager();
    blocks.Load();

    try
    {
        if (args.Contains("--blocks"))
        {
            Console.WriteLine($"屏蔽规则（{blocks.Entries.Count} 条，配置文件：{NetWatch.Core.Wfp.BlockManager.ConfigPath}）");
            foreach (var e in blocks.Entries)
                Console.WriteLine($"  {(e.Enabled ? "[启用] " : "[停用] ")}{e.Remote,-20} {(e.AppPath ?? "所有程序"),-50} 创建于 {e.CreatedUtc:yyyy-MM-dd HH:mm}");
            return 0;
        }

        bool unblock = args.Contains("--unblock");
        var remote = ArgAfter(args, unblock ? "--unblock" : "--block")
            ?? throw new InvalidOperationException($"用法：netwatch-cli {(unblock ? "--unblock" : "--block")} <IP|网段> [--app <程序路径>]");
        var app = ArgAfter(args, "--app");

        if (unblock)
        {
            blocks.Remove(new NetWatch.Core.Wfp.BlockEntry(remote, app, DateTime.Now, true));
            Console.WriteLine($"已移除屏蔽：{remote}（{(app ?? "所有程序")}）");
        }
        else
        {
            var entry = blocks.Add(remote, app);
            Console.WriteLine($"已屏蔽：{entry.Remote}（{entry.AppPath ?? "所有程序"}）");
            Console.WriteLine("提示：已建立的旧连接不会被切断，重新启动目标程序即可完全阻断。");
        }
        return 0;
    }
    catch (Exception ex)
    {
        Console.WriteLine("操作失败：" + ex.Message);
        if (blocks.EngineError != null) Console.WriteLine("（WFP 引擎错误：" + blocks.EngineError + "）");
        return 1;
    }
}

static string? ArgAfter(string[] args, string key)
{
    var i = Array.IndexOf(args, key);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static int RunSniffView(string[] args)
{
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    var target = ArgAfter(args, "--sniff");
    if (string.IsNullOrEmpty(target))
    {
        Console.WriteLine("用法：netwatch-cli --sniff <IP|网段> [秒数，默认 15]");
        return 1;
    }
    int seconds = args.Length > 1 && int.TryParse(args[^1], out var v) && !args[^1].Equals(target) ? v : 15;

    PacketSniffer sniffer;
    try { sniffer = new PacketSniffer(new[] { target }); sniffer.Start(); }
    catch (Exception ex) { Console.WriteLine("抓包启动失败：" + ex.Message); return 1; }
    using var s = sniffer;

    long count = 0;
    sniffer.PacketReceived += p =>
    {
        Interlocked.Increment(ref count);
        var t = p.TimeUtc.ToLocalTime();
        Console.WriteLine($"{t:HH:mm:ss.fff} {(p.Outbound ? "↑发" : "↓收")} {p.RemoteIp}:{p.RemotePort,-5} {p.Protocol} {p.PayloadLen,5}B  {Cut(PayloadDescribe.Summary(p, 90), 92)}");
        if (System.Environment.GetEnvironmentVariable("SNIFF_HEX") != null && p.Payload.Length >= 2 && p.Payload[0] == 0x16 && p.Payload[1] == 0x03 && p.Payload.Length > 6 && p.Payload[5] == 0x01)
            Console.WriteLine(PayloadDescribe.HexDump(p.Payload, 640));
    };

    Console.WriteLine($"抓包 {seconds} 秒：{target}（{sniffer.InterfaceCount} 个监听点）…");
    System.Threading.Thread.Sleep(TimeSpan.FromSeconds(seconds));
    Console.WriteLine($"\n结束，共 {Interlocked.Read(ref count)} 个包。");
    return 0;
}

static int RunRemotesView(string[] args)
{
    var secArg = ArgAfter(args, "--remotes");
    int seconds = secArg != null && int.TryParse(secArg, out var v) ? v : 15;
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    Console.WriteLine($"NetWatch CLI · 目标 IP 视图 — 监听 {seconds} 秒（需要管理员权限）");

    NetworkMonitor mon;
    try { mon = NetworkMonitor.Start(); }
    catch (Exception ex) { Console.WriteLine("启动失败：" + ex.Message); return 1; }
    using var monitor = mon;
    var procs = new ProcessInfoCache();
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var last = 0.0;

    while (sw.Elapsed.TotalSeconds < seconds)
    {
        System.Threading.Thread.Sleep(3000);
        double elapsed = sw.Elapsed.TotalSeconds - last;
        last = sw.Elapsed.TotalSeconds;
        if (elapsed <= 0) elapsed = 3;
        var remotes = monitor.SnapshotRemotes();
        Console.WriteLine($"── {DateTime.Now:HH:mm:ss}  活动远程 IP {remotes.Count} 个");
        foreach (var r in remotes.Where(r => r.TickSent + r.TickRecv > 0)
                                 .OrderByDescending(r => r.TickSent + r.TickRecv)
                                 .Take(12))
        {
            var apps = string.Join(",", r.Pids.Select(p => procs.Get(p).Name).Distinct().Take(3));
            Console.WriteLine($"   {Cut(r.Ip, 40),-40} ↑ {Fmt.Bytes(r.TickSent / elapsed),9}/s   ↓ {Fmt.Bytes(r.TickRecv / elapsed),9}/s   {Cut(apps, 34)}");
        }
    }

    Console.WriteLine("\n══ 按远程 IP 累计（前 20 名）══");
    foreach (var r in monitor.SnapshotRemotes(false)
                             .OrderByDescending(r => r.TotalSent + r.TotalRecv)
                             .Take(20))
    {
        var apps = string.Join(",", r.Pids.Select(p => procs.Get(p).Name).Distinct().Take(3));
        Console.WriteLine($"   {Cut(r.Ip, 40),-40} 累计 ↑ {Fmt.Bytes(r.TotalSent),10}   ↓ {Fmt.Bytes(r.TotalRecv),10}   {Cut(apps, 30)}");
    }
    return 0;
}

static void DumpEvents()
{
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    Console.WriteLine("KernelTraceEventParser 上与 Tcp/Udp 相关的事件名：");
    foreach (var name in typeof(KernelTraceEventParser).GetEvents()
                 .Select(e => e.Name)
                 .Where(n => n.Contains("Tcp", StringComparison.OrdinalIgnoreCase)
                          || n.Contains("Udp", StringComparison.OrdinalIgnoreCase))
                 .Distinct()
                 .OrderBy(n => n))
        Console.WriteLine("  " + name);
}
