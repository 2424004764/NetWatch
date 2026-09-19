using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetWatch.Core.Wfp;

/// <summary>一条屏蔽规则：禁止（可选限定于某个程序的）所有发往 Remote 的连接。Remote 支持 IP 或 CIDR 网段。</summary>
public sealed record BlockEntry(string Remote, string? AppPath, DateTime CreatedUtc, bool Enabled);

/// <summary>
/// 屏蔽管理：在 WFP 里维护一个 NetWatch 专属子层，把 BlockEntry 列表变成出站 BLOCK 过滤器。
/// 过滤器不设 PERSISTENT 标志（重启自动消失），规则以配置文件为准、启动时重建——
/// 卸载程序或删除配置即可彻底移除屏蔽，不会在系统里留残留。
/// </summary>
public sealed class BlockManager : IDisposable
{
    /// <summary>NetWatch 专属子层的固定 GUID。</summary>
    private static readonly Guid SubLayerKey = new("5A3F6C9E-1B2D-4E8A-9C7F-0D2E4B6A8C01");

    private readonly object _gate = new();
    private readonly List<BlockEntry> _entries = new();
    private IntPtr _engine;
    private bool _disposed;

    /// <summary>配置文件路径（%APPDATA%\NetWatch\blocks.json）。</summary>
    public static string ConfigPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetWatch", "blocks.json");

    /// <summary>引擎不可用（非管理员/BFE 未运行）时的最后一次错误；为 null 表示可用。</summary>
    public string? EngineError { get; private set; }

    public IReadOnlyList<BlockEntry> Entries
    {
        get { lock (_gate) return _entries.ToList(); }
    }

    public int ActiveCount
    {
        get { lock (_gate) return _entries.Count(e => e.Enabled); }
    }

    // ── 生命周期 ─────────────────────────────────────────

    /// <summary>读取配置并把 WFP 子层同步为配置内容（幂等，每次启动调用一次）。</summary>
    public void Load()
    {
        lock (_gate)
        {
            _entries.Clear();
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var loaded = JsonSerializer.Deserialize<List<BlockEntry>>(File.ReadAllText(ConfigPath));
                    if (loaded != null) _entries.AddRange(loaded);
                }
            }
            catch (Exception ex)
            {
                Log.Error("读取屏蔽配置失败：" + ex.Message);
            }
        }

        try
        {
            EnsureEngine();
            // 子层里的过滤器可能是上次运行的残留：先按配置删除对应 key，再重新添加启用的条目
            lock (_gate)
            {
                foreach (var e in _entries) DeleteFiltersFor(e, ignoreErrors: true);
                foreach (var e in _entries)
                    if (e.Enabled) AddFiltersFor(e);
            }
            EngineError = null;
        }
        catch (Exception ex)
        {
            EngineError = ex.Message;
            Log.Error("WFP 引擎不可用，屏蔽功能受限：" + ex.Message);
        }
    }

    public BlockEntry Add(string remote, string? appPath)
    {
        remote = NormalizeRemote(remote);
        if (appPath != null)
        {
            appPath = Path.GetFullPath(appPath);
            if (!File.Exists(appPath))
                throw new InvalidOperationException($"程序不存在：{appPath}");
        }

        lock (_gate)
        {
            foreach (var e in _entries)
                if (e.Remote.Equals(remote, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(e.AppPath, appPath, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("相同的屏蔽规则已存在。");

            var entry = new BlockEntry(remote, appPath, DateTime.Now, true);
            AddFiltersFor(entry);
            _entries.Add(entry);
            SaveLocked();
            return entry;
        }
    }

    public void Remove(BlockEntry entry)
    {
        lock (_gate)
        {
            var i = _entries.FindIndex(e => Matches(e, entry));
            if (i < 0) return;
            DeleteFiltersFor(_entries[i], ignoreErrors: false);
            _entries.RemoveAt(i);
            SaveLocked();
        }
    }

    public void SetEnabled(BlockEntry entry, bool enabled)
    {
        lock (_gate)
        {
            var i = _entries.FindIndex(e => Matches(e, entry));
            if (i < 0) return;
            var e = _entries[i];
            if (e.Enabled == enabled) return;
            if (enabled) AddFiltersFor(e);
            else DeleteFiltersFor(e, ignoreErrors: false);
            _entries[i] = e with { Enabled = enabled };
            SaveLocked();
        }
    }

    /// <summary>某远程地址当前是否处于屏蔽状态（用于连接列表标注，不需要 WFP 引擎）。</summary>
    public bool IsBlocked(string? appPath, IPAddress remote)
    {
        List<BlockEntry> snapshot;
        lock (_gate) snapshot = _entries.ToList();

        foreach (var e in snapshot)
        {
            if (!e.Enabled) continue;
            if (e.AppPath != null && !string.Equals(e.AppPath, appPath, StringComparison.OrdinalIgnoreCase)) continue;
            if (RemoteContains(e.Remote, remote)) return true;
        }
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_engine != IntPtr.Zero)
        {
            try { WfpNative.FwpmEngineClose0(_engine); } catch { }
            _engine = IntPtr.Zero;
        }
    }

    // ── 地址解析 ─────────────────────────────────────────

    /// <summary>规范化远程地址："1.2.3.4"、"10.0.0.0/24"、"::1"、"2001:db8::/32"。</summary>
    private static string NormalizeRemote(string s)
    {
        s = s.Trim();
        var slash = s.IndexOf('/');
        var ipPart = slash < 0 ? s : s[..slash];
        var prefixPart = slash < 0 ? "" : s[(slash + 1)..];

        if (!IPAddress.TryParse(ipPart, out var ip))
            throw new InvalidOperationException($"无法识别的 IP 地址：{s}");

        int familyBits = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        int prefix = familyBits;
        if (prefixPart.Length > 0)
        {
            if (!int.TryParse(prefixPart, out prefix) || prefix < 0 || prefix > familyBits)
                throw new InvalidOperationException($"网段前缀不合法（0–{familyBits}）：{s}");
        }
        return slash < 0 ? ip.ToString() : $"{ip}/{prefix}";
    }

    private static (IPAddress addr, int prefix) ParseRemote(string remote)
    {
        var slash = remote.IndexOf('/');
        if (slash < 0) return (IPAddress.Parse(remote),
            IPAddress.Parse(remote).AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
        return (IPAddress.Parse(remote[..slash]), int.Parse(remote[(slash + 1)..]));
    }

    private static bool RemoteContains(string remote, IPAddress ip)
    {
        try
        {
            var (net, prefix) = ParseRemote(remote);
            if (net.AddressFamily != ip.AddressFamily) return false;

            var netBytes = net.GetAddressBytes();
            var ipBytes = ip.GetAddressBytes();
            int fullBytes = prefix / 8, remBits = prefix % 8;
            for (int i = 0; i < fullBytes; i++)
                if (netBytes[i] != ipBytes[i]) return false;
            if (remBits > 0)
            {
                int mask = 0xFF << (8 - remBits);
                if ((netBytes[fullBytes] & mask) != (ipBytes[fullBytes] & mask)) return false;
            }
            return true;
        }
        catch { return false; }
    }

    // ── WFP 过滤器管理 ───────────────────────────────────

    private void EnsureEngine()
    {
        if (_engine != IntPtr.Zero) return;
        var rc = WfpNative.FwpmEngineOpen0(IntPtr.Zero, WfpNative.RPC_C_AUTHN_WINNT,
            IntPtr.Zero, IntPtr.Zero, out _engine);
        if (rc != 0)
            throw new InvalidOperationException($"打开 WFP 引擎失败（0x{rc:X8}）。需要管理员权限且 BFE 服务正在运行。");

        using var namePtr = new NativeString("NetWatch 屏蔽子层");
        var subLayer = new WfpNative.FWPM_SUBLAYER0
        {
            SubLayerKey = SubLayerKey,
            DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = namePtr.Ptr },
            Weight = 0xFF,
        };
        rc = WfpNative.FwpmSubLayerAdd0(_engine, ref subLayer, IntPtr.Zero);
        if (rc != 0 && rc != WfpNative.FWP_E_ALREADY_EXISTS)
            throw new InvalidOperationException($"注册 WFP 子层失败（0x{rc:X8}）。");
    }

    /// <summary>为一条规则在 v4/v6 两个连接授权层各加一个 BLOCK 过滤器（事务保证成对成功）。</summary>
    private void AddFiltersFor(BlockEntry e)
    {
        EnsureEngine();
        var (net, prefix) = ParseRemote(e.Remote);
        bool isV4 = net.AddressFamily == AddressFamily.InterNetwork;

        IntPtr appIdPtr = IntPtr.Zero;
        if (e.AppPath != null)
        {
            var rc = WfpNative.FwpmGetAppIdFromFileName0(e.AppPath, out appIdPtr);
            if (rc != 0)
                throw new InvalidOperationException($"无法解析程序路径“{e.AppPath}”（0x{rc:X8}）。");
        }

        var rcTx = WfpNative.FwpmTransactionBegin0(_engine, 0);
        try
        {
            if (isV4)
            {
                var b = net.GetAddressBytes();
                // FWP_V4_ADDR_MASK 要求网络序：第一段八位组是整数的最高字节
                uint addr = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
                uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
                var v4 = new WfpNative.V4AddrMask { Addr = addr, Mask = mask };
                AddSingleFilter(e, WfpNative.LayerAleAuthConnectV4,
                    WfpNative.FWP_V4_ADDR_MASK,
                    NativeStruct.Alloc(v4), appIdPtr);
            }
            else
            {
                var v6 = new WfpNative.V6AddrAndMask { Addr = net.GetAddressBytes(), PrefixLength = (byte)prefix };
                AddSingleFilter(e, WfpNative.LayerAleAuthConnectV6,
                    WfpNative.FWP_V6_ADDR_MASK,
                    NativeStruct.Alloc(v6), appIdPtr);
            }
            WfpNative.FwpmTransactionCommit0(_engine);
        }
        catch
        {
            if (rcTx == 0) WfpNative.FwpmTransactionAbort0(_engine);
            throw;
        }
        finally
        {
            if (appIdPtr != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref appIdPtr);
        }
    }

    private void AddSingleFilter(BlockEntry e, Guid layerKey, uint conditionValueType,
        IntPtr remoteValuePtr, IntPtr appIdPtr)
    {
        var conditions = new List<WfpNative.FWPM_FILTER_CONDITION0>();
        var allocs = new List<IDisposable>();
        try
        {
            if (appIdPtr != IntPtr.Zero)
                conditions.Add(new WfpNative.FWPM_FILTER_CONDITION0
                {
                    FieldKey = WfpNative.ConditionAleAppId,
                    MatchType = WfpNative.FWP_MATCH_EQUAL,
                    ConditionValue = new WfpNative.FWP_CONDITION_VALUE0
                    {
                        Type = WfpNative.FWP_BYTE_BLOB_TYPE,
                        Value = new WfpNative.FWP_VALUE0Union { Pointer = appIdPtr },
                    },
                });

            conditions.Add(new WfpNative.FWPM_FILTER_CONDITION0
            {
                FieldKey = WfpNative.ConditionIpRemoteAddress,
                MatchType = WfpNative.FWP_MATCH_EQUAL,
                ConditionValue = new WfpNative.FWP_CONDITION_VALUE0
                {
                    Type = conditionValueType,
                    Value = new WfpNative.FWP_VALUE0Union { Pointer = remoteValuePtr },
                },
            });

            var pin = GCHandle.Alloc(conditions.ToArray(), GCHandleType.Pinned);
            allocs.Add(new GCHandleDisposable(pin));
            var name = new NativeString($"NetWatch 屏蔽 {e.Remote}{(e.AppPath != null ? " ← " + Path.GetFileName(e.AppPath) : "")}");
            allocs.Add(name);
            var remoteAlloc = new IntPtrDisposable(remoteValuePtr);
            allocs.Add(remoteAlloc);

            var filter = new WfpNative.FWPM_FILTER0
            {
                FilterKey = FilterKeyFor(e, layerKey),
                DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = name.Ptr },
                LayerKey = layerKey,
                SubLayerKey = SubLayerKey,
                Weight = new WfpNative.FWP_VALUE0
                {
                    // FWP_EMPTY：让 BFE 根据条件自动分配权重（官方示例做法）
                    Type = WfpNative.FWP_EMPTY,
                },
                NumFilterConditions = (uint)conditions.Count,
                FilterCondition = pin.AddrOfPinnedObject(),
                Action = new WfpNative.FWPM_ACTION0 { Type = WfpNative.FWP_ACTION_BLOCK },
            };

            var rc = WfpNative.FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out _);
            if (rc != 0)
                throw new InvalidOperationException($"添加屏蔽过滤器失败（0x{rc:X8}）— {layerKey}");
        }
        finally
        {
            foreach (var d in allocs) d.Dispose();
        }
    }

    private void DeleteFiltersFor(BlockEntry e, bool ignoreErrors)
    {
        if (_engine == IntPtr.Zero) return;
        foreach (var layer in new[] { WfpNative.LayerAleAuthConnectV4, WfpNative.LayerAleAuthConnectV6 })
        {
            var key = FilterKeyFor(e, layer);
            var rc = WfpNative.FwpmFilterDeleteByKey0(_engine, ref key);
            if (rc != 0 && !ignoreErrors && rc != WfpNative.FWP_E_ALREADY_EXISTS)
                Log.Error($"移除屏蔽过滤器失败（0x{rc:X8}）：{e.Remote} {e.AppPath}");
        }
    }

    private static Guid FilterKeyFor(BlockEntry e, Guid layerKey)
    {
        var md5 = MD5.HashData(Encoding.UTF8.GetBytes($"{SubLayerKey}|{e.Remote}|{e.AppPath}|{layerKey}"));
        return new Guid(md5);
    }

    private void SaveLocked()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) { Log.Error("保存屏蔽配置失败：" + ex.Message); }
    }

    private static bool Matches(BlockEntry a, BlockEntry b)
        => a.Remote.Equals(b.Remote, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.AppPath, b.AppPath, StringComparison.OrdinalIgnoreCase);

    // ── 非托管资源小工具 ─────────────────────────────────

    private sealed class NativeString : IDisposable
    {
        public IntPtr Ptr;
        public NativeString(string s) => Ptr = Marshal.StringToHGlobalUni(s);
        public void Dispose()
        {
            if (Ptr != IntPtr.Zero) { Marshal.FreeHGlobal(Ptr); Ptr = IntPtr.Zero; }
        }
    }

    private static class NativeStruct
    {
        public static IntPtr Alloc<T>(T s) where T : struct
        {
            var p = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(s, p, false);
            return p;
        }
    }

    private sealed class IntPtrDisposable : IDisposable
    {
        private readonly IntPtr _p;
        public IntPtrDisposable(IntPtr p) => _p = p;
        public void Dispose()
        {
            if (_p != IntPtr.Zero) Marshal.FreeHGlobal(_p);
        }
    }

    private sealed class GCHandleDisposable : IDisposable
    {
        private readonly GCHandle _h;
        public GCHandleDisposable(GCHandle h) => _h = h;
        public void Dispose() => _h.Free();
    }
}
