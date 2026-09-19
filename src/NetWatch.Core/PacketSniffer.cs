using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace NetWatch.Core;

/// <summary>捕获到的一个数据包（已按协议解出负载）。</summary>
public sealed record PacketInfo(
    DateTime TimeUtc,
    bool Outbound,
    string RemoteIp,
    int RemotePort,
    int LocalPort,
    string Protocol,
    int PayloadLen,
    byte[] Payload);

/// <summary>
/// 轻量抓包器：管理员权限下用 IPv4 原始套接字（SIO_RCVALL 混杂模式）收包，
/// 解析 IP/TCP/UDP 头，按「远程 IP / 网段」过滤后回调负载。
/// 不装驱动、不动防火墙；仅支持 IPv4，回环（127.0.0.1）流量不可见。
/// </summary>
public sealed class PacketSniffer : IDisposable
{
    private const int MaxPayload = 8192;
    private const int SioRcvAll = unchecked((int)0x98000001); // IOC_IN | IOC_VENDOR | 1

    private readonly List<(uint Net, uint Mask)> _filters = new();
    private readonly List<Socket> _sockets = new();
    private readonly List<Thread> _threads = new();
    private volatile bool _stopped;
    private bool _disposed;

    /// <summary>收到匹配的包时触发（在抓包线程上回调，处理要快）。</summary>
    public event Action<PacketInfo>? PacketReceived;

    /// <summary>因缓冲区满被丢弃的包数。</summary>
    public long Dropped { get; private set; }

    /// <summary>实际开始监听的网卡数（0 表示抓包不可用）。</summary>
    public int InterfaceCount => _sockets.Count;

    /// <param name="remoteFilter">IP 或 CIDR 网段（"1.2.3.4" / "10.0.0.0/24"），可传多个。</param>
    public PacketSniffer(IEnumerable<string> remoteFilter)
    {
        foreach (var f in remoteFilter)
        {
            var s = f.Trim();
            var slash = s.IndexOf('/');
            var ip = IPAddress.Parse(slash < 0 ? s : s[..slash]);
            if (ip.AddressFamily != AddressFamily.InterNetwork)
                throw new NotSupportedException($"抓包目前仅支持 IPv4：{f}");
            int prefix = slash < 0 ? 32 : int.Parse(s[(slash + 1)..]);
            uint net = ToUint(ip);
            uint mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
            _filters.Add((net & mask, mask));
        }
    }

    public void Start()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;
            IPInterfaceProperties props;
            try { props = nic.GetIPProperties(); } catch { continue; }
            foreach (var addr in props.UnicastAddresses)
            {
                if (addr.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                var local = addr.Address;
                try
                {
                    var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    sock.Bind(new IPEndPoint(local, 0));
                    sock.ReceiveBufferSize = 1 << 20;
                    sock.IOControl(SioRcvAll, BitConverter.GetBytes(1), null);
                    _sockets.Add(sock);
                    var t = new Thread(() => ReceiveLoop(sock, local))
                    {
                        IsBackground = true,
                        Name = "NetWatch-Sniff-" + local,
                    };
                    _threads.Add(t);
                    t.Start();
                }
                catch (Exception ex)
                {
                    Log.Error($"网卡 {nic.Name}（{local}）无法开启抓包：{ex.Message}");
                }
            }
        }
        if (_sockets.Count == 0)
            throw new InvalidOperationException("没有可用的网卡开启抓包（需要管理员权限）。");
        Log.Info($"抓包已启动：{_sockets.Count} 个监听点，过滤 {string.Join(", ", _filters.ConvertAll(f => f.Net + "/" + MaskBits(f.Mask)))}");
    }

    private void ReceiveLoop(Socket sock, IPAddress local)
    {
        var buf = new byte[65536];
        var localBytes = local.GetAddressBytes();
        while (!_stopped)
        {
            int n;
            try { n = sock.Receive(buf); }
            catch (SocketException) { if (!_stopped) Thread.Sleep(50); continue; }
            catch (ObjectDisposedException) { break; }
            catch { break; }
            if (n < 20) continue;
            try { Parse(buf, n, localBytes); }
            catch { /* 单个坏包不影响整体 */ }
        }
    }

    private void Parse(byte[] p, int n, byte[] local)
    {
        // IPv4 头
        int ihl = (p[0] & 0x0F) * 4;
        if (ihl < 20 || n < ihl) return;
        int protocol = p[9];
        var src = new byte[4]; Array.Copy(p, 12, src, 0, 4);
        var dst = new byte[4]; Array.Copy(p, 16, dst, 0, 4);
        int totalLen = (p[2] << 8) | p[3];
        if (totalLen > n) totalLen = n;

        bool srcIsLocal = src[0] == local[0] && src[1] == local[1] && src[2] == local[2] && src[3] == local[3];
        var remote = srcIsLocal ? dst : src;
        if (!Matches(remote)) return;

        int remotePort, localPort, payloadOffset;
        string proto;
        switch (protocol)
        {
            case 6: // TCP
                if (totalLen < ihl + 20) return;
                int tcpOff = ihl;
                int srcPort = (p[tcpOff] << 8) | p[tcpOff + 1];
                int dstPort = (p[tcpOff + 2] << 8) | p[tcpOff + 3];
                int dataOff = ((p[tcpOff + 12] >> 4) & 0x0F) * 4;
                if (dataOff < 20 || totalLen < tcpOff + dataOff) return;
                payloadOffset = tcpOff + dataOff;
                remotePort = srcIsLocal ? dstPort : srcPort;
                localPort = srcIsLocal ? srcPort : dstPort;
                proto = "TCP";
                break;
            case 17: // UDP
                if (totalLen < ihl + 8) return;
                int udpOff = ihl;
                int usrc = (p[udpOff] << 8) | p[udpOff + 1];
                int udst = (p[udpOff + 2] << 8) | p[udpOff + 3];
                payloadOffset = udpOff + 8;
                remotePort = srcIsLocal ? udst : usrc;
                localPort = srcIsLocal ? usrc : udst;
                proto = "UDP";
                break;
            default:
                return;
        }

        int payloadLen = totalLen - payloadOffset;
        if (payloadLen <= 0)
        {
            PayloadOf(p, 0, 0, out var empty); // 交一个空负载（握手类包）
            PacketReceived?.Invoke(new PacketInfo(DateTime.UtcNow, srcIsLocal,
                remote[0] + "." + remote[1] + "." + remote[2] + "." + remote[3],
                remotePort, localPort, proto, 0, empty));
            return;
        }

        PayloadOf(p, payloadOffset, Math.Min(payloadLen, MaxPayload), out var payload);
        PacketReceived?.Invoke(new PacketInfo(DateTime.UtcNow, srcIsLocal,
            remote[0] + "." + remote[1] + "." + remote[2] + "." + remote[3],
            remotePort, localPort, proto, payloadLen, payload));
    }

    private static void PayloadOf(byte[] p, int offset, int len, out byte[] payload)
    {
        payload = new byte[len];
        if (len > 0) Array.Copy(p, offset, payload, 0, len);
    }

    private bool Matches(byte[] ip)
    {
        uint v = ToUint(ip);
        foreach (var (net, mask) in _filters)
            if ((v & mask) == net)
                return true;
        return false;
    }

    private static uint ToUint(IPAddress ip) => ToUint(ip.GetAddressBytes());

    private static uint ToUint(byte[] b)
        => (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);

    private static int MaskBits(uint mask)
    {
        int bits = 0;
        while ((mask & 0x80000000) != 0) { bits++; mask <<= 1; }
        return bits;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _stopped = true;
        foreach (var s in _sockets)
            try { s.Close(); } catch { }
        _sockets.Clear();
    }
}
