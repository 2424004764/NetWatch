using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace NetWatch.Core.Mitm;

/// <summary>一次完整的 HTTP 请求/响应交换（明文已解开）。</summary>
public sealed record HttpExchange(
    DateTime TimeUtc,
    bool IsTls,
    string Method,
    string Url,
    int Status,
    string ContentType,
    long ReqBodyLen,
    long RespBodyLen,
    string ReqHead,
    string RespHead,
    byte[] ReqBody,
    byte[] RespBody)
{
    /// <summary>把请求体解成可读文本（自动 gzip/br/deflate + 字符集），二进制返回 null。</summary>
    public string? ReqText => BodyToText(ReqBody, HeaderValue(ReqHead, "Content-Encoding"));
    /// <summary>把响应体解成可读文本，二进制返回 null。</summary>
    public string? RespText => BodyToText(RespBody, HeaderValue(RespHead, "Content-Encoding"));

    private static string? HeaderValue(string head, string name)
    {
        foreach (var line in head.Split("\r\n"))
        {
            var idx = line.IndexOf(':');
            if (idx > 0 && line[..idx].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                return line[(idx + 1)..].Trim();
        }
        return null;
    }

    private static string? BodyToText(byte[] body, string? encoding)
    {
        if (body.Length == 0) return null;
        var data = body;
        try
        {
            if (encoding != null)
            {
                if (encoding.Contains("gzip", StringComparison.OrdinalIgnoreCase))
                {
                    using var inp = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
                    using var outp = new MemoryStream();
                    inp.CopyTo(outp);
                    data = outp.ToArray();
                }
                else if (encoding.Contains("br", StringComparison.OrdinalIgnoreCase))
                {
                    using var inp = new BrotliStream(new MemoryStream(data), CompressionMode.Decompress);
                    using var outp = new MemoryStream();
                    inp.CopyTo(outp);
                    data = outp.ToArray();
                }
                else if (encoding.Contains("deflate", StringComparison.OrdinalIgnoreCase))
                {
                    using var inp = new DeflateStream(new MemoryStream(data), CompressionMode.Decompress);
                    using var outp = new MemoryStream();
                    inp.CopyTo(outp);
                    data = outp.ToArray();
                }
            }
        }
        catch { /* 解压失败就按原始字节处理 */ }

        int n = Math.Min(data.Length, 512), printable = 0;
        for (int i = 0; i < n; i++)
            if (data[i] >= 0x20 && data[i] < 0x7F || data[i] is 0x0A or 0x0D or 0x09) printable++;
        if ((double)printable / n < 0.7) return null;
        return Encoding.UTF8.GetString(data);
    }
}

/// <summary>
/// 内置 HTTP(S) 调试代理（同 Fiddler 的 MITM 原理）：
/// 监听 127.0.0.1 随机端口；HTTPS 的 CONNECT 通道用本地 CA 动态签发的证书
/// 与客户端握手、与真实服务器正常校验握手，双向转发并记录明文。
/// 根证书需先安装到当前用户信任存储，客户端才会信任（有开关，可随时移除）。
/// </summary>
public sealed class MitmProxy : IDisposable
{
    private const int CaptureCap = 256 * 1024; // 单个请求/响应体的捕获上限（转发不受限）
    private static readonly HashSet<string> HttpMethods = new(StringComparer.OrdinalIgnoreCase)
        { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT" };

    private TcpListener? _listener;
    private volatile bool _stopped;

    public int Port { get; private set; }
    public event Action<HttpExchange>? ExchangeLogged;

    public void Start()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start(64);
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        new Thread(AcceptLoop) { IsBackground = true, Name = "NetWatch-Mitm-Accept" }.Start();
        Log.Info($"MITM 调试代理已启动：127.0.0.1:{Port}");
    }

    private void AcceptLoop()
    {
        while (!_stopped)
        {
            TcpClient client;
            try { client = _listener!.AcceptTcpClient(); }
            catch { break; }
            new Thread(() => Handle(client)) { IsBackground = true }.Start();
        }
    }

    private void Handle(TcpClient client)
    {
        using var _ = client;
        try
        {
            client.ReceiveTimeout = 30_000;
            client.SendTimeout = 30_000;
            var stream = client.GetStream();
            var head = ReadHead(stream);
            if (head == null) return;
            var text = Encoding.ASCII.GetString(head);
            var firstLine = text.Split("\r\n")[0];

            if (firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
            {
                HandleConnect(stream, firstLine);
            }
            else
            {
                HandlePlainProxy(stream, head, text);
            }
        }
        catch (Exception ex)
        {
            Log.Error("MITM 连接处理异常：" + ex.Message);
        }
    }

    private void HandleConnect(NetworkStream stream, string firstLine)
    {
        var target = firstLine["CONNECT ".Length..].Trim().Split(' ')[0]; // 去掉结尾的 HTTP/1.1
        var colon = target.LastIndexOf(':');
        var host = colon > 0 ? target[..colon] : target;
        int port = colon > 0 ? int.Parse(target[(colon + 1)..]) : 443;
        WriteAscii(stream, "HTTP/1.1 200 Connection Established\r\n\r\n");

        if (port != 443)
        {
            // 非 HTTPS 的 CONNECT：盲转发
            using var up = new TcpClient();
            up.Connect(host, port);
            RelayBlind(stream, up.GetStream());
            return;
        }

        X509Certificate2 leaf;
        try { leaf = CertMaker.LeafFor(host); }
        catch (Exception ex) { Log.Error($"为 {host} 签发证书失败：" + ex.Message); return; }

        var clientSsl = new SslStream(stream, false);
        try { clientSsl.AuthenticateAsServer(leaf, clientCertificateRequired: false, enabledSslProtocols: SslProtocols.None, checkCertificateRevocation: false); }
        catch (Exception ex) { Log.Error($"与客户端 TLS 握手失败（{host}）：" + ex.Message); return; }

        using var upstream = new TcpClient();
        upstream.ReceiveTimeout = 30_000;
        upstream.SendTimeout = 30_000;
        upstream.Connect(host, port);
        var serverSsl = new SslStream(upstream.GetStream(), false);
        try { serverSsl.AuthenticateAsClient(host); }
        catch (Exception ex) { Log.Error($"与服务器 TLS 握手失败（{host}）：" + ex.Message); return; }

        PumpHttp(clientSsl, serverSsl, "https");
    }

    private void HandlePlainProxy(NetworkStream stream, byte[] head, string text)
    {
        // 代理形式的明文请求：GET http://host/path → 转成源形式再转发
        var lines = text.Split("\r\n");
        var parts = lines[0].Split(' ');
        if (parts.Length < 3 || !Uri.TryCreate(parts[1], UriKind.Absolute, out var uri))
            return;
        var host = uri.Host;
        var port = uri.Port == 80 ? 80 : uri.Port;
        var pathAndQuery = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
        lines[0] = $"{parts[0]} {pathAndQuery} {parts[2]}";
        var newHead = Encoding.ASCII.GetBytes(string.Join("\r\n", lines));

        using var upstream = new TcpClient();
        upstream.Connect(host, port);
        var target = upstream.GetStream();

        // 首包（已改写）由 Exchange 内部负责写入，避免重复发送；记录用改写后的文本（相对路径）
        var rewrittenText = string.Join("\r\n", lines);
        PumpOneExchange(stream, target, rewrittenHeadBytes: newHead, headBytesFromClient: head, isTls: false, hostOverride: host, initialRequestText: rewrittenText);
        // 之后继续在同一连接上按 keep-alive 循环
        PumpHttp(stream, target, "http", hostOverride: host);
    }

    /// <summary>循环处理（已就绪的）HTTP/1.1 连接，直到任一端关闭。</summary>
    private void PumpHttp(Stream client, Stream target, string scheme, string? hostOverride = null)
    {
        while (!_stopped)
        {
            var head = ReadHead(client);
            if (head == null) break;
            var text = Encoding.ASCII.GetString(head);
            var method = text.Split(' ')[0];
            if (!HttpMethods.Contains(method))
            {
                // TLS 隧道里跑的不是 HTTP：盲转发
                RelayBlind(client, target, head);
                return;
            }
            Exchange(client, target, head, text, scheme == "https", hostOverride);
        }
    }

    /// <summary>处理一次明文代理请求（首包已从客户端读出并改写）。</summary>
    private void PumpOneExchange(Stream client, Stream target, byte[] rewrittenHeadBytes,
        byte[] headBytesFromClient, bool isTls, string? hostOverride, string initialRequestText)
        => Exchange(client, target, headBytesFromClient, initialRequestText, isTls, hostOverride,
            preWrittenHead: rewrittenHeadBytes);

    /// <summary>单个请求/响应交换：转发并记录。</summary>
    private void Exchange(Stream client, Stream target, byte[] head, string headText, bool isTls,
        string? hostOverride, byte[]? preWrittenHead = null)
    {
        var headers = ParseHeaders(headText);
        var method = headText.Split(' ')[0];
        headers.TryGetValue("host", out var hostHdr);
        var host = hostOverride ?? hostHdr ?? "";

        long reqLen = headers.TryGetValue("content-length", out var cl) && long.TryParse(cl, out var rl0) ? rl0 : 0;
        bool reqChunked = IsChunked(headers);

        (preWrittenHead ?? head).AsSpan(); // 已改写时直接用改写后的
        if (preWrittenHead != null) target.Write(preWrittenHead);
        else target.Write(head);

        long reqTotal;
        byte[] reqCap;
        if (reqChunked) reqTotal = RelayChunked(client, target, out reqCap);
        else reqTotal = RelayCounted(client, target, reqLen, CaptureCap, out reqCap);

        // 响应（处理 1xx 临时响应）
        int status = 0;
        string respHead = "";
        byte[] respCap = Array.Empty<byte>();
        long respTotal = 0;
        string contentType = "";
        while (true)
        {
            var rHead = ReadHead(target);
            if (rHead == null) return;
            respHead = Encoding.ASCII.GetString(rHead);
            var respParts = respHead.Split(' ');
            status = respParts.Length > 1 && int.TryParse(respParts[1], out var st) ? st : 0;
            var rHeaders = ParseHeaders(respHead);
            rHeaders.TryGetValue("content-type", out contentType);

            bool noBody = status is >= 100 and <= 199 or 204 or 304 || method == "HEAD";
            client.Write(rHead); // 响应头要写回客户端，不是发回服务器
            if (noBody)
            {
                respCap = Array.Empty<byte>();
                respTotal = 0;
                if (status >= 200) break;
                continue;
            }

            if (IsChunked(rHeaders))
            {
                respTotal = RelayChunked(target, client, out respCap);
                break;
            }
            if (rHeaders.TryGetValue("content-length", out var rcl) && long.TryParse(rcl, out var rl))
            {
                respTotal = RelayCounted(target, client, rl, CaptureCap, out respCap);
                break;
            }
            // 没有长度信息：读到对端关闭
            respTotal = RelayUntilEof(target, client, CaptureCap, out respCap);
            break;
        }

        var url = (isTls ? "https://" : "http://") + host + RequestPath(headText, isTls);
        ExchangeLogged?.Invoke(new HttpExchange(DateTime.UtcNow, isTls, method, url, status,
            contentType ?? "", reqTotal, respTotal, headText, respHead, reqCap, respCap));

        var conn = HeaderOf(headers, "connection") ?? "";
        if (conn.Contains("close", StringComparison.OrdinalIgnoreCase)) return;
    }

    // ── 转发工具 ─────────────────────────────────────────

    private static bool IsChunked(Dictionary<string, string> h)
        => h.TryGetValue("transfer-encoding", out var te)
        && te.Contains("chunked", StringComparison.OrdinalIgnoreCase);

    private static string RequestPath(string headText, bool isTls)
    {
        var line = headText.Split("\r\n")[0].Split(' ');
        if (line.Length < 2) return "/";
        return line[1];
    }

    /// <summary>按长度转发，捕获前 cap 字节。</summary>
    private static long RelayCounted(Stream src, Stream dst, long len, int cap, out byte[] captured)
    {
        var buf = new byte[16384];
        var capMs = new MemoryStream();
        long done = 0;
        while (done < len)
        {
            int want = (int)Math.Min(buf.Length, len - done);
            int n = src.Read(buf, 0, want);
            if (n <= 0) break;
            dst.Write(buf, 0, n);
            if (capMs.Length < cap) capMs.Write(buf, 0, (int)Math.Min(n, cap - capMs.Length));
            done += n;
        }
        captured = capMs.ToArray();
        return done;
    }

    private static long RelayUntilEof(Stream src, Stream dst, int cap, out byte[] captured)
    {
        var buf = new byte[16384];
        var capMs = new MemoryStream();
        long total = 0;
        while (true)
        {
            int n = src.Read(buf, 0, buf.Length);
            if (n <= 0) break;
            dst.Write(buf, 0, n);
            if (capMs.Length < cap) capMs.Write(buf, 0, (int)Math.Min(n, cap - capMs.Length));
            total += n;
        }
        captured = capMs.ToArray();
        return total;
    }

    /// <summary>逐块解析 chunked 编码，原样转发，捕获解码后的内容。</summary>
    private static long RelayChunked(Stream src, Stream dst, out byte[] captured)
    {
        var capMs = new MemoryStream();
        long total = 0;
        var buf = new byte[1];
        while (true)
        {
            // 读块大小行
            var sizeLine = new StringBuilder();
            while (true)
            {
                int n = src.Read(buf, 0, 1);
                if (n <= 0) { captured = capMs.ToArray(); return total; }
                dst.Write(buf, 0, 1);
                if (buf[0] == '\n') break;
                if (buf[0] != '\r') sizeLine.Append((char)buf[0]);
            }
            var sizeText = sizeLine.ToString().Split(';')[0].Trim();
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size))
            {
                captured = capMs.ToArray();
                return total;
            }
            if (size == 0)
            {
                // 尾部：读到空行为止
                while (true)
                {
                    int n = src.Read(buf, 0, 1);
                    if (n <= 0) break;
                    dst.Write(buf, 0, 1);
                    if (buf[0] == '\n') break;
                }
                captured = capMs.ToArray();
                return total;
            }
            total += RelayCounted(src, dst, size, int.MaxValue, out var chunk);
            if (capMs.Length < CaptureCap) capMs.Write(chunk, 0, (int)Math.Min(chunk.Length, CaptureCap - capMs.Length));
            // 块尾 \r\n
            RelayCounted(src, dst, 2, 0, out _);
        }
    }

    /// <summary>双向盲转发（非 HTTP 流量）。</summary>
    private void RelayBlind(Stream a, Stream b, byte[]? pendingForB = null)
    {
        if (pendingForB != null) b.Write(pendingForB);
        var t1 = new Thread(() => { try { CopyForever(a, b); } catch { } }) { IsBackground = true };
        var t2 = new Thread(() => { try { CopyForever(b, a); } catch { } }) { IsBackground = true };
        t1.Start(); t2.Start();
        t1.Join(); t2.Join();
    }

    private static void CopyForever(Stream src, Stream dst)
    {
        var buf = new byte[16384];
        while (true)
        {
            int n = src.Read(buf, 0, buf.Length);
            if (n <= 0) break;
            dst.Write(buf, 0, n);
        }
    }

    // ── 基础 IO ──────────────────────────────────────────

    /// <summary>读到 HTTP 头结束（\r\n\r\n），超过 64KB 放弃。</summary>
    private static byte[]? ReadHead(Stream s)
    {
        var ms = new MemoryStream();
        var buf = new byte[1];
        int got = 0;
        while (got < 64 * 1024)
        {
            int n = s.Read(buf, 0, 1);
            if (n <= 0) break;
            ms.Write(buf, 0, 1);
            got++;
            if (got >= 4)
            {
                var b = ms.GetBuffer();
                if (b[got - 4] == 13 && b[got - 3] == 10 && b[got - 2] == 13 && b[got - 1] == 10)
                    return ms.ToArray();
            }
        }
        return got > 0 ? ms.ToArray() : null;
    }

    private static void WriteAscii(Stream s, string text)
    {
        var b = Encoding.ASCII.GetBytes(text);
        s.Write(b, 0, b.Length);
    }

    private static Dictionary<string, string> ParseHeaders(string headText)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = headText.Split("\r\n");
        for (int i = 1; i < lines.Length; i++)
        {
            var idx = lines[i].IndexOf(':');
            if (idx > 0)
                result[lines[i][..idx].Trim()] = lines[i][(idx + 1)..].Trim();
        }
        return result;
    }

    private static string? HeaderOf(Dictionary<string, string> h, string name)
        => h.TryGetValue(name, out var v) ? v : null;

    public void Dispose()
    {
        if (_stopped) return;
        _stopped = true;
        try { _listener?.Stop(); } catch { }
    }
}
