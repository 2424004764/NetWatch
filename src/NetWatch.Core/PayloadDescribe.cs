using System;
using System.Text;

namespace NetWatch.Core;

/// <summary>
/// 把数据包负载变成"人能看懂的摘要"：
/// TLS（含握手 SNI 目标域名）、DNS 查询域名、HTTP 请求/响应摘要、gzip/zip、纯文本、二进制。
/// </summary>
public static class PayloadDescribe
{
    /// <summary>结合端口/方向生成结构化预览。</summary>
    public static string Summary(PacketInfo p, int maxChars = 110)
    {
        if (p.Payload.Length == 0) return "（无负载 · 握手/ACK）";

        // DNS（UDP 53）
        if (p.Protocol == "UDP" && (p.RemotePort == 53 || p.LocalPort == 53))
        {
            var dns = DnsSummary(p.Payload, outbound: p.RemotePort == 53);
            if (dns != null) return dns;
        }

        // TLS
        var tls = TlsSummary(p.Payload);
        if (tls != null) return tls;

        if (p.Payload.Length >= 4 && p.Payload[0] == 'P' && p.Payload[1] == 'K' && p.Payload[2] == 0x03) return "zip 数据";
        if (p.Payload.Length >= 2 && p.Payload[0] == 0x1F && p.Payload[1] == 0x8B) return "gzip 压缩内容";

        // QUIC（UDP 443）
        if (p.Protocol == "UDP" && (p.RemotePort == 443 || p.LocalPort == 443))
            return "🔒 QUIC/HTTP3 加密数据（明文不可见）";

        // HTTP / 纯文本 / 二进制
        if (IsAsciiWord(p.Payload, "HTTP/1."))
            return Cut("HTTP 响应 · " + FirstLine(p.Payload, 40), maxChars);
        foreach (var m in new[] { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH " })
            if (IsAsciiWord(p.Payload, m))
            {
                var host = FindHeader(p.Payload, "Host");
                return Cut("HTTP " + FirstLine(p.Payload, 48) + (host != null ? " · Host: " + host : ""), maxChars);
            }

        // 可读文本：截取内容；否则归为二进制
        if (PrintableRatio(p.Payload) > 0.7)
            return Cut(Sanitize(p.Payload, maxChars), maxChars + 2);
        return $"二进制数据（{LengthText(p)}）";
    }

    /// <summary>完整文本视图（保留换行，截断）。</summary>
    public static string FullText(byte[] data, int maxChars = 16384)
    {
        if (data.Length == 0) return "（无负载）";
        var sb = new StringBuilder();
        int used = 0;
        foreach (var b in data)
        {
            if (used >= maxChars) { sb.Append("…（已截断）"); break; }
            char c = b == '\r' || b == '\n' || b == '\t' ? (char)b : Printable(b) ? (char)b : '·';
            sb.Append(c);
            used++;
        }
        return sb.ToString();
    }

    /// <summary>经典十六进制转储。</summary>
    public static string HexDump(byte[] data, int maxBytes = 4096)
    {
        var sb = new StringBuilder();
        int n = Math.Min(data.Length, maxBytes);
        for (int i = 0; i < n; i += 16)
        {
            sb.Append(i.ToString("X4")).Append("  ");
            for (int j = 0; j < 16; j++)
            {
                if (i + j < n) sb.Append(data[i + j].ToString("X2")).Append(' ');
                else sb.Append("   ");
                if (j == 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < n; j++)
                sb.Append(Printable(data[i + j]) ? (char)data[i + j] : '.');
            sb.Append('\n');
        }
        if (data.Length > maxBytes) sb.Append($"…（共 {data.Length} 字节，已截断）\n");
        return sb.ToString();
    }

    // ── TLS ──────────────────────────────────────────────

    private static string? TlsSummary(byte[] d)
    {
        if (d.Length < 6 || d[0] < 20 || d[0] > 23 || d[1] != 0x03) return null;
        switch (d[0])
        {
            case 0x16: // 握手
                if (d.Length > 6 && d[5] == 0x01)
                {
                    var sni = ExtractSni(d);
                    return sni != null
                        ? $"🔒 TLS 握手 → 目标域名 {sni}（SNI 明文）"
                        : "🔒 TLS 握手（ClientHello，未见 SNI）";
                }
                return "🔒 TLS 握手（服务端/协商）";
            case 0x17: return "🔒 TLS 加密应用数据（明文不可见）";
            case 0x15: return "🔒 TLS Alert（告警/连接关闭）";
            default: return "🔒 TLS ChangeCipherSpec";
        }
    }

    /// <summary>从 ClientHello 扩展里提取 SNI 主机名。</summary>
    private static string? ExtractSni(byte[] d)
    {
        try
        {
            int pos = 9 + 2 + 32;                 // 记录头5 + 握手头4 + 版本2 + 随机32
            int sid = d[pos]; pos += 1 + sid;      // 会话 ID
            int cs = (d[pos] << 8) | d[pos + 1]; pos += 2 + cs;
            int comp = d[pos]; pos += 1 + comp;
            int extTotal = (d[pos] << 8) | d[pos + 1]; pos += 2;
            int end = Math.Min(pos + extTotal, d.Length);
            while (pos + 4 <= end)
            {
                int et = (d[pos] << 8) | d[pos + 1];
                int el = (d[pos + 2] << 8) | d[pos + 3];
                pos += 4;
                // SNI 扩展数据布局：list_len(2) + type(1)=0x00 + name_len(2) + name
                if (et == 0x0000 && pos + 5 <= d.Length && d[pos + 2] == 0x00)
                {
                    int nl = (d[pos + 3] << 8) | d[pos + 4];
                    if (pos + 5 + nl <= d.Length && nl > 0 && nl <= 253)
                    {
                        var name = Encoding.ASCII.GetString(d, pos + 5, nl);
                        if (IsDomainLike(name)) return name;
                    }
                }
                pos += el;
            }
        }
        catch { }
        return null;
    }

    private static bool IsDomainLike(string s)
    {
        foreach (var c in s)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '*')) return false;
        return s.Contains('.');
    }

    // ── DNS ─────────────────────────────────────────────

    private static string? DnsSummary(byte[] d, bool outbound)
    {
        if (d.Length < 13) return null;
        try
        {
            bool isQuery = (d[2] & 0x80) == 0;
            int qd = (d[4] << 8) | d[5];
            int an = (d[6] << 8) | d[7];
            var name = ReadDnsName(d, 12);
            if (name == null) return null;
            if (isQuery) return $"DNS 查询 {name}";
            return $"DNS 应答 {name}" + (an > 0 ? $" · {an} 条记录" : "");
        }
        catch { return null; }
    }

    private static string? ReadDnsName(byte[] d, int pos)
    {
        var sb = new StringBuilder();
        while (pos < d.Length && pos < 300)
        {
            byte len = d[pos];
            if (len == 0) break;
            if (len > 63) return null; // 压缩指针，不处理
            pos++;
            if (pos + len > d.Length) return null;
            for (int i = 0; i < len; i++)
            {
                char c = (char)d[pos + i];
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_')) return null;
                sb.Append(c);
            }
            sb.Append('.');
            pos += len;
        }
        var s = sb.ToString().TrimEnd('.');
        return s.Length > 0 ? s : null;
    }

    // ── HTTP / 文本工具 ──────────────────────────────────

    private static bool IsAsciiWord(byte[] d, string word)
    {
        if (d.Length < word.Length) return false;
        for (int i = 0; i < word.Length; i++)
            if ((char)d[i] != word[i]) return false;
        return true;
    }

    private static string FirstLine(byte[] d, int max)
    {
        int end = Array.IndexOf(d, (byte)'\r');
        if (end < 0) end = Array.IndexOf(d, (byte)'\n');
        if (end < 0) end = Math.Min(d.Length, max);
        return Encoding.ASCII.GetString(d, 0, Math.Min(end, max));
    }

    private static string? FindHeader(byte[] d, string name)
    {
        var text = Encoding.ASCII.GetString(d, 0, Math.Min(d.Length, 2048));
        int idx = text.IndexOf("\r\n" + name + ":", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        int start = idx + name.Length + 3;
        int end = text.IndexOf("\r\n", start, StringComparison.Ordinal);
        if (end < 0) end = text.Length;
        var v = text[start..end].Trim();
        return v.Length > 0 ? v : null;
    }

    /// <summary>内容是否以二进制为主（文本视图不可读，应改用十六进制）。</summary>
    public static bool LooksBinary(byte[] d)
        => d.Length > 0 && PrintableRatio(d) < 0.7;

    private static double PrintableRatio(byte[] d)
    {
        int n = Math.Min(d.Length, 512), ok = 0;
        for (int i = 0; i < n; i++)
            if (Printable(d[i]) || d[i] == '\r' || d[i] == '\n' || d[i] == '\t') ok++;
        return (double)ok / n;
    }

    private static bool Printable(byte b) => b is >= 0x20 and < 0x7F;

    private static string Sanitize(byte[] d, int maxChars)
    {
        var sb = new StringBuilder(maxChars + 8);
        int used = 0;
        foreach (var b in d)
        {
            if (used >= maxChars) { sb.Append('…'); break; }
            sb.Append(b == '\r' || b == '\n' ? ' ' : Printable(b) ? (char)b : '·');
            used++;
        }
        return sb.ToString();
    }

    private static string Cut(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    private static string LengthText(PacketInfo p)
        => p.PayloadLen < 1024 ? p.PayloadLen + " 字节" : Fmt.Bytes(p.PayloadLen);
}
