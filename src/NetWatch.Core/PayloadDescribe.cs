using System;
using System.Text;

namespace NetWatch.Core;

/// <summary>把数据包负载变成人能读的摘要：识别 TLS/压缩/HTTP/JSON/纯文本/二进制。</summary>
public static class PayloadDescribe
{
    /// <summary>生成简短预览（不可打印字符替换为·）。</summary>
    public static string Preview(byte[] data, int maxChars = 110)
    {
        if (data.Length == 0) return "（无负载，仅握手/头部）";
        var kind = KindOf(data);
        var text = Sanitize(data, maxChars);
        return kind.Length > 0 ? $"{kind} | {text}" : text;
    }

    /// <summary>完整文本视图（保留换行，截断到 maxChars）。</summary>
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

    /// <summary>经典十六进制转储：0000  47 45 54 …  GET…</summary>
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

    private static string KindOf(byte[] d)
    {
        if (d.Length >= 2 && d[0] == 0x1F && d[1] == 0x8B) return "gzip 压缩";
        if (d.Length >= 3 && d[0] == 0x78 && (d[1] == 0x01 || d[1] == 0x9C || d[1] == 0xDA)) return "zlib 压缩";
        if (d.Length >= 5 && d[0] >= 20 && d[0] <= 23 && d[1] == 0x03) return "🔒 TLS 加密（无法查看明文）";
        if (d.Length >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 0x03 && d[3] == 0x04) return "zip 数据";
        return "";
    }

    private static bool Printable(byte b)
        => b is >= 0x20 and < 0x7F;

    private static string Sanitize(byte[] d, int maxChars)
    {
        var sb = new StringBuilder(maxChars + 8);
        int used = 0;
        foreach (var b in d)
        {
            if (used >= maxChars) { sb.Append('…'); break; }
            if (b == '\r' || b == '\n') { sb.Append(' '); used++; continue; }
            sb.Append(Printable(b) ? (char)b : '·');
            used++;
        }
        return sb.ToString();
    }
}
