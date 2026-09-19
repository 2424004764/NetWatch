using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NetWatch.Core.Mitm;

/// <summary>
/// MITM 调试代理的证书工厂：
/// 1) 首次运行生成一个本地根 CA（保存在 %APPDATA%\NetWatch）；
/// 2) 按目标域名动态签发短效叶证书（内存缓存），用于和本机客户端做 TLS；
/// 3) 根 CA 需要用户显式安装到「受信任的根证书」后，客户端才会信任这些叶证书。
/// 全部使用 .NET 内置的 CertificateRequest，无外部依赖。
/// </summary>
public static class CertMaker
{
    public static string DataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetWatch");
    public static string CaPfxPath => Path.Combine(DataDir, "mitm-ca.pfx");
    public static string CaCerPath => Path.Combine(DataDir, "mitm-ca.cer");

    private static readonly object Gate = new();
    private static readonly Dictionary<string, X509Certificate2> LeafCache = new(StringComparer.OrdinalIgnoreCase);

    public static X509Certificate2 EnsureRootCa()
    {
        lock (Gate)
        {
            if (File.Exists(CaPfxPath))
            {
                try { return new X509Certificate2(CaPfxPath); } catch { }
            }
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=NetWatch Debug Root CA", rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            var ca = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
            Directory.CreateDirectory(DataDir);
            File.WriteAllBytes(CaPfxPath, ca.Export(X509ContentType.Pfx));
            File.WriteAllBytes(CaCerPath, ca.Export(X509ContentType.Cert));
            Log.Info("已生成 MITM 调试根证书：" + CaPfxPath);
            return ca;
        }
    }

    /// <summary>为某个域名（或 IP）签发带 SAN 的叶证书。</summary>
    public static X509Certificate2 LeafFor(string host)
    {
        lock (Gate)
        {
            if (LeafCache.TryGetValue(host, out var cached)) return cached;

            using var ca = EnsureRootCa();
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest($"CN={host}", rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            var san = new SubjectAlternativeNameBuilder();
            if (System.Net.IPAddress.TryParse(host, out var ip)) san.AddIpAddress(ip);
            else san.AddDnsName(host);
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));

            var serial = new byte[12];
            RandomNumberGenerator.Fill(serial);
            serial[0] &= 0x7F;
            var pub = req.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMonths(6), serial);
            using var withKey = pub.CopyWithPrivateKey(rsa);
            // SChannel 不支持临时密钥：经 PFX 回读一次，把私钥落进用户密钥容器
            var pfx = withKey.Export(X509ContentType.Pfx);
            var leaf = new X509Certificate2(pfx, (string?)null,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            LeafCache[host] = leaf;
            return leaf;
        }
    }

    public static bool IsRootCaInstalled()
    {
        using var ca = EnsureRootCa();
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, ca.Thumbprint, validOnly: false).Count > 0;
    }

    /// <summary>把根 CA 装入当前用户的「受信任的根证书」（Windows 会弹一次安全确认框）。</summary>
    public static void InstallRootCa()
    {
        using var ca = EnsureRootCa();
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(ca);
        Log.Info("MITM 调试根证书已安装到当前用户信任存储。");
    }

    public static void RemoveRootCa()
    {
        using var ca = EnsureRootCa();
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (var c in store.Certificates.Find(X509FindType.FindByThumbprint, ca.Thumbprint, false))
            store.Remove(c);
        Log.Info("MITM 调试根证书已从信任存储移除。");
    }
}
