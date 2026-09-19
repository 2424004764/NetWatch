using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NetWatch.Core.Mitm;

/// <summary>当前用户的系统代理（WinINET）开关：开启后浏览器等遵循系统代理的程序都会走本地 MITM 代理。</summary>
public static class SystemProxy
{
    private const string SettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    [DllImport("wininet.dll")]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey, writable: false);
        return key?.GetValue("ProxyEnable") is int i && i == 1;
    }

    /// <summary>开启系统代理指向本地端口（localhost 等地址绕过）。</summary>
    public static void Enable(int port)
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey, writable: true);
        if (key == null) throw new InvalidOperationException("无法打开系统代理设置。");
        key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
        key.SetValue("ProxyOverride", "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>", RegistryValueKind.String);
        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        NotifyChanged();
        Log.Info($"系统代理已开启 → 127.0.0.1:{port}");
    }

    public static void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey, writable: true);
        key?.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        NotifyChanged();
        Log.Info("系统代理已关闭。");
    }

    private static void NotifyChanged()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }
}
