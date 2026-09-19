using System;
using System.Collections.Generic;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using NetWatch.Core;
using NetWatch.Core.Wfp;

namespace NetWatch.App;

public partial class ConnectionsWindow : Window
{
    private readonly string _appName;
    private readonly string? _appPath;
    private readonly BlockManager _blocks;
    private readonly Func<List<ConnectionInfo>> _fetch;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };

    /// <summary>连接行（带屏蔽标注）。</summary>
    public sealed record ConnRow(string Protocol, string Local, string Remote, string State, int Pid, bool Blocked)
    {
        public string RemoteText => Blocked ? Remote + "   ⛔ 已屏蔽" : Remote;
    }

    public ConnectionsWindow(string appName, string? appPath, BlockManager blocks, Func<List<ConnectionInfo>> fetch)
    {
        _appName = appName;
        _appPath = appPath;
        _blocks = blocks;
        _fetch = fetch;
        InitializeComponent();
        Title = $"连接详情 — {appName}";
        HeaderText.Text = $"{appName} · 活动连接（每 2 秒自动刷新，右键可屏蔽远程 IP）";
        Loaded += (_, _) => { Refresh(); _timer.Start(); };
        Closed += (_, _) => _timer.Stop();
        _timer.Tick += (_, _) => Refresh();
    }

    private void Refresh()
    {
        try
        {
            var rows = new List<ConnRow>();
            foreach (var c in _fetch())
            {
                var ip = ExtractIp(c.Remote);
                bool blocked = ip != null
                    && IPAddress.TryParse(ip, out var addr)
                    && _blocks.IsBlocked(_appPath, addr);
                rows.Add(new ConnRow(c.Protocol, c.Local, c.Remote, c.State, c.Pid, blocked));
            }
            ConnGrid.ItemsSource = rows;
        }
        catch (Exception ex) { Log.Error("刷新连接失败：" + ex.Message); }
    }

    /// <summary>"1.2.3.4:443" / "[::1]:443" → IP 部分；"*" 或空返回 null。</summary>
    private static string? ExtractIp(string? remote)
    {
        if (string.IsNullOrEmpty(remote) || remote == "*") return null;
        if (remote.StartsWith('['))
        {
            var end = remote.IndexOf(']');
            return end > 0 ? remote[1..end] : null;
        }
        var colon = remote.LastIndexOf(':');
        return colon > 0 ? remote[..colon] : remote;
    }

    private ConnRow? SelectedConn => ConnGrid.SelectedItem as ConnRow;

    private void CtxMenu_Opening(object sender, ContextMenuEventArgs e)
    {
        if (ConnGrid.ContextMenu is { } menu)
        {
            var ip = SelectedConn is { } row ? ExtractIp(row.Remote) : null;
            foreach (var item in menu.Items)
                if (item is MenuItem mi) mi.IsEnabled = ip != null;
        }
    }

    private void OnBlockAppIp(object sender, RoutedEventArgs e) => Block(confirmScope: true);
    private void OnBlockAllIp(object sender, RoutedEventArgs e) => Block(confirmScope: false);

    private void Block(bool confirmScope)
    {
        if (SelectedConn is not { } row) return;
        var ip = ExtractIp(row.Remote);
        if (ip == null) return;
        if (confirmScope && string.IsNullOrEmpty(_appPath))
        {
            MessageBox.Show(this, "该应用没有可识别的文件路径（系统或受保护进程），只能按“所有程序”屏蔽。",
                "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var scope = confirmScope ? $"仅 {_appName}" : "所有程序";
        if (MessageBox.Show(this,
                $"确定禁止 {scope} 与 {ip} 建立新的出站连接？\n\n（已建立的旧连接不受影响，重启目标程序后完全阻断）",
                "屏蔽确认", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        try
        {
            _blocks.Add(ip, confirmScope ? _appPath : null);
            Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "屏蔽失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnUnblockIp(object sender, RoutedEventArgs e)
    {
        if (SelectedConn is not { } row) return;
        var ip = ExtractIp(row.Remote);
        if (ip == null || !IPAddress.TryParse(ip, out var addr))
        {
            MessageBox.Show(this, "无法解析该远程地址。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // 找出覆盖该 IP 的规则（应用级 + 全局）并逐一移除
        var toRemove = new List<BlockEntry>();
        foreach (var entry in _blocks.Entries)
        {
            if (!entry.Enabled) continue;
            if (entry.AppPath != null && !string.Equals(entry.AppPath, _appPath, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                var slash = entry.Remote.IndexOf('/');
                var net = IPAddress.Parse(slash < 0 ? entry.Remote : entry.Remote[..slash]);
                if (net.AddressFamily != addr.AddressFamily) continue;
                if (PrefixContains(entry.Remote, addr)) toRemove.Add(entry);
            }
            catch { }
        }
        if (toRemove.Count == 0)
        {
            MessageBox.Show(this, $"没有找到覆盖 {ip} 的屏蔽规则。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var names = string.Join("\n", toRemove.Select(b => $"{b.Remote}（{b.AppPath ?? "所有程序"}）"));
        if (MessageBox.Show(this, $"确定移除以下屏蔽规则？\n\n{names}", "取消屏蔽",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        try
        {
            foreach (var entry in toRemove) _blocks.Remove(entry);
            Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "操作失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static bool PrefixContains(string remote, IPAddress ip)
    {
        try
        {
            var slash = remote.IndexOf('/');
            if (slash < 0) return IPAddress.Parse(remote).Equals(ip);
            var net = IPAddress.Parse(remote[..slash]);
            int prefix = int.Parse(remote[(slash + 1)..]);
            var a = net.GetAddressBytes();
            var b = ip.GetAddressBytes();
            int full = prefix / 8, rem = prefix % 8;
            for (int i = 0; i < full; i++)
                if (a[i] != b[i]) return false;
            if (rem > 0)
            {
                int m = 0xFF << (8 - rem);
                if ((a[full] & m) != (b[full] & m)) return false;
            }
            return true;
        }
        catch { return false; }
    }
}
