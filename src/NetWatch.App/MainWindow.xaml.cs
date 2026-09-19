using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using NetWatch.Core;
using NetWatch.Core.Wfp;
using WinForms = System.Windows.Forms;

namespace NetWatch.App;

public partial class MainWindow : Window
{
    private readonly NetworkMonitor? _monitor;
    private readonly BlockManager _blocks = new();
    private readonly ProcessInfoCache _procs = new();
    private readonly ObservableCollection<AppRow> _rows = new();
    private readonly Dictionary<string, AppRow> _byKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly ObservableCollection<IpRow> _ipRows = new();
    private readonly Dictionary<string, IpRow> _ipByAddr = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, ImageSource?> _iconCache = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private double _lastElapsedSec;
    private long _grandUp, _grandDown;
    private readonly DateTime _started = DateTime.Now;
    private WinForms.NotifyIcon? _tray;
    private bool _reallyExit;

    public MainWindow()
    {
        InitializeComponent();
        Icon = Icons.WindowIcon();

        var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
        view.CustomSort = Comparer<object>.Create((a, b) => ((AppRow)b).SortScore.CompareTo(((AppRow)a).SortScore));
        AppList.ItemsSource = view;

        var ipView = (ListCollectionView)CollectionViewSource.GetDefaultView(_ipRows);
        ipView.CustomSort = Comparer<object>.Create((a, b) => ((IpRow)b).SortScore.CompareTo(((IpRow)a).SortScore));
        IpList.ItemsSource = ipView;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            _monitor = NetworkMonitor.Start();
        }
        catch (Exception ex)
        {
            Log.Error("监控启动失败：" + ex.Message);
            _reallyExit = true;
            MessageBox.Show(this, ex.Message + "\n\n请右键 NetWatch，选择“以管理员身份运行”。",
                "NetWatch 无法启动", MessageBoxButton.OK, MessageBoxImage.Error);
            Dispatcher.BeginInvoke(() => Application.Current.Shutdown(), DispatcherPriority.Background);
            return;
        }

        Log.Info($"诊断：内核监控启动 {sw.ElapsedMilliseconds} ms");
        _timer.Tick += OnTick;
        _timer.Start();
        sw.Restart();
        try { _blocks.Load(); }
        catch (Exception ex) { Log.Error("屏蔽功能初始化失败：" + ex.Message); }
        Log.Info($"诊断：屏蔽规则加载 {sw.ElapsedMilliseconds} ms");
        Loaded += (_, _) => InitTray();
        Closed += Window_Closed;
    }

    private void OnTick(object? sender, EventArgs e)
    {
        if (_monitor is null) return;
        try { Tick(); }
        catch (Exception ex) { Log.Error("刷新失败：" + ex.Message); }
    }

    private bool _firstTick = true;
    private int _idleTicks;

    private void Tick()
    {
        var swTick = _firstTick ? System.Diagnostics.Stopwatch.StartNew() : null;
        var mon = _monitor!;
        double nowSec = _clock.Elapsed.TotalSeconds;
        double elapsed = nowSec - _lastElapsedSec;
        _lastElapsedSec = nowSec;
        if (elapsed <= 0.1 || elapsed > 5) elapsed = 1;

        var snap = mon.Snapshot();
        List<ConnectionInfo> conns;
        try { conns = ConnectionHelper.GetConnections(); }
        catch { conns = new List<ConnectionInfo>(); }
        var connByPid = new Dictionary<int, int>();
        foreach (var c in conns)
            connByPid[c.Pid] = connByPid.TryGetValue(c.Pid, out var n) ? n + 1 : 1;

        long tickUp = 0, tickDown = 0;
        var aggByKey = new Dictionary<string, AppAgg>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in snap)
        {
            tickUp += p.TickSent;
            tickDown += p.TickRecv;
            if (p.TotalSent == 0 && p.TotalRecv == 0) continue;

            var info = _procs.Get(p.Pid);
            var key = info.Path ?? ("!" + info.Name);
            if (!aggByKey.TryGetValue(key, out var a))
            {
                a = new AppAgg
                {
                    Name = info.Path is not null ? Path.GetFileName(info.Path) : info.Name,
                    Path = info.Path,
                };
                aggByKey[key] = a;
            }
            a.DeltaUp += p.TickSent;
            a.DeltaDown += p.TickRecv;
            a.TotalUp += p.TotalSent;
            a.TotalDown += p.TotalRecv;
            a.Pids.Add(p.Pid);
            if (!info.Alive) a.HasDead = true;
        }

        foreach (var a in aggByKey.Values)
        {
            var s = a.Path ?? "系统或受保护进程";
            if (a.Pids.Count > 1) s += $"（{a.Pids.Count} 个进程）";
            if (a.HasDead) s += " · 进程已退出";
            a.SubTitle = s;
        }

        var nowUtc = DateTime.UtcNow;
        foreach (var kv in aggByKey)
        {
            if (!_byKey.TryGetValue(kv.Key, out var row))
            {
                row = new AppRow(kv.Key, kv.Value.Name, kv.Value.SubTitle, GetIcon(kv.Value.Path), kv.Value.Path);
                _byKey[kv.Key] = row;
                _rows.Add(row);
            }
            if (row.Icon is null && kv.Value.Path is not null && _iconCache.TryGetValue(kv.Value.Path, out var laterIcon))
                row.Icon = laterIcon; // 后台提取完成后回填
            row.Apply(kv.Value, connByPid, elapsed, nowUtc);
        }

        // 清理：长期没有新数据、且进程已全部退出的行
        for (int i = _rows.Count - 1; i >= 0; i--)
        {
            var row = _rows[i];
            if ((nowUtc - row.LastUpdatedUtc).TotalSeconds < 60) continue;
            if (row.Pids.Any(_procs.IsAlive)) continue;
            _rows.RemoveAt(i);
            _byKey.Remove(row.Key);
        }

        UpdateIpRows(mon.SnapshotRemotes(), conns, elapsed, nowUtc);

        // 空闲自适应：连续 5 个周期总流量小于 2KB 则降频到 3 秒，有流量立即恢复 1 秒
        _idleTicks = (tickUp + tickDown) < 2048 ? _idleTicks + 1 : 0;
        _timer.Interval = TimeSpan.FromSeconds(_idleTicks >= 5 ? 3 : 1);

        if (swTick != null)
        {
            _firstTick = false;
            Log.Info($"诊断：首次刷新 {swTick.ElapsedMilliseconds} ms，聚合 {aggByKey.Count} 个应用 / {snap.Count} 个进程");
        }

        double upSpeed = tickUp / elapsed, downSpeed = tickDown / elapsed;
        _grandUp += tickUp;
        _grandDown += tickDown;
        TotalUpSpeed.Text = Fmt.Speed(upSpeed);
        TotalDownSpeed.Text = Fmt.Speed(downSpeed);
        GrandUp.Text = Fmt.Bytes(_grandUp);
        GrandDown.Text = Fmt.Bytes(_grandDown);
        StatusText.Text = $"ETW 事件 {mon.EventCount:N0} · 活动连接 {conns.Count} · 已运行 {(DateTime.Now - _started).ToString(@"hh\:mm\:ss")}";
        var active = _blocks.ActiveCount;
        BtnBlockList.Content = active > 0 ? $"🚫 屏蔽管理 ({active})" : "🚫 屏蔽管理";

        if (_tray is not null)
        {
            var tip = $"NetWatch  ↑{Fmt.Bytes(upSpeed)}/s ↓{Fmt.Bytes(downSpeed)}/s";
            _tray.Text = tip.Length <= 63 ? tip : tip[..63];
        }

        ((ListCollectionView)CollectionViewSource.GetDefaultView(_rows)).Refresh();
    }

    /// <summary>目标 IP 视图：按远程地址聚合，显示各 IP 的收发速率/累计值与通信应用。</summary>
    private void UpdateIpRows(List<RemoteSnapshot> remotes, List<ConnectionInfo> conns,
        double elapsed, DateTime nowUtc)
    {
        var connByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in conns)
        {
            var ip = ConnectionHelper.ExtractIp(c.Remote);
            if (ip != null)
                connByIp[ip] = connByIp.TryGetValue(ip, out var n) ? n + 1 : 1;
        }

        foreach (var r in remotes)
        {
            if (r.TotalSent == 0 && r.TotalRecv == 0) continue;

            var names = new List<string>();
            var paths = new List<string>();
            foreach (var pid in r.Pids)
            {
                var info = _procs.Get(pid);
                if (!names.Contains(info.Name)) names.Add(info.Name);
                if (info.Path != null && !paths.Contains(info.Path)) paths.Add(info.Path);
            }
            var apps = names.Count == 0 ? "—" : string.Join(", ", names.Take(4)) + (names.Count > 4 ? $" 等 {names.Count} 项" : "");
            connByIp.TryGetValue(r.Ip, out var connCount);

            bool blocked = false;
            if (System.Net.IPAddress.TryParse(r.Ip, out var addr))
            {
                foreach (var b in _blocks.Entries)
                {
                    if (!b.Enabled || !RemoteCovers(b.Remote, addr)) continue;
                    if (b.AppPath == null || paths.Any(p => string.Equals(p, b.AppPath, StringComparison.OrdinalIgnoreCase)))
                    {
                        blocked = true;
                        break;
                    }
                }
            }

            if (!_ipByAddr.TryGetValue(r.Ip, out var row))
            {
                row = new IpRow(r.Ip);
                _ipByAddr[r.Ip] = row;
                _ipRows.Add(row);
            }
            row.Apply(r.TickSent, r.TickRecv, r.TotalSent, r.TotalRecv, apps, paths, connCount, blocked, elapsed, nowUtc);
        }

        for (int i = _ipRows.Count - 1; i >= 0; i--)
        {
            var row = _ipRows[i];
            if ((nowUtc - row.LastUpdatedUtc).TotalSeconds > 90 && row.SortScore < 1)
            {
                _ipRows.RemoveAt(i);
                _ipByAddr.Remove(row.Ip);
            }
        }

        ((ListCollectionView)CollectionViewSource.GetDefaultView(_ipRows)).Refresh();
    }

    private static bool RemoteCovers(string remote, System.Net.IPAddress ip)
    {
        try
        {
            var slash = remote.IndexOf('/');
            var net = System.Net.IPAddress.Parse(slash < 0 ? remote : remote[..slash]);
            if (net.AddressFamily != ip.AddressFamily) return false;
            if (slash < 0) return net.Equals(ip);
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

    // ── 交互 ─────────────────────────────────────────────

    private void AppList_MouseDoubleClick(object sender, MouseButtonEventArgs e) => OpenConnections();

    private void OnViewConnections(object sender, RoutedEventArgs e) => OpenConnections();

    private void OpenConnections()
    {
        if (AppList.SelectedItem is not AppRow row) return;
        var pids = row.Pids.ToHashSet();
        var win = new ConnectionsWindow(row.Name, row.Path, _blocks, () =>
        {
            try { return ConnectionHelper.GetConnections(pids); }
            catch { return new List<ConnectionInfo>(); }
        })
        { Owner = this };
        win.Show();
    }

    private void OnOpenHttpDebug(object sender, RoutedEventArgs e)
    {
        foreach (Window w in Application.Current.Windows)
            if (w is HttpDebugWindow existing)
            {
                existing.Activate();
                return;
            }
        new HttpDebugWindow().Show(); // 独立窗口：避免 Owner 机制把主窗口压在下面
    }

    private void OnOpenBlockList(object sender, RoutedEventArgs e)
    {
        foreach (Window w in Application.Current.Windows)
            if (w is BlockListWindow existing)
            {
                existing.Activate();
                return;
            }
        new BlockListWindow(_blocks).Show();
    }

    // ── 搜索 ─────────────────────────────────────────────

    private string _searchText = "";

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (SearchBox is null) return; // XAML 解析期保护
        _searchText = SearchBox.Text.Trim();
        ApplySearchFilter();
    }

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape) SearchBox.Clear();
    }

    private void ApplySearchFilter()
    {
        var appView = (ListCollectionView)CollectionViewSource.GetDefaultView(_rows);
        var ipView = (ListCollectionView)CollectionViewSource.GetDefaultView(_ipRows);
        if (_searchText.Length == 0)
        {
            appView.Filter = null;
            ipView.Filter = null;
        }
        else
        {
            appView.Filter = o => o is AppRow a && (Hit(a.Name) || Hit(a.Path));
            ipView.Filter = o => o is IpRow r && (Hit(r.Ip) || Hit(r.AppsText));
        }
        appView.Refresh();
        ipView.Refresh();
    }

    private bool Hit(string? s)
        => s is not null && s.Contains(_searchText, StringComparison.OrdinalIgnoreCase);

    // ── 视图切换 ─────────────────────────────────────────

    private void OnViewApp(object sender, RoutedEventArgs e)
    {
        if (AppList is null || IpList is null) return; // XAML 解析期 IsChecked=True 会提前触发
        AppList.Visibility = Visibility.Visible;
        IpList.Visibility = Visibility.Collapsed;
    }

    private void OnViewIp(object sender, RoutedEventArgs e)
    {
        if (AppList is null || IpList is null) return;
        AppList.Visibility = Visibility.Collapsed;
        IpList.Visibility = Visibility.Visible;
    }

    // ── 目标 IP 视图交互 ─────────────────────────────────

    private void IpList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (IpList.SelectedItem is not IpRow row) return;
        var ip = row.Ip;
        var win = new ConnectionsWindow($"→ {ip}", null, _blocks, () =>
        {
            try
            {
                return ConnectionHelper.GetConnections()
                    .Where(c => string.Equals(ConnectionHelper.ExtractIp(c.Remote), ip, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }
            catch { return new List<ConnectionInfo>(); }
        })
        { Owner = this };
        win.Show();
    }

    private void OnBlockIpGlobal(object sender, RoutedEventArgs e)
    {
        if (IpList.SelectedItem is not IpRow row) return;
        if (MessageBox.Show(this,
                $"确定禁止所有程序与 {row.Ip} 建立新的出站连接？\n\n（已建立的旧连接不受影响，重启相关程序后完全阻断）",
                "屏蔽确认", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            _blocks.Add(row.Ip, null);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "屏蔽失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnUnblockIpRow(object sender, RoutedEventArgs e)
    {
        if (IpList.SelectedItem is not IpRow row) return;
        if (!System.Net.IPAddress.TryParse(row.Ip, out var addr))
        {
            MessageBox.Show(this, "无法解析该地址。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var toRemove = _blocks.Entries
            .Where(b => b.Enabled && RemoteCovers(b.Remote, addr))
            .ToList();
        if (toRemove.Count == 0)
        {
            MessageBox.Show(this, $"没有找到覆盖 {row.Ip} 的屏蔽规则。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var detail = string.Join("\n", toRemove.Select(b => $"{b.Remote}（{b.AppPath ?? "所有程序"}）"));
        if (MessageBox.Show(this, $"确定移除以下屏蔽规则？\n\n{detail}", "取消屏蔽",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            foreach (var b in toRemove) _blocks.Remove(b);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "操作失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCopyIp(object sender, RoutedEventArgs e)
    {
        if (IpList.SelectedItem is IpRow row)
            try { Clipboard.SetText(row.Ip); } catch { }
    }

    private void OnCapturePackets(object sender, RoutedEventArgs e)
    {
        if (IpList.SelectedItem is not IpRow row) return;
        CaptureWindow win;
        try { win = new CaptureWindow(row.Ip); }
        catch (Exception ex)
        {
            MessageBox.Show(this, "打开抓包失败：" + ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        if (win.StartupFailed) return;
        win.Show();
    }

    private void OnOpenIpLocation(object sender, RoutedEventArgs e)
    {
        if (IpList.SelectedItem is not IpRow row) return;
        var paths = row.Paths
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (paths.Count == 0)
        {
            MessageBox.Show(this,
                $"没有找到与 {row.Ip} 关联的可执行文件路径。\n\n系统进程或受保护进程可能无法读取文件位置。",
                "文件位置", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        IEnumerable<string> selected = paths;
        if (paths.Count > 1)
        {
            var names = string.Join("\n", paths.Select((p, i) => $"{i + 1}. {p}"));
            if (MessageBox.Show(this,
                    $"该 IP 关联了多个应用，将打开以下文件位置：\n\n{names}",
                    "打开关联应用文件位置", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
                return;
        }

        foreach (var path in selected)
        {
            try
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
                {
                    UseShellExecute = true,
                });
            }
            catch (Exception ex)
            {
                Log.Error("打开目标 IP 关联文件位置失败：" + ex.Message);
            }
        }
    }

    private void OnOpenLocation(object sender, RoutedEventArgs e)
    {
        if (AppList.SelectedItem is not AppRow row || string.IsNullOrEmpty(row.Path)) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{row.Path}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { Log.Error("打开文件位置失败：" + ex.Message); }
    }

    // ── 托盘 ─────────────────────────────────────────────

    private void InitTray()
    {
        if (_tray is not null) return;
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("显示主窗口", null, (_, _) => ShowMain());
        menu.Items.Add("屏蔽管理", null, (_, _) => Dispatcher.Invoke(() => OnOpenBlockList(this, new RoutedEventArgs())));
        menu.Items.Add("HTTP 调试", null, (_, _) => Dispatcher.Invoke(() => OnOpenHttpDebug(this, new RoutedEventArgs())));
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("退出 NetWatch", null, (_, _) => ExitApp());
        _tray = new WinForms.NotifyIcon
        {
            Icon = Icons.TrayIcon(),
            Text = "NetWatch",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _tray.DoubleClick += (_, _) => ShowMain();
    }

    private void ShowMain()
    {
        Dispatcher.Invoke(() =>
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
        });
    }

    private void ExitApp()
    {
        Dispatcher.Invoke(() =>
        {
            _reallyExit = true;
            Close();
            Application.Current.Shutdown();
        });
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_reallyExit || _monitor is null) return;
        e.Cancel = true;
        Hide();
    }

    private void Window_Closed(object? sender, EventArgs e)
    {
        _timer.Stop();
        _tray?.Dispose();
        _tray = null;
        _monitor?.Dispose();
        _blocks.Dispose();
    }

    // ── 图标缓存 ─────────────────────────────────────────

    private readonly HashSet<string> _iconPending = new();

    private ImageSource? GetIcon(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        if (_iconCache.TryGetValue(path, out var cached)) return cached;
        lock (_iconPending)
        {
            if (!_iconPending.Add(path)) return null; // 已有后台任务在提取
        }
        var captured = path;
        System.Threading.Tasks.Task.Run(() =>
        {
            ImageSource? src = null;
            try
            {
                using var ic = System.Drawing.Icon.ExtractAssociatedIcon(captured);
                if (ic != null) src = Icons.ToImageSource(ic.ToBitmap()); // Freeze 过，可跨线程
            }
            catch { }
            _iconCache[captured] = src;
            lock (_iconPending) _iconPending.Remove(captured);
        });
        return null;
    }
}
