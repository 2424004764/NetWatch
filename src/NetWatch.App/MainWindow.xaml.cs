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
using WinForms = System.Windows.Forms;

namespace NetWatch.App;

public partial class MainWindow : Window
{
    private readonly NetworkMonitor? _monitor;
    private readonly ProcessInfoCache _procs = new();
    private readonly ObservableCollection<AppRow> _rows = new();
    private readonly Dictionary<string, AppRow> _byKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ImageSource?> _iconCache = new(StringComparer.OrdinalIgnoreCase);
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

        _timer.Tick += OnTick;
        _timer.Start();
        Loaded += (_, _) => InitTray();
        Closed += Window_Closed;
    }

    private void OnTick(object? sender, EventArgs e)
    {
        if (_monitor is null) return;
        try { Tick(); }
        catch (Exception ex) { Log.Error("刷新失败：" + ex.Message); }
    }

    private void Tick()
    {
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

        double upSpeed = tickUp / elapsed, downSpeed = tickDown / elapsed;
        _grandUp += tickUp;
        _grandDown += tickDown;
        TotalUpSpeed.Text = Fmt.Speed(upSpeed);
        TotalDownSpeed.Text = Fmt.Speed(downSpeed);
        GrandUp.Text = Fmt.Bytes(_grandUp);
        GrandDown.Text = Fmt.Bytes(_grandDown);
        StatusText.Text = $"ETW 事件 {mon.EventCount:N0} · 活动连接 {conns.Count} · 已运行 {(DateTime.Now - _started).ToString(@"hh\:mm\:ss")}";

        if (_tray is not null)
        {
            var tip = $"NetWatch  ↑{Fmt.Bytes(upSpeed)}/s ↓{Fmt.Bytes(downSpeed)}/s";
            _tray.Text = tip.Length <= 63 ? tip : tip[..63];
        }

        ((ListCollectionView)CollectionViewSource.GetDefaultView(_rows)).Refresh();
    }

    // ── 交互 ─────────────────────────────────────────────

    private void AppList_MouseDoubleClick(object sender, MouseButtonEventArgs e) => OpenConnections();

    private void OnViewConnections(object sender, RoutedEventArgs e) => OpenConnections();

    private void OpenConnections()
    {
        if (AppList.SelectedItem is not AppRow row) return;
        var pids = row.Pids.ToHashSet();
        var win = new ConnectionsWindow(row.Name, () =>
        {
            try { return ConnectionHelper.GetConnections(pids); }
            catch { return new List<ConnectionInfo>(); }
        })
        { Owner = this };
        win.Show();
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
    }

    // ── 图标缓存 ─────────────────────────────────────────

    private ImageSource? GetIcon(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        if (_iconCache.TryGetValue(path, out var cached)) return cached;
        ImageSource? src = null;
        try
        {
            using var ic = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (ic != null) src = Icons.ToImageSource(ic.ToBitmap());
        }
        catch { }
        _iconCache[path] = src;
        return src;
    }
}
