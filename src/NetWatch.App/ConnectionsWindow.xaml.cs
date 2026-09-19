using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Threading;
using NetWatch.Core;

namespace NetWatch.App;

public partial class ConnectionsWindow : Window
{
    private readonly Func<List<ConnectionInfo>> _fetch;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };

    public ConnectionsWindow(string appName, Func<List<ConnectionInfo>> fetch)
    {
        _fetch = fetch;
        InitializeComponent();
        Title = $"连接详情 — {appName}";
        HeaderText.Text = $"{appName} · 活动连接（每 2 秒自动刷新）";
        Loaded += (_, _) => { Refresh(); _timer.Start(); };
        Closed += (_, _) => _timer.Stop();
        _timer.Tick += (_, _) => Refresh();
    }

    private void Refresh()
    {
        try { ConnGrid.ItemsSource = _fetch(); }
        catch (Exception ex) { Log.Error("刷新连接失败：" + ex.Message); }
    }
}
