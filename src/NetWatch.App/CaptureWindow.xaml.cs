using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Controls;
using System.Windows.Threading;
using NetWatch.Core;

namespace NetWatch.App;

public partial class CaptureWindow : Window
{
    private const int MaxRows = 2000;

    private sealed class PacketRow
    {
        // 必须是属性：WPF 绑定不认公共字段（否则单元格全空）
        public string Time { get; set; } = "";
        public string Dir { get; set; } = "";
        public bool IsOut { get; set; }
        public string Remote { get; set; } = "";
        public string Proto { get; set; } = "";
        public string Len { get; set; } = "";
        public string Preview { get; set; } = "";
        public PacketInfo Packet { get; set; } = null!;
    }

    private readonly PacketSniffer? _sniffer;
    private readonly ConcurrentQueue<PacketInfo> _queue = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(400) };
    private bool _paused;
    private bool _hexMode;
    private int _intDirection; // 0=全部 1=仅上行 2=仅下行
    private long _captured;

    /// <summary>构造失败（抓包引擎未启动）时为 true，调用方不应再 Show()。</summary>
    public bool StartupFailed { get; private set; }

    public CaptureWindow(string remote)
    {
        InitializeComponent();
        Title = $"数据包 — {remote}";
        HeaderText.Text = $"{remote} · 实时数据包捕获（发往 / 来自该地址的流量）";

        try
        {
            _sniffer = new PacketSniffer(new[] { remote });
            _sniffer.Start();
        }
        catch (Exception ex)
        {
            StartupFailed = true;
            MessageBox.Show(this, "抓包启动失败：" + ex.Message, "NetWatch",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        _sniffer.PacketReceived += p => _queue.Enqueue(p);
        _timer.Tick += (_, _) => DrainQueue();
        _timer.Start();
        Closed += (_, _) => { _timer.Stop(); _sniffer?.Dispose(); };
    }

    private List<PacketRow> Rows { get; } = new();

    private ListCollectionView View
        => (ListCollectionView)System.Windows.Data.CollectionViewSource.GetDefaultView(Rows);

    private void DrainQueue()
    {
        if (_sniffer is null || StartupFailed) return;
        if (_paused) { _queue.Clear(); return; }
        if (PacketGrid.ItemsSource is null) PacketGrid.ItemsSource = Rows;

        var view = View;
        int added = 0;
        while (_queue.TryDequeue(out var p))
        {
            _captured++;
            var row = new PacketRow
            {
                Time = p.TimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
                Dir = p.Outbound ? "↑ 发" : "↓ 收",
                IsOut = p.Outbound,
                Remote = p.RemoteIp + ":" + p.RemotePort,
                Proto = p.Protocol,
                Len = p.PayloadLen + " B",
                Preview = PayloadDescribe.Preview(p.Payload, 130),
                Packet = p,
            };
            Rows.Add(row);
            added++;
        }

        while (Rows.Count > MaxRows)
            Rows.RemoveAt(0);

        if (added > 0)
            view.Refresh();

        StatusText.Text = $"已捕获 {_captured:N0} 个包 · 列表保留最近 {Rows.Count:N0} 条" +
                          (_sniffer.Dropped > 0 ? $" · 丢弃 {_sniffer.Dropped:N0}" : "") +
                          (_paused ? " · 已暂停" : "");
    }

    private void OnTogglePause(object sender, RoutedEventArgs e)
    {
        _paused = !_paused;
        BtnPause.Content = _paused ? "▶ 继续" : "⏸ 暂停";
    }

    private void OnDirFilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PacketGrid is null) return; // XAML 解析期 ComboBox IsSelected=True 会提前触发
        if (DirFilter.SelectedIndex >= 0) _intDirection = DirFilter.SelectedIndex;
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        View.Filter = _intDirection switch
        {
            1 => o => ((PacketRow)o).IsOut,
            2 => o => !((PacketRow)o).IsOut,
            _ => null,
        };
        View.Refresh();
    }

    private void OnViewModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PacketGrid is null) return; // XAML 解析期提前触发
        if (ViewMode.SelectedIndex == 1) _hexMode = true;
        else if (ViewMode.SelectedIndex == 0) _hexMode = false;
        RenderSelected();
    }

    private void OnPacketSelected(object sender, SelectionChangedEventArgs e) => RenderSelected();

    private void RenderSelected()
    {
        if (PacketGrid?.SelectedItem is not PacketRow row) return;
        DetailBox.Text = _hexMode
            ? PayloadDescribe.HexDump(row.Packet.Payload)
            : PayloadDescribe.FullText(row.Packet.Payload);
    }

    private void OnClear(object sender, RoutedEventArgs e)
    {
        Rows.Clear();
        View.Refresh();
        DetailBox.Text = "（选择上方数据包查看内容）";
    }

    // 让文本框自动滚动到底部（最新内容）
    private void DetailBox_TextChanged(object sender, TextChangedEventArgs e)
        => DetailBox.ScrollToEnd();
}
