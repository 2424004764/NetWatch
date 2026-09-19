using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using NetWatch.Core;
using NetWatch.Core.Mitm;

namespace NetWatch.App;

public partial class HttpDebugWindow : Window
{
    private const int MaxRows = 1500;

    private sealed class HttpRow
    {
        // 必须是属性：WPF 绑定不认公共字段
        public string Time { get; set; } = "";
        public string Method { get; set; } = "";
        public string StatusText { get; set; } = "";
        public bool IsError { get; set; }
        public string Url { get; set; } = "";
        public string ReqText { get; set; } = "";
        public string RespText { get; set; } = "";
        public string ContentType { get; set; } = "";
        public HttpExchange Exchange { get; set; } = null!;
    }

    private readonly MitmProxy _proxy;
    private readonly ConcurrentQueue<HttpExchange> _queue = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(400) };
    private long _count;

    public HttpDebugWindow()
    {
        InitializeComponent();
        Title = "HTTP 调试 — NetWatch";

        _proxy = new MitmProxy();
        _proxy.ExchangeLogged += e => _queue.Enqueue(e);
        _proxy.Start();
        HeaderText.Text = $"内置调试代理已运行：127.0.0.1:{_proxy.Port}（HTTPS 明文可见，原理同 Fiddler）";

        _timer.Tick += (_, _) => Drain();
        _timer.Start();
        Closed += OnClosed;
        RefreshToolbar();
    }

    private List<HttpRow> Rows { get; } = new();

    private System.Windows.Data.ListCollectionView View
        => (System.Windows.Data.ListCollectionView)System.Windows.Data.CollectionViewSource.GetDefaultView(Rows);

    private void Drain()
    {
        if (ReqGrid.ItemsSource is null) ReqGrid.ItemsSource = Rows;
        int added = 0;
        while (_queue.TryDequeue(out var e))
        {
            _count++;
            Rows.Add(new HttpRow
            {
                Time = e.TimeUtc.ToLocalTime().ToString("HH:mm:ss.fff"),
                Method = e.Method,
                StatusText = e.Status == 0 ? "—" : e.Status.ToString(),
                IsError = e.Status >= 400,
                Url = e.Url,
                ReqText = Fmt.Bytes(e.ReqBodyLen),
                RespText = Fmt.Bytes(e.RespBodyLen),
                ContentType = ShortType(e.ContentType),
                Exchange = e,
            });
            added++;
        }
        while (Rows.Count > MaxRows) Rows.RemoveAt(0);
        if (added > 0) View.Refresh();
        UpdateStatus();
    }

    private string _filter = "";

    private void OnFilterChanged(object sender, TextChangedEventArgs e)
    {
        if (ReqGrid is null) return; // XAML 解析期保护
        _filter = FilterBox.Text.Trim();
        View.Filter = _filter.Length == 0 ? null : o => MatchesFilter((HttpRow)o);
        View.Refresh();
        UpdateStatus();
    }

    private bool MatchesFilter(HttpRow r)
    {
        foreach (var raw in _filter.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            bool neg = raw.StartsWith("!");
            var term = (neg ? raw[1..] : raw).ToLowerInvariant();
            if (term.Length == 0) continue;
            bool hit = r.Method.ToLowerInvariant().Contains(term)
                       || r.Url.ToLowerInvariant().Contains(term)
                       || r.StatusText.Contains(term, StringComparison.OrdinalIgnoreCase)
                       || r.ContentType.ToLowerInvariant().Contains(term);
            if (neg == hit) return false; // 排除词命中，或必需词未命中
        }
        return true;
    }

    private void UpdateStatus()
    {
        int shown = ReqGrid.ItemsSource is null ? Rows.Count : View.Count;
        StatusText.Text = $"已捕获 {_count:N0} 个请求" +
                          (shown < Rows.Count ? $" · 筛选显示 {shown:N0}" : "") +
                          $" · 代理端口 {_proxy.Port}" +
                          (SystemProxy.IsEnabled() ? " · 系统代理已接管" : "") +
                          (_launchedName is { } ln ? " · 已带代理启动 " + ln : "");
    }

    private static string ShortType(string contentType)
        => contentType.Length > 0 && contentType.Contains(';') ? contentType[..contentType.IndexOf(';')] : contentType;

    private void RefreshToolbar()
    {
        bool installed = false;
        try { installed = CertMaker.IsRootCaInstalled(); }
        catch (Exception ex) { Log.Error("查询证书状态失败：" + ex.Message); }
        BtnCert.Content = installed ? "① 移除调试根证书" : "① 安装调试根证书";
        bool proxyOn = SystemProxy.IsEnabled();
        BtnSysProxy.Content = proxyOn ? "③ 还原系统代理" : "③ 全局接管系统代理（高级）";
    }

    private void OnToggleCert(object sender, RoutedEventArgs e)
    {
        try
        {
            if (CertMaker.IsRootCaInstalled())
            {
                if (MessageBox.Show(this, "确定移除 NetWatch 调试根证书？移除后将无法查看 HTTPS 明文。",
                        "移除证书", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                    CertMaker.RemoveRootCa();
            }
            else
            {
                if (MessageBox.Show(this,
                        "即将安装 NetWatch 调试根证书到当前用户的「受信任的根证书」。\n\n" +
                        "安装后，走本机调试代理的 HTTPS 内容对你可见（Windows 会再弹一次安全确认）。\n" +
                        "仅建议在自己开发机上、调试自己的软件时使用；用完请点「移除调试根证书」。",
                        "安装调试根证书", MessageBoxButton.OKCancel, MessageBoxImage.Warning) == MessageBoxResult.OK)
                    CertMaker.InstallRootCa();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        RefreshToolbar();
    }

    private void OnToggleProxy(object sender, RoutedEventArgs e)
    {
        try
        {
            if (SystemProxy.IsEnabled()) SystemProxy.Disable();
            else SystemProxy.Enable(_proxy.Port);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        RefreshToolbar();
    }

    private string? _launchedName;

    private void OnCopyProxy(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText("http://127.0.0.1:" + _proxy.Port);
            BtnCopyProxy.Content = "已复制 127.0.0.1:" + _proxy.Port;
            var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            t.Tick += (_, _) => { t.Stop(); BtnCopyProxy.Content = "复制代理地址"; };
            t.Start();
            UpdateStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnLaunchTarget(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择要调试的程序（将以代理环境变量启动）",
            Filter = "程序 (*.exe)|*.exe",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var url = "http://127.0.0.1:" + _proxy.Port;
            var psi = new System.Diagnostics.ProcessStartInfo(dlg.FileName)
            {
                UseShellExecute = false,
                WorkingDirectory = System.IO.Path.GetDirectoryName(dlg.FileName) ?? "",
            };
            foreach (var k in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" })
                psi.EnvironmentVariables[k] = url;
            psi.EnvironmentVariables["NO_PROXY"] = psi.EnvironmentVariables["no_proxy"] = "localhost,127.0.0.1,::1";
            var name = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName).ToLowerInvariant();
            if (name.Contains("chrome") || name.Contains("msedge") || name.Contains("chromium")
                || name.Contains("brave") || name.Contains("opera") || name.Contains("vivaldi"))
                psi.ArgumentList.Add("--proxy-server=" + url); // Chromium 系不吃环境变量
            System.Diagnostics.Process.Start(psi);
            _launchedName = System.IO.Path.GetFileName(dlg.FileName);
            UpdateStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnReqSelected(object sender, SelectionChangedEventArgs e) => RenderSelected();

    private bool _hexMode;

    private void OnViewModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ReqGrid is null) return; // XAML 解析期保护
        _hexMode = ViewMode.SelectedIndex == 1;
        RenderSelected();
    }

    private string BodySection(byte[] body, string? text)
    {
        if (body.Length == 0) return "（无）";
        if (_hexMode || text == null)
        {
            var note = text == null && !_hexMode ? "二进制内容，十六进制视图：\n" : "";
            return note + PayloadDescribe.HexDump(body, 8192);
        }
        return text;
    }

    private void RenderSelected()
    {
        if (ReqGrid?.SelectedItem is not HttpRow row) return;
        var e = row.Exchange;
        var sb = new StringBuilder();
        sb.Append("──── 请求 ────\n").Append(e.ReqHead.TrimEnd()).Append('\n');
        sb.Append("\n【请求体】\n").Append(BodySection(e.ReqBody, e.ReqText)).Append('\n');
        sb.Append("\n──── 响应 ────\n").Append(e.RespHead.TrimEnd()).Append('\n');
        sb.Append("\n【响应体】\n").Append(BodySection(e.RespBody, e.RespText)).Append('\n');
        DetailBox.Text = sb.ToString();
    }

    private void OnClear(object sender, RoutedEventArgs e)
    {
        Rows.Clear();
        View.Refresh();
        DetailBox.Text = "（尚未捕获到请求——先把流量接入本代理（三选一）：\n  ① 点「复制代理地址」，填进你要调试的软件的代理设置（只影响它）\n  ② 点「启动调试目标…」，带代理启动你的程序（Go/.NET/Python/Node/curl 自动生效）\n  ③ 点「③ 全局接管系统代理（高级）」让所有软件走本代理，接好后重启/刷新要看的软件\n接入后，这里会实时列出请求）";
        UpdateStatus();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _timer.Stop();
        try { if (SystemProxy.IsEnabled()) SystemProxy.Disable(); } catch { }
        _proxy.Dispose();
    }
}
