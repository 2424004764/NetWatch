using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using NetWatch.Core;
using NetWatch.Core.Qos;

namespace NetWatch.App;

public partial class UploadLimitListWindow : Window
{
    private readonly UploadLimitManager _limits;

    private sealed class LimitRow
    {
        public UploadLimitEntry Entry { get; set; } = null!;
        public string AppPath { get; set; } = "";
        public string Rate { get; set; } = "";
        public string State { get; set; } = "";
        public string Created { get; set; } = "";
    }

    public UploadLimitListWindow(UploadLimitManager limits)
    {
        _limits = limits;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    private void Refresh()
    {
        var entries = _limits.Entries;
        LimitGrid.ItemsSource = entries.Select(e => new LimitRow
        {
            Entry = e,
            AppPath = e.AppPath,
            Rate = Fmt.Speed(e.BytesPerSecond),
            State = e.Enabled ? "生效中" : "已停用",
            Created = e.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
        }).ToList();
        HintText.Text = _limits.LastError is null
            ? $"共 {entries.Count} 条单程序规则。仅限制上传；这不是多个 exe 共享的严格总上限。修改或取消后请重启目标程序或重新建立连接。"
            : "⚠ " + _limits.LastError;
    }

    private LimitRow? Selected => LimitGrid.SelectedItem as LimitRow;

    private void OnAdd(object sender, RoutedEventArgs e)
    {
        var win = new UploadLimitAddWindow(_limits) { Owner = this };
        if (win.ShowDialog() == true) Refresh();
    }

    private void OnEdit(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        var win = new UploadLimitAddWindow(_limits, editing: row.Entry) { Owner = this };
        if (win.ShowDialog() == true) Refresh();
    }

    private void OnToggle(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        try
        {
            _limits.SetEnabled(row.Entry, !row.Entry.Enabled);
            Refresh();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        if (MessageBox.Show(this, $"确定取消该程序的上传限速？\n\n{row.AppPath}",
                "取消上传限速", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            _limits.Remove(row.Entry);
            Refresh();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
