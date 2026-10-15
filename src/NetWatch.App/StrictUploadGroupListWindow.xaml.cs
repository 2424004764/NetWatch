using System;
using System.Linq;
using System.Windows;
using NetWatch.Core;
using NetWatch.Core.Qos;

namespace NetWatch.App;

public partial class StrictUploadGroupListWindow : Window
{
    private readonly StrictUploadLimitClient _client;

    private sealed class GroupRow
    {
        public UploadProcessGroup Group { get; init; } = null!;
        public string Name => Group.Name;
        public string Members => string.Join("; ", Group.AppPaths);
        public string Rate => Fmt.Speed(Group.BytesPerSecond);
        public string State => Group.StateText;
        public string Accounted => Fmt.Bytes(Group.AccountedBytes);
        public string Queued => Fmt.Bytes(Group.QueuedBytes);
    }

    public StrictUploadGroupListWindow(StrictUploadLimitClient client)
    {
        _client = client;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    private GroupRow? Selected => GroupGrid.SelectedItem as GroupRow;

    private void Refresh()
    {
        try
        {
            var groups = _client.List();
            GroupGrid.ItemsSource = groups.Select(g => new GroupRow { Group = g }).ToList();
            StatusText.Text = _client.State switch
            {
                StrictUploadDriverState.DriverUnavailable => "⚠ 严格限速驱动未加载。当前不会创建或保存活动规则，也不会限制流量。",
                StrictUploadDriverState.ServiceUnavailable => "⚠ 严格限速服务未安装或未启动。",
                StrictUploadDriverState.ProtocolMismatch => "⚠ 严格限速服务协议版本不兼容。",
                StrictUploadDriverState.AccessDenied => "⚠ 访问严格限速服务被拒绝。",
                StrictUploadDriverState.UnsupportedCapability => "⚠ 驱动未实现严格流量整形；组仅为未启用配置。",
                StrictUploadDriverState.Degraded => "⚠ 驱动处于降级状态，严格限速不可用。",
                _ => $"共 {groups.Count} 个未启用进程组配置。严格限速数据面尚未确认。",
            };
        }
        catch (Exception ex)
        {
            GroupGrid.ItemsSource = null;
            StatusText.Text = "⚠ " + ex.Message;
        }
    }

    private void OnAdd(object sender, RoutedEventArgs e)
    {
        var win = new StrictUploadGroupAddWindow(_client) { Owner = this };
        if (win.ShowDialog() == true) Refresh();
    }

    private void OnEdit(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        var win = new StrictUploadGroupAddWindow(_client, row.Group) { Owner = this };
        if (win.ShowDialog() == true) Refresh();
    }

    private void OnToggle(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        try
        {
            _client.SetEnabled(row.Group, !row.Group.Enabled);
            Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "严格上传限速", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        if (MessageBox.Show(this, $"确定删除进程组“{row.Group.Name}”？\n\n{row.Members}",
                "删除严格上传进程组", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try { _client.Remove(row.Group); Refresh(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "严格上传限速", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Refresh();
    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
