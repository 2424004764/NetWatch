using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows;
using NetWatch.Core.Qos;

namespace NetWatch.App;

public partial class StrictUploadGroupAddWindow : Window
{
    private readonly StrictUploadLimitClient _client;
    private readonly UploadProcessGroup? _editing;

    public StrictUploadGroupAddWindow(StrictUploadLimitClient client, UploadProcessGroup? editing = null,
        string? initialPath = null)
    {
        _client = client;
        _editing = editing;
        InitializeComponent();
        if (editing is not null)
        {
            NameBox.Text = editing.Name;
            PathsBox.Text = string.Join(Environment.NewLine, editing.AppPaths);
            RateBox.Text = editing.BytesPerSecond >= 1024 * 1024
                ? (editing.BytesPerSecond / 1024d / 1024d).ToString("0.##", CultureInfo.InvariantCulture)
                : (editing.BytesPerSecond / 1024d).ToString("0.##", CultureInfo.InvariantCulture);
            UnitBox.SelectedIndex = editing.BytesPerSecond >= 1024 * 1024 ? 1 : 0;
            Title = "修改严格上传进程组 — NetWatch";
        }
        else
        {
            NameBox.Text = "新进程组";
            if (!string.IsNullOrWhiteSpace(initialPath)) PathsBox.Text = initialPath;
        }
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择进程组成员 exe",
            Filter = "程序 (*.exe)|*.exe|所有文件 (*.*)|*.*",
            Multiselect = true,
        };
        if (dlg.ShowDialog(this) != true) return;
        var existing = PathsBox.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        foreach (var file in dlg.FileNames)
            if (!existing.Contains(file, StringComparer.OrdinalIgnoreCase)) existing.Add(file);
        PathsBox.Text = string.Join(Environment.NewLine, existing);
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var paths = PathsBox.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim()).Where(p => p.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (paths.Length == 0 || paths.Any(p => !File.Exists(p)))
        {
            MessageBox.Show(this, "请填写至少一个存在的 exe 路径，每行一个。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!double.TryParse(RateBox.Text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var rate) || rate <= 0)
        {
            MessageBox.Show(this, "请输入大于 0 的共享上传速度。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var multiplier = UnitBox.SelectedIndex == 1 ? 1024d * 1024d : 1024d;
        var bytes = rate * multiplier;
        if (bytes > long.MaxValue || bytes < 1)
        {
            MessageBox.Show(this, "共享上传速度超出可用范围。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        try
        {
            var value = checked((long)Math.Round(bytes));
            if (_editing is null)
                _client.Create(NameBox.Text.Trim(), paths, value);
            else
                _client.Update(_editing with
                {
                    Name = NameBox.Text.Trim(),
                    AppPaths = paths,
                    BytesPerSecond = value,
                });
            DialogResult = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "设置严格限速失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
