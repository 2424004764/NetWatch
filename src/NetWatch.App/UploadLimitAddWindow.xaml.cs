using System;
using System.Globalization;
using System.IO;
using System.Windows;
using NetWatch.Core.Qos;

namespace NetWatch.App;

public partial class UploadLimitAddWindow : Window
{
    private readonly UploadLimitManager _limits;
    private readonly UploadLimitEntry? _editing;
    public UploadLimitEntry? ResultEntry { get; private set; }

    public UploadLimitAddWindow(UploadLimitManager limits, string? appPath = null, UploadLimitEntry? editing = null)
    {
        _limits = limits;
        _editing = editing;
        InitializeComponent();
        if (editing is not null)
        {
            AppBox.Text = editing.AppPath;
            RateBox.Text = editing.BytesPerSecond >= 1024 * 1024
                ? (editing.BytesPerSecond / 1024d / 1024d).ToString("0.##", CultureInfo.InvariantCulture)
                : (editing.BytesPerSecond / 1024d).ToString("0.##", CultureInfo.InvariantCulture);
            UnitBox.SelectedIndex = editing.BytesPerSecond >= 1024 * 1024 ? 1 : 0;
            Title = "修改上传限速 — NetWatch";
        }
        else if (!string.IsNullOrWhiteSpace(appPath))
        {
            AppBox.Text = appPath;
        }
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择要限速的程序",
            Filter = "程序 (*.exe)|*.exe|所有文件 (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true) AppBox.Text = dlg.FileName;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var path = AppBox.Text.Trim();
        if (path.Length == 0 || !File.Exists(path))
        {
            MessageBox.Show(this, "请选择存在的 exe 程序。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!double.TryParse(RateBox.Text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var rate) || rate <= 0)
        {
            MessageBox.Show(this, "请输入大于 0 的上传速度。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var multiplier = UnitBox.SelectedIndex == 1 ? 1024d * 1024d : 1024d;
        var bytes = rate * multiplier;
        if (bytes > long.MaxValue || bytes < 1)
        {
            MessageBox.Show(this, "上传速度超出可用范围。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        try
        {
            var value = checked((long)Math.Round(bytes));
            if (_editing is null) ResultEntry = _limits.Add(path, value);
            else
            {
                _limits.Update(_editing, value);
                ResultEntry = _editing with { BytesPerSecond = value };
            }
            DialogResult = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "设置限速失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
