using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using NetWatch.Core.Wfp;

namespace NetWatch.App;

public partial class BlockAddWindow : Window
{
    private readonly BlockManager _blocks;
    public BlockEntry? ResultEntry { get; private set; }
    private bool _remoteTouched;

    public BlockAddWindow(BlockManager blocks)
    {
        _blocks = blocks;
        InitializeComponent();
    }

    private void RemoteBox_GotFocus(object sender, RoutedEventArgs e)
    {
        if (!_remoteTouched)
        {
            RemoteBox.SelectAll();
            _remoteTouched = true;
        }
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择要限制的程序",
            Filter = "程序 (*.exe)|*.exe|所有文件 (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true)
            AppBox.Text = dlg.FileName;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var remote = RemoteBox.Text.Trim();
        var app = AppBox.Text.Trim();
        if (remote.Length == 0)
        {
            MessageBox.Show(this, "请填写要屏蔽的 IP 或网段。", "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            ResultEntry = _blocks.Add(remote, app.Length == 0 ? null : app);
            DialogResult = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "添加失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
