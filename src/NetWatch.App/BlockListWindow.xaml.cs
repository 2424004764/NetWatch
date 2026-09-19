using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using NetWatch.Core.Wfp;

namespace NetWatch.App;

public partial class BlockListWindow : Window
{
    private readonly BlockManager _blocks;

    private sealed class BlockRow
    {
        public BlockEntry Entry = null!;
        public string Remote = "";
        public string Scope = "";
        public string State = "";
        public string Created = "";
    }

    public BlockListWindow(BlockManager blocks)
    {
        _blocks = blocks;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    private void Refresh()
    {
        var rows = new List<BlockRow>();
        foreach (var e in _blocks.Entries)
        {
            rows.Add(new BlockRow
            {
                Entry = e,
                Remote = e.Remote,
                Scope = e.AppPath ?? "所有程序",
                State = e.Enabled ? "生效中" : "已停用",
                Created = e.CreatedUtc.ToString("yyyy-MM-dd HH:mm"),
            });
        }
        BlockGrid.ItemsSource = rows;
        HintText.Text = _blocks.EngineError is null
            ? $"共 {rows.Count} 条规则。屏蔽 = 禁止指定程序（或全部程序）与目标 IP / 网段建立新的出站连接。"
            : "⚠ " + _blocks.EngineError;
    }

    private void OnAdd(object sender, RoutedEventArgs e)
    {
        var win = new BlockAddWindow(_blocks) { Owner = this };
        if (win.ShowDialog() == true && win.ResultEntry != null)
            Refresh();
    }

    private void OnToggle(object sender, RoutedEventArgs e)
    {
        if (BlockGrid.SelectedItem is not BlockRow row) return;
        try
        {
            _blocks.SetEnabled(row.Entry, !row.Entry.Enabled);
            Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (BlockGrid.SelectedItem is not BlockRow row) return;
        if (MessageBox.Show(this, $"确定删除屏蔽规则？\n\n{row.Remote}（{row.Scope}）",
                "删除规则", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            _blocks.Remove(row.Entry);
            Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
