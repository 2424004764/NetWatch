using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Windows.Media;
using NetWatch.Core;

namespace NetWatch.App;

/// <summary>一次刷新周期内，同一个应用程序（可能多个进程）的聚合流量。</summary>
public sealed class AppAgg
{
    public double DeltaUp, DeltaDown;
    public long TotalUp, TotalDown;
    public readonly HashSet<int> Pids = new();
    public string Name = "";
    public string SubTitle = "";
    public string? Path;
    public bool HasDead;
}

/// <summary>列表中的一行：一个应用程序的实时速率与累计流量。</summary>
public sealed class AppRow : INotifyPropertyChanged
{
    private double _upSpeed, _downSpeed;
    private long _totalUp, _totalDown;
    private int _connCount;
    private string _subTitle;

    public string Key { get; }
    public string Name { get; }
    public string? Path { get; }
    public HashSet<int> Pids { get; } = new();
    private ImageSource? _icon;
    public ImageSource? Icon
    {
        get => _icon;
        set
        {
            if (_icon == value) return;
            _icon = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Icon)));
        }
    }
    public DateTime LastUpdatedUtc { get; private set; } = DateTime.UtcNow;
    /// <summary>排序权重：当前总速率（越大越靠前）。</summary>
    public double SortScore => _upSpeed + _downSpeed;

    public AppRow(string key, string name, string subTitle, ImageSource? icon, string? path)
    {
        Key = key;
        Name = name;
        _subTitle = subTitle;
        Icon = icon;
        Path = path;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string SubTitle => _subTitle;
    public string UpSpeedText => Fmt.Speed(_upSpeed);
    public string DownSpeedText => Fmt.Speed(_downSpeed);
    public string TotalUpText => Fmt.Bytes(_totalUp);
    public string TotalDownText => Fmt.Bytes(_totalDown);
    public string ConnText => _connCount == 0 ? "—" : _connCount.ToString();
    public string ToolTipText => Path ?? Name;

    public void Apply(AppAgg agg, IReadOnlyDictionary<int, int> connByPid, double elapsedSeconds, DateTime nowUtc)
    {
        foreach (var pid in agg.Pids) Pids.Add(pid);
        // 指数平滑，避免数值抖动
        _upSpeed = 0.5 * (agg.DeltaUp / elapsedSeconds) + 0.5 * _upSpeed;
        _downSpeed = 0.5 * (agg.DeltaDown / elapsedSeconds) + 0.5 * _downSpeed;
        _totalUp = agg.TotalUp;
        _totalDown = agg.TotalDown;

        int n = 0;
        foreach (var pid in Pids)
            if (connByPid.TryGetValue(pid, out var c)) n += c;
        _connCount = n;

        _subTitle = agg.SubTitle;
        LastUpdatedUtc = nowUtc;

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SubTitle)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UpSpeedText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DownSpeedText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(TotalUpText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(TotalDownText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ConnText)));
    }
}
