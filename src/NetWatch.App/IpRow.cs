using System;
using System.ComponentModel;
using NetWatch.Core;

namespace NetWatch.App;

/// <summary>目标 IP 视图中的一行：某个远程 IP 的实时速率、累计流量与通信应用。</summary>
public sealed class IpRow : INotifyPropertyChanged
{
    private double _upSpeed, _downSpeed;
    private long _totalUp, _totalDown;
    private string _apps = "";
    private int _conns;
    private bool _blocked;

    public string Ip { get; }
    public DateTime LastUpdatedUtc { get; private set; } = DateTime.UtcNow;
    public double SortScore => _upSpeed + _downSpeed;

    public IpRow(string ip) => Ip = ip;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string IpText => _blocked ? Ip + "   ⛔ 已屏蔽" : Ip;
    public string UpSpeedText => Fmt.Speed(_upSpeed);
    public string DownSpeedText => Fmt.Speed(_downSpeed);
    public string TotalUpText => Fmt.Bytes(_totalUp);
    public string TotalDownText => Fmt.Bytes(_totalDown);
    public string AppsText => _apps;
    public string ConnText => _conns == 0 ? "—" : _conns.ToString();
    public string ToolTipText => Ip + (_blocked ? "（已屏蔽）" : "");

    public void Apply(double deltaUp, double deltaDown, long totalUp, long totalDown,
        string apps, int conns, bool blocked, double elapsedSeconds, DateTime nowUtc)
    {
        _upSpeed = 0.5 * (deltaUp / elapsedSeconds) + 0.5 * _upSpeed;
        _downSpeed = 0.5 * (deltaDown / elapsedSeconds) + 0.5 * _downSpeed;
        _totalUp = totalUp;
        _totalDown = totalDown;
        _apps = apps;
        _conns = conns;
        _blocked = blocked;
        LastUpdatedUtc = nowUtc;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IpText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(UpSpeedText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DownSpeedText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(TotalUpText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(TotalDownText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(AppsText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ToolTipText)));
    }
}
