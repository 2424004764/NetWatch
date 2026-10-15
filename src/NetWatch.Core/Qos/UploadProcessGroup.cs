using System;
using System.Collections.Generic;
using System.Linq;

namespace NetWatch.Core.Qos;

public enum StrictUploadDriverState
{
    Unknown,
    ServiceUnavailable,
    DriverUnavailable,
    ProtocolMismatch,
    AccessDenied,
    DeviceRemoved,
    UnsupportedCapability,
    Rejected,
    PartialApply,
    QueueOverflow,
    Degraded,
    Ready,
    Active,
    Error,
}

/// <summary>多个 exe 共享同一个严格上传令牌桶的进程组定义。</summary>
public sealed record UploadProcessGroup(
    string GroupId,
    string Name,
    IReadOnlyList<string> AppPaths,
    long BytesPerSecond,
    DateTime CreatedUtc,
    bool Enabled,
    StrictUploadDriverState DriverState,
    long AccountedBytes,
    long QueuedBytes)
{
    public long BurstBytes { get; init; } = 64 * 1024;
    public long QueueLimitBytes { get; init; } = 2 * 1024 * 1024;
    public ulong BitsPerSecond => checked((ulong)BytesPerSecond * 8UL);
    public int MemberCount => AppPaths.Count;
    public string StateText => DriverState switch
    {
        StrictUploadDriverState.Ready => Enabled ? "已就绪" : "已停用",
        StrictUploadDriverState.Active => "严格限速中",
        StrictUploadDriverState.ServiceUnavailable => "服务未安装",
        StrictUploadDriverState.DriverUnavailable => "驱动未加载",
        StrictUploadDriverState.ProtocolMismatch => "协议不兼容",
        StrictUploadDriverState.AccessDenied => "访问被拒绝",
        StrictUploadDriverState.DeviceRemoved => "驱动设备已断开",
        StrictUploadDriverState.UnsupportedCapability => "驱动能力不支持",
        StrictUploadDriverState.Rejected => "配置被拒绝",
        StrictUploadDriverState.PartialApply => "部分应用失败",
        StrictUploadDriverState.QueueOverflow => "队列溢出",
        StrictUploadDriverState.Degraded => "降级状态",
        StrictUploadDriverState.Error => "执行错误",
        _ => "检查中",
    };

    public UploadProcessGroup Normalize()
    {
        if (string.IsNullOrWhiteSpace(GroupId) || !Guid.TryParseExact(GroupId, "N", out _))
            throw new InvalidOperationException("进程组标识无效。");
        if (BytesPerSecond <= 0 || BytesPerSecond > StrictUploadProtocol.MaxBytesPerSecond)
            throw new InvalidOperationException("共享上传速率超出允许范围。");
        if (BurstBytes <= 0 || BurstBytes > StrictUploadProtocol.MaxBurstBytes)
            throw new InvalidOperationException("突发容量超出允许范围。");
        if (QueueLimitBytes < 0 || QueueLimitBytes > StrictUploadProtocol.MaxQueuedBytes)
            throw new InvalidOperationException("队列上限超出允许范围。");
        if (string.IsNullOrWhiteSpace(Name) || Name.Trim().Length > StrictUploadProtocol.MaxNameLength)
            throw new InvalidOperationException("进程组名称不能为空且不能超过 128 个字符。");
        if (AppPaths is null || AppPaths.Count == 0 || AppPaths.Count > StrictUploadProtocol.MaxMembersPerGroup)
            throw new InvalidOperationException("进程组成员数量无效。");

        var normalizedPaths = AppPaths
            .Where(static p => !string.IsNullOrWhiteSpace(p))
            .Select(PathNormalizer.NormalizeExistingExe)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (normalizedPaths.Length == 0 || normalizedPaths.Length > StrictUploadProtocol.MaxMembersPerGroup)
            throw new InvalidOperationException("过滤空路径后进程组必须至少包含一个成员，且不能超过成员上限。");

        return this with
        {
            Name = Name.Trim(),
            AppPaths = normalizedPaths,
            DriverState = StrictUploadDriverState.Unknown,
            AccountedBytes = 0,
            QueuedBytes = 0,
        };
    }
}

internal static class PathNormalizer
{
    public static string NormalizeExistingExe(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("程序路径不能为空。", nameof(path));
        var full = System.IO.Path.GetFullPath(path.Trim());
        if (!full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("进程组成员只能是 exe 程序。");
        if (!System.IO.File.Exists(full)) throw new InvalidOperationException($"程序不存在：{full}");
        return full;
    }
}
