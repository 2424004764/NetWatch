using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace NetWatch.Core.Qos;

/// <summary>StrictService 到 NetWatchStrict 控制设备的最小 IOCTL 客户端。</summary>
public sealed class StrictDriverDeviceClient : IDisposable
{
    public const string DevicePath = @"\\.\NetWatchStrict";
    private SafeFileHandle? _handle;

    public StrictUploadDriverState State { get; private set; } = StrictUploadDriverState.DriverUnavailable;
    public string? LastError { get; private set; }
    public StrictUploadDriverCapabilities? Capabilities { get; private set; }
    public bool HasShapingCapability => State is StrictUploadDriverState.Ready or StrictUploadDriverState.Active
        && Capabilities is { } capabilities
        && (capabilities.CapabilityBits & StrictDriverAbi.RequiredShapingCapabilities)
            == StrictDriverAbi.RequiredShapingCapabilities
        && LastError is null;

    public bool TryConnect()
    {
        Close();
        _handle = CreateFile(DevicePath, 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (_handle.IsInvalid)
        {
            SetError(Marshal.GetLastWin32Error(), StrictUploadDriverState.DriverUnavailable);
            return false;
        }

        var request = NewHeader(1, 64);
        var response = new StrictDriverHelloResponse();
        if (!Ioctl(StrictDriverAbi.HelloIoctl, request, ref response, out var error))
        {
            SetError(error, StrictUploadDriverState.DeviceRemoved);
            Close();
            return false;
        }
        if (response.Header.Magic != StrictDriverAbi.Magic || response.Header.MajorVersion != StrictDriverAbi.MajorVersion
            || response.Header.RequestId != request.RequestId || response.Header.SessionId != request.SessionId
            || response.Header.Command != (uint)StrictDriverCommand.Hello)
        {
            SetError(0, StrictUploadDriverState.ProtocolMismatch);
            Close();
            return false;
        }

        Capabilities = new StrictUploadDriverCapabilities(
            response.Header.MajorVersion, response.Header.MinorVersion, response.CapabilityBits,
            checked((int)response.MaxGroups), checked((int)response.MaxMembersPerGroup),
            checked((int)response.MaxQueueBytes), response.DriverBuild.ToString());
        State = (response.CapabilityBits & StrictDriverAbi.RequiredShapingCapabilities)
                == StrictDriverAbi.RequiredShapingCapabilities
            ? (response.NativeStatus == 0 ? StrictUploadDriverState.Ready : StrictUploadDriverState.Degraded)
            : StrictUploadDriverState.UnsupportedCapability;
        LastError = State == StrictUploadDriverState.UnsupportedCapability
            ? "驱动仅提供控制设备探测，未实现严格流量整形能力。"
            : response.NativeStatus == 0 ? null : $"驱动返回状态 0x{response.NativeStatus:X8}。";
        return true;
    }

    public bool Ping()
    {
        if (_handle is null || _handle.IsInvalid) return false;
        var request = NewHeader(5, 64);
        var response = new StrictDriverMessageHeader();
        if (!Ioctl(StrictDriverAbi.PingIoctl, request, ref response, out var error))
        {
            SetError(error, StrictUploadDriverState.DeviceRemoved);
            return false;
        }
        return true;
    }

    public IReadOnlyList<StrictUploadDriverStats> QueryStats(Guid sessionId, long generation)
    {
        if (sessionId == Guid.Empty || generation <= 0) throw new ArgumentOutOfRangeException(nameof(sessionId));
        if (_handle is null || _handle.IsInvalid) throw new InvalidOperationException("严格限速驱动设备不可用。");
        var request = NewHeader((uint)StrictDriverCommand.QueryStats, (uint)StrictDriverAbiLayout.HeaderSize);
        request.SessionId = sessionId;
        request.Generation = generation;
        var input = Marshal.AllocHGlobal(StrictDriverAbiLayout.HeaderSize);
        var outputCapacity = StrictDriverAbiLayout.StatsResponseHeaderSize
            + StrictUploadProtocol.MaxGroups * StrictDriverAbiLayout.GroupStatsSize;
        var output = Marshal.AllocHGlobal(outputCapacity);
        try
        {
            Marshal.StructureToPtr(request, input, false);
            if (!DeviceIoControl(_handle, StrictDriverAbi.QueryStatsIoctl, input, StrictDriverAbiLayout.HeaderSize,
                    output, outputCapacity, out var returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "查询严格限速驱动统计失败。");
            if (returned < StrictDriverAbiLayout.StatsResponseHeaderSize)
                throw new InvalidOperationException("驱动统计响应头长度不足。");
            var response = Marshal.PtrToStructure<StrictDriverStatsResponseHeader>(output);
            if (response.Header.Magic != StrictDriverAbi.Magic
                || response.Header.MajorVersion != StrictDriverAbi.MajorVersion
                || response.Header.Command != (uint)StrictDriverCommand.QueryStats
                || response.Header.RequestId != request.RequestId
                || response.Header.SessionId != sessionId
                || response.Header.Generation != generation
                || response.Header.TotalSize != returned
                || response.EntrySize != StrictDriverAbiLayout.GroupStatsSize
                || response.GroupCount > StrictUploadProtocol.MaxGroups
                || returned != StrictDriverAbiLayout.StatsResponseHeaderSize
                    + response.GroupCount * StrictDriverAbiLayout.GroupStatsSize)
                throw new InvalidOperationException("驱动统计响应与请求不匹配或布局无效。");

            var result = new StrictUploadDriverStats[response.GroupCount];
            for (var i = 0; i < result.Length; i++)
            {
                var offset = IntPtr.Add(output, StrictDriverAbiLayout.StatsResponseHeaderSize
                    + i * StrictDriverAbiLayout.GroupStatsSize);
                var stats = Marshal.PtrToStructure<StrictDriverGroupStats>(offset);
                if (stats.Generation != generation)
                    throw new InvalidOperationException("驱动统计 generation 与活动组表不匹配。");
                result[i] = new StrictUploadDriverStats(stats.GroupId.ToString("N"), stats.Generation,
                    stats.AccountedBytes, stats.QueuedBytes, stats.DroppedBytes, stats.UnmatchedFlows,
                    stats.ActiveFlows, stats.BurstPeakBytes, DateTime.UtcNow);
            }
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(input);
            Marshal.FreeHGlobal(output);
        }
    }

    public bool RemoveSession(Guid sessionId, long generation)
    {
        if (sessionId == Guid.Empty || generation <= 0) throw new ArgumentOutOfRangeException(nameof(sessionId));
        if (_handle is null || _handle.IsInvalid) return false;
        var request = NewHeader((uint)StrictDriverCommand.RemoveSession, (uint)StrictDriverAbiLayout.HeaderSize);
        request.SessionId = sessionId;
        request.Generation = generation;
        var response = new StrictDriverMessageHeader();
        if (!Ioctl(StrictDriverAbi.RemoveSessionIoctl, request, ref response, out var error))
        {
            SetError(error, StrictUploadDriverState.DeviceRemoved);
            return false;
        }
        return response.Magic == StrictDriverAbi.Magic
            && response.MajorVersion == StrictDriverAbi.MajorVersion
            && response.HeaderSize == StrictDriverAbiLayout.HeaderSize
            && response.TotalSize == StrictDriverAbiLayout.HeaderSize
            && response.Command == (uint)StrictDriverCommand.RemoveSession
            && response.SessionId == sessionId
            && response.Generation == generation
            && response.RequestId == request.RequestId;
    }

    public bool ApplySnapshot(Guid sessionId, long generation, IReadOnlyList<StrictDriverGroupInput> groups)
    {
        if (!HasShapingCapability || _handle is null || _handle.IsInvalid)
        {
            State = StrictUploadDriverState.UnsupportedCapability;
            LastError = "驱动未声明完整的数据面能力，拒绝提交组表。";
            return false;
        }

        var payload = StrictDriverAbi.EncodeSnapshot(sessionId, generation, groups);
        var input = Marshal.AllocHGlobal(payload.Length);
        var output = Marshal.AllocHGlobal(StrictDriverAbiLayout.HeaderSize);
        try
        {
            Marshal.Copy(payload, 0, input, payload.Length);
            if (!DeviceIoControl(_handle, StrictDriverAbi.ApplySnapshotIoctl, input, payload.Length,
                    output, StrictDriverAbiLayout.HeaderSize, out var returned, IntPtr.Zero))
            {
                SetError(Marshal.GetLastWin32Error(), StrictUploadDriverState.Rejected);
                return false;
            }
            if (returned < StrictDriverAbiLayout.HeaderSize)
            {
                State = StrictUploadDriverState.ProtocolMismatch;
                LastError = "驱动返回的快照确认结构长度不足。";
                return false;
            }
            var response = Marshal.PtrToStructure<StrictDriverMessageHeader>(output);
            if (response.Magic != StrictDriverAbi.Magic
                || response.MajorVersion != StrictDriverAbi.MajorVersion
                || response.MinorVersion != StrictDriverAbi.MinorVersion
                || response.HeaderSize != StrictDriverAbiLayout.HeaderSize
                || response.TotalSize != StrictDriverAbiLayout.HeaderSize
                || response.Command != (uint)StrictDriverCommand.ApplySnapshot
                || response.RequestId == Guid.Empty
                || response.SessionId != sessionId
                || response.Generation != generation)
            {
                State = StrictUploadDriverState.ProtocolMismatch;
                LastError = "驱动快照确认与请求不匹配。";
                return false;
            }
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(input);
            Marshal.FreeHGlobal(output);
        }
    }

    public static byte[] ResolveAppId(string exePath)
    {
        var status = FwpmGetAppIdFromFileName(exePath, out var appId);
        if (status != 0) throw new Win32Exception(unchecked((int)status), $"无法为程序获取 WFP AppId：{exePath}");
        try
        {
            if (appId == IntPtr.Zero) throw new InvalidOperationException("WFP 返回空 AppId。");
            var size = Marshal.ReadInt32(appId);
            if (size <= 0 || size > 4096) throw new InvalidOperationException("WFP AppId 长度超出协议限制。");
            var data = Marshal.ReadIntPtr(appId, IntPtr.Size == 8 ? 8 : 4);
            if (data == IntPtr.Zero) throw new InvalidOperationException("WFP 返回空 AppId 数据指针。");
            var value = new byte[size];
            Marshal.Copy(data, value, 0, size);
            return value;
        }
        finally
        {
            FwpmFreeMemory(ref appId);
        }
    }

    private bool Ioctl<TIn, TOut>(uint code, TIn input, ref TOut output, out int error)
        where TIn : struct where TOut : struct
    {
        error = 0;
        var inputSize = Marshal.SizeOf<TIn>();
        var outputSize = Marshal.SizeOf<TOut>();
        var inputPtr = Marshal.AllocHGlobal(inputSize);
        var outputPtr = Marshal.AllocHGlobal(outputSize);
        try
        {
            Marshal.StructureToPtr(input, inputPtr, false);
            if (!DeviceIoControl(_handle!, code, inputPtr, inputSize, outputPtr, outputSize,
                    out _, IntPtr.Zero))
            {
                error = Marshal.GetLastWin32Error();
                return false;
            }
            output = Marshal.PtrToStructure<TOut>(outputPtr);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(inputPtr);
            Marshal.FreeHGlobal(outputPtr);
        }
    }

    private static StrictDriverMessageHeader NewHeader(uint command, uint totalSize)
        => new()
        {
            Magic = StrictDriverAbi.Magic,
            MajorVersion = StrictDriverAbi.MajorVersion,
            MinorVersion = StrictDriverAbi.MinorVersion,
            HeaderSize = (uint)StrictDriverAbiLayout.HeaderSize,
            TotalSize = totalSize,
            Command = command,
            RequestId = Guid.NewGuid(),
            SessionId = Guid.NewGuid(),
            Generation = 1,
        };

    private void SetError(int nativeError, StrictUploadDriverState state)
    {
        State = state;
        LastError = nativeError == 0 ? "严格限速驱动设备不可用。" :
            new Win32Exception(nativeError).Message;
    }

    public void Close()
    {
        _handle?.Dispose();
        _handle = null;
        Capabilities = null;
    }

    public void Dispose() => Close();

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmGetAppIdFromFileName0", CharSet = CharSet.Unicode)]
    private static extern uint FwpmGetAppIdFromFileName(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    private static extern void FwpmFreeMemory(ref IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code,
        IntPtr input, int inputSize, IntPtr output, int outputSize,
        out int returned, IntPtr overlapped);
}
