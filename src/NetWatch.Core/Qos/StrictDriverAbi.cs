using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NetWatch.Core.Qos;

public enum StrictDriverCommand : uint
{
    Hello = 1,
    ApplySnapshot = 2,
    RemoveSession = 3,
    QueryStats = 4,
    Ping = 5,
}

public static class StrictDriverAbi
{
    public const uint Magic = StrictUploadProtocol.Magic;
    public const ushort MajorVersion = StrictUploadProtocol.MajorVersion;
    public const ushort MinorVersion = StrictUploadProtocol.MinorVersion;
    public const uint DeviceType = 0x8337;
    public const uint FileReadAccess = 1;
    public const uint FileWriteAccess = 2;
    public const uint MethodBuffered = 0;
    public const ulong CapabilityStrictShaping = 1UL << 0;
    public const ulong CapabilityAsyncQueue = 1UL << 1;
    public const ulong CapabilityTransportReinject = 1UL << 2;
    public const ulong CapabilityTeardownSafe = 1UL << 3;
    public const ulong CapabilityLiveStats = 1UL << 4;
    public const ulong RequiredShapingCapabilities = CapabilityStrictShaping
        | CapabilityAsyncQueue | CapabilityTransportReinject | CapabilityTeardownSafe | CapabilityLiveStats;

    public static uint Ioctl(StrictDriverCommand command, uint access)
        => (DeviceType << 16) | (access << 14) | ((uint)command << 2) | MethodBuffered;

    public static uint HelloIoctl => Ioctl(StrictDriverCommand.Hello, FileReadAccess);
    public static uint ApplySnapshotIoctl => Ioctl(StrictDriverCommand.ApplySnapshot, FileWriteAccess);
    public static uint RemoveSessionIoctl => Ioctl(StrictDriverCommand.RemoveSession, FileWriteAccess);
    public static uint QueryStatsIoctl => Ioctl(StrictDriverCommand.QueryStats, FileReadAccess);
    public static uint PingIoctl => Ioctl(StrictDriverCommand.Ping, FileReadAccess);

    public static byte[] EncodeSnapshot(Guid sessionId, long generation, IReadOnlyList<StrictDriverGroupInput> groups)
    {
        if (sessionId == Guid.Empty) throw new ArgumentException("Session ID must not be empty.", nameof(sessionId));
        if (generation <= 0) throw new ArgumentOutOfRangeException(nameof(generation));
        if (groups.Count > StrictUploadProtocol.MaxGroups) throw new ArgumentOutOfRangeException(nameof(groups));

        var encoded = new List<(StrictDriverGroupInput Group, byte[] AppIds)>();
        foreach (var group in groups)
        {
            if (group.GroupId == Guid.Empty || group.AppIds.Count == 0
                || group.AppIds.Count > StrictUploadProtocol.MaxMembersPerGroup
                || group.BytesPerSecond <= 0 || group.BytesPerSecond > StrictUploadProtocol.MaxBytesPerSecond
                || group.BurstBytes <= 0 || group.BurstBytes > StrictUploadProtocol.MaxBurstBytes
                || group.QueueLimitBytes < 0 || group.QueueLimitBytes > StrictUploadProtocol.MaxQueuedBytes)
                throw new ArgumentOutOfRangeException(nameof(groups), "Snapshot group is outside ABI bounds.");
            using var appIdStream = new MemoryStream();
            using var writer = new BinaryWriter(appIdStream, Encoding.UTF8, leaveOpen: true);
            foreach (var appId in group.AppIds)
            {
                if (appId.Length is 0 or > 4096) throw new ArgumentOutOfRangeException(nameof(groups));
                writer.Write(checked((uint)appId.Length));
                writer.Write(appId);
            }
            if (appIdStream.Length > 64 * 1024) throw new ArgumentOutOfRangeException(nameof(groups));
            encoded.Add((group, appIdStream.ToArray()));
        }

        var totalSize = checked(Marshal.SizeOf<StrictDriverSnapshotHeader>()
            + encoded.Sum(entry => Marshal.SizeOf<StrictDriverGroupEntryHeader>() + entry.AppIds.Length));
        if (totalSize > 4 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(groups));
        using var stream = new MemoryStream(totalSize);
        using var output = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        var header = new StrictDriverMessageHeader
        {
            Magic = Magic,
            MajorVersion = MajorVersion,
            MinorVersion = MinorVersion,
            HeaderSize = (uint)Marshal.SizeOf<StrictDriverMessageHeader>(),
            TotalSize = (uint)totalSize,
            Command = (uint)StrictDriverCommand.ApplySnapshot,
            RequestId = Guid.NewGuid(),
            SessionId = sessionId,
            Generation = generation,
        };
        WriteHeader(output, header);
        output.Write((uint)encoded.Count);
        output.Write((uint)Marshal.SizeOf<StrictDriverGroupEntryHeader>());
        foreach (var entry in encoded)
        {
            output.Write(entry.Group.GroupId.ToByteArray());
            output.Write((uint)entry.Group.AppIds.Count);
            output.Write((uint)entry.AppIds.Length);
            output.Write(entry.Group.BytesPerSecond);
            output.Write(entry.Group.BurstBytes);
            output.Write(entry.Group.QueueLimitBytes);
            output.Write(entry.AppIds);
        }
        return stream.ToArray();
    }

    private static void WriteHeader(BinaryWriter writer, StrictDriverMessageHeader header)
    {
        writer.Write(header.Magic);
        writer.Write(header.MajorVersion);
        writer.Write(header.MinorVersion);
        writer.Write(header.HeaderSize);
        writer.Write(header.TotalSize);
        writer.Write(header.Command);
        writer.Write(header.Flags);
        writer.Write(header.RequestId.ToByteArray());
        writer.Write(header.SessionId.ToByteArray());
        writer.Write(header.Generation);
    }
}

public sealed record StrictDriverGroupInput(
    Guid GroupId,
    IReadOnlyList<byte[]> AppIds,
    long BytesPerSecond,
    long BurstBytes,
    long QueueLimitBytes);

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct StrictDriverMessageHeader
{
    public uint Magic;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint HeaderSize;
    public uint TotalSize;
    public uint Command;
    public uint Flags;
    public Guid RequestId;
    public Guid SessionId;
    public long Generation;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct StrictDriverHelloResponse
{
    public StrictDriverMessageHeader Header;
    public ulong CapabilityBits;
    public uint MaxGroups;
    public uint MaxMembersPerGroup;
    public uint MaxQueueBytes;
    public uint DriverBuild;
    public int NativeStatus;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct StrictDriverSnapshotHeader
{
    public StrictDriverMessageHeader Header;
    public uint GroupCount;
    public uint EntrySize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct StrictDriverGroupEntryHeader
{
    public Guid GroupId;
    public uint MemberCount;
    public uint AppIdBytes;
    public long BytesPerSecond;
    public long BurstBytes;
    public long QueueLimitBytes;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct StrictDriverStatsResponseHeader
{
    public StrictDriverMessageHeader Header;
    public uint GroupCount;
    public uint EntrySize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct StrictDriverGroupStats
{
    public Guid GroupId;
    public long Generation;
    public long AccountedBytes;
    public long QueuedBytes;
    public long DroppedBytes;
    public long UnmatchedFlows;
    public long ActiveFlows;
    public long BurstPeakBytes;
}

public static class StrictDriverAbiLayout
{
    public static int HeaderSize => Marshal.SizeOf<StrictDriverMessageHeader>();
    public static int HelloResponseSize => Marshal.SizeOf<StrictDriverHelloResponse>();
    public static int SnapshotHeaderSize => Marshal.SizeOf<StrictDriverSnapshotHeader>();
    public static int GroupEntryHeaderSize => Marshal.SizeOf<StrictDriverGroupEntryHeader>();
    public static int StatsResponseHeaderSize => Marshal.SizeOf<StrictDriverStatsResponseHeader>();
    public static int GroupStatsSize => Marshal.SizeOf<StrictDriverGroupStats>();
}
