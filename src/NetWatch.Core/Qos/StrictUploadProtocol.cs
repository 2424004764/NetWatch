using System;
using System.Collections.Generic;

namespace NetWatch.Core.Qos;

public static class StrictUploadProtocol
{
    public const uint Magic = 0x4E575354;
    public const ushort MajorVersion = 1;
    public const ushort MinorVersion = 0;
    public const int MaxGroups = 256;
    public const int MaxMembersPerGroup = 64;
    public const int MaxNameLength = 128;
    public const long MaxBytesPerSecond = 1_250_000_000;
    public const long MaxBurstBytes = 4 * 1024 * 1024;
    public const long MaxQueuedBytes = 16 * 1024 * 1024;
}

public enum StrictUploadErrorCode
{
    None,
    InvalidRequest,
    ProtocolMismatch,
    AccessDenied,
    ServiceUnavailable,
    DriverUnavailable,
    DeviceRemoved,
    UnsupportedCapability,
    Rejected,
    PartialApply,
    Timeout,
    InternalError,
}

public sealed record StrictUploadRequest(
    string Operation,
    string SessionId,
    UploadProcessGroup? Group = null,
    ushort MajorVersion = StrictUploadProtocol.MajorVersion,
    ushort MinorVersion = StrictUploadProtocol.MinorVersion,
    Guid RequestId = default,
    long Generation = 0);

public sealed record StrictUploadResponse<T>(
    bool Ok,
    StrictUploadDriverState State,
    string? Error,
    T? Payload,
    ushort MajorVersion = StrictUploadProtocol.MajorVersion,
    ushort MinorVersion = StrictUploadProtocol.MinorVersion,
    Guid RequestId = default,
    long Generation = 0,
    StrictUploadErrorCode ErrorCode = StrictUploadErrorCode.None,
    int NativeStatus = 0,
    bool Retryable = false);

public sealed record StrictUploadListPayload(IReadOnlyList<UploadProcessGroup> Groups);
public sealed record StrictUploadGroupPayload(UploadProcessGroup? Group);
public sealed record StrictUploadEmptyPayload(bool Completed);

public sealed record StrictUploadDriverCapabilities(
    ushort MajorVersion,
    ushort MinorVersion,
    ulong CapabilityBits,
    int MaxGroups,
    int MaxMembersPerGroup,
    int MaxQueueBytes,
    string DriverVersion);

public sealed record StrictUploadDriverStats(
    string GroupId,
    long Generation,
    long AccountedBytes,
    long QueuedBytes,
    long DroppedBytes,
    long UnmatchedFlows,
    long ActiveFlows,
    long BurstPeakBytes,
    DateTime SampledUtc);
