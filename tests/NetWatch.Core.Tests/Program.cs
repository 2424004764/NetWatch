using NetWatch.Core.Qos;
using NetWatch.Core.Wfp;
using System.Runtime.InteropServices;

var tests = new (string Name, Action Run)[]
{
    ("shared bucket enforces aggregate burst", SharedAggregateBurst),
    ("tokens refill at configured rate", RefillRate),
    ("fractional time slices preserve refill remainder", FractionalRefillRemainder),
    ("concurrent members share one aggregate burst", ConcurrentSharedBurst),
    ("queue remains bounded and counts drops", BoundedQueue),
    ("driver ABI ioctl codes and layouts are stable", AbiLayout),
    ("WFP management ABI structures match x64 layout", WfpInteropLayout),
    ("snapshot encoding preserves group members and generation", SnapshotEncoding),
    ("snapshot encoding rejects invalid ABI inputs", SnapshotBounds),
    ("group validation rejects invalid rates and bounds", GroupBounds),
    ("driver capability gate requires the complete data plane", CapabilityGate),
};

var failed = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.Error.WriteLine($"FAIL {test.Name}: {ex.Message}");
    }
}

Console.WriteLine($"{tests.Length - failed}/{tests.Length} tests passed.");
return failed == 0 ? 0 : 1;

static void SharedAggregateBurst()
{
    var bucket = new SharedTokenBucket(100, 100, 1000, 1000);
    Assert(bucket.TryConsume(60, 0), "first member should consume from shared burst");
    Assert(bucket.TryConsume(40, 0), "second member should consume remaining shared burst");
    Assert(!bucket.TryConsume(1, 0), "members must not each receive a private burst");
    Assert(bucket.Snapshot().AccountedBytes == 100, "accounted bytes must be aggregate");
}

static void RefillRate()
{
    var bucket = new SharedTokenBucket(200, 200, 1000, 1000);
    Assert(bucket.TryConsume(200, 0), "initial burst should be available");
    Assert(!bucket.TryConsume(1, 0), "empty bucket should reject immediate send");
    Assert(bucket.TryConsume(100, 500), "half a second should refill 100 bytes");
    Assert(!bucket.TryConsume(1, 500), "consumed refill should not be duplicated");
}

static void FractionalRefillRemainder()
{
    var bucket = new SharedTokenBucket(1, 1, 0, 10_000_000);
    Assert(bucket.TryConsume(1, 0), "initial token should be available");
    for (var tick = 1; tick <= 10_000_000; tick++) bucket.TryConsume(1, tick);
    Assert(bucket.Snapshot().AvailableTokens > 0.99, "fractional refills must accumulate instead of being discarded");
    Assert(bucket.TryConsume(1, 10_010_000), "accumulated fractional refill should eventually become consumable");
    Assert(bucket.Snapshot().AccountedBytes == 2, "one second at one byte per second should replenish one byte");
}

static void ConcurrentSharedBurst()
{
    var bucket = new SharedTokenBucket(10_000, 512, 0, 1_000_000);
    var accepted = 0;
    Parallel.For(0, 64, _ =>
    {
        if (bucket.TryConsume(16, 0)) Interlocked.Increment(ref accepted);
    });
    Assert(accepted == 32, "all concurrent consumers must share the one aggregate burst");
    Assert(bucket.Snapshot().AccountedBytes == 512, "concurrent accounted bytes must equal the shared burst");
}

static void BoundedQueue()
{
    var bucket = new SharedTokenBucket(100, 100, 128, 1000);
    Assert(bucket.TryEnqueue(80), "first queued chunk should fit");
    Assert(!bucket.TryEnqueue(64), "queue must reject data beyond limit");
    var snapshot = bucket.Snapshot();
    Assert(snapshot.QueuedBytes == 80, "queue size must remain bounded");
    Assert(snapshot.DroppedBytes == 64, "overflow bytes must be counted");
    Assert(bucket.DequeueUpTo(32) == 32, "dequeue should return available bytes");
    Assert(bucket.Snapshot().QueuedBytes == 48, "dequeue must reduce queue size");
}

static void AbiLayout()
{
    Assert(StrictDriverAbi.HelloIoctl == 0x83374004, "hello IOCTL value changed");
    Assert(StrictDriverAbi.ApplySnapshotIoctl == 0x83378008, "snapshot IOCTL value changed");
    Assert(StrictDriverAbi.RemoveSessionIoctl == 0x8337800C, "remove IOCTL value changed");
    Assert(StrictDriverAbi.QueryStatsIoctl == 0x83374010, "stats IOCTL value changed");
    Assert(StrictDriverAbi.PingIoctl == 0x83374014, "ping IOCTL value changed");
    Assert(StrictDriverAbiLayout.HeaderSize == 64, "header ABI size changed");
    Assert(StrictDriverAbiLayout.SnapshotHeaderSize == 72, "snapshot ABI size changed");
    Assert(StrictDriverAbiLayout.StatsResponseHeaderSize == 72, "stats response header ABI size changed");
    Assert(StrictDriverAbiLayout.GroupEntryHeaderSize == 48, "group entry ABI size changed");
    Assert(Marshal.SizeOf<StrictDriverGroupStats>() == 72, "stats ABI size changed");
}

static void WfpInteropLayout()
{
    Assert(Marshal.SizeOf<WfpNative.FWPM_SESSION0>() == WfpNative.ExpectedFwpmSession0SizeX64,
        $"FWPM_SESSION0 size mismatch: {Marshal.SizeOf<WfpNative.FWPM_SESSION0>()}");
    Assert(Marshal.SizeOf<WfpNative.FWPM_PROVIDER0>() == WfpNative.ExpectedFwpmProvider0SizeX64,
        $"FWPM_PROVIDER0 size mismatch: {Marshal.SizeOf<WfpNative.FWPM_PROVIDER0>()}");
    Assert(Marshal.SizeOf<WfpNative.FWPM_CALLOUT0>() == WfpNative.ExpectedFwpmCallout0SizeX64,
        $"FWPM_CALLOUT0 size mismatch: {Marshal.SizeOf<WfpNative.FWPM_CALLOUT0>()}");
    Assert(Marshal.SizeOf<WfpNative.FWPM_SUBLAYER0>() == 72, "FWPM_SUBLAYER0 size mismatch");
    Assert(Marshal.SizeOf<WfpNative.FWPM_FILTER0>() == WfpNative.ExpectedFwpmFilter0SizeX64,
        $"FWPM_FILTER0 size mismatch: {Marshal.SizeOf<WfpNative.FWPM_FILTER0>()}");
    Assert(WfpNative.ValidateStrictInteropLayout(), "WFP layout gate rejected the current process ABI");
}

static void SnapshotEncoding()
{
    var session = Guid.NewGuid();
    var groupId = Guid.NewGuid();
    var appIds = new[] { new byte[] { 1, 2, 3 }, new byte[] { 0x10, 0x20 } };
    var encoded = StrictDriverAbi.EncodeSnapshot(session, 17,
        new[] { new StrictDriverGroupInput(groupId, appIds, 4096, 8192, 16384) });
    Assert(BitConverter.ToUInt32(encoded, 0) == StrictDriverAbi.Magic, "snapshot magic mismatch");
    Assert(BitConverter.ToUInt32(encoded, 12) == encoded.Length, "snapshot total size mismatch");
    Assert(BitConverter.ToUInt32(encoded, 16) == (uint)StrictDriverCommand.ApplySnapshot, "snapshot command mismatch");
    Assert(new Guid(encoded.AsSpan(40, 16)) == session, "snapshot session mismatch");
    Assert(BitConverter.ToInt64(encoded, 56) == 17, "snapshot generation mismatch");
    Assert(BitConverter.ToUInt32(encoded, 64) == 1, "snapshot group count mismatch");
    Assert(BitConverter.ToUInt32(encoded, 68) == StrictDriverAbiLayout.GroupEntryHeaderSize, "snapshot entry size mismatch");
    Assert(new Guid(encoded.AsSpan(72, 16)) == groupId, "group ID mismatch");
    Assert(BitConverter.ToUInt32(encoded, 88) == 2, "member count mismatch");
    Assert(BitConverter.ToUInt32(encoded, 92) == 13, "opaque app-id block size mismatch");
    Assert(encoded[120] == 3 && encoded[124] == 1 && encoded[125] == 2 && encoded[126] == 3
        && encoded[127] == 2 && encoded[131] == 0x10 && encoded[132] == 0x20,
        "member app IDs were not encoded as length-prefixed opaque bytes");
}

static void SnapshotBounds()
{
    AssertThrows<ArgumentException>(() => StrictDriverAbi.EncodeSnapshot(Guid.Empty, 1, Array.Empty<StrictDriverGroupInput>()));
    AssertThrows<ArgumentOutOfRangeException>(() => StrictDriverAbi.EncodeSnapshot(Guid.NewGuid(), 0, Array.Empty<StrictDriverGroupInput>()));
    AssertThrows<ArgumentOutOfRangeException>(() => StrictDriverAbi.EncodeSnapshot(Guid.NewGuid(), 1,
        new[] { new StrictDriverGroupInput(Guid.NewGuid(), Array.Empty<byte[]>(), 10, 10, 0) }));
}

static void GroupBounds()
{
    var processPath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
        ?? throw new InvalidOperationException("current process path unavailable");
    var exePath = System.IO.Path.ChangeExtension(processPath, ".exe");
    var valid = new UploadProcessGroup(Guid.NewGuid().ToString("N"), "group",
        new[] { exePath }, 1024, DateTime.UtcNow, false, StrictUploadDriverState.Unknown, 10, 20);
    var normalized = valid.Normalize();
    Assert(normalized.AppPaths.Count == 1, "valid group should preserve a member");
    Assert(normalized.DriverState == StrictUploadDriverState.Unknown, "client must not set driver state");
    Assert(normalized.AccountedBytes == 0 && normalized.QueuedBytes == 0, "client must not set driver stats");
    AssertThrows<InvalidOperationException>(() => (valid with { BytesPerSecond = 0 }).Normalize());
    AssertThrows<InvalidOperationException>(() => (valid with { BurstBytes = StrictUploadProtocol.MaxBurstBytes + 1 }).Normalize());
    AssertThrows<InvalidOperationException>(() => (valid with { QueueLimitBytes = StrictUploadProtocol.MaxQueuedBytes + 1 }).Normalize());
    AssertThrows<InvalidOperationException>(() => (valid with { Name = new string('x', StrictUploadProtocol.MaxNameLength + 1) }).Normalize());
}

static void CapabilityGate()
{
    Assert(StrictDriverAbi.RequiredShapingCapabilities == 0x1FUL,
        "all required strict data-plane capabilities must remain part of the gate");
    Assert((StrictDriverAbi.CapabilityStrictShaping & StrictDriverAbi.RequiredShapingCapabilities)
        != StrictDriverAbi.RequiredShapingCapabilities,
        "the shaping bit alone must not enable strict filters");
    Assert((StrictDriverAbi.RequiredShapingCapabilities & StrictDriverAbi.CapabilityAsyncQueue) != 0
        && (StrictDriverAbi.RequiredShapingCapabilities & StrictDriverAbi.CapabilityTransportReinject) != 0
        && (StrictDriverAbi.RequiredShapingCapabilities & StrictDriverAbi.CapabilityTeardownSafe) != 0
        && (StrictDriverAbi.RequiredShapingCapabilities & StrictDriverAbi.CapabilityLiveStats) != 0,
        "queue, reinjection, teardown and live-stat capabilities must all be required");
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void AssertThrows<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}
