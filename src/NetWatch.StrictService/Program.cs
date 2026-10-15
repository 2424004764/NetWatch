using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NetWatch.Core.Qos;

namespace NetWatch.StrictService;

internal static class Program
{
    private const int ErrorFailedServiceControllerConnect = 1063;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStartPending = 2;
    private const uint ServiceStopPending = 3;
    private const uint ServiceRunning = 4;
    private const uint ServiceStopped = 1;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ControlStop = 1;
    private const uint ControlShutdown = 5;
    private const string ServiceName = "NetWatchStrictService";
    private static readonly ServiceMainCallback ServiceMainRoot = ServiceMain;
    private static readonly ServiceHandlerCallback ServiceHandlerRoot = ServiceHandler;
    private static StrictUploadServiceHost? _host;
    private static IntPtr _statusHandle;
    private static ServiceStatus _status;

    public static void Main()
    {
        var table = new[]
        {
            new ServiceTableEntry { Name = ServiceName, Main = ServiceMainRoot },
            new ServiceTableEntry(),
        };
        if (StartServiceControllerDispatcher(table)) return;

        var error = Marshal.GetLastWin32Error();
        if (error != ErrorFailedServiceControllerConnect)
            throw new Win32Exception(error, "无法连接 Windows 服务控制管理器。");

        using var host = new StrictUploadServiceHost(installWfpControlObjects: false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; host.Stop(); };
        host.Run();
    }

    private static void ServiceMain(uint argc, IntPtr argv)
    {
        _statusHandle = RegisterServiceCtrlHandlerEx(ServiceName, ServiceHandlerRoot, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero) return;

        SetServiceState(ServiceStartPending, 0, 3000);
        try
        {
            using var host = new StrictUploadServiceHost(installWfpControlObjects: true);
            _host = host;
            SetServiceState(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, 0);
            host.Run();
            SetServiceState(ServiceStopped, 0, 0);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[{DateTime.Now:O}] Service stopped after an error: {ex}");
            SetServiceState(ServiceStopped, 0, 0, 1);
        }
        finally
        {
            _host = null;
        }
        GC.KeepAlive(argc);
        GC.KeepAlive(argv);
    }

    private static uint ServiceHandler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ControlStop or ControlShutdown)
        {
            SetServiceState(ServiceStopPending, 0, 3000);
            _host?.Stop();
        }
        GC.KeepAlive(eventType);
        GC.KeepAlive(eventData);
        GC.KeepAlive(context);
        return 0;
    }

    private static void SetServiceState(uint state, uint accepted, uint waitHint, uint exitCode = 0)
    {
        if (_statusHandle == IntPtr.Zero) return;
        _status.ServiceType = ServiceWin32OwnProcess;
        _status.CurrentState = state;
        _status.ControlsAccepted = accepted;
        _status.Win32ExitCode = exitCode;
        _status.ServiceSpecificExitCode = 0;
        _status.CheckPoint = state is ServiceStartPending or ServiceStopPending ? _status.CheckPoint + 1 : 0;
        _status.WaitHint = waitHint;
        SetServiceStatus(_statusHandle, ref _status);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? Name;
        public ServiceMainCallback? Main;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainCallback(uint argc, IntPtr argv);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint ServiceHandlerCallback(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceControllerDispatcher([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, ServiceHandlerCallback handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus serviceStatus);
}

internal sealed class StrictUploadServiceHost : IDisposable
{
    private readonly ConcurrentDictionary<string, SessionState> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _stop = new();
    private readonly Timer _reaper;
    private readonly ConcurrentBag<Task> _clients = new();
    private readonly ConcurrentDictionary<NamedPipeServerStream, byte> _activePipes = new();
    private readonly StrictDriverDeviceClient _driver = new();
    private readonly StrictWfpFilterManager? _wfpFilters;
    private int _stopping;
    private bool _disposed;

    public StrictUploadServiceHost(bool installWfpControlObjects)
    {
        _driver.TryConnect();
        if (installWfpControlObjects)
            _wfpFilters = new StrictWfpFilterManager();
        _reaper = new Timer(_ => ReapSessions(), null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
    }

    public void Run()
    {
        LogService($"NetWatch strict upload control plane started. Driver state: {_driver.State}.");
        while (!_stop.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe();
                pipe.WaitForConnectionAsync(_stop.Token).GetAwaiter().GetResult();
                var connectedPipe = pipe;
                _activePipes.TryAdd(connectedPipe, 0);
                _clients.Add(Task.Run(() =>
                {
                    try { using (connectedPipe) Handle(connectedPipe); }
                    finally { _activePipes.TryRemove(connectedPipe, out _); }
                }));
                pipe = null;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                if (!_stop.IsCancellationRequested) LogService("Pipe accept failed: " + ex.Message);
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    public void Stop()
    {
        Interlocked.Exchange(ref _stopping, 1);
        _stop.Cancel();
        foreach (var pipe in _activePipes.Keys)
        {
            try { pipe.Dispose(); } catch { }
        }
    }

    private bool IsStopping => Volatile.Read(ref _stopping) != 0;

    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            WindowsIdentity.GetCurrent().User!,
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            StrictUploadLimitClient.PipeName, PipeDirection.InOut, 8,
            PipeTransmissionMode.Byte, PipeOptions.WriteThrough,
            8192, 8192, security);
    }

    private void Handle(NamedPipeServerStream pipe)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        var line = reader.ReadLine();
        if (string.IsNullOrWhiteSpace(line) || line.Length > 128 * 1024) return;

        StrictUploadRequest? request;
        try { request = JsonSerializer.Deserialize<StrictUploadRequest>(line, JsonOptions); }
        catch (Exception ex)
        {
            Write(writer, Failure<StrictUploadEmptyPayload>(Guid.Empty, StrictUploadErrorCode.InvalidRequest,
                StrictUploadDriverState.Error, ex.Message));
            return;
        }

        if (request is null || !Guid.TryParseExact(request.SessionId, "N", out _)
            || request.RequestId == Guid.Empty || request.MajorVersion != StrictUploadProtocol.MajorVersion)
        {
            var code = request is not null && request.MajorVersion != StrictUploadProtocol.MajorVersion
                ? StrictUploadErrorCode.ProtocolMismatch : StrictUploadErrorCode.InvalidRequest;
            Write(writer, Failure<StrictUploadEmptyPayload>(request?.RequestId ?? Guid.Empty, code,
                code == StrictUploadErrorCode.ProtocolMismatch ? StrictUploadDriverState.ProtocolMismatch : StrictUploadDriverState.Error,
                code == StrictUploadErrorCode.ProtocolMismatch ? "严格限速服务协议版本不兼容。" : "请求头无效或缺少 session/request ID。"));
            return;
        }

        if (IsStopping)
        {
            Write(writer, Failure<StrictUploadEmptyPayload>(request?.RequestId ?? Guid.Empty,
                StrictUploadErrorCode.ServiceUnavailable, StrictUploadDriverState.ServiceUnavailable,
                "严格限速服务正在停止。"));
            return;
        }

        while (true)
        {
            var session = GetSession(request.SessionId);
            lock (session.Gate)
            {
                if (IsStopping)
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.ServiceUnavailable, StrictUploadDriverState.ServiceUnavailable,
                        "严格限速服务正在停止。", session.Generation));
                    return;
                }
                if (!_sessions.TryGetValue(request.SessionId, out var current) || !ReferenceEquals(current, session))
                    continue;
                session.LastSeenUtc = DateTime.UtcNow;
                var operationName = request.Operation.ToLowerInvariant();
                if (request.Generation != session.Generation && operationName is not "heartbeat" and not "list")
                {
                    Write(writer, new StrictUploadResponse<StrictUploadEmptyPayload>(false,
                        StrictUploadDriverState.Rejected, "严格限速会话 generation 已过期，请先刷新组表。",
                        null, StrictUploadProtocol.MajorVersion, StrictUploadProtocol.MinorVersion,
                        request.RequestId, session.Generation, StrictUploadErrorCode.Rejected));
                    return;
                }
                WriteOperation(writer, session, request);
                return;
            }
        }
    }

    private void WriteOperation(StreamWriter writer, SessionState session, StrictUploadRequest request)
    {
        var operation = request.Operation.ToLowerInvariant();
        switch (operation)
        {
            case "list":
                var listedGroups = session.Groups.Values.OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase).ToArray();
                if (listedGroups.Any(group => group.Enabled))
                {
                    try
                    {
                        var stats = _driver.QueryStats(Guid.ParseExact(request.SessionId, "N"), session.Generation)
                            .ToDictionary(item => item.GroupId, StringComparer.OrdinalIgnoreCase);
                        listedGroups = listedGroups.Select(group => stats.TryGetValue(group.GroupId, out var item)
                            ? group with
                            {
                                DriverState = _driver.HasShapingCapability
                                    ? StrictUploadDriverState.Active : StrictUploadDriverState.UnsupportedCapability,
                                AccountedBytes = item.AccountedBytes,
                                QueuedBytes = item.QueuedBytes,
                            }
                            : group with { DriverState = StrictUploadDriverState.Degraded }).ToArray();
                    }
                    catch (Exception ex)
                    {
                        Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                            StrictUploadErrorCode.DeviceRemoved, StrictUploadDriverState.DeviceRemoved,
                            "读取活动组统计失败，不能确认驱动状态：" + ex.Message, session.Generation));
                        return;
                    }
                }
                Write(writer, Success(request, _driver.State,
                    new StrictUploadListPayload(listedGroups), session.Generation));
                return;
            case "heartbeat":
                Write(writer, Success(request, _driver.State, new StrictUploadEmptyPayload(true), session.Generation));
                return;
            case "remove-all":
                var hasEnabledGroups = session.Groups.Values.Any(group => group.Enabled);
                if (hasEnabledGroups || _driver.HasShapingCapability)
                {
                    var clearGeneration = checked(session.Generation + 1);
                    if (!ApplyCandidateTable(request.SessionId, clearGeneration, Array.Empty<UploadProcessGroup>()))
                    {
                        Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                            StrictUploadErrorCode.DeviceRemoved, StrictUploadDriverState.DeviceRemoved,
                            _driver.LastError ?? "驱动未确认清理会话，保留服务端状态。", session.Generation));
                        return;
                    }
                }
                session.Groups.Clear();
                session.Generation++;
                Write(writer, Success(request, _driver.State, new StrictUploadEmptyPayload(true), session.Generation));
                return;
            case "remove":
                if (request.Group is null || !Guid.TryParseExact(request.Group.GroupId, "N", out _))
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.InvalidRequest, StrictUploadDriverState.Error, "进程组标识无效。", session.Generation));
                    return;
                }
                if (!session.Groups.ContainsKey(request.Group.GroupId))
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.Rejected, StrictUploadDriverState.Rejected, "进程组不存在。", session.Generation));
                    return;
                }
                var remainingGroups = session.Groups.Where(pair => !StringComparer.OrdinalIgnoreCase.Equals(pair.Key, request.Group.GroupId))
                    .Select(pair => pair.Value).ToArray();
                var hadActiveBeforeRemoval = session.Groups.Values.Any(group => group.Enabled);
                var hasRemainingActiveGroups = remainingGroups.Any(group => group.Enabled);
                var nextRemoveGeneration = checked(session.Generation + 1);
                if ((hadActiveBeforeRemoval || hasRemainingActiveGroups)
                    && !ApplyCandidateTable(request.SessionId, nextRemoveGeneration, remainingGroups))
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.Rejected, _driver.State,
                        _driver.LastError ?? "驱动未确认移除后的组表状态，保留原服务状态。", session.Generation));
                    return;
                }
                session.Groups.Remove(request.Group.GroupId);
                session.Generation = nextRemoveGeneration;
                Write(writer, Success(request, _driver.State, new StrictUploadEmptyPayload(true), session.Generation));
                return;
            case "create":
            case "update":
            case "enable":
            case "disable":
                if (request.Group is null)
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.InvalidRequest, StrictUploadDriverState.Error, "进程组内容缺失。", session.Generation));
                    return;
                }
                UploadProcessGroup normalized;
                try { normalized = request.Group.Normalize(); }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.InvalidRequest, StrictUploadDriverState.Rejected, ex.Message, session.Generation));
                    return;
                }
                if (operation == "create" && session.Groups.ContainsKey(normalized.GroupId)
                    || operation != "create" && !session.Groups.ContainsKey(normalized.GroupId))
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.Rejected, StrictUploadDriverState.Rejected,
                        operation == "create" ? "进程组标识已存在。" : "进程组不存在。", session.Generation));
                    return;
                }
                var enableRequested = operation == "enable" || operation == "update" && normalized.Enabled;
                var candidateGroups = new Dictionary<string, UploadProcessGroup>(session.Groups, StringComparer.OrdinalIgnoreCase);
                candidateGroups[normalized.GroupId] = normalized with { Enabled = enableRequested };
                var hadActiveGroups = session.Groups.Values.Any(group => group.Enabled);
                var hasActiveGroups = candidateGroups.Values.Any(group => group.Enabled);
                if (hasActiveGroups && HasOverlappingMembers(candidateGroups.Values))
                {
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        StrictUploadErrorCode.Rejected, StrictUploadDriverState.Rejected,
                        "同一个 exe 不能同时属于多个已启用的严格限速组。", session.Generation));
                    return;
                }
                var nextGeneration = checked(session.Generation + 1);
                if ((hadActiveGroups || hasActiveGroups)
                    && !ApplyCandidateTable(request.SessionId, nextGeneration, candidateGroups.Values))
                {
                    var unavailable = _driver.State is StrictUploadDriverState.DriverUnavailable or StrictUploadDriverState.DeviceRemoved;
                    Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                        unavailable ? StrictUploadErrorCode.DriverUnavailable : StrictUploadErrorCode.UnsupportedCapability,
                        unavailable ? _driver.State : StrictUploadDriverState.UnsupportedCapability,
                        _driver.LastError ?? "驱动未确认候选组表；服务未提交新状态。", session.Generation));
                    return;
                }
                session.Groups.Clear();
                foreach (var pair in candidateGroups)
                    session.Groups[pair.Key] = pair.Value with
                    {
                        DriverState = pair.Value.Enabled ? StrictUploadDriverState.Active : _driver.State,
                        AccountedBytes = 0,
                        QueuedBytes = 0,
                    };
                session.Generation = nextGeneration;
                if (operation == "enable" || operation == "disable")
                    Write(writer, Success(request, _driver.State, new StrictUploadEmptyPayload(true), session.Generation));
                else
                    Write(writer, Success(request, _driver.State,
                        new StrictUploadGroupPayload(session.Groups[normalized.GroupId]), session.Generation));
                return;
            default:
                Write(writer, Failure<StrictUploadEmptyPayload>(request.RequestId,
                    StrictUploadErrorCode.InvalidRequest, StrictUploadDriverState.Error, "未知严格限速操作。", session.Generation));
                return;
        }
    }

    private static bool HasOverlappingMembers(IEnumerable<UploadProcessGroup> groups)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups)
        {
            if (!group.Enabled) continue;
            foreach (var path in group.AppPaths)
                if (!seen.Add(path)) return true;
        }
        return false;
    }

    private bool ApplyCandidateTable(string sessionId, long generation, IEnumerable<UploadProcessGroup> groups)
    {
        if (_driver.State is StrictUploadDriverState.DriverUnavailable or StrictUploadDriverState.DeviceRemoved
            or StrictUploadDriverState.ProtocolMismatch or StrictUploadDriverState.AccessDenied)
            return false;
        var activeGroups = groups.Where(group => group.Enabled).ToArray();
        var sessionGuid = Guid.ParseExact(sessionId, "N");
        var wasEnabled = _wfpFilters?.FiltersEnabled == true;
        if (wasEnabled) _wfpFilters!.SetFiltersEnabled(false);
        if (activeGroups.Length == 0)
        {
            var removed = _driver.RemoveSession(sessionGuid, generation);
            if (!removed && wasEnabled)
                _wfpFilters!.SetFiltersEnabled(true);
            return removed;
        }
        if (!_driver.HasShapingCapability || _wfpFilters is null)
        {
            if (wasEnabled)
            {
                try { _wfpFilters!.SetFiltersEnabled(true); }
                catch (Exception ex) { LogService("WFP filter rollback failed after capability rejection: " + ex.Message); }
            }
            return false;
        }
        if (!_driver.ApplySnapshot(sessionGuid, generation, BuildDriverGroups(activeGroups)))
        {
            if (wasEnabled)
            {
                try { _wfpFilters.SetFiltersEnabled(true); }
                catch (Exception ex) { LogService("WFP filter rollback failed after snapshot rejection: " + ex.Message); }
            }
            return false;
        }
        try
        {
            _wfpFilters.SetFiltersEnabled(true);
            return true;
        }
        catch (Exception ex)
        {
            LogService("WFP filter enable failed after snapshot apply; removing the driver session: " + ex.Message);
            if (!_driver.RemoveSession(sessionGuid, checked(generation + 1)))
                LogService("Driver session rollback was not confirmed: " + _driver.LastError);
            throw;
        }
    }

    private IReadOnlyList<StrictDriverGroupInput> BuildDriverGroups(IEnumerable<UploadProcessGroup> groups)
        => groups.Where(group => group.Enabled).Select(group => new StrictDriverGroupInput(
            Guid.ParseExact(group.GroupId, "N"),
            group.AppPaths.Select(StrictDriverDeviceClient.ResolveAppId).ToArray(),
            group.BytesPerSecond,
            group.BurstBytes,
            group.QueueLimitBytes)).ToArray();

    private SessionState GetSession(string sessionId)
        => _sessions.GetOrAdd(sessionId, _ => new SessionState());

    private static StrictUploadResponse<T> Success<T>(StrictUploadRequest request,
        StrictUploadDriverState state, T payload, long generation)
        => new(true, state, null, payload, StrictUploadProtocol.MajorVersion,
            StrictUploadProtocol.MinorVersion, request.RequestId, generation);

    private static StrictUploadResponse<T> Failure<T>(Guid requestId, StrictUploadErrorCode code,
        StrictUploadDriverState state, string error, long generation = 0)
        => new(false, state, error, default, StrictUploadProtocol.MajorVersion,
            StrictUploadProtocol.MinorVersion, requestId, generation, code,
            code == StrictUploadErrorCode.DriverUnavailable ? unchecked((int)0xC000000E) : 0,
            code is StrictUploadErrorCode.ServiceUnavailable or StrictUploadErrorCode.DeviceRemoved or StrictUploadErrorCode.Timeout);

    private static void Write<T>(StreamWriter writer, StrictUploadResponse<T> response)
        => writer.WriteLine(JsonSerializer.Serialize(response, JsonOptions));

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };

    private void ReapSessions()
    {
        var cutoff = DateTime.UtcNow - TimeSpan.FromSeconds(20);
        foreach (var pair in _sessions)
        {
            lock (pair.Value.Gate)
            {
                if (pair.Value.LastSeenUtc < cutoff)
                {
                    var requiresDriverCleanup = pair.Value.Groups.Values.Any(group => group.Enabled)
                        || _driver.HasShapingCapability;
                    var wasEnabled = _wfpFilters?.FiltersEnabled == true;
                    if (wasEnabled) _wfpFilters!.SetFiltersEnabled(false);
                    var cleanupConfirmed = !requiresDriverCleanup
                        || _driver.RemoveSession(Guid.ParseExact(pair.Key, "N"), Math.Max(1, pair.Value.Generation + 1));
                    if (cleanupConfirmed)
                    {
                        pair.Value.Groups.Clear();
                        _sessions.TryRemove(pair.Key, out _);
                    }
                    else
                    {
                        if (wasEnabled) _wfpFilters!.SetFiltersEnabled(true);
                        pair.Value.LastSeenUtc = DateTime.UtcNow;
                        LogService($"Session cleanup was not confirmed for {pair.Key}; retaining state. {_driver.LastError}");
                    }
                }
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _reaper.Dispose();
        Stop();
        try { Task.WaitAll(_clients.ToArray(), TimeSpan.FromSeconds(3)); } catch { }
        var filtersDisabled = true;
        try { _wfpFilters?.SetFiltersEnabled(false); }
        catch (Exception ex)
        {
            filtersDisabled = false;
            LogService("Service stop could not disable WFP filters: " + ex.Message);
        }
        foreach (var pair in _sessions)
            lock (pair.Value.Gate)
            {
                var requiresDriverCleanup = pair.Value.Groups.Values.Any(group => group.Enabled)
                    || _driver.HasShapingCapability;
                if (requiresDriverCleanup && filtersDisabled
                    && !_driver.RemoveSession(Guid.ParseExact(pair.Key, "N"), Math.Max(1, pair.Value.Generation + 1)))
                    LogService($"Service stop could not confirm driver cleanup for {pair.Key}. {_driver.LastError}");
                pair.Value.Groups.Clear();
            }
        _sessions.Clear();
        _wfpFilters?.Dispose();
        _driver.Dispose();
    }

    private sealed class SessionState
    {
        public object Gate { get; } = new();
        public Dictionary<string, UploadProcessGroup> Groups { get; } = new(StringComparer.OrdinalIgnoreCase);
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public long Generation { get; set; }
    }

    private static void LogService(string message)
        => Console.Error.WriteLine($"[{DateTime.Now:O}] {message}");
}
