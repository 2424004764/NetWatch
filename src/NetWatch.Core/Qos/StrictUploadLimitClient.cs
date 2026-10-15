using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace NetWatch.Core.Qos;

/// <summary>
/// NetWatch 严格上传限速控制面客户端。数据面由 Windows 服务 + WFP callout 驱动提供；
/// 服务不可用时不会回退到多条独立 QoS 规则。
/// </summary>
public sealed class StrictUploadLimitClient : IDisposable
{
    public const int ProtocolVersion = 1;
    public const string PipeName = "NetWatch.StrictUpload.v1";

    private readonly string _sessionId = Guid.NewGuid().ToString("N");
    private readonly object _gate = new();
    private Timer? _heartbeat;
    private long _generation;
    private bool _disposed;

    public string SessionId => _sessionId;
    public StrictUploadDriverState State { get; private set; } = StrictUploadDriverState.Unknown;
    public string? LastError { get; private set; }

    public void StartSession()
    {
        lock (_gate)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(StrictUploadLimitClient));
            _heartbeat ??= new Timer(_ => SendHeartbeat(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }
    }

    public IReadOnlyList<UploadProcessGroup> List()
        => Send<StrictUploadListPayload>(Request("list")).Groups;

    public UploadProcessGroup Create(string name, IEnumerable<string> appPaths, long bytesPerSecond)
    {
        var group = NewGroup(name, appPaths, bytesPerSecond);
        return Send<StrictUploadGroupPayload>(Request("create", group)).Group
            ?? throw new InvalidOperationException("严格限速服务返回了空进程组。");
    }

    public UploadProcessGroup Update(UploadProcessGroup group)
    {
        var normalized = group.Normalize();
        return Send<StrictUploadGroupPayload>(Request("update", normalized)).Group
            ?? throw new InvalidOperationException("严格限速服务返回了空进程组。");
    }

    public void SetEnabled(UploadProcessGroup group, bool enabled)
        => Send<StrictUploadEmptyPayload>(Request(
            enabled ? "enable" : "disable", group with { Enabled = enabled }));

    public void Remove(UploadProcessGroup group)
        => Send<StrictUploadEmptyPayload>(Request("remove", group));

    public void RemoveAll()
    {
        try { Send<StrictUploadEmptyPayload>(Request("remove-all")); }
        catch (Exception ex) { LastError = ex.Message; Log.Error("清理严格上传进程组失败：" + ex.Message); }
    }

    private void SendHeartbeat()
    {
        if (_disposed) return;
        try { Send<StrictUploadEmptyPayload>(Request("heartbeat")); }
        catch (Exception ex) { LastError = ex.Message; }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _heartbeat?.Change(Timeout.Infinite, Timeout.Infinite);
            _heartbeat?.Dispose();
            _heartbeat = null;
            try { Send<StrictUploadEmptyPayload>(Request("remove-all")); }
            catch (Exception ex) { LastError = ex.Message; Log.Error("清理严格上传进程组失败：" + ex.Message); }
            _disposed = true;
        }
    }

    private StrictUploadRequest Request(string operation, UploadProcessGroup? group = null)
        => new(operation, _sessionId, group, ProtocolVersion, 0, Guid.NewGuid(), Interlocked.Read(ref _generation));

    private T Send<T>(StrictUploadRequest request)
    {
        lock (_gate)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(StrictUploadLimitClient));
            try
            {
                using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut,
                    PipeOptions.WriteThrough | PipeOptions.Asynchronous);
                pipe.Connect(700);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true)
                { AutoFlush = true };
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
                writer.WriteLine(JsonSerializer.Serialize(request, JsonOptions));
                var line = reader.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) throw new InvalidOperationException("严格限速服务未返回结果。");
                var envelope = JsonSerializer.Deserialize<StrictUploadResponse<T>>(line, JsonOptions)
                    ?? throw new InvalidOperationException("严格限速服务返回了无效结果。");
                if (envelope.MajorVersion != ProtocolVersion)
                {
                    State = StrictUploadDriverState.ProtocolMismatch;
                    throw new InvalidOperationException("严格限速服务协议版本不兼容，请升级 NetWatch 服务与界面。");
                }
                if (envelope.RequestId != request.RequestId)
                    throw new InvalidOperationException("严格限速服务响应 ID 与请求不匹配。");
                if (!envelope.Ok)
                    throw new StrictUploadServiceException(envelope.ErrorCode, envelope.NativeStatus,
                        envelope.Retryable, envelope.Error ?? "严格限速服务拒绝了请求。");
                if (envelope.Payload is null)
                    throw new InvalidOperationException("严格限速服务返回了空结果。");
                Interlocked.Exchange(ref _generation, envelope.Generation);
                State = envelope.State;
                LastError = envelope.Error;
                return envelope.Payload;
            }
            catch (StrictUploadServiceException ex)
            {
                State = ex.Code switch
                {
                    StrictUploadErrorCode.DriverUnavailable => StrictUploadDriverState.DriverUnavailable,
                    StrictUploadErrorCode.ProtocolMismatch => StrictUploadDriverState.ProtocolMismatch,
                    StrictUploadErrorCode.AccessDenied => StrictUploadDriverState.AccessDenied,
                    StrictUploadErrorCode.DeviceRemoved => StrictUploadDriverState.DeviceRemoved,
                    StrictUploadErrorCode.UnsupportedCapability => StrictUploadDriverState.UnsupportedCapability,
                    StrictUploadErrorCode.PartialApply => StrictUploadDriverState.PartialApply,
                    _ => StrictUploadDriverState.Error,
                };
                LastError = ex.Message;
                throw;
            }
            catch (TimeoutException)
            {
                State = StrictUploadDriverState.ServiceUnavailable;
                LastError = "严格上传服务未安装或未启动。当前不能启用跨进程总限速。";
                throw new InvalidOperationException(LastError);
            }
            catch (IOException ex)
            {
                State = StrictUploadDriverState.ServiceUnavailable;
                LastError = "严格上传服务不可用：" + ex.Message;
                throw new InvalidOperationException(LastError, ex);
            }
            catch (Exception ex)
            {
                State = StrictUploadDriverState.Error;
                LastError = ex.Message;
                throw;
            }
        }
    }

    private static UploadProcessGroup NewGroup(string name, IEnumerable<string> paths, long bytesPerSecond)
    {
        if (bytesPerSecond <= 0) throw new InvalidOperationException("共享上传速度必须大于 0。");
        var normalized = paths.Select(PathNormalizer.NormalizeExistingExe)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (normalized.Length == 0) throw new InvalidOperationException("进程组至少需要一个 exe 成员。");
        return new UploadProcessGroup(Guid.NewGuid().ToString("N"), name, normalized,
            bytesPerSecond, DateTime.UtcNow, true, StrictUploadDriverState.Unknown, 0, 0);
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };
}
