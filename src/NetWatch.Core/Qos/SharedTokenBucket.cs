using System;

namespace NetWatch.Core.Qos;

/// <summary>线程安全的共享字节令牌桶参考实现，供服务验证和驱动移植测试使用。</summary>
public sealed class SharedTokenBucket
{
    private readonly object _gate = new();
    private readonly long _rateBytesPerSecond;
    private readonly long _burstBytes;
    private readonly long _queueLimitBytes;
    private readonly long _frequency;
    private double _tokens;
    private long _lastTimestamp;
    private long _accountedBytes;
    private long _queuedBytes;
    private long _droppedBytes;
    private long _burstPeakBytes;

    public SharedTokenBucket(long rateBytesPerSecond, long burstBytes, long queueLimitBytes,
        long timestampFrequency, long initialTimestamp = 0)
    {
        if (rateBytesPerSecond <= 0 || rateBytesPerSecond > StrictUploadProtocol.MaxBytesPerSecond)
            throw new ArgumentOutOfRangeException(nameof(rateBytesPerSecond));
        if (burstBytes <= 0 || burstBytes > StrictUploadProtocol.MaxBurstBytes)
            throw new ArgumentOutOfRangeException(nameof(burstBytes));
        if (queueLimitBytes < 0 || queueLimitBytes > StrictUploadProtocol.MaxQueuedBytes)
            throw new ArgumentOutOfRangeException(nameof(queueLimitBytes));
        if (timestampFrequency <= 0) throw new ArgumentOutOfRangeException(nameof(timestampFrequency));

        _rateBytesPerSecond = rateBytesPerSecond;
        _burstBytes = burstBytes;
        _queueLimitBytes = queueLimitBytes;
        _frequency = timestampFrequency;
        _lastTimestamp = initialTimestamp;
        _tokens = burstBytes;
    }

    public bool TryConsume(long bytes, long timestamp)
    {
        if (bytes <= 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        lock (_gate)
        {
            RefillLocked(timestamp);
            if (_tokens < bytes) return false;
            _tokens -= bytes;
            _accountedBytes = checked(_accountedBytes + bytes);
            var usedBurst = _burstBytes - (long)_tokens;
            if (usedBurst > _burstPeakBytes) _burstPeakBytes = usedBurst;
            return true;
        }
    }

    public bool TryEnqueue(long bytes)
    {
        if (bytes <= 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        lock (_gate)
        {
            if (bytes > _queueLimitBytes - _queuedBytes)
            {
                _droppedBytes = checked(_droppedBytes + bytes);
                return false;
            }
            _queuedBytes += bytes;
            return true;
        }
    }

    public long DequeueUpTo(long maximumBytes)
    {
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        lock (_gate)
        {
            var taken = Math.Min(maximumBytes, _queuedBytes);
            _queuedBytes -= taken;
            return taken;
        }
    }

    public StrictUploadBucketSnapshot Snapshot()
    {
        lock (_gate)
            return new StrictUploadBucketSnapshot(_tokens, _accountedBytes, _queuedBytes,
                _droppedBytes, _burstPeakBytes);
    }

    private void RefillLocked(long timestamp)
    {
        if (timestamp < _lastTimestamp) timestamp = _lastTimestamp;
        var elapsed = (timestamp - _lastTimestamp) / (double)_frequency;
        if (elapsed > 0)
        {
            _tokens = Math.Min(_burstBytes, _tokens + elapsed * _rateBytesPerSecond);
            _lastTimestamp = timestamp;
        }
    }
}

public sealed record StrictUploadBucketSnapshot(
    double AvailableTokens,
    long AccountedBytes,
    long QueuedBytes,
    long DroppedBytes,
    long BurstPeakBytes);
