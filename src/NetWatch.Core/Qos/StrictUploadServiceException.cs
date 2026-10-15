using System;

namespace NetWatch.Core.Qos;

public sealed class StrictUploadServiceException : InvalidOperationException
{
    public StrictUploadErrorCode Code { get; }
    public int NativeStatus { get; }
    public bool Retryable { get; }

    public StrictUploadServiceException(StrictUploadErrorCode code, int nativeStatus,
        bool retryable, string message) : base(message)
    {
        Code = code;
        NativeStatus = nativeStatus;
        Retryable = retryable;
    }
}
