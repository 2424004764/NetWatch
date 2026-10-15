#ifdef NW_TOKEN_BUCKET_HOST_TEST
#include "../tests/token_bucket_test_shim.h"
#else
#include "netwatch_strict.h"
#endif

NTSTATUS NwTokenBucketInitialize(PNW_TOKEN_BUCKET bucket, UINT64 rateBytesPerSecond, UINT64 burstBytes)
{
    if (bucket == NULL || rateBytesPerSecond == 0 || rateBytesPerSecond > 1250000000ULL
        || burstBytes == 0 || burstBytes > 4ULL * 1024 * 1024)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(bucket, sizeof(*bucket));
    KeInitializeSpinLock(&bucket->Lock);
    bucket->RateBytesPerSecond = rateBytesPerSecond;
    bucket->BurstBytes = burstBytes;
    bucket->Tokens = burstBytes;
    bucket->LastRefillTime100ns = KeQueryInterruptTime();
    return STATUS_SUCCESS;
}

BOOLEAN NwTokenBucketTryConsume(PNW_TOKEN_BUCKET bucket, UINT32 bytes, UINT64 now100ns)
{
    KIRQL oldIrql;
    UINT64 elapsed;
    UINT64 used;
    BOOLEAN allowed = FALSE;

    if (bucket == NULL || bytes == 0) return FALSE;

    KeAcquireSpinLock(&bucket->Lock, &oldIrql);
    if (now100ns < bucket->LastRefillTime100ns) now100ns = bucket->LastRefillTime100ns;
    elapsed = now100ns - bucket->LastRefillTime100ns;
    if (elapsed != 0)
    {
        const UINT64 denominator = 10000000ULL;
        const UINT64 deficit = bucket->BurstBytes - bucket->Tokens;
        UINT64 numerator;
        UINT64 wholeTokens;
        UINT64 remainder;

        if (deficit == 0)
        {
            bucket->RefillRemainder = 0;
        }
        else if (elapsed > ((~(UINT64)0) - bucket->RefillRemainder) / bucket->RateBytesPerSecond)
        {
            bucket->Tokens = bucket->BurstBytes;
            bucket->RefillRemainder = 0;
        }
        else
        {
            numerator = elapsed * bucket->RateBytesPerSecond + bucket->RefillRemainder;
            wholeTokens = numerator / denominator;
            remainder = numerator % denominator;
            if (wholeTokens >= deficit)
            {
                bucket->Tokens = bucket->BurstBytes;
                bucket->RefillRemainder = 0;
            }
            else
            {
                bucket->Tokens += wholeTokens;
                bucket->RefillRemainder = remainder;
            }
        }
        bucket->LastRefillTime100ns = now100ns;
    }

    if (bucket->Tokens >= bytes)
    {
        bucket->Tokens -= bytes;
        InterlockedAdd64(&bucket->AccountedBytes, bytes);
        used = bucket->BurstBytes - bucket->Tokens;
        if ((LONG64)used > InterlockedCompareExchange64(&bucket->BurstPeakBytes, 0, 0))
            InterlockedExchange64(&bucket->BurstPeakBytes, (LONG64)used);
        allowed = TRUE;
    }
    else
    {
        InterlockedAdd64(&bucket->DroppedBytes, bytes);
    }
    KeReleaseSpinLock(&bucket->Lock, oldIrql);
    return allowed;
}
