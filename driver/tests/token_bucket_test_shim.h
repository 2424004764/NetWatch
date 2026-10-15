#pragma once
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <windows.h>

#define KSPIN_LOCK NW_HOST_SPIN_LOCK
typedef struct _NW_HOST_SPIN_LOCK { volatile LONG Value; } NW_HOST_SPIN_LOCK;
typedef uint8_t BOOLEAN;
typedef uint8_t KIRQL;
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef int64_t LONG64;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER 0xC000000D
#endif
#define NTSTATUS int32_t
#ifndef RtlZeroMemory
#define RtlZeroMemory(pointer, bytes) memset((pointer), 0, (bytes))
#endif

typedef struct _NW_TOKEN_BUCKET {
    KSPIN_LOCK Lock;
    UINT64 RateBytesPerSecond;
    UINT64 BurstBytes;
    UINT64 Tokens;
    UINT64 RefillRemainder;
    UINT64 LastRefillTime100ns;
    volatile LONG64 AccountedBytes;
    volatile LONG64 DroppedBytes;
    volatile LONG64 BurstPeakBytes;
} NW_TOKEN_BUCKET, *PNW_TOKEN_BUCKET;

static inline void KeInitializeSpinLock(NW_HOST_SPIN_LOCK* lock)
{
    lock->Value = 0;
}
static inline void KeAcquireSpinLock(NW_HOST_SPIN_LOCK* lock, KIRQL* oldIrql)
{
    *oldIrql = 0;
    while (InterlockedCompareExchange(&lock->Value, 1, 0) != 0) SwitchToThread();
}
static inline void KeReleaseSpinLock(NW_HOST_SPIN_LOCK* lock, KIRQL oldIrql)
{
    (void)oldIrql;
    InterlockedExchange(&lock->Value, 0);
}
static inline UINT64 KeQueryInterruptTime(void) { return 0; }
