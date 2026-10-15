#include <stdio.h>
#include <windows.h>
#define NW_PENDING_QUEUE_HOST_TEST
#include "../src/pending_queue.c"

static int Check(int condition, const char* message)
{
    if (!condition) fprintf(stderr, "FAIL %s\n", message);
    else printf("PASS %s\n", message);
    return condition;
}

static NW_DEVICE_CONTEXT concurrentContext;
static NW_PENDING_PACKET concurrentPackets[8][256];

static DWORD WINAPI EnqueueRange(void* parameter)
{
    const UINT32 worker = (UINT32)(ULONG_PTR)parameter;
    for (UINT32 index = 0; index < 256; ++index)
    {
        concurrentPackets[worker][index].Bytes = 1;
        if (!NwPendingTryEnqueue(&concurrentContext, &concurrentPackets[worker][index]))
            return 1;
    }
    return 0;
}

int main(void)
{
    NW_DEVICE_CONTEXT context;
    NW_PENDING_PACKET first, second, overflow;
    int ok = 1;
    memset(&context, 0, sizeof(context));
    KeInitializeSpinLock(&context.PendingLock);
    InitializeListHead(&context.PendingPackets);
    first.Bytes = NW_STRICT_MAX_PENDING_BYTES - 8;
    second.Bytes = 8;
    overflow.Bytes = 1;
    ok &= Check(NwPendingTryEnqueue(&context, &first), "enqueue within byte limit");
    ok &= Check(NwPendingTryEnqueue(&context, &second), "fill byte limit exactly");
    ok &= Check(context.PendingItemCount == 2 && context.PendingBytes == NW_STRICT_MAX_PENDING_BYTES,
        "queue accounting reaches exact configured limit");
    ok &= Check(!NwPendingTryEnqueue(&context, &overflow), "reject item over byte limit");
    ok &= Check(NwPendingDequeue(&context) == &first, "dequeue preserves FIFO order");
    ok &= Check(context.PendingBytes == 8 && context.PendingItemCount == 1,
        "dequeue subtracts exact bytes and item count");
    ok &= Check(NwPendingDequeue(&context) == &second, "dequeue final queued item");
    ok &= Check(context.PendingBytes == 0 && context.PendingItemCount == 0,
        "empty queue accounting returns to zero");

    memset(&concurrentContext, 0, sizeof(concurrentContext));
    KeInitializeSpinLock(&concurrentContext.PendingLock);
    InitializeListHead(&concurrentContext.PendingPackets);
    HANDLE threads[8];
    for (UINT32 worker = 0; worker < 8; ++worker)
        threads[worker] = CreateThread(NULL, 0, EnqueueRange, (void*)(ULONG_PTR)worker, 0, NULL);
    WaitForMultipleObjects(8, threads, TRUE, INFINITE);
    for (UINT32 worker = 0; worker < 8; ++worker) CloseHandle(threads[worker]);
    ok &= Check(concurrentContext.PendingItemCount == 8 * 256,
        "concurrent producers preserve item count");
    ok &= Check(concurrentContext.PendingBytes == 8 * 256,
        "concurrent producers preserve byte count");
    UINT32 drained = 0;
    while (NwPendingDequeue(&concurrentContext) != NULL) ++drained;
    ok &= Check(drained == 8 * 256 && concurrentContext.PendingItemCount == 0
        && concurrentContext.PendingBytes == 0, "concurrent queue drains cleanly");
    return ok ? 0 : 1;
}
