#include <stdio.h>
#include <windows.h>
#define NW_TOKEN_BUCKET_HOST_TEST
#include "../src/token_bucket.c"

static int Check(int condition, const char* message)
{
    if (!condition) fprintf(stderr, "FAIL %s\n", message);
    else printf("PASS %s\n", message);
    return condition;
}

static NW_TOKEN_BUCKET stressBucket;

static DWORD WINAPI ConsumeRange(void* parameter)
{
    (void)parameter;
    for (UINT32 i = 0; i < 128; ++i)
        (void)NwTokenBucketTryConsume(&stressBucket, 1, 0);
    return 0;
}

int main(void)
{
    NW_TOKEN_BUCKET shared;
    NW_TOKEN_BUCKET slow;
    int ok = 1;
    ok &= Check(NwTokenBucketInitialize(&shared, 100, 100) == STATUS_SUCCESS, "initialize shared bucket");
    ok &= Check(NwTokenBucketTryConsume(&shared, 60, 0), "member one consumes shared burst");
    ok &= Check(NwTokenBucketTryConsume(&shared, 40, 0), "member two consumes remaining burst");
    ok &= Check(!NwTokenBucketTryConsume(&shared, 1, 0), "shared burst is not duplicated per member");
    ok &= Check(shared.AccountedBytes == 100 && shared.DroppedBytes == 1, "aggregate accounting and drop count");

    ok &= Check(NwTokenBucketInitialize(&slow, 1, 1) == STATUS_SUCCESS, "initialize low-rate bucket");
    ok &= Check(NwTokenBucketTryConsume(&slow, 1, 0), "consume low-rate initial burst");
    for (uint64_t tick = 1; tick <= 10000000ULL; ++tick)
        (void)NwTokenBucketTryConsume(&slow, 1, tick);
    ok &= Check(slow.AccountedBytes == 2, "sub-byte refill remainder accumulates to a token");

    HANDLE threads[64];
    ok &= Check(NwTokenBucketInitialize(&stressBucket, 100000, 1024) == STATUS_SUCCESS,
        "initialize concurrent shared bucket");
    for (UINT32 i = 0; i < 64; ++i)
    {
        threads[i] = CreateThread(NULL, 0, ConsumeRange, NULL, 0, NULL);
        if (threads[i] == NULL) return 2;
    }
    WaitForMultipleObjects(64, threads, TRUE, INFINITE);
    for (UINT32 i = 0; i < 64; ++i) CloseHandle(threads[i]);
    ok &= Check(stressBucket.AccountedBytes == 1024,
        "concurrent members consume exactly one aggregate burst");
    ok &= Check(stressBucket.DroppedBytes == 64 * 128 - 1024,
        "concurrent over-limit bytes are counted exactly");
    return ok ? 0 : 1;
}
