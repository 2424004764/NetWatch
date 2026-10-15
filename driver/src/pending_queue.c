#ifdef NW_PENDING_QUEUE_HOST_TEST
#include "../tests/pending_queue_test_shim.h"
#else
#include "netwatch_strict.h"
#endif

BOOLEAN NwPendingTryEnqueue(PNW_DEVICE_CONTEXT context, PNW_PENDING_PACKET packet)
{
    KIRQL oldIrql;
    UINT64 nextBytes;
    if (context == NULL || packet == NULL || packet->Bytes == 0) return FALSE;
    if (packet->Bytes > NW_STRICT_MAX_PENDING_BYTES) return FALSE;

    KeAcquireSpinLock(&context->PendingLock, &oldIrql);
    nextBytes = context->PendingBytes + packet->Bytes;
    if (nextBytes < context->PendingBytes
        || context->PendingItemCount >= NW_STRICT_MAX_PENDING_ITEMS
        || nextBytes > NW_STRICT_MAX_PENDING_BYTES
#ifndef NW_PENDING_QUEUE_HOST_TEST
        || packet->Flow == NULL
        || packet->Flow->Group == NULL
        || packet->Flow->Group->QueueLimitBytes == 0
        || (UINT64)packet->Bytes > packet->Flow->Group->QueueLimitBytes
        || (UINT64)InterlockedCompareExchange64(&packet->Flow->Group->QueuedBytes, 0, 0)
            > packet->Flow->Group->QueueLimitBytes - packet->Bytes
#endif
        )
    {
        KeReleaseSpinLock(&context->PendingLock, oldIrql);
#ifndef NW_PENDING_QUEUE_HOST_TEST
        if (packet->Flow != NULL && packet->Flow->Group != NULL)
            InterlockedAdd64(&packet->Flow->Group->Bucket.DroppedBytes, packet->Bytes);
#endif
        return FALSE;
    }
    InitializeListHead(&packet->Link);
    InsertTailList(&context->PendingPackets, &packet->Link);
    context->PendingItemCount++;
    context->PendingBytes = nextBytes;
#ifndef NW_PENDING_QUEUE_HOST_TEST
    InterlockedAdd64(&packet->Flow->Group->QueuedBytes, packet->Bytes);
#endif
    KeReleaseSpinLock(&context->PendingLock, oldIrql);
    return TRUE;
}

PNW_PENDING_PACKET NwPendingDequeue(PNW_DEVICE_CONTEXT context)
{
    KIRQL oldIrql;
    PNW_PENDING_PACKET packet = NULL;
    if (context == NULL) return NULL;

    KeAcquireSpinLock(&context->PendingLock, &oldIrql);
    if (!IsListEmpty(&context->PendingPackets))
    {
        PLIST_ENTRY entry = RemoveHeadList(&context->PendingPackets);
        packet = CONTAINING_RECORD(entry, NW_PENDING_PACKET, Link);
        if (context->PendingItemCount != 0) context->PendingItemCount--;
        if (context->PendingBytes >= packet->Bytes) context->PendingBytes -= packet->Bytes;
        else context->PendingBytes = 0;
#ifndef NW_PENDING_QUEUE_HOST_TEST
        if (packet->Flow != NULL && packet->Flow->Group != NULL)
            InterlockedAdd64(&packet->Flow->Group->QueuedBytes, -(LONG64)packet->Bytes);
#endif
    }
    KeReleaseSpinLock(&context->PendingLock, oldIrql);
    return packet;
}

#ifndef NW_PENDING_QUEUE_HOST_TEST

static void NTAPI NwInjectionComplete(
    void* completionContext,
    NET_BUFFER_LIST* netBufferList,
    BOOLEAN dispatchLevel)
{
    PNW_PENDING_PACKET packet = (PNW_PENDING_PACKET)completionContext;
    PNW_DEVICE_CONTEXT context = packet == NULL ? NULL : packet->DeviceContext;
    PNW_FLOW_CONTEXT flow = packet == NULL ? NULL : packet->Flow;
    UNREFERENCED_PARAMETER(netBufferList);
    if (flow != NULL)
        InterlockedDecrement(&flow->InjectionInProgress);
    if (packet != NULL)
        NwPendingCompleteDrop(context, packet, dispatchLevel);
    if (flow != NULL)
        NwFlowReleaseReference(flow);
    if (context != NULL && InterlockedDecrement(&context->InFlightPackets) == 0)
        KeSetEvent(&context->InFlightZeroEvent, IO_NO_INCREMENT, FALSE);
}

void NwPendingCompleteDrop(PNW_DEVICE_CONTEXT context, PNW_PENDING_PACKET packet, BOOLEAN dispatchLevel)
{
    UNREFERENCED_PARAMETER(context);
    if (packet == NULL) return;
    if (packet->Clone != NULL)
    {
        FwpsFreeCloneNetBufferList0(packet->Clone, 0);
        packet->Clone = NULL;
    }
    if (packet->Original != NULL)
    {
        FwpsDereferenceNetBufferList0(packet->Original, dispatchLevel);
        packet->Original = NULL;
    }
    if (packet->ControlData != NULL)
    {
        ExFreePoolWithTag(packet->ControlData, NW_STRICT_TAG);
        packet->ControlData = NULL;
    }
    if (packet->HeaderIncludeHeader != NULL)
    {
        ExFreePoolWithTag(packet->HeaderIncludeHeader, NW_STRICT_TAG);
        packet->HeaderIncludeHeader = NULL;
    }
    if (packet->Pended && packet->ClassifyHandle != 0)
    {
        FWPS_CLASSIFY_OUT0 classifyOut;
        RtlZeroMemory(&classifyOut, sizeof(classifyOut));
        classifyOut.actionType = FWP_ACTION_BLOCK;
        classifyOut.flags = FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        FwpsCompleteClassify0(packet->ClassifyHandle, 0, &classifyOut);
        packet->ClassifyHandle = 0;
        packet->Pended = FALSE;
    }
    if (packet->Flow != NULL)
    {
        NwFlowReleaseReference(packet->Flow);
        packet->Flow = NULL;
    }
    ExFreePoolWithTag(packet, NW_STRICT_TAG);
}

void NwPendingDrain(PNW_DEVICE_CONTEXT context, BOOLEAN completeClassify)
{
    PNW_PENDING_PACKET packet;
    if (context == NULL) return;
    for (;;)
    {
        packet = NwPendingDequeue(context);
        if (packet == NULL) break;
        if (!completeClassify) packet->Pended = FALSE;
        NwPendingCompleteDrop(context, packet, FALSE);
    }
}

void NwPendingCancelFlow(PNW_DEVICE_CONTEXT context, PNW_FLOW_CONTEXT flow)
{
    KIRQL oldIrql;
    PLIST_ENTRY link;
    PLIST_ENTRY next;
    if (context == NULL || flow == NULL) return;
    KeAcquireSpinLock(&context->PendingLock, &oldIrql);
    for (link = context->PendingPackets.Flink; link != &context->PendingPackets; link = next)
    {
        next = link->Flink;
        PNW_PENDING_PACKET packet = CONTAINING_RECORD(link, NW_PENDING_PACKET, Link);
        if (packet->Flow == flow)
        {
            RemoveEntryList(&packet->Link);
            if (context->PendingItemCount != 0) context->PendingItemCount--;
            if (context->PendingBytes >= packet->Bytes) context->PendingBytes -= packet->Bytes;
            else context->PendingBytes = 0;
            if (packet->Flow->Group != NULL)
                InterlockedAdd64(&packet->Flow->Group->QueuedBytes, -(LONG64)packet->Bytes);
            packet->Cancelled = TRUE;
            KeReleaseSpinLock(&context->PendingLock, oldIrql);
            NwPendingCompleteDrop(context, packet, FALSE);
            KeAcquireSpinLock(&context->PendingLock, &oldIrql);
        }
    }
    KeReleaseSpinLock(&context->PendingLock, oldIrql);
}

static BOOLEAN NwPendingExpired(PNW_PENDING_PACKET packet, UINT64 now)
{
    return packet == NULL || now >= packet->EnqueuedAt100ns
        && now - packet->EnqueuedAt100ns > (UINT64)NW_STRICT_PENDING_TIMEOUT_MS * 10000ULL;
}

void NwPendingPump(PNW_DEVICE_CONTEXT context)
{
    UINT32 processed = 0;
    UINT64 now;
    if (context == NULL || InterlockedCompareExchange(&context->Stopping, 0, 0) != 0) return;
    now = KeQueryInterruptTime();
    while (processed++ < NW_STRICT_PENDING_PUMP_BATCH)
    {
        PNW_PENDING_PACKET packet = NwPendingDequeue(context);
        PNW_FLOW_CONTEXT flow;
        HANDLE injectionHandle;
        NTSTATUS status;
        KIRQL flowIrql;
        BOOLEAN requeued;
        if (packet == NULL) break;
        if (packet->Cancelled || packet->Flow == NULL || NwPendingExpired(packet, now))
        {
            NwPendingCompleteDrop(context, packet, TRUE);
            continue;
        }
        flow = packet->Flow;
        requeued = FALSE;
        KeAcquireSpinLock(&flow->InjectionLock, &flowIrql);
        if (flow->State != NW_FLOW_STATE_ASSOCIATED
            || packet->Generation != flow->Group->Generation
            || InterlockedCompareExchange(&context->Stopping, 0, 0) != 0)
        {
            KeReleaseSpinLock(&flow->InjectionLock, flowIrql);
            NwPendingCompleteDrop(context, packet, TRUE);
            continue;
        }
        InterlockedIncrement(&flow->InjectionInProgress);
        InterlockedIncrement(&flow->References); /* completion reference */
        InterlockedIncrement(&flow->References); /* pump local reference */
        if (!NwTokenBucketTryConsume(&flow->Group->Bucket, packet->Bytes, now))
        {
            if (InterlockedCompareExchange(&context->Stopping, 0, 0) == 0)
                requeued = NwPendingTryEnqueue(context, packet);
            InterlockedDecrement(&flow->InjectionInProgress);
            KeReleaseSpinLock(&flow->InjectionLock, flowIrql);
            NwFlowReleaseReference(flow); /* completion reference */
            NwFlowReleaseReference(flow); /* pump local reference */
            if (!requeued)
                NwPendingCompleteDrop(context, packet, TRUE);
            break;
        }
        injectionHandle = packet->AddressFamily == AF_INET ? context->InjectionV4 : context->InjectionV6;
        if (injectionHandle == NULL)
        {
            InterlockedDecrement(&flow->InjectionInProgress);
            KeReleaseSpinLock(&flow->InjectionLock, flowIrql);
            NwFlowReleaseReference(flow); /* completion reference */
            NwFlowReleaseReference(flow); /* pump local reference */
            NwPendingCompleteDrop(context, packet, TRUE);
            continue;
        }
        if (InterlockedIncrement(&context->InFlightPackets) == 1)
            KeResetEvent(&context->InFlightZeroEvent);
        packet->Injected = TRUE;
        status = FwpsInjectTransportSendAsync1(
            injectionHandle,
            NULL,
            packet->EndpointHandle,
            0,
            &packet->SendParams,
            packet->AddressFamily,
            packet->CompartmentId,
            packet->Clone,
            NwInjectionComplete,
            packet);
        KeReleaseSpinLock(&flow->InjectionLock, flowIrql);
        if (!NT_SUCCESS(status))
        {
            InterlockedDecrement(&context->InFlightPackets);
            InterlockedDecrement(&flow->InjectionInProgress);
            NwFlowReleaseReference(flow); /* completion reference */
            NwFlowReleaseReference(flow); /* pump local reference */
            NwPendingCompleteDrop(context, packet, TRUE);
            continue;
        }
        NwFlowReleaseReference(flow); /* pump local reference; callback owns the other */
    }
}

#endif
