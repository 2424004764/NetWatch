#include "netwatch_strict.h"

static const GUID NwCalloutFlowV4 = { 0xd8a1e037, 0x5294, 0x4b2f, { 0x92, 0xad, 0x34, 0x77, 0x5d, 0x93, 0x0e, 0x11 } };
static const GUID NwCalloutFlowV6 = { 0xb1e1976a, 0x10c6, 0x40c2, { 0x85, 0x32, 0x52, 0x1c, 0x04, 0x73, 0x2d, 0x60 } };
static const GUID NwCalloutTransportV4 = { 0x478f21f0, 0x3e8a, 0x43ee, { 0x97, 0x84, 0x14, 0xdc, 0x25, 0xc6, 0x88, 0x5b } };
static const GUID NwCalloutTransportV6 = { 0xf1ab0340, 0x78e3, 0x47b6, { 0xa0, 0x2a, 0xda, 0xe3, 0xf1, 0x95, 0x7e, 0x96 } };

static PNW_DEVICE_CONTEXT g_DeviceContext;
static const UINT8 g_TransportSlotV4 = 2;
static const UINT8 g_TransportSlotV6 = 3;
static const LONG NwFlowRegistering = NW_FLOW_STATE_REGISTERING;
static const LONG NwFlowAssociated = NW_FLOW_STATE_ASSOCIATED;
static const LONG NwFlowDeletePending = NW_FLOW_STATE_DELETE_PENDING;
static const LONG NwFlowDetaching = NW_FLOW_STATE_DETACHING;

void NwSetCalloutDeviceContext(PNW_DEVICE_CONTEXT context)
{
    g_DeviceContext = context;
}

static void NwFlowRelease(PNW_FLOW_CONTEXT flow)
{
    if (InterlockedDecrement(&flow->References) == 0)
    {
        InterlockedDecrement64(&flow->Group->ActiveFlows);
        ExReleaseRundownProtection(&flow->Group->FlowRundown);
        ExFreePoolWithTag(flow, NW_STRICT_TAG);
    }
}

void NwFlowReleaseReference(PNW_FLOW_CONTEXT flow)
{
    NwFlowRelease(flow);
}

void NwRemoveAllFlowContexts(PNW_DEVICE_CONTEXT context)
{
    KIRQL contextIrql;
    KIRQL flowIrql;
    NTSTATUS removeStatus;
    if (context == NULL) return;
    for (;;)
    {
        PNW_FLOW_CONTEXT flow;
        KeAcquireSpinLock(&context->FlowLock, &contextIrql);
        if (IsListEmpty(&context->FlowContexts))
        {
            KeReleaseSpinLock(&context->FlowLock, contextIrql);
            break;
        }
        flow = CONTAINING_RECORD(context->FlowContexts.Flink, NW_FLOW_CONTEXT, Link);
        InterlockedIncrement(&flow->References);
        KeAcquireSpinLock(&flow->InjectionLock, &flowIrql);
        flow->State = NwFlowDetaching;
        flow->InList = FALSE;
        RemoveEntryList(&flow->Link);
        KeReleaseSpinLock(&flow->InjectionLock, flowIrql);
        KeReleaseSpinLock(&context->FlowLock, contextIrql);
        NwPendingCancelFlow(context, flow);
        removeStatus = FwpsFlowRemoveContext0(flow->FlowHandle, flow->LayerId, flow->CalloutId);
        NwFlowRelease(flow);
        if (removeStatus != STATUS_SUCCESS && removeStatus != STATUS_PENDING
            && InterlockedCompareExchange(&flow->DeleteCallbackSeen, 0, 0) == 0)
            NwFlowRelease(flow);
    }
}

static PNW_FLOW_CONTEXT NwFlowReference(
    PNW_DEVICE_CONTEXT context,
    UINT64 flowHandle,
    UINT16 layerId)
{
    PLIST_ENTRY link;
    PNW_FLOW_CONTEXT found = NULL;
    KIRQL oldIrql;
    if (context == NULL || flowHandle == 0) return NULL;
    KeAcquireSpinLock(&context->FlowLock, &oldIrql);
    for (link = context->FlowContexts.Flink; link != &context->FlowContexts; link = link->Flink)
    {
        PNW_FLOW_CONTEXT flow = CONTAINING_RECORD(link, NW_FLOW_CONTEXT, Link);
        if (flow->FlowHandle == flowHandle && flow->LayerId == layerId && flow->State == NwFlowAssociated)
        {
            InterlockedIncrement(&flow->References);
            found = flow;
            break;
        }
    }
    KeReleaseSpinLock(&context->FlowLock, oldIrql);
    return found;
}

static void NTAPI NwFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContextValue)
{
    PNW_FLOW_CONTEXT flow = (PNW_FLOW_CONTEXT)(ULONG_PTR)flowContextValue;
    PNW_DEVICE_CONTEXT context;
    KIRQL contextIrql;
    KIRQL flowIrql;
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    if (flow == NULL) return;

    if (InterlockedCompareExchange(&flow->DeleteCallbackSeen, 1, 0) != 0)
        return;
    context = flow->DeviceContext;
    KeAcquireSpinLock(&context->FlowLock, &contextIrql);
    KeAcquireSpinLock(&flow->InjectionLock, &flowIrql);
    if (flow->State == NwFlowRegistering || flow->State == NwFlowAssociated
        || flow->State == NW_FLOW_STATE_INJECTING
        || flow->State == NwFlowDetaching)
    {
        flow->State = flow->State == NwFlowRegistering ? NwFlowDeletePending : NwFlowDetaching;
        if (flow->InList)
        {
            flow->InList = FALSE;
            RemoveEntryList(&flow->Link);
        }
    }
    KeReleaseSpinLock(&flow->InjectionLock, flowIrql);
    KeReleaseSpinLock(&context->FlowLock, contextIrql);

    NwPendingCancelFlow(context, flow);
    NwFlowRelease(flow);
}

static NTSTATUS NwRegisterOne(PDEVICE_OBJECT deviceObject, PNW_DEVICE_CONTEXT context,
    UINT32 slot, const GUID* calloutKey, FWPS_CALLOUT_CLASSIFY_FN1 classifyFn, BOOLEAN isFlowCallout)
{
    FWPS_CALLOUT1 callout;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *calloutKey;
    callout.classifyFn = classifyFn;
    callout.flowDeleteFn = isFlowCallout ? NwFlowDelete : NULL;

    NTSTATUS status = FwpsCalloutRegister1(deviceObject, &callout, &context->CalloutIds[slot]);
    if (NT_SUCCESS(status)) context->CalloutsRegistered[slot] = TRUE;
    return status;
}

NTSTATUS NwRegisterCallouts(PDEVICE_OBJECT deviceObject, PNW_DEVICE_CONTEXT context)
{
    NTSTATUS status;
    NwSetCalloutDeviceContext(context);
    status = NwRegisterOne(deviceObject, context, 0, &NwCalloutFlowV4, NwClassify, FALSE);
    if (!NT_SUCCESS(status)) goto Failure;
    status = NwRegisterOne(deviceObject, context, 1, &NwCalloutFlowV6, NwClassify, FALSE);
    if (!NT_SUCCESS(status)) goto Failure;
    status = NwRegisterOne(deviceObject, context, g_TransportSlotV4, &NwCalloutTransportV4, NwClassify, TRUE);
    if (!NT_SUCCESS(status)) goto Failure;
    status = NwRegisterOne(deviceObject, context, g_TransportSlotV6, &NwCalloutTransportV6, NwClassify, TRUE);
    if (!NT_SUCCESS(status)) goto Failure;
    return STATUS_SUCCESS;

Failure:
    NwUnregisterCallouts(context);
    NwSetCalloutDeviceContext(NULL);
    return status;
}

NTSTATUS NwUnregisterCallouts(PNW_DEVICE_CONTEXT context)
{
    NTSTATUS finalStatus = STATUS_SUCCESS;
    for (LONG i = RTL_NUMBER_OF(context->CalloutIds) - 1; i >= 0; --i)
    {
        if (context->CalloutsRegistered[i])
        {
            NTSTATUS status = FwpsCalloutUnregisterById0(context->CalloutIds[i]);
            if (!NT_SUCCESS(status))
            {
                finalStatus = status;
                continue;
            }
            context->CalloutsRegistered[i] = FALSE;
            context->CalloutIds[i] = 0;
        }
    }
    if (NT_SUCCESS(finalStatus) && g_DeviceContext == context) g_DeviceContext = NULL;
    return finalStatus;
}

static PNW_GROUP_RUNTIME NwFindGroupByAppIdLocked(const FWP_BYTE_BLOB* appId, PNW_DEVICE_CONTEXT context)
{
    UINT32 groupIndex;
    UINT32 memberIndex;
    if (appId == NULL || appId->data == NULL) return NULL;

    for (groupIndex = 0; groupIndex < context->GroupCount; ++groupIndex)
    {
        PNW_GROUP_RUNTIME group = &context->Groups[groupIndex];
        const UCHAR* cursor = group->AppIds;
        UINT32 remaining = group->AppIdBytes;
        for (memberIndex = 0; memberIndex < group->MemberCount; ++memberIndex)
        {
            UINT32 length;
            if (remaining < sizeof(UINT32)) return NULL;
            RtlCopyMemory(&length, cursor, sizeof(length));
            cursor += sizeof(UINT32);
            remaining -= sizeof(UINT32);
            if (length == appId->size && length <= remaining
                && RtlCompareMemory(appId->data, cursor, length) == length)
                return group;
            if (length > remaining) return NULL;
            cursor += length;
            remaining -= length;
        }
    }
    return NULL;
}

static UINT32 NwGetNblBytes(NET_BUFFER_LIST* lists)
{
    UINT64 total = 0;
    NET_BUFFER_LIST* nbl;
    for (nbl = lists; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
    {
        NET_BUFFER* buffer;
        for (buffer = NET_BUFFER_LIST_FIRST_NB(nbl); buffer != NULL; buffer = NET_BUFFER_NEXT_NB(buffer))
        {
            total += NET_BUFFER_DATA_LENGTH(buffer);
            if (total > 0xFFFFFFFFULL) return 0xFFFFFFFFu;
        }
    }
    return (UINT32)total;
}

static BOOLEAN NwCaptureTransportMetadata(
    const FWPS_INCOMING_VALUES0* fixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    UINT16 layerId,
    PNW_PENDING_PACKET packet)
{
    UINT32 addressIndex;
    const FWP_VALUE0* value;
    if (fixedValues == NULL || metadata == NULL || packet == NULL) return FALSE;
    addressIndex = layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4
        ? FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS
        : FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
    if (addressIndex >= fixedValues->valueCount) return FALSE;
    value = &fixedValues->incomingValue[addressIndex].value;
    RtlZeroMemory(packet->RemoteAddress, sizeof(packet->RemoteAddress));
    if (layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4)
    {
        if (value->type != FWP_UINT32) return FALSE;
        UINT32 networkAddress = RtlUlongByteSwap(value->uint32);
        RtlCopyMemory(packet->RemoteAddress, &networkAddress, sizeof(networkAddress));
    }
    else
    {
        if (value->type != FWP_BYTE_ARRAY16_TYPE || value->byteArray16 == NULL) return FALSE;
        RtlCopyMemory(packet->RemoteAddress, value->byteArray16->byteArray16, 16);
    }
    packet->SendParams.remoteAddress = packet->RemoteAddress;
    packet->SendParams.remoteScopeId = metadata->remoteScopeId;
    if (FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA)
        && metadata->controlData != NULL && metadata->controlDataLength != 0)
    {
        if (metadata->controlDataLength > 64 * 1024) return FALSE;
        packet->ControlData = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, metadata->controlDataLength, NW_STRICT_TAG);
        if (packet->ControlData == NULL) return FALSE;
        RtlCopyMemory(packet->ControlData, metadata->controlData, metadata->controlDataLength);
        packet->SendParams.controlData = (WSACMSGHDR*)packet->ControlData;
        packet->SendParams.controlDataLength = metadata->controlDataLength;
    }
    if (FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_TRANSPORT_HEADER_INCLUDE_HEADER)
        && metadata->headerIncludeHeader != NULL && metadata->headerIncludeHeaderLength != 0)
    {
        if (metadata->headerIncludeHeaderLength > 64 * 1024) return FALSE;
        packet->HeaderIncludeHeader = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, metadata->headerIncludeHeaderLength, NW_STRICT_TAG);
        if (packet->HeaderIncludeHeader == NULL) return FALSE;
        RtlCopyMemory(packet->HeaderIncludeHeader, metadata->headerIncludeHeader,
            metadata->headerIncludeHeaderLength);
        packet->SendParams.headerIncludeHeader = packet->HeaderIncludeHeader;
        packet->SendParams.headerIncludeHeaderLength = metadata->headerIncludeHeaderLength;
    }
    return TRUE;
}

static BOOLEAN NwQueueTransportPacket(
    PNW_DEVICE_CONTEXT context,
    PNW_FLOW_CONTEXT flow,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    const FWPS_INCOMING_VALUES0* fixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    NET_BUFFER_LIST* original,
    UINT32 bytes,
    UINT16 layerId,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    NTSTATUS status;
    UINT64 classifyHandle = 0;
    NET_BUFFER_LIST* clone = NULL;
    PNW_PENDING_PACKET packet = NULL;

    if (context == NULL || flow == NULL || classifyContext == NULL || filter == NULL
        || fixedValues == NULL || metadata == NULL || original == NULL || classifyOut == NULL
        || !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)
        || !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_COMPARTMENT_ID))
        return FALSE;
    if (InterlockedCompareExchange(&context->Stopping, 0, 0) != 0) return FALSE;

    status = FwpsAllocateCloneNetBufferList0(original, NULL, NULL, 0, &clone);
    if (!NT_SUCCESS(status)) return FALSE;
    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status))
    {
        FwpsFreeCloneNetBufferList0(clone, 0);
        return FALSE;
    }
    status = FwpsPendClassify0(classifyHandle, filter->filterId, 0, classifyOut);
    if (!NT_SUCCESS(status))
    {
        FwpsReleaseClassifyHandle0(classifyHandle);
        FwpsFreeCloneNetBufferList0(clone, 0);
        return FALSE;
    }
    FwpsReleaseClassifyHandle0(classifyHandle);

    packet = (PNW_PENDING_PACKET)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*packet), NW_STRICT_TAG);
    if (packet == NULL)
    {
        FwpsCompleteClassify0(classifyHandle, 0, classifyOut);
        FwpsFreeCloneNetBufferList0(clone, 0);
        return FALSE;
    }
    RtlZeroMemory(packet, sizeof(*packet));
    packet->Clone = clone;
    packet->ClassifyHandle = classifyHandle;
    packet->FilterId = filter->filterId;
    packet->EndpointHandle = metadata->transportEndpointHandle;
    packet->Generation = flow->Group->Generation;
    packet->CompartmentId = metadata->compartmentId;
    packet->AddressFamily = layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4 ? AF_INET : AF_INET6;
    packet->Bytes = bytes;
    packet->EnqueuedAt100ns = KeQueryInterruptTime();
    InterlockedIncrement(&flow->References);
    packet->Flow = flow;
    packet->DeviceContext = context;
    packet->Pended = TRUE;
    if (!NwCaptureTransportMetadata(fixedValues, metadata, layerId, packet))
    {
        NwPendingCompleteDrop(context, packet, FALSE);
        return FALSE;
    }

    FwpsReferenceNetBufferList0(original, FALSE);
    packet->Original = original;
    if (!NwPendingTryEnqueue(context, packet))
    {
        NwPendingCompleteDrop(context, packet, FALSE);
        return FALSE;
    }

    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    return TRUE;
}

static void NwPermit(FWPS_CLASSIFY_OUT0* classifyOut)
{
    if (classifyOut != NULL && (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

void NTAPI NwClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContextValue,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    PNW_DEVICE_CONTEXT context = g_DeviceContext;
    UINT16 layerId;
    UNREFERENCED_PARAMETER(flowContextValue);

    if (classifyOut == NULL || (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) return;
    if (context == NULL || inFixedValues == NULL)
    {
        NwPermit(classifyOut);
        return;
    }
    layerId = inFixedValues->layerId;

    if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 || layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6)
    {
        UINT32 appIndex = layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4
            ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID
            : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID;
        const FWP_BYTE_BLOB* appId = NULL;
        PNW_GROUP_RUNTIME group = NULL;
        PNW_FLOW_CONTEXT flow = NULL;
        KIRQL oldIrql;
        UINT32 transportSlot = layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4
            ? g_TransportSlotV4 : g_TransportSlotV6;
        UINT16 transportLayer = layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4
            ? FWPS_LAYER_OUTBOUND_TRANSPORT_V4 : FWPS_LAYER_OUTBOUND_TRANSPORT_V6;
        if (appIndex < inFixedValues->valueCount
            && inFixedValues->incomingValue[appIndex].value.type == FWP_BYTE_BLOB_TYPE)
            appId = inFixedValues->incomingValue[appIndex].value.byteBlob;
        if (appId != NULL && inMetaValues != NULL
            && FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE))
        {
            KeAcquireSpinLock(&context->GroupLock, &oldIrql);
            group = NwFindGroupByAppIdLocked(appId, context);
            if (group != NULL)
            {
                if (!ExAcquireRundownProtection(&group->FlowRundown)) group = NULL;
                else InterlockedIncrement64(&group->ActiveFlows);
            }
            KeReleaseSpinLock(&context->GroupLock, oldIrql);
            if (group != NULL)
            {
                flow = (PNW_FLOW_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*flow), NW_STRICT_TAG);
                if (flow != NULL)
                {
                    RtlZeroMemory(flow, sizeof(*flow));
                    KeInitializeSpinLock(&flow->InjectionLock);
                    flow->References = 2;
                    flow->State = NwFlowRegistering;
                    flow->Group = group;
                    flow->FlowHandle = inMetaValues->flowHandle;
                    flow->LayerId = transportLayer;
                    flow->CalloutId = context->CalloutIds[transportSlot];
                    flow->DeviceContext = context;
                    BOOLEAN duplicate = FALSE;
                    KeAcquireSpinLock(&context->FlowLock, &oldIrql);
                    {
                        PLIST_ENTRY link;
                        for (link = context->FlowContexts.Flink; link != &context->FlowContexts; link = link->Flink)
                        {
                            PNW_FLOW_CONTEXT existing = CONTAINING_RECORD(link, NW_FLOW_CONTEXT, Link);
                            if (existing->FlowHandle == flow->FlowHandle)
                            {
                                duplicate = TRUE;
                                break;
                            }
                        }
                    }
                    if (!duplicate) InsertTailList(&context->FlowContexts, &flow->Link);
                    if (!duplicate) flow->InList = TRUE;
                    KeReleaseSpinLock(&context->FlowLock, oldIrql);
                    if (duplicate)
                    {
                        NwFlowRelease(flow);
                        NwFlowRelease(flow);
                        flow = NULL;
                        group = NULL;
                    }
                    else if (NT_SUCCESS(FwpsFlowAssociateContext0(flow->FlowHandle, transportLayer,
                            flow->CalloutId, (UINT64)(ULONG_PTR)flow)))
                    {
                        KeAcquireSpinLock(&context->FlowLock, &oldIrql);
                        if (flow->State == NwFlowRegistering)
                            flow->State = NwFlowAssociated;
                        else if (flow->State == NwFlowDeletePending)
                            flow->State = NwFlowDetaching;
                        KeReleaseSpinLock(&context->FlowLock, oldIrql);
                        group = NULL;
                    }
                    else
                    {
                        BOOLEAN releaseOwner = FALSE;
                        KeAcquireSpinLock(&context->FlowLock, &oldIrql);
                        if (flow->State == NwFlowRegistering)
                        {
                            flow->State = NwFlowDetaching;
                            RemoveEntryList(&flow->Link);
                            releaseOwner = TRUE;
                        }
                        KeReleaseSpinLock(&context->FlowLock, oldIrql);
                        if (releaseOwner) NwFlowRelease(flow);
                        NwFlowRelease(flow);
                        flow = NULL;
                        group = NULL;
                    }
                }
                if (flow != NULL) NwFlowRelease(flow);
                else if (group != NULL)
                {
                    InterlockedDecrement64(&group->ActiveFlows);
                    ExReleaseRundownProtection(&group->FlowRundown);
                    group = NULL;
                }
                if (group != NULL) ExReleaseRundownProtection(&group->FlowRundown);
            }
        }
        NwPermit(classifyOut);
        return;
    }

    if ((layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4 || layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V6)
        && layerData != NULL && inMetaValues != NULL
        && FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE))
    {
        HANDLE injectionHandle = layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4
            ? context->InjectionV4 : context->InjectionV6;
        FWPS_PACKET_INJECTION_STATE injectionState = injectionHandle == NULL
            ? FWPS_PACKET_NOT_INJECTED
            : FwpsQueryPacketInjectionState0(injectionHandle, (NET_BUFFER_LIST*)layerData, NULL);
        if (injectionState == FWPS_PACKET_INJECTED_BY_SELF
            || injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
        {
            NwPermit(classifyOut);
            return;
        }
        PNW_FLOW_CONTEXT flow = NwFlowReference(context, inMetaValues->flowHandle, layerId);
        if (flow == NULL)
        {
            NwPermit(classifyOut);
            return;
        }
        {
            UINT32 bytes = NwGetNblBytes((NET_BUFFER_LIST*)layerData);
            if (bytes != 0 && !NwTokenBucketTryConsume(&flow->Group->Bucket, bytes, KeQueryInterruptTime()))
            {
                if (!NwQueueTransportPacket(context, flow, classifyContext, filter, inFixedValues,
                        inMetaValues, (NET_BUFFER_LIST*)layerData, bytes, layerId, classifyOut))
                    classifyOut->actionType = FWP_ACTION_BLOCK;
                else
                {
                    NwFlowRelease(flow);
                    return;
                }
            }
            else
                classifyOut->actionType = FWP_ACTION_PERMIT;
        }
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        NwFlowRelease(flow);
        return;
    }

    NwPermit(classifyOut);
}
