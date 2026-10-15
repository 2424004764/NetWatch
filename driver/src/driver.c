#include "netwatch_strict.h"

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(NW_DEVICE_CONTEXT, NwGetDeviceContext)

static WDFDEVICE g_ControlDevice;

static VOID NwPendingDpcRoutine(
    _In_ KDPC* dpc,
    _In_opt_ PVOID deferredContext,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2)
{
    PNW_DEVICE_CONTEXT context = (PNW_DEVICE_CONTEXT)deferredContext;
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);
    NwPendingPump(context);
}

static NTSTATUS NwComplete(WDFREQUEST request, NTSTATUS status, size_t information)
{
    WdfRequestCompleteWithInformation(request, status, information);
    return status;
}

static BOOLEAN NwGuidIsZero(const GUID* value)
{
    static const GUID zero = { 0 };
    return value != NULL && RtlCompareMemory(value, &zero, sizeof(GUID)) == sizeof(GUID);
}

static NTSTATUS NwValidateHeader(const NW_MESSAGE_HEADER* header, size_t inputLength, UINT32 command)
{
    if (header == NULL || inputLength < sizeof(NW_MESSAGE_HEADER)) return STATUS_BUFFER_TOO_SMALL;
    if (header->Magic != NW_STRICT_MAGIC || header->MajorVersion != NW_STRICT_PROTOCOL_MAJOR)
        return STATUS_REVISION_MISMATCH;
    if (header->HeaderSize != sizeof(NW_MESSAGE_HEADER) || header->TotalSize != inputLength)
        return STATUS_INVALID_PARAMETER;
    if (header->Command != command) return STATUS_INVALID_DEVICE_REQUEST;
    return STATUS_SUCCESS;
}

void NTAPI NwEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request,
    size_t outputBufferLength, size_t inputBufferLength, ULONG ioControlCode)
{
    UNREFERENCED_PARAMETER(outputBufferLength);
    WDFDEVICE device = WdfIoQueueGetDevice(queue);
    PNW_DEVICE_CONTEXT context = NwGetDeviceContext(device);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t information = 0;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInput = 0;
    KIRQL groupIrql = PASSIVE_LEVEL;

    switch (ioControlCode)
    {
    case IOCTL_NW_STRICT_HELLO:
    case IOCTL_NW_STRICT_PING:
        status = WdfRequestRetrieveInputBuffer(request, sizeof(NW_MESSAGE_HEADER), &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        status = WdfRequestRetrieveOutputBuffer(request,
            ioControlCode == IOCTL_NW_STRICT_HELLO ? sizeof(NW_HELLO_RESPONSE) : sizeof(NW_MESSAGE_HEADER),
            &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        actualInput = inputBufferLength;
        status = NwValidateHeader((const NW_MESSAGE_HEADER*)inputBuffer, actualInput,
            ioControlCode == IOCTL_NW_STRICT_HELLO ? 1 : 5);
        if (!NT_SUCCESS(status)) break;
        if (ioControlCode == IOCTL_NW_STRICT_HELLO)
        {
            NW_HELLO_RESPONSE* response = (NW_HELLO_RESPONSE*)outputBuffer;
            RtlZeroMemory(response, sizeof(*response));
            response->Header = *(NW_MESSAGE_HEADER*)inputBuffer;
            response->Header.TotalSize = sizeof(*response);
            response->CapabilityBits = InterlockedCompareExchange(&context->CapabilitiesReady, 0, 0) != 0
                ? NW_STRICT_CAPABILITY_REQUIRED : 0;
            response->MaxGroups = NW_STRICT_MAX_GROUPS;
            response->MaxMembersPerGroup = NW_STRICT_MAX_MEMBERS;
            response->MaxQueueBytes = InterlockedCompareExchange(&context->CapabilitiesReady, 0, 0) != 0
                ? (UINT32)NW_STRICT_MAX_PENDING_BYTES : 0;
            response->DriverBuild = 1;
            response->NativeStatus = InterlockedCompareExchange(&context->CapabilitiesReady, 0, 0) != 0
                ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
            information = sizeof(*response);
        }
        else
        {
            RtlCopyMemory(outputBuffer, inputBuffer, sizeof(NW_MESSAGE_HEADER));
            information = sizeof(NW_MESSAGE_HEADER);
        }
        status = STATUS_SUCCESS;
        break;

    case IOCTL_NW_STRICT_APPLY_SNAPSHOT:
        status = WdfRequestRetrieveInputBuffer(request, sizeof(NW_SNAPSHOT_HEADER), &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(NW_MESSAGE_HEADER), &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        status = NwValidateHeader((const NW_MESSAGE_HEADER*)inputBuffer, inputBufferLength, 2);
        if (!NT_SUCCESS(status)) break;
        if (inputBufferLength > 4 * 1024 * 1024)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            const NW_SNAPSHOT_HEADER* snapshot = (const NW_SNAPSHOT_HEADER*)inputBuffer;
            size_t remaining;
            const UCHAR* cursor;
            UINT32 groupIndex;
            UINT32 totalAppIdBytes = 0;
            NW_GROUP_RUNTIME* newGroups = NULL;
            PUCHAR newAppIdStorage = NULL;
            PUCHAR appIdCursor = NULL;
            if (snapshot->GroupCount > NW_STRICT_MAX_GROUPS
                || snapshot->EntrySize != sizeof(NW_GROUP_ENTRY_HEADER)
                || snapshot->Header.Generation <= 0
                || (snapshot->Header.SessionId.Data1 == 0 && snapshot->Header.SessionId.Data2 == 0
                    && snapshot->Header.SessionId.Data3 == 0 && snapshot->Header.SessionId.Data4[0] == 0
                    && snapshot->Header.SessionId.Data4[1] == 0 && snapshot->Header.SessionId.Data4[2] == 0
                    && snapshot->Header.SessionId.Data4[3] == 0 && snapshot->Header.SessionId.Data4[4] == 0
                    && snapshot->Header.SessionId.Data4[5] == 0 && snapshot->Header.SessionId.Data4[6] == 0
                    && snapshot->Header.SessionId.Data4[7] == 0)
                || inputBufferLength < sizeof(NW_SNAPSHOT_HEADER))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            remaining = inputBufferLength - sizeof(NW_SNAPSHOT_HEADER);
            cursor = (const UCHAR*)inputBuffer + sizeof(NW_SNAPSHOT_HEADER);
            for (groupIndex = 0; groupIndex < snapshot->GroupCount; ++groupIndex)
            {
                const NW_GROUP_ENTRY_HEADER* entry;
                UINT32 memberIndex;
                UINT32 memberBytes = 0;
                const UCHAR* memberCursor;
                if (remaining < sizeof(NW_GROUP_ENTRY_HEADER))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                entry = (const NW_GROUP_ENTRY_HEADER*)cursor;
                {
                    const UCHAR* previous = (const UCHAR*)inputBuffer + sizeof(NW_SNAPSHOT_HEADER);
                    UINT32 checkIndex;
                    for (checkIndex = 0; checkIndex < groupIndex; ++checkIndex)
                    {
                        const NW_GROUP_ENTRY_HEADER* prior = (const NW_GROUP_ENTRY_HEADER*)previous;
                        if (RtlCompareMemory(&prior->GroupId, &entry->GroupId, sizeof(GUID)) == sizeof(GUID))
                        {
                            status = STATUS_INVALID_PARAMETER;
                            break;
                        }
                        previous += sizeof(NW_GROUP_ENTRY_HEADER) + prior->AppIdBytes;
                    }
                    if (!NT_SUCCESS(status)) break;
                }
                if (entry->MemberCount == 0 || entry->MemberCount > NW_STRICT_MAX_MEMBERS
                    || entry->AppIdBytes == 0 || entry->AppIdBytes > 64 * 1024
                    || entry->BytesPerSecond <= 0 || entry->BytesPerSecond > 1250000000LL
                    || entry->BurstBytes <= 0 || entry->BurstBytes > 4 * 1024 * 1024
                    || entry->QueueLimitBytes < 0 || entry->QueueLimitBytes > 16 * 1024 * 1024
                    || entry->AppIdBytes > remaining - sizeof(NW_GROUP_ENTRY_HEADER))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                memberCursor = cursor + sizeof(NW_GROUP_ENTRY_HEADER);
                for (memberIndex = 0; memberIndex < entry->MemberCount; ++memberIndex)
                {
                    UINT32 appIdLength;
                    if (memberBytes > entry->AppIdBytes
                        || entry->AppIdBytes - memberBytes < sizeof(UINT32))
                    {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    RtlCopyMemory(&appIdLength, memberCursor + memberBytes, sizeof(appIdLength));
                    memberBytes += sizeof(UINT32);
                    if (appIdLength == 0 || appIdLength > 4096
                        || appIdLength > entry->AppIdBytes - memberBytes)
                    {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    memberBytes += appIdLength;
                }
                if (!NT_SUCCESS(status)) break;
                if (memberBytes != entry->AppIdBytes)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                cursor += sizeof(NW_GROUP_ENTRY_HEADER) + entry->AppIdBytes;
                remaining -= sizeof(NW_GROUP_ENTRY_HEADER) + entry->AppIdBytes;
                if (entry->AppIdBytes > NW_STRICT_MAX_APPID_BYTES_TOTAL - totalAppIdBytes)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                totalAppIdBytes += entry->AppIdBytes;
            }
            if (!NT_SUCCESS(status)) break;
            if (remaining != 0)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            newGroups = (NW_GROUP_RUNTIME*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(NW_GROUP_RUNTIME) * snapshot->GroupCount, NW_STRICT_TAG);
            if (newGroups == NULL && snapshot->GroupCount != 0)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            if (newGroups != NULL)
                RtlZeroMemory(newGroups, sizeof(NW_GROUP_RUNTIME) * snapshot->GroupCount);
            if (totalAppIdBytes != 0)
            {
                newAppIdStorage = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalAppIdBytes, NW_STRICT_TAG);
                if (newAppIdStorage == NULL)
                {
                    if (newGroups != NULL) ExFreePoolWithTag(newGroups, NW_STRICT_TAG);
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }
            }

            cursor = (const UCHAR*)inputBuffer + sizeof(NW_SNAPSHOT_HEADER);
            remaining = inputBufferLength - sizeof(NW_SNAPSHOT_HEADER);
            appIdCursor = newAppIdStorage;
            for (groupIndex = 0; groupIndex < snapshot->GroupCount; ++groupIndex)
            {
                const NW_GROUP_ENTRY_HEADER* entry = (const NW_GROUP_ENTRY_HEADER*)cursor;
                NW_GROUP_RUNTIME* runtime = &newGroups[groupIndex];
                runtime->GroupId = entry->GroupId;
                runtime->Generation = (UINT64)snapshot->Header.Generation;
                runtime->MemberCount = entry->MemberCount;
                runtime->AppIdBytes = entry->AppIdBytes;
                runtime->QueueLimitBytes = (UINT64)entry->QueueLimitBytes;
                runtime->AppIds = appIdCursor;
                ExInitializeRundownProtection(&runtime->FlowRundown);
                RtlCopyMemory(appIdCursor, cursor + sizeof(NW_GROUP_ENTRY_HEADER), entry->AppIdBytes);
                status = NwTokenBucketInitialize(&runtime->Bucket,
                    (UINT64)entry->BytesPerSecond, (UINT64)entry->BurstBytes);
                if (!NT_SUCCESS(status)) break;
                appIdCursor += entry->AppIdBytes;
                cursor += sizeof(NW_GROUP_ENTRY_HEADER) + entry->AppIdBytes;
                remaining -= sizeof(NW_GROUP_ENTRY_HEADER) + entry->AppIdBytes;
            }
            if (!NT_SUCCESS(status))
            {
                if (newAppIdStorage != NULL) ExFreePoolWithTag(newAppIdStorage, NW_STRICT_TAG);
                if (newGroups != NULL) ExFreePoolWithTag(newGroups, NW_STRICT_TAG);
                break;
            }

            KeAcquireSpinLock(&context->GroupLock, &groupIrql);
            if ((!NwGuidIsZero(&context->SessionId)
                    && RtlCompareMemory(&context->SessionId, &snapshot->Header.SessionId, sizeof(GUID)) != sizeof(GUID))
                || (!NwGuidIsZero(&context->SessionId)
                    && snapshot->Header.Generation <= context->AppliedGeneration))
            {
                const BOOLEAN wrongOwner = !NwGuidIsZero(&context->SessionId)
                    && RtlCompareMemory(&context->SessionId, &snapshot->Header.SessionId, sizeof(GUID)) != sizeof(GUID);
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                if (newAppIdStorage != NULL) ExFreePoolWithTag(newAppIdStorage, NW_STRICT_TAG);
                if (newGroups != NULL) ExFreePoolWithTag(newGroups, NW_STRICT_TAG);
                status = wrongOwner ? STATUS_SHARING_VIOLATION : STATUS_REVISION_MISMATCH;
                break;
            }
            {
            PNW_GROUP_RUNTIME oldGroups = context->Groups;
            PUCHAR oldAppIdStorage = context->AppIdStorage;
            UINT32 oldGroupCount = context->GroupCount;
            UINT32 oldIndex;
            for (oldIndex = 0; oldIndex < oldGroupCount; ++oldIndex)
            {
                if (InterlockedCompareExchange64(&oldGroups[oldIndex].QueuedBytes, 0, 0) != 0)
                {
                    KeReleaseSpinLock(&context->GroupLock, groupIrql);
                    if (newAppIdStorage != NULL) ExFreePoolWithTag(newAppIdStorage, NW_STRICT_TAG);
                    if (newGroups != NULL) ExFreePoolWithTag(newGroups, NW_STRICT_TAG);
                    status = STATUS_DEVICE_BUSY;
                    break;
                }
            }
            if (!NT_SUCCESS(status)) break;

                for (oldIndex = 0; oldIndex < oldGroupCount; ++oldIndex)
                {
                    if (InterlockedCompareExchange64(&oldGroups[oldIndex].ActiveFlows, 0, 0) != 0)
                    {
                        KeReleaseSpinLock(&context->GroupLock, groupIrql);
                        if (newAppIdStorage != NULL) ExFreePoolWithTag(newAppIdStorage, NW_STRICT_TAG);
                        if (newGroups != NULL) ExFreePoolWithTag(newGroups, NW_STRICT_TAG);
                        status = STATUS_DEVICE_BUSY;
                        break;
                    }
                }
                if (!NT_SUCCESS(status)) break;
                for (oldIndex = 0; oldIndex < oldGroupCount; ++oldIndex)
                    ExRundownCompleted(&oldGroups[oldIndex].FlowRundown);
                context->Groups = newGroups;
                context->SessionId = snapshot->Header.SessionId;
                context->AppIdStorage = newAppIdStorage;
                context->AppIdStorageBytes = totalAppIdBytes;
                context->GroupCount = snapshot->GroupCount;
                context->AppliedGeneration = snapshot->Header.Generation;
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                for (oldIndex = 0; oldIndex < oldGroupCount; ++oldIndex)
                    ExWaitForRundownProtectionRelease(&oldGroups[oldIndex].FlowRundown);
                if (oldGroups != NULL) ExFreePoolWithTag(oldGroups, NW_STRICT_TAG);
                if (oldAppIdStorage != NULL) ExFreePoolWithTag(oldAppIdStorage, NW_STRICT_TAG);
            }
            {
                NW_MESSAGE_HEADER responseHeader = snapshot->Header;
                responseHeader.TotalSize = sizeof(NW_MESSAGE_HEADER);
                RtlCopyMemory(outputBuffer, &responseHeader, sizeof(responseHeader));
            }
            information = sizeof(NW_MESSAGE_HEADER);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_NW_STRICT_REMOVE_SESSION:
        status = WdfRequestRetrieveInputBuffer(request, sizeof(NW_MESSAGE_HEADER), &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(NW_MESSAGE_HEADER), &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        status = NwValidateHeader((const NW_MESSAGE_HEADER*)inputBuffer, inputBufferLength, 3);
        if (!NT_SUCCESS(status)) break;
        {
            const NW_MESSAGE_HEADER* header = (const NW_MESSAGE_HEADER*)inputBuffer;
            PNW_GROUP_RUNTIME oldGroups = NULL;
            PUCHAR oldAppIdStorage = NULL;
            UINT32 oldGroupIndex;
            UINT32 oldGroupCount;
            if (NwGuidIsZero(&header->SessionId) || header->Generation <= 0)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            KeAcquireSpinLock(&context->GroupLock, &groupIrql);
            if (NwGuidIsZero(&context->SessionId))
            {
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                RtlCopyMemory(outputBuffer, inputBuffer, sizeof(NW_MESSAGE_HEADER));
                information = sizeof(NW_MESSAGE_HEADER);
                status = STATUS_SUCCESS;
                break;
            }
            if (RtlCompareMemory(&context->SessionId, &header->SessionId, sizeof(GUID)) != sizeof(GUID))
            {
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                status = NwGuidIsZero(&context->SessionId) ? STATUS_SUCCESS : STATUS_SHARING_VIOLATION;
                RtlCopyMemory(outputBuffer, inputBuffer, sizeof(NW_MESSAGE_HEADER));
                information = sizeof(NW_MESSAGE_HEADER);
                break;
            }
            if (header->Generation <= context->AppliedGeneration)
            {
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                status = STATUS_REVISION_MISMATCH;
                break;
            }
            oldGroups = context->Groups;
            oldAppIdStorage = context->AppIdStorage;
            oldGroupCount = context->GroupCount;
            for (oldGroupIndex = 0; oldGroupIndex < oldGroupCount; ++oldGroupIndex)
            {
                if (InterlockedCompareExchange64(&oldGroups[oldGroupIndex].ActiveFlows, 0, 0) != 0)
                {
                    KeReleaseSpinLock(&context->GroupLock, groupIrql);
                    status = STATUS_DEVICE_BUSY;
                    break;
                }
            }
            if (!NT_SUCCESS(status)) break;
            for (oldGroupIndex = 0; oldGroupIndex < oldGroupCount; ++oldGroupIndex)
                ExRundownCompleted(&oldGroups[oldGroupIndex].FlowRundown);
            context->Groups = NULL;
            context->GroupCount = 0;
            context->AppIdStorage = NULL;
            context->AppIdStorageBytes = 0;
            RtlZeroMemory(&context->SessionId, sizeof(context->SessionId));
            context->AppliedGeneration = 0;
            RtlZeroMemory(context->Stats, sizeof(context->Stats));
            KeReleaseSpinLock(&context->GroupLock, groupIrql);
            for (oldGroupIndex = 0; oldGroupIndex < oldGroupCount; ++oldGroupIndex)
                ExWaitForRundownProtectionRelease(&oldGroups[oldGroupIndex].FlowRundown);
            if (oldGroups != NULL) ExFreePoolWithTag(oldGroups, NW_STRICT_TAG);
            if (oldAppIdStorage != NULL) ExFreePoolWithTag(oldAppIdStorage, NW_STRICT_TAG);
            RtlCopyMemory(outputBuffer, inputBuffer, sizeof(NW_MESSAGE_HEADER));
            information = sizeof(NW_MESSAGE_HEADER);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_NW_STRICT_QUERY_STATS:
        status = WdfRequestRetrieveInputBuffer(request, sizeof(NW_MESSAGE_HEADER), &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) break;
        status = NwValidateHeader((const NW_MESSAGE_HEADER*)inputBuffer, inputBufferLength, 4);
        if (!NT_SUCCESS(status)) break;
        {
            const NW_MESSAGE_HEADER* header = (const NW_MESSAGE_HEADER*)inputBuffer;
            PNW_STATS_RESPONSE_HEADER response;
            size_t required;
            UINT32 index;
            if (header->Generation <= 0 || NwGuidIsZero(&header->SessionId))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            required = sizeof(NW_STATS_RESPONSE_HEADER)
                + sizeof(NW_GROUP_STATS) * NW_STRICT_MAX_GROUPS;
            status = WdfRequestRetrieveOutputBuffer(request, required, &outputBuffer, NULL);
            if (!NT_SUCCESS(status)) break;
            KeAcquireSpinLock(&context->GroupLock, &groupIrql);
            if (RtlCompareMemory(&context->SessionId, &header->SessionId, sizeof(GUID)) != sizeof(GUID))
            {
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                status = STATUS_SHARING_VIOLATION;
                break;
            }
            if (header->Generation != context->AppliedGeneration)
            {
                KeReleaseSpinLock(&context->GroupLock, groupIrql);
                status = STATUS_REVISION_MISMATCH;
                break;
            }
            required = sizeof(NW_STATS_RESPONSE_HEADER)
                + sizeof(NW_GROUP_STATS) * context->GroupCount;
            response = (PNW_STATS_RESPONSE_HEADER)outputBuffer;
            RtlZeroMemory(response, required);
            response->Header = *header;
            response->Header.TotalSize = (UINT32)required;
            response->GroupCount = context->GroupCount;
            response->EntrySize = sizeof(NW_GROUP_STATS);
            for (index = 0; index < context->GroupCount; ++index)
            {
                PNW_GROUP_RUNTIME runtime = &context->Groups[index];
                NW_GROUP_STATS* stats = (NW_GROUP_STATS*)((PUCHAR)outputBuffer
                    + sizeof(NW_STATS_RESPONSE_HEADER) + sizeof(NW_GROUP_STATS) * index);
                stats->GroupId = runtime->GroupId;
                stats->Generation = (INT64)runtime->Generation;
                stats->AccountedBytes = InterlockedCompareExchange64(&runtime->Bucket.AccountedBytes, 0, 0);
                stats->QueuedBytes = InterlockedCompareExchange64(&runtime->QueuedBytes, 0, 0);
                stats->DroppedBytes = InterlockedCompareExchange64(&runtime->Bucket.DroppedBytes, 0, 0);
                stats->BurstPeakBytes = InterlockedCompareExchange64(&runtime->Bucket.BurstPeakBytes, 0, 0);
                stats->UnmatchedFlows = InterlockedCompareExchange64(&runtime->UnmatchedFlows, 0, 0);
                stats->ActiveFlows = InterlockedCompareExchange64(&runtime->ActiveFlows, 0, 0);
            }
            information = required;
            KeReleaseSpinLock(&context->GroupLock, groupIrql);
            status = STATUS_SUCCESS;
        }
        break;
    }

    NwComplete(request, status, information);
}

static NTSTATUS NwCreateControlDevice(PDRIVER_OBJECT driverObject)
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\NetWatchStrict");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\NetWatchStrict");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(
        WdfGetDriver(), &sddl);
    if (deviceInit == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetDeviceType(deviceInit, NW_STRICT_DEVICE_TYPE);
    WdfDeviceInitSetExclusive(deviceInit, TRUE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);
    NTSTATUS status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, NW_DEVICE_CONTEXT);
    status = WdfDeviceCreate(&deviceInit, &attributes, &g_ControlDevice);
    if (!NT_SUCCESS(status)) return status;

    PNW_DEVICE_CONTEXT context = NwGetDeviceContext(g_ControlDevice);
    RtlZeroMemory(context, sizeof(*context));
    context->DeviceObject = WdfDeviceWdmGetDeviceObject(g_ControlDevice);
    KeInitializeSpinLock(&context->GroupLock);
    KeInitializeSpinLock(&context->FlowLock);
    InitializeListHead(&context->FlowContexts);
    KeInitializeSpinLock(&context->PendingLock);
    InitializeListHead(&context->PendingPackets);
    KeInitializeTimerEx(&context->PendingTimer, NotificationTimer);
    KeInitializeDpc(&context->PendingDpc, NwPendingDpcRoutine, context);
    KeInitializeEvent(&context->InFlightZeroEvent, NotificationEvent, TRUE);
    context->Stopping = 0;
    context->CapabilitiesReady = 0;
    context->InFlightPackets = 0;
    status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &context->InjectionV4);
    if (!NT_SUCCESS(status)) return status;
    status = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_TRANSPORT, &context->InjectionV6);
    if (!NT_SUCCESS(status))
    {
        FwpsInjectionHandleDestroy0(context->InjectionV4);
        context->InjectionV4 = NULL;
        return status;
    }

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -((LONGLONG)NW_STRICT_PENDING_PUMP_PERIOD_MS * 10000LL);
    KeSetTimerEx(&context->PendingTimer, dueTime, NW_STRICT_PENDING_PUMP_PERIOD_MS,
        &context->PendingDpc);
    context->PendingTimerStarted = TRUE;

    status = WdfDeviceCreateSymbolicLink(g_ControlDevice, &symbolicLink);
    if (!NT_SUCCESS(status))
    {
        KeCancelTimer(&context->PendingTimer);
        context->PendingTimerStarted = FALSE;
        KeRemoveQueueDpc(&context->PendingDpc);
        KeFlushQueuedDpcs();
        FwpsInjectionHandleDestroy0(context->InjectionV4);
        FwpsInjectionHandleDestroy0(context->InjectionV6);
        context->InjectionV4 = NULL;
        context->InjectionV6 = NULL;
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
        return status;
    }

    status = NwRegisterCallouts(context->DeviceObject, context);
    if (!NT_SUCCESS(status))
    {
        KeCancelTimer(&context->PendingTimer);
        context->PendingTimerStarted = FALSE;
        KeRemoveQueueDpc(&context->PendingDpc);
        KeFlushQueuedDpcs();
        FwpsInjectionHandleDestroy0(context->InjectionV4);
        FwpsInjectionHandleDestroy0(context->InjectionV6);
        context->InjectionV4 = NULL;
        context->InjectionV6 = NULL;
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
        return status;
    }

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = NwEvtIoDeviceControl;
    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttributes);
    queueAttributes.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfIoQueueCreate(g_ControlDevice, &queueConfig, &queueAttributes, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        NwUnregisterCallouts(context);
        KeCancelTimer(&context->PendingTimer);
        context->PendingTimerStarted = FALSE;
        KeRemoveQueueDpc(&context->PendingDpc);
        KeFlushQueuedDpcs();
        NwPendingDrain(context, TRUE);
        if (context->InjectionV4 != NULL)
        {
            FwpsInjectionHandleDestroy0(context->InjectionV4);
            context->InjectionV4 = NULL;
        }
        if (context->InjectionV6 != NULL)
        {
            FwpsInjectionHandleDestroy0(context->InjectionV6);
            context->InjectionV6 = NULL;
        }
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
        return status;
    }

    InterlockedExchange(&context->CapabilitiesReady, 1);
    WdfControlFinishInitializing(g_ControlDevice);
    UNREFERENCED_PARAMETER(driverObject);
    return STATUS_SUCCESS;
}

void NwEvtDriverUnload(WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);
    if (g_ControlDevice != NULL)
    {
        PNW_DEVICE_CONTEXT context = NwGetDeviceContext(g_ControlDevice);
        PNW_GROUP_RUNTIME oldGroups;
        PUCHAR oldAppIdStorage;
        UINT32 oldGroupIndex;
        UINT32 oldGroupCount;
        KIRQL oldIrql;
        NTSTATUS unregisterStatus;
        LARGE_INTEGER unregisterDelay;
        InterlockedExchange(&context->Stopping, 1);
        KeCancelTimer(&context->PendingTimer);
        context->PendingTimerStarted = FALSE;
        KeRemoveQueueDpc(&context->PendingDpc);
        KeFlushQueuedDpcs();
        NwPendingDrain(context, TRUE);
        NwRemoveAllFlowContexts(context);
        if (InterlockedCompareExchange(&context->InFlightPackets, 0, 0) != 0)
            KeWaitForSingleObject(&context->InFlightZeroEvent, Executive, KernelMode, FALSE, NULL);
        InterlockedExchange(&context->CapabilitiesReady, 0);
        unregisterDelay.QuadPart = -10000LL;
        for (;;)
        {
            unregisterStatus = NwUnregisterCallouts(context);
            if (NT_SUCCESS(unregisterStatus)) break;
            if (unregisterStatus != STATUS_DEVICE_BUSY && unregisterStatus != STATUS_PENDING)
                return;
            KeDelayExecutionThread(KernelMode, FALSE, &unregisterDelay);
        }
        NwSetCalloutDeviceContext(NULL);
        if (context->InjectionV4 != NULL)
        {
            FwpsInjectionHandleDestroy0(context->InjectionV4);
            context->InjectionV4 = NULL;
        }
        if (context->InjectionV6 != NULL)
        {
            FwpsInjectionHandleDestroy0(context->InjectionV6);
            context->InjectionV6 = NULL;
        }
        KeAcquireSpinLock(&context->FlowLock, &oldIrql);
        NT_ASSERT(IsListEmpty(&context->FlowContexts));
        KeReleaseSpinLock(&context->FlowLock, oldIrql);
        KeAcquireSpinLock(&context->GroupLock, &oldIrql);
        oldGroups = context->Groups;
        oldAppIdStorage = context->AppIdStorage;
        oldGroupCount = context->GroupCount;
        for (oldGroupIndex = 0; oldGroupIndex < oldGroupCount; ++oldGroupIndex)
            ExRundownCompleted(&oldGroups[oldGroupIndex].FlowRundown);
        context->Groups = NULL;
        context->GroupCount = 0;
        context->AppIdStorage = NULL;
        context->AppIdStorageBytes = 0;
        KeReleaseSpinLock(&context->GroupLock, oldIrql);
        for (oldGroupIndex = 0; oldGroupIndex < oldGroupCount; ++oldGroupIndex)
            ExWaitForRundownProtectionRelease(&oldGroups[oldGroupIndex].FlowRundown);
        if (oldGroups != NULL) ExFreePoolWithTag(oldGroups, NW_STRICT_TAG);
        if (oldAppIdStorage != NULL) ExFreePoolWithTag(oldAppIdStorage, NW_STRICT_TAG);
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = NwEvtDriverUnload;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    NTSTATUS status = WdfDriverCreate(driverObject, registryPath, &attributes, &config, &driver);
    if (!NT_SUCCESS(status)) return status;
    return NwCreateControlDevice(driverObject);
}
