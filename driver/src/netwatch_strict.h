#pragma once

#include <ntddk.h>
#ifndef _KERNEL_MODE
#define _KERNEL_MODE 1
#endif
#include <wdf.h>
#include <ndis.h>
#include <initguid.h>
#include <fwpsk.h>

#define NW_STRICT_DEVICE_TYPE 0x8337
#define NW_STRICT_IOCTL(function, access) CTL_CODE(NW_STRICT_DEVICE_TYPE, function, METHOD_BUFFERED, access)
#define IOCTL_NW_STRICT_HELLO NW_STRICT_IOCTL(1, FILE_READ_ACCESS)
#define IOCTL_NW_STRICT_APPLY_SNAPSHOT NW_STRICT_IOCTL(2, FILE_WRITE_ACCESS)
#define IOCTL_NW_STRICT_REMOVE_SESSION NW_STRICT_IOCTL(3, FILE_WRITE_ACCESS)
#define IOCTL_NW_STRICT_QUERY_STATS NW_STRICT_IOCTL(4, FILE_READ_ACCESS)
#define IOCTL_NW_STRICT_PING NW_STRICT_IOCTL(5, FILE_READ_ACCESS)

#define NW_STRICT_MAGIC 0x4E575354
#define NW_STRICT_PROTOCOL_MAJOR 1
#define NW_STRICT_PROTOCOL_MINOR 0
#define NW_STRICT_MAX_CALLOUTS 6
#define NW_STRICT_MAX_GROUPS 256
#define NW_STRICT_MAX_MEMBERS 64
#define NW_STRICT_MAX_APPID_BYTES_PER_GROUP (64 * 1024)
#define NW_STRICT_MAX_APPID_BYTES_TOTAL (4 * 1024 * 1024)
#define NW_STRICT_MAX_PENDING_ITEMS 4096
#define NW_STRICT_MAX_PENDING_BYTES (2ULL * 1024 * 1024)
#define NW_STRICT_PENDING_PUMP_BATCH 64
#define NW_STRICT_PENDING_PUMP_PERIOD_MS 2
#define NW_STRICT_PENDING_TIMEOUT_MS 5000
#define NW_STRICT_CAPABILITY_STRICT_SHAPING (1ULL << 0)
#define NW_STRICT_CAPABILITY_ASYNC_QUEUE (1ULL << 1)
#define NW_STRICT_CAPABILITY_TRANSPORT_REINJECT (1ULL << 2)
#define NW_STRICT_CAPABILITY_TEARDOWN_SAFE (1ULL << 3)
#define NW_STRICT_CAPABILITY_LIVE_STATS (1ULL << 4)
#define NW_STRICT_CAPABILITY_REQUIRED (NW_STRICT_CAPABILITY_STRICT_SHAPING \
    | NW_STRICT_CAPABILITY_ASYNC_QUEUE | NW_STRICT_CAPABILITY_TRANSPORT_REINJECT \
    | NW_STRICT_CAPABILITY_TEARDOWN_SAFE | NW_STRICT_CAPABILITY_LIVE_STATS)
#define NW_STRICT_TAG 'tSWN'
#define NW_FLOW_STATE_REGISTERING 1
#define NW_FLOW_STATE_ASSOCIATED 2
#define NW_FLOW_STATE_DELETE_PENDING 3
#define NW_FLOW_STATE_DETACHING 4
#define NW_FLOW_STATE_INJECTING 5
#define NW_FLOW_STATE_DELETE_AFTER_INJECT 6

#if (NTDDI_VERSION < NTDDI_WIN7)
#error NetWatch strict async transport callouts require WFP classify version 1 or later.
#endif

DEFINE_GUID(GUID_DEVINTERFACE_NETWATCH_STRICT, 0x34bcf6aa, 0xa819, 0x43f4, 0xa1, 0x8c, 0x71, 0x13, 0x0f, 0x1b, 0x92, 0xe4);
DEFINE_GUID(NW_STRICT_CALLOUT_CONNECT_V4, 0xd8a1e037, 0x5294, 0x4b2f, 0x92, 0xad, 0x34, 0x77, 0x5d, 0x93, 0x0e, 0x11);
DEFINE_GUID(NW_STRICT_CALLOUT_CONNECT_V6, 0xb1e1976a, 0x10c6, 0x40c2, 0x85, 0x32, 0x52, 0x1c, 0x04, 0x73, 0x2d, 0x60);
DEFINE_GUID(NW_STRICT_CALLOUT_OUT_V4, 0x478f21f0, 0x3e8a, 0x43ee, 0x97, 0x84, 0x14, 0xdc, 0x25, 0xc6, 0x88, 0x5b);
DEFINE_GUID(NW_STRICT_CALLOUT_OUT_V6, 0xf1ab0340, 0x78e3, 0x47b6, 0xa0, 0x2a, 0xda, 0xe3, 0xf1, 0x95, 0x7e, 0x96);

#pragma pack(push, 8)
typedef struct _NW_MESSAGE_HEADER {
    UINT32 Magic;
    UINT16 MajorVersion;
    UINT16 MinorVersion;
    UINT32 HeaderSize;
    UINT32 TotalSize;
    UINT32 Command;
    UINT32 Flags;
    GUID RequestId;
    GUID SessionId;
    INT64 Generation;
} NW_MESSAGE_HEADER, *PNW_MESSAGE_HEADER;

typedef struct _NW_HELLO_RESPONSE {
    NW_MESSAGE_HEADER Header;
    UINT64 CapabilityBits;
    UINT32 MaxGroups;
    UINT32 MaxMembersPerGroup;
    UINT32 MaxQueueBytes;
    UINT32 DriverBuild;
    INT32 NativeStatus;
} NW_HELLO_RESPONSE, *PNW_HELLO_RESPONSE;

typedef struct _NW_SNAPSHOT_HEADER {
    NW_MESSAGE_HEADER Header;
    UINT32 GroupCount;
    UINT32 EntrySize;
} NW_SNAPSHOT_HEADER, *PNW_SNAPSHOT_HEADER;

typedef struct _NW_GROUP_ENTRY_HEADER {
    GUID GroupId;
    UINT32 MemberCount;
    UINT32 AppIdBytes;
    INT64 BytesPerSecond;
    INT64 BurstBytes;
    INT64 QueueLimitBytes;
} NW_GROUP_ENTRY_HEADER, *PNW_GROUP_ENTRY_HEADER;

typedef struct _NW_STATS_RESPONSE_HEADER {
    NW_MESSAGE_HEADER Header;
    UINT32 GroupCount;
    UINT32 EntrySize;
} NW_STATS_RESPONSE_HEADER, *PNW_STATS_RESPONSE_HEADER;

typedef struct _NW_GROUP_STATS {
    GUID GroupId;
    INT64 Generation;
    INT64 AccountedBytes;
    INT64 QueuedBytes;
    INT64 DroppedBytes;
    INT64 UnmatchedFlows;
    INT64 ActiveFlows;
    INT64 BurstPeakBytes;
} NW_GROUP_STATS, *PNW_GROUP_STATS;
#pragma pack(pop)

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

typedef struct _NW_GROUP_RUNTIME {
    GUID GroupId;
    UINT64 Generation;
    UINT32 MemberCount;
    UINT32 AppIdBytes;
    UINT64 QueueLimitBytes;
    PUCHAR AppIds;
    EX_RUNDOWN_REF FlowRundown;
    NW_TOKEN_BUCKET Bucket;
    volatile LONG64 UnmatchedFlows;
    volatile LONG64 ActiveFlows;
    volatile LONG64 QueuedBytes;
} NW_GROUP_RUNTIME, *PNW_GROUP_RUNTIME;

typedef struct _NW_FLOW_CONTEXT NW_FLOW_CONTEXT, *PNW_FLOW_CONTEXT;
typedef struct _NW_DEVICE_CONTEXT NW_DEVICE_CONTEXT, *PNW_DEVICE_CONTEXT;

typedef struct _NW_FLOW_CONTEXT {
    LIST_ENTRY Link;
    volatile LONG References;
    KSPIN_LOCK InjectionLock;
    volatile LONG InjectionInProgress;
    volatile LONG State;
    volatile LONG DeleteCallbackSeen;
    BOOLEAN InList;
    PNW_DEVICE_CONTEXT DeviceContext;
    PNW_GROUP_RUNTIME Group;
    UINT64 FlowHandle;
    UINT32 CalloutId;
    UINT16 LayerId;
    UINT16 AddressFamily;
} NW_FLOW_CONTEXT, *PNW_FLOW_CONTEXT;

typedef struct _NW_PENDING_PACKET {
    LIST_ENTRY Link;
    NET_BUFFER_LIST* Clone;
    NET_BUFFER_LIST* Original;
    UINT64 ClassifyHandle;
    UINT64 FilterId;
    UINT64 EndpointHandle;
    UINT64 Generation;
    ULONG CompartmentId;
    ADDRESS_FAMILY AddressFamily;
    SCOPE_ID RemoteScopeId;
    UCHAR RemoteAddress[16];
    PUCHAR ControlData;
    PUCHAR HeaderIncludeHeader;
    FWPS_TRANSPORT_SEND_PARAMS1 SendParams;
    UINT32 Bytes;
    UINT64 EnqueuedAt100ns;
    PNW_DEVICE_CONTEXT DeviceContext;
    PNW_FLOW_CONTEXT Flow;
    BOOLEAN Pended;
    BOOLEAN Injected;
    BOOLEAN Cancelled;
    BOOLEAN Counted;
} NW_PENDING_PACKET, *PNW_PENDING_PACKET;

typedef struct _NW_DEVICE_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    UINT32 CalloutIds[NW_STRICT_MAX_CALLOUTS];
    BOOLEAN CalloutsRegistered[NW_STRICT_MAX_CALLOUTS];
    KSPIN_LOCK GroupLock;
    KSPIN_LOCK FlowLock;
    LIST_ENTRY FlowContexts;
    KSPIN_LOCK PendingLock;
    LIST_ENTRY PendingPackets;
    UINT32 PendingItemCount;
    UINT64 PendingBytes;
    KTIMER PendingTimer;
    KDPC PendingDpc;
    BOOLEAN PendingTimerStarted;
    volatile LONG Stopping;
    volatile LONG CapabilitiesReady;
    volatile LONG InFlightPackets;
    KEVENT InFlightZeroEvent;
    HANDLE InjectionV4;
    HANDLE InjectionV6;
    INT64 AppliedGeneration;
    GUID SessionId;
    UINT32 GroupCount;
    PUCHAR AppIdStorage;
    SIZE_T AppIdStorageBytes;
    PNW_GROUP_RUNTIME Groups;
    NW_GROUP_STATS Stats[NW_STRICT_MAX_GROUPS];
} NW_DEVICE_CONTEXT, *PNW_DEVICE_CONTEXT;

DRIVER_INITIALIZE DriverEntry;
void NwEvtDriverUnload(WDFDRIVER driver);
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL NwEvtIoDeviceControl;

void NTAPI NwClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut);

NTSTATUS NwRegisterCallouts(PDEVICE_OBJECT deviceObject, PNW_DEVICE_CONTEXT context);
NTSTATUS NwUnregisterCallouts(PNW_DEVICE_CONTEXT context);
void NwSetCalloutDeviceContext(PNW_DEVICE_CONTEXT context);
void NwRemoveAllFlowContexts(PNW_DEVICE_CONTEXT context);
void NwFlowReleaseReference(PNW_FLOW_CONTEXT flow);
NTSTATUS NwTokenBucketInitialize(PNW_TOKEN_BUCKET bucket, UINT64 rateBytesPerSecond, UINT64 burstBytes);
BOOLEAN NwTokenBucketTryConsume(PNW_TOKEN_BUCKET bucket, UINT32 bytes, UINT64 now100ns);
BOOLEAN NwPendingTryEnqueue(PNW_DEVICE_CONTEXT context, PNW_PENDING_PACKET packet);
PNW_PENDING_PACKET NwPendingDequeue(PNW_DEVICE_CONTEXT context);
void NwPendingDrain(PNW_DEVICE_CONTEXT context, BOOLEAN completeClassify);
void NwPendingCancelFlow(PNW_DEVICE_CONTEXT context, PNW_FLOW_CONTEXT flow);
void NwPendingPump(PNW_DEVICE_CONTEXT context);
void NwPendingCompleteDrop(PNW_DEVICE_CONTEXT context, PNW_PENDING_PACKET packet, BOOLEAN dispatchLevel);
