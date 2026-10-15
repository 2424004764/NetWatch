#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

typedef uint8_t BOOLEAN;
typedef uint8_t KIRQL;
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef struct _NW_HOST_SPIN_LOCK { atomic_flag Value; } KSPIN_LOCK;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY* Flink; struct _LIST_ENTRY* Blink; } LIST_ENTRY;
typedef struct _NW_PENDING_PACKET NW_PENDING_PACKET, *PNW_PENDING_PACKET;
typedef struct _NW_DEVICE_CONTEXT NW_DEVICE_CONTEXT, *PNW_DEVICE_CONTEXT;
struct _NW_PENDING_PACKET { LIST_ENTRY Link; UINT64 ClassifyHandle; UINT64 FilterId; void* Flow; UINT32 Bytes; };
struct _NW_DEVICE_CONTEXT { KSPIN_LOCK PendingLock; LIST_ENTRY PendingPackets; UINT32 PendingItemCount; UINT64 PendingBytes; };
#define NW_STRICT_MAX_PENDING_ITEMS 4096
#define NW_STRICT_MAX_PENDING_BYTES (2ULL * 1024 * 1024)
#define TRUE 1
#define FALSE 0
#define InitializeListHead(list) do { (list)->Flink=(list); (list)->Blink=(list); } while (0)
#define IsListEmpty(list) ((list)->Flink == (list))
#define InsertTailList(list,entry) do { (entry)->Blink=(list)->Blink; (entry)->Flink=(list); (list)->Blink->Flink=(entry); (list)->Blink=(entry); } while (0)
static inline LIST_ENTRY* RemoveHeadList(LIST_ENTRY* list) { LIST_ENTRY* e=list->Flink; e->Flink->Blink=list; list->Flink=e->Flink; return e; }
#define CONTAINING_RECORD(address,type,field) ((type*)((char*)(address)-offsetof(type,field)))
static inline void KeInitializeSpinLock(KSPIN_LOCK* lock) { atomic_flag_clear(&lock->Value); }
static inline void KeAcquireSpinLock(KSPIN_LOCK* lock, KIRQL* irql) { *irql=0; while(atomic_flag_test_and_set(&lock->Value)){} }
static inline void KeReleaseSpinLock(KSPIN_LOCK* lock, KIRQL irql) { (void)irql; atomic_flag_clear(&lock->Value); }
