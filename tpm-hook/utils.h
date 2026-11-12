#pragma once
#include "global.h"
#include "hook.h"

namespace Utils {
    NTSTATUS ObReferenceObjectByName(PUNICODE_STRING name, POBJECT_TYPE type, PVOID* object);
    NTSTATUS GenerateRandomKey(PGENKEY out);
    NTSTATUS SaveKey(PGENKEY k);
    NTSTATUS LoadKey(PGENKEY k);
}

extern "C" NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    PVOID ParseContext, PVOID* Object);

extern "C" POBJECT_TYPE* IoDriverObjectType;
