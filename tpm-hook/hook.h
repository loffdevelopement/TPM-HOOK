#pragma once
#include "global.h"

namespace Hook {
    extern PDEVICE_OBJECT filterDevice;
    extern PDEVICE_OBJECT lowerDevice;
    extern GENKEY         generatedKey;

    NTSTATUS Install(PDRIVER_OBJECT self);
    NTSTATUS Uninstall(void);
    NTSTATUS Dispatch(PDEVICE_OBJECT device, PIRP irp);
    NTSTATUS Completion(PDEVICE_OBJECT device, PIRP irp, PVOID context);
}

typedef struct _IOC_REQUEST {
    PVOID    systemBuffer;
    ULONG    outputLength;
    UINT32   commandCode;
    UINT32   nvIndex;
} IOC_REQUEST, *PIOC_REQUEST;
