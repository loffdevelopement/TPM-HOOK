#include "hook.h"
#include "utils.h"

namespace Hook {

PDEVICE_OBJECT filterDevice = nullptr;
PDEVICE_OBJECT lowerDevice  = nullptr;
GENKEY         generatedKey = {};

static UINT32 BE32(UINT32 v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v & 0xFF0000) >> 8) | ((v & 0xFF000000) >> 24);
}
static inline UINT16 R16(const UCHAR* p) { return (UINT16)((p[0] << 8) | p[1]); }
static inline UINT32 R32(const UCHAR* p) { return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) | ((UINT32)p[2] << 8) | p[3]; }

static void WriteErrorResponse(UCHAR* buf, ULONG bufCap, UINT32 rc, PIRP irp) {
    if (bufCap < 10) return;
    buf[0] = 0x80; buf[1] = 0x01;
    buf[2] = 0; buf[3] = 0; buf[4] = 0; buf[5] = 0x0A;
    buf[6] = (UCHAR)(rc >> 24); buf[7] = (UCHAR)(rc >> 16);
    buf[8] = (UCHAR)(rc >> 8);  buf[9] = (UCHAR)(rc);
    irp->IoStatus.Information = 10;
    irp->IoStatus.Status = STATUS_SUCCESS;
}

NTSTATUS Completion(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
    UNREFERENCED_PARAMETER(device);
    PIOC_REQUEST req = (PIOC_REQUEST)context;

    if (NT_SUCCESS(irp->IoStatus.Status) && req->systemBuffer) {
        UCHAR* buf = (UCHAR*)req->systemBuffer;
        ULONG len = (ULONG)irp->IoStatus.Information;

        if ((req->commandCode == TPM_CC_NV_ReadPublic || req->commandCode == TPM_CC_NV_Read) &&
            req->nvIndex != 0) {
            WriteErrorResponse(buf, req->outputLength, 0x0000018B, irp);
        }
        else if (req->commandCode == TPM_CC_ReadPublic && generatedKey.ready) {
            do {
                if (len < 10) break;
                UINT32 respCode = R32(buf + 6);
                if (respCode != 0) break;

                ULONG off = 10;
                if (off + 2 > len) break;
                UINT16 outPublicSize = R16(buf + off); off += 2;
                if (off + outPublicSize > len) break;
                ULONG paEnd = off + outPublicSize;

                if (off + 2 > paEnd) break;
                UINT16 type = R16(buf + off); off += 2;
                if (type != 0x0001) break;
                if (off + 2 > paEnd) break;
                off += 2;
                if (off + 4 > paEnd) break;
                off += 4;
                if (off + 2 > paEnd) break;
                UINT16 authPolSize = R16(buf + off); off += 2;
                if (off + authPolSize > paEnd) break;
                off += authPolSize;

                if (off + 2 > paEnd) break;
                UINT16 symAlg = R16(buf + off); off += 2;
                if (symAlg != 0x0010) {
                    if (off + 4 > paEnd) break;
                    off += 4;
                }
                if (off + 2 > paEnd) break;
                UINT16 schemeAlg = R16(buf + off); off += 2;
                if (schemeAlg != 0x0010) {
                    if (off + 2 > paEnd) break;
                    off += 2;
                }
                if (off + 6 > paEnd) break;
                off += 2;
                off += 4;

                if (off + 2 > paEnd) break;
                UINT16 modSize = R16(buf + off);
                ULONG modOff = off + 2;
                if (modOff + modSize > paEnd) break;
                if (modSize == 0 || modSize > 512) break;

                RtlCopyMemory(buf + modOff, generatedKey.rsa.buffer, modSize);
            } while (0);
        }
    }

    ExFreePoolWithTag(req, POOL_TAG);
    if (irp->PendingReturned) IoMarkIrpPending(irp);
    return STATUS_SUCCESS;
}

NTSTATUS Dispatch(PDEVICE_OBJECT device, PIRP irp) {
    if (device != filterDevice || !lowerDevice) {
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);

    if (ioc->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
        ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_TPM_SUBMIT_COMMAND) {

        PVOID sys = irp->AssociatedIrp.SystemBuffer;
        ULONG inLen = ioc->Parameters.DeviceIoControl.InputBufferLength;

        if (sys && inLen >= sizeof(TPM_HEADER)) {
            PTPM_HEADER hdr = (PTPM_HEADER)sys;
            UINT32 cc = BE32(hdr->commandCode);
            UCHAR* raw = (UCHAR*)sys;

            UINT32 nv = 0;
            bool hook = false;
            if (cc == TPM_CC_ReadPublic) {
                hook = true;
            } else if (cc == TPM_CC_NV_ReadPublic && inLen >= 14) {
                UINT32 n = R32(raw + 10);
                if (n == EK_CERT_RSA || n == EK_CERT_ECC || n == EK_CERT_RSA2 || n == EK_CERT_ECC2) {
                    hook = true; nv = n;
                }
            } else if (cc == TPM_CC_NV_Read && inLen >= 18) {
                UINT32 n = R32(raw + 14);
                if (n == EK_CERT_RSA || n == EK_CERT_ECC || n == EK_CERT_RSA2 || n == EK_CERT_ECC2) {
                    hook = true; nv = n;
                }
            }

            if (hook) {
                PIOC_REQUEST req = (PIOC_REQUEST)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IOC_REQUEST), POOL_TAG);
                if (req) {
                    req->systemBuffer = sys;
                    req->outputLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
                    req->commandCode  = cc;
                    req->nvIndex      = nv;
                    IoCopyCurrentIrpStackLocationToNext(irp);
                    IoSetCompletionRoutine(irp, Completion, req, TRUE, FALSE, FALSE);
                    return IoCallDriver(lowerDevice, irp);
                }
            }
        }
    }

    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(lowerDevice, irp);
}

NTSTATUS Install(PDRIVER_OBJECT self) {
    if (!self) return STATUS_INVALID_PARAMETER;

    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\TPM");
    PDRIVER_OBJECT targetDriver = nullptr;
    NTSTATUS st = Utils::ObReferenceObjectByName(&name, *IoDriverObjectType, (PVOID*)&targetDriver);
    if (!NT_SUCCESS(st)) return st;

    PDEVICE_OBJECT targetDevice = targetDriver->DeviceObject;
    if (!targetDevice) { ObDereferenceObject(targetDriver); return STATUS_NO_SUCH_DEVICE; }

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        self->MajorFunction[i] = Dispatch;
    }

    st = IoCreateDevice(self, 0, nullptr,
        targetDevice->DeviceType,
        targetDevice->Characteristics,
        FALSE, &filterDevice);
    if (!NT_SUCCESS(st)) { ObDereferenceObject(targetDriver); return st; }

    lowerDevice = IoAttachDeviceToDeviceStack(filterDevice, targetDevice);
    if (!lowerDevice) {
        IoDeleteDevice(filterDevice);
        filterDevice = nullptr;
        ObDereferenceObject(targetDriver);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    filterDevice->Flags |= lowerDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    ObDereferenceObject(targetDriver);
    return STATUS_SUCCESS;
}

NTSTATUS Uninstall(void) {
    if (filterDevice && lowerDevice) {
        IoDetachDevice(lowerDevice);
        IoDeleteDevice(filterDevice);
        filterDevice = nullptr;
        lowerDevice = nullptr;
    }
    return STATUS_SUCCESS;
}

}
