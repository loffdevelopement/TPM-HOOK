#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <bcrypt.h>

#if defined(DBG) && DBG
#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[x] " fmt "\n", __VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

#define IOCTL_TPM_SUBMIT_COMMAND 0x0022C00C
#define TPM_CC_ReadPublic        0x00000173
#define TPM_CC_NV_ReadPublic     0x00000169
#define TPM_CC_NV_Read           0x0000014E

#define EK_CERT_RSA  0x01C00002
#define EK_CERT_ECC  0x01C0000A
#define EK_CERT_RSA2 0x01C00012
#define EK_CERT_ECC2 0x01C00014

#define POOL_TAG 'sftN'

#pragma pack(push, 1)
typedef struct _TPM_HEADER {
    UINT16 tag;
    UINT32 paramSize;
    UINT32 commandCode;
} TPM_HEADER, *PTPM_HEADER;

typedef struct _TPM2B_PUBLIC_KEY_RSA {
    UINT16 size;
    UCHAR  buffer[512];
} TPM2B_PUBLIC_KEY_RSA, *PTPM2B_PUBLIC_KEY_RSA;
#pragma pack(pop)

typedef struct _GENKEY {
    TPM2B_PUBLIC_KEY_RSA rsa;
    BOOLEAN ready;
} GENKEY, *PGENKEY;
