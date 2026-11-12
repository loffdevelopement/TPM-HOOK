#include "utils.h"

typedef struct _BCRYPT_RSAKEY_BLOB_LOCAL {
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
} BCRYPT_RSAKEY_BLOB_LOCAL, *PBCRYPT_RSAKEY_BLOB_LOCAL;

#ifndef BCRYPT_RSA_ALGORITHM
#define BCRYPT_RSA_ALGORITHM L"RSA"
#endif
#ifndef BCRYPT_RSAPUBLIC_BLOB
#define BCRYPT_RSAPUBLIC_BLOB L"RSAPUBLICBLOB"
#endif

namespace Utils {

NTSTATUS ObReferenceObjectByName(PUNICODE_STRING name, POBJECT_TYPE type, PVOID* object) {
    return ::ObReferenceObjectByName(name, OBJ_CASE_INSENSITIVE, nullptr, 0, type, KernelMode, nullptr, object);
}

NTSTATUS GenerateRandomKey(PGENKEY out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    UCHAR blob[1024];
    ULONG got = 0;
    PBCRYPT_RSAKEY_BLOB_LOCAL hdr = nullptr;
    ULONG modOff = 0;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) return st;

    st = BCryptGenerateKeyPair(alg, &key, 2048, 0);
    if (!NT_SUCCESS(st)) goto cleanup;

    st = BCryptFinalizeKeyPair(key, 0);
    if (!NT_SUCCESS(st)) goto cleanup;

    st = BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob, sizeof(blob), &got, 0);
    if (!NT_SUCCESS(st)) goto cleanup;

    hdr = (PBCRYPT_RSAKEY_BLOB_LOCAL)blob;
    modOff = sizeof(BCRYPT_RSAKEY_BLOB_LOCAL) + hdr->cbPublicExp;
    if (hdr->cbModulus > sizeof(out->rsa.buffer)) { st = STATUS_BUFFER_TOO_SMALL; goto cleanup; }

    out->rsa.size = (UINT16)((hdr->cbModulus >> 8) | (hdr->cbModulus << 8));
    RtlCopyMemory(out->rsa.buffer, blob + modOff, hdr->cbModulus);
    out->ready = TRUE;

cleanup:
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return st;
}

static const UCHAR XOR_KEY[16] = {
    0x5A, 0x9C, 0x3E, 0xF1, 0x72, 0xB8, 0xD4, 0x06,
    0xAB, 0x11, 0x5F, 0xE3, 0x49, 0x8C, 0xD1, 0x27
};

static void XorTransform(UCHAR* buf, ULONG len) {
    for (ULONG i = 0; i < len; i++) buf[i] ^= XOR_KEY[i & 0xF];
}

NTSTATUS SaveKey(PGENKEY k) {
    UNICODE_STRING path = RTL_CONSTANT_STRING(
        L"\\SystemRoot\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventlog-System.etl.part");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE h = nullptr;
    IO_STATUS_BLOCK iosb;

    NTSTATUS st = ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, nullptr,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ,
        FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr, 0);
    if (!NT_SUCCESS(st)) return st;

    UCHAR buf[sizeof(TPM2B_PUBLIC_KEY_RSA)];
    RtlCopyMemory(buf, &k->rsa, sizeof(buf));
    XorTransform(buf, sizeof(buf));

    st = ZwWriteFile(h, nullptr, nullptr, nullptr, &iosb, buf, sizeof(buf), nullptr, nullptr);
    ZwClose(h);
    return st;
}

NTSTATUS LoadKey(PGENKEY k) {
    UNICODE_STRING path = RTL_CONSTANT_STRING(
        L"\\SystemRoot\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventlog-System.etl.part");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE h = nullptr;
    IO_STATUS_BLOCK iosb;

    NTSTATUS st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr, 0);
    if (!NT_SUCCESS(st)) return st;

    UCHAR buf[sizeof(TPM2B_PUBLIC_KEY_RSA)];
    st = ZwReadFile(h, nullptr, nullptr, nullptr, &iosb, buf, sizeof(buf), nullptr, nullptr);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return st;
    if (iosb.Information != sizeof(buf)) return STATUS_END_OF_FILE;

    XorTransform(buf, sizeof(buf));
    RtlCopyMemory(&k->rsa, buf, sizeof(buf));
    k->ready = TRUE;
    return STATUS_SUCCESS;
}

}
