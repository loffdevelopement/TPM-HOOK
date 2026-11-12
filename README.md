# tpm-hook

Windows kernel driver that intercepts TPM 2.0 commands and spoofs the Endorsement Key (EK) modulus. Designed to return a stable, randomly generated 2048-bit RSA key in place of the real EK, so hardware-based identification that relies on the TPM cannot track the machine.

Tested on Windows 11 23H2 (build 22631).

## How it works

The driver attaches as an upper filter on the `\Driver\TPM` device stack using `IoAttachDeviceToDeviceStack`. Every IRP sent to the real TPM driver passes through our dispatch routine first.

For `IRP_MJ_DEVICE_CONTROL` IRPs carrying `IOCTL_TPM_SUBMIT_COMMAND`, the driver inspects the TPM 2.0 command header:

- **`TPM2_ReadPublic` (0x00000173)** — the completion routine parses the `TPMT_PUBLIC` structure in the response, walks to the `unique.rsa` field, and overwrites the modulus with the fake key.
- **`TPM2_NV_ReadPublic` (0x00000169)** and **`TPM2_NV_Read` (0x0000014E)** targeting standard EK certificate NV handles (`0x01C00002`, `0x01C0000A`, `0x01C00012`, `0x01C00014`) — the response is rewritten as a `TPM_RC_HANDLE` error, so callers that verify the EK certificate chain give up and accept the bare EK.

All other IRPs pass through untouched via `IoSkipCurrentIrpStackLocation` + `IoCallDriver`.

The fake RSA key is generated once using `BCryptGenerateKeyPair` and persisted XOR-obfuscated on disk. Subsequent loads reuse the stored key, so the spoofed EK is stable across reboots.

## Build

Requirements: Visual Studio 2022, Windows Driver Kit (WDK).

```
msbuild tpm-hook.sln /p:Configuration=Release /p:Platform=x64
```

Output: `x64/Release/tpm-hook.sys`

## Usage

The driver is designed to be manually mapped (entry point is `Entry`, not `DriverEntry`). It is not meant to be installed as a signed service.

1. Clean the cached TPM attestation data so Windows re-queries the TPM on next boot (requires administrator):
   ```
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TPM\KeyAttestationKeys" /f
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TPM\PlatformQuoteKeys" /f
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\HealthCert" /f
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Admin" /f
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\TaskStates" /f
   ```
   Warning: if BitLocker is active on the system volume, deleting these keys may trigger the recovery screen on next boot. Verify with `manage-bde -status C:` first and back up the recovery key.

2. Reboot.

3. Immediately after boot, map `tpm-hook.sys` with your preferred manual mapper (kdmapper or any loader that supports an `Entry` export).

4. Verify the spoof is active: run `tpm-info.exe` (included in `tpm-info/`). The reported EK hash should differ from the real one and remain consistent across reboots.

## Project layout

```
tpm-hook/
├── tpm-hook.sln
├── tpm-hook/              (driver sources)
│   ├── entry.cpp          (driver entry point)
│   ├── hook.cpp / hook.h  (filter attach + command interception)
│   ├── utils.cpp / utils.h (RSA key generation + persistence)
│   ├── stealth.cpp        (module list unlink)
│   └── global.h           (shared types and constants)
└── tpm-info/              (usermode EK reader for testing)
```

## Stealth features

- Filter attach instead of dispatch table swap — the real TPM driver's `MajorFunction` array is never modified.
- Unlinks itself from `PsLoadedModuleList` and clears its `BaseDllName` / `FullDllName` after install.
- All `DbgPrintEx` calls are compiled out in release builds.
- Pool tag is set to a common value (`Ntfs`) to blend with legitimate allocations.
- Fake key persisted to a path that mimics ETW log backups.

## Limitations

This is a proof of concept. The filter device remains visible to anyone who enumerates the attached-device chain of `\Driver\TPM`. Modern anticheat (EAC, BattlEye, Vanguard) can detect this. The project is not UD and should not be used on accounts or against targets where detection has consequences.

The MmUnloadedDrivers scrub is a stub — a build-specific pattern scan is required for a real wipe.

## Disclaimer

For educational and research purposes only. Do not use this driver to violate terms of service of any software or online service.

## Credits

Original concept: [SamuelTulach/tpm-spoofer](https://github.com/SamuelTulach/tpm-spoofer). This project is a rewrite with a proper TPM2 response parser, filter attach instead of dispatch swap, key persistence, and basic kernel stealth.

## License

MIT
