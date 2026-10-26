/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable firmware execution probe; never installed on the host. */
#include <efi.h>
#include <Guid/GlobalVariable.h>

EFI_STATUS efi_main(EFI_HANDLE, EFI_SYSTEM_TABLE *);

EFI_STATUS
efi_main(EFI_HANDLE image __unused, EFI_SYSTEM_TABLE *system)
{
	EFI_GUID global = EFI_GLOBAL_VARIABLE;
	UINT8 secure = 255, setup = 255;
	UINTN size = sizeof(secure);
	EFI_STATUS status;

	status = system->RuntimeServices->GetVariable(L"SecureBoot", &global,
	    NULL, &size, &secure);
	if (EFI_ERROR(status) || size != sizeof(secure) || secure > 1)
		goto fail;
	size = sizeof(setup);
	status = system->RuntimeServices->GetVariable(L"SetupMode", &global,
	    NULL, &size, &setup);
	if (EFI_ERROR(status) || size != sizeof(setup) || setup > 1)
		goto fail;
	status = system->ConOut->OutputString(system->ConOut,
	    secure ? L"FIRMWARE_PROBE SecureBoot=1\r\n" :
	    L"FIRMWARE_PROBE SecureBoot=0\r\n");
	if (EFI_ERROR(status))
		return (status);
	status = system->ConOut->OutputString(system->ConOut,
	    setup ? L"FIRMWARE_PROBE SetupMode=1\r\n" :
	    L"FIRMWARE_PROBE SetupMode=0\r\n");
	if (EFI_ERROR(status))
		return (status);
	status = system->ConOut->OutputString(system->ConOut,
	    L"FIRMWARE_PROBE_EXECUTED\r\n");
	if (EFI_ERROR(status))
		return (status);
	system->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0,
	    NULL);
	return (EFI_DEVICE_ERROR);
fail:
	system->ConOut->OutputString(system->ConOut,
	    L"FIRMWARE_PROBE_VARIABLE_FAILURE\r\n");
	return (EFI_DEVICE_ERROR);
}
