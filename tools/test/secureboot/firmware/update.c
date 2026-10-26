/* SPDX-License-Identifier: BSD-2-Clause */
/* Test-only firmware update client. Inputs live on the private VM ESP. */
#include <efi.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <Protocol/SimpleFileSystem.h>

#define LIMIT 65536
static UINT8 original[LIMIT], observed[LIMIT], expected[LIMIT];
static UINT8 valid[LIMIT], invalid[LIMIT], newer[LIMIT];
static EFI_GUID database = EFI_IMAGE_SECURITY_DATABASE_GUID;
static UINT32 attributes = EFI_VARIABLE_NON_VOLATILE |
    EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS |
    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

EFI_STATUS efi_main(EFI_HANDLE, EFI_SYSTEM_TABLE *);

static int
equal(const UINT8 *a, UINTN na, const UINT8 *b, UINTN nb)
{
	if (na != nb)
		return (0);
	for (UINTN i = 0; i < na; i++)
		if (a[i] != b[i])
			return (0);
	return (1);
}

static EFI_STATUS
read_file(EFI_FILE_PROTOCOL *root, CHAR16 *name, UINT8 *buffer, UINTN *size)
{
	EFI_FILE_PROTOCOL *file;
	EFI_STATUS status;
	UINT8 extra;
	UINTN n = 1;

	status = root->Open(root, &file, name, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(status))
		return (status);
	*size = LIMIT;
	status = file->Read(file, size, buffer);
	if (!EFI_ERROR(status)) {
		status = file->Read(file, &n, &extra);
		if (!EFI_ERROR(status) && (n != 0 || *size == 0))
			status = EFI_BAD_BUFFER_SIZE;
	}
	file->Close(file);
	return (status);
}

static int
matches(EFI_SYSTEM_TABLE *system, const UINT8 *data, UINTN length)
{
	UINTN size = LIMIT;
	UINT32 attr = 0;
	EFI_STATUS status;

	status = system->RuntimeServices->GetVariable(L"db", &database,
	    &attr, &size, observed);
	return (!EFI_ERROR(status) && attr == attributes &&
	    equal(data, length, observed, size));
}

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system)
{
	EFI_GUID global = EFI_GLOBAL_VARIABLE;
	EFI_GUID loaded_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
	EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
	EFI_LOADED_IMAGE_PROTOCOL *loaded;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
	EFI_FILE_PROTOCOL *root;
	EFI_STATUS status;
	UINT8 secure, setup;
	UINTN size = 1, original_size = LIMIT, expected_size, valid_size, invalid_size, newer_size;
	UINT32 attr = 0;

	status = system->RuntimeServices->GetVariable(L"SecureBoot", &global, NULL, &size, &secure);
	if (EFI_ERROR(status) || size != 1 || secure != 1)
		goto fail;
	size = 1;
	status = system->RuntimeServices->GetVariable(L"SetupMode", &global, NULL, &size, &setup);
	if (EFI_ERROR(status) || size != 1 || setup != 0)
		goto fail;
	status = system->RuntimeServices->GetVariable(L"db", &database, &attr, &original_size, original);
	if (EFI_ERROR(status) || attr != attributes)
		goto fail;
	status = system->BootServices->HandleProtocol(image, &loaded_guid, (VOID **)&loaded);
	if (EFI_ERROR(status))
		goto fail;
	status = system->BootServices->HandleProtocol(loaded->DeviceHandle, &fs_guid, (VOID **)&fs);
	if (EFI_ERROR(status) || EFI_ERROR(fs->OpenVolume(fs, &root)))
		goto fail;
	status = read_file(root, L"\\db.expected", expected, &expected_size);
	if (!EFI_ERROR(status))
		status = read_file(root, L"\\db.valid.auth", valid, &valid_size);
	if (!EFI_ERROR(status)) {
		if (equal(original, original_size, expected, expected_size))
			status = read_file(root, L"\\db.newer.auth", newer, &newer_size);
		else
			status = read_file(root, L"\\db.invalid.auth", invalid, &invalid_size);
	}
	root->Close(root);
	if (EFI_ERROR(status))
		goto fail;
	if (equal(original, original_size, expected, expected_size)) {
		/* Fresh boot after the replacement: old timestamp must remain stale. */
		status = system->RuntimeServices->SetVariable(L"db", &database, attributes, valid_size, valid);
		if (status != EFI_SECURITY_VIOLATION || !matches(system, expected, expected_size))
			goto fail;
		system->ConOut->OutputString(system->ConOut, L"AUTH_PERSISTED_REPLAY_REJECTED\r\n");
		status = system->RuntimeServices->SetVariable(L"db", &database, attributes, newer_size, newer);
		if (EFI_ERROR(status) || !matches(system, expected, expected_size))
			goto fail;
		system->ConOut->OutputString(system->ConOut, L"AUTH_NEWER_UPDATE_ACCEPTED\r\n");
		status = system->RuntimeServices->SetVariable(L"db", &database, attributes, newer_size, newer);
		if (status != EFI_SECURITY_VIOLATION || !matches(system, expected, expected_size))
			goto fail;
		system->ConOut->OutputString(system->ConOut, L"AUTH_NEWER_REPLAY_REJECTED\r\n");
		system->ConOut->OutputString(system->ConOut, L"AUTH_REPLAY_PASS\r\n");
		system->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
		return (EFI_DEVICE_ERROR);
	}
	status = system->RuntimeServices->SetVariable(L"db", &database, attributes, invalid_size, invalid);
	if (status != EFI_SECURITY_VIOLATION || !matches(system, original, original_size))
		goto fail;
	system->ConOut->OutputString(system->ConOut, L"AUTH_UPDATE_UNAUTHORIZED_REJECTED\r\n");
	status = system->RuntimeServices->SetVariable(L"db", &database, attributes, valid_size, valid);
	if (EFI_ERROR(status) || !matches(system, expected, expected_size))
		goto fail;
	system->ConOut->OutputString(system->ConOut, L"AUTH_UPDATE_ACCEPTED\r\n");
	status = system->RuntimeServices->SetVariable(L"db", &database, attributes, valid_size, valid);
	if (status != EFI_SECURITY_VIOLATION || !matches(system, expected, expected_size))
		goto fail;
	system->ConOut->OutputString(system->ConOut, L"AUTH_UPDATE_REPLAY_REJECTED\r\n");
	system->ConOut->OutputString(system->ConOut, L"AUTH_UPDATE_PASS\r\n");
	system->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
	return (EFI_DEVICE_ERROR);
fail:
	system->ConOut->OutputString(system->ConOut, L"AUTH_UPDATE_FAIL\r\n");
	return (EFI_DEVICE_ERROR);
}
