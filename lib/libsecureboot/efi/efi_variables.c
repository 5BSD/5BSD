/*-
 * Copyright (c) 2019 Stormshield.
 * Copyright (c) 2019 Semihalf.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <stand.h>
#include <string.h>

#include <efi.h>
#include <efilib.h>
#include <Uefi.h>
#include <Guid/ImageAuthentication.h>

#define NEED_BRSSL_H
#include "../libsecureboot-priv.h"
#include <brssl.h>

static EFI_GUID ImageSecurityDatabaseGUID = EFI_IMAGE_SECURITY_DATABASE_GUID;

static EFI_GUID efiCertX509GUID = EFI_CERT_X509_GUID;
static EFI_GUID efiCertX509Sha256GUID = EFI_CERT_X509_SHA256_GUID;
static EFI_GUID efiCertX509Sha384GUID = EFI_CERT_X509_SHA384_GUID;
static EFI_GUID efiCertX509Sha5122UID = EFI_CERT_X509_SHA512_GUID;

/*
 * Check if Secure Boot is enabled in firmware.
 * We evaluate two variables - Secure Boot and Setup Mode.
 * Secure Boot is enforced only if the first one equals 1 and the other 0.
 */
int
efi_secure_boot_enabled(void)
{
	UINT8 SecureBoot;
	UINT8 SetupMode;
	size_t length;
	EFI_STATUS status;

	length = sizeof(SecureBoot);
	status = efi_global_getenv("SecureBoot", &SecureBoot, &length);
	if (status != EFI_SUCCESS) {
		if (status == EFI_NOT_FOUND)
			return (0);

		printf("Failed to read \"SecureBoot\" variable\n");
		return (-efi_status_to_errno(status));
	}

	if (length != sizeof(SecureBoot) || SecureBoot > 1)
		return (-EIO);

	length = sizeof(SetupMode);
	status = efi_global_getenv("SetupMode", &SetupMode, &length);
	if (status != EFI_SUCCESS || length != sizeof(SetupMode)) {
		printf("Failed to read valid \"SetupMode\" variable\n");
		return (-EIO);
	}

	printf("   SecureBoot: %d, SetupMode: %d\n", SecureBoot, SetupMode);

	if (SetupMode > 1 || (SecureBoot == 1 && SetupMode != 0))
		return (-EIO);
	return (SecureBoot == 1 && SetupMode == 0);
}

/* Database errors must never silently discard a revocation policy. */
static UINT8 *
efi_read_database(const char *name, size_t *size)
{
	UINT8 *data;
	size_t allocated;
	EFI_STATUS status;

	*size = 0;
	status = efi_getenv(&ImageSecurityDatabaseGUID, name, NULL, size);
	if (status == EFI_NOT_FOUND) {
		*size = 0;
		return (NULL);
	}
	if (status != EFI_BUFFER_TOO_SMALL || *size == 0)
		panic("Secure Boot: cannot size signature database %s", name);
	allocated = *size;
	data = malloc(allocated);
	if (data == NULL)
		panic("Secure Boot: cannot allocate signature database %s", name);
	status = efi_getenv(&ImageSecurityDatabaseGUID, name, data, size);
	if (status != EFI_SUCCESS || *size == 0 || *size > allocated)
		panic("Secure Boot: cannot read signature database %s", name);
	return (data);
}

/* Validate before accessing a list's payload or advancing to the next list. */
static size_t
efi_signature_entries(const EFI_SIGNATURE_LIST *list, size_t remaining)
{
	size_t payload;

	if (remaining < sizeof(*list) || list->SignatureListSize < sizeof(*list) ||
	    list->SignatureListSize > remaining ||
	    list->SignatureHeaderSize > list->SignatureListSize - sizeof(*list) ||
	    list->SignatureSize <= sizeof(EFI_GUID))
		panic("Secure Boot: malformed signature database");
	payload = list->SignatureListSize - sizeof(*list) - list->SignatureHeaderSize;
	if (payload == 0 || payload % list->SignatureSize != 0)
		panic("Secure Boot: malformed signature database entries");
	return (payload / list->SignatureSize);
}

static br_x509_certificate *
efi_get_certs(const char *name, size_t *count)
{
	UINT8 *database, *cursor, *entry;
	br_x509_certificate *certs = NULL;
	EFI_SIGNATURE_LIST *list;
	size_t remaining, entries, length;

	*count = 0;
	database = efi_read_database(name, &remaining);
	for (cursor = database; remaining > 0;
	    remaining -= list->SignatureListSize, cursor += list->SignatureListSize) {
		list = (EFI_SIGNATURE_LIST *)cursor;
		entries = efi_signature_entries(list, remaining);
		if (memcmp(&efiCertX509GUID, &list->SignatureType, sizeof(EFI_GUID)) != 0)
			continue;
		if (list->SignatureHeaderSize != 0)
			panic("Secure Boot: malformed X509 signature list");
		entry = cursor + sizeof(*list);
		length = list->SignatureSize - sizeof(EFI_GUID);
		for (size_t i = 0; i < entries; i++, entry += list->SignatureSize) {
			certs = realloc(certs, (*count + 1) * sizeof(*certs));
			if (certs == NULL)
				panic("Secure Boot: cannot allocate certificates");
			certs[*count].data = malloc(length);
			if (certs[*count].data == NULL)
				panic("Secure Boot: cannot allocate certificate");
			certs[*count].data_len = length;
			memcpy(certs[*count].data, entry + sizeof(EFI_GUID), length);
			(*count)++;
		}
	}
	free(database);
	return (certs);
}

/*
 * Extract revoked certificate TBS hashes, not PE/COFF image hashes.
 * The existing verifier conservatively revokes these certificates regardless
 * of the EFI revocation timestamp; it does not implement timestamp exceptions.
 */
hash_data *
efi_get_forbidden_digests(size_t *count)
{
	UINT8 *database, *cursor, *entry;
	hash_data *digests = NULL;
	EFI_SIGNATURE_LIST *list;
	size_t remaining, entries, hash_size;

	*count = 0;
	database = efi_read_database("dbx", &remaining);
	for (cursor = database; remaining > 0;
	    remaining -= list->SignatureListSize, cursor += list->SignatureListSize) {
		list = (EFI_SIGNATURE_LIST *)cursor;
		entries = efi_signature_entries(list, remaining);
		if (memcmp(&efiCertX509Sha256GUID, &list->SignatureType, sizeof(EFI_GUID)) == 0)
			hash_size = br_sha256_SIZE;
		else if (memcmp(&efiCertX509Sha384GUID, &list->SignatureType, sizeof(EFI_GUID)) == 0)
			hash_size = br_sha384_SIZE;
		else if (memcmp(&efiCertX509Sha5122UID, &list->SignatureType, sizeof(EFI_GUID)) == 0)
			hash_size = br_sha512_SIZE;
		else
			continue;
		if (list->SignatureHeaderSize != 0 ||
		    list->SignatureSize != sizeof(EFI_GUID) + hash_size + sizeof(EFI_TIME))
			panic("Secure Boot: malformed certificate revocation list");
		entry = cursor + sizeof(*list);
		for (size_t i = 0; i < entries; i++, entry += list->SignatureSize) {
			digests = realloc(digests, (*count + 1) * sizeof(*digests));
			if (digests == NULL)
				panic("Secure Boot: cannot allocate revoked hashes");
			digests[*count].data = malloc(hash_size);
			if (digests[*count].data == NULL)
				panic("Secure Boot: cannot allocate revoked hash");
			digests[*count].hash_size = hash_size;
			memcpy(digests[*count].data, entry + sizeof(EFI_GUID), hash_size);
			(*count)++;
		}
	}
	free(database);
	return (digests);
}

/* Copy x509 certificates from db */
br_x509_certificate*
efi_get_trusted_certs(size_t *count)
{
	return (efi_get_certs("db", count));
}

/* Copy forbidden certificates from dbx */
br_x509_certificate*
efi_get_forbidden_certs(size_t *count)
{
	return (efi_get_certs("dbx", count));
}
