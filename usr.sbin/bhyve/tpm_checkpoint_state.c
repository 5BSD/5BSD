/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "tpm_checkpoint_state.h"
#include "tpm_local_state.h"
#include "tpm_swtpm_control.h"

#define TPM_CHECKPOINT_BACKEND_SWTPM 1U
#define TPM_CHECKPOINT_VERSION_2_0 2U

static bool
tpm_checkpoint_storage_id_valid(const uint8_t *id)
{
	uint8_t nonzero;

	if (id == NULL)
		return (false);
	nonzero = 0;
	for (size_t i = 0; i < TPM_CHECKPOINT_STORAGE_ID_SIZE; i++)
		nonzero |= id[i];
	return (nonzero != 0);
}

int
tpm_checkpoint_storage_id_parse(const char *text,
    uint8_t id[TPM_CHECKPOINT_STORAGE_ID_SIZE])
{
	uint8_t candidate[TPM_CHECKPOINT_STORAGE_ID_SIZE];
	unsigned int high, low;
	char c;

	if (text == NULL || id == NULL ||
	    strnlen(text, TPM_CHECKPOINT_STORAGE_ID_SIZE * 2 + 1) !=
	    TPM_CHECKPOINT_STORAGE_ID_SIZE * 2)
		return (EINVAL);
	for (size_t i = 0; i < TPM_CHECKPOINT_STORAGE_ID_SIZE; i++) {
		c = text[i * 2];
		if (c >= '0' && c <= '9')
			high = c - '0';
		else if (c >= 'a' && c <= 'f')
			high = c - 'a' + 10;
		else
			return (EINVAL);
		c = text[i * 2 + 1];
		if (c >= '0' && c <= '9')
			low = c - '0';
		else if (c >= 'a' && c <= 'f')
			low = c - 'a' + 10;
		else
			return (EINVAL);
		candidate[i] = (high << 4) | low;
	}
	if (!tpm_checkpoint_storage_id_valid(candidate))
		return (EINVAL);
	memcpy(id, candidate, sizeof(candidate));
	return (0);
}

static int
tpm_checkpoint_local_valid(const struct tpm_checkpoint_view *view)
{
	struct tpm_crb_local_state crb;
	uint8_t ppi[TPM_PPI_LOCAL_DATA_SIZE];
	int error;

	if (view->intf == NULL || view->ppi == NULL ||
	    view->intf_length != TPM_CRB_LOCAL_STATE_SIZE ||
	    view->ppi_length != TPM_PPI_LOCAL_STATE_SIZE)
		return (EINVAL);
	error = tpm_crb_local_state_decode(view->intf, view->intf_length,
	    &crb);
	explicit_bzero(&crb, sizeof(crb));
	if (error != 0)
		return (error);
	error = tpm_ppi_local_state_decode(view->ppi, view->ppi_length,
	    ppi, sizeof(ppi));
	explicit_bzero(ppi, sizeof(ppi));
	return (error);
}

int
tpm_checkpoint_state_size(const struct tpm_checkpoint_view *view,
    size_t *size)
{
	size_t total;
	int error;

	if (view == NULL || size == NULL ||
	    !tpm_checkpoint_storage_id_valid(view->storage_id) ||
	    !tpm_checkpoint_storage_id_valid(view->key_id))
		return (EINVAL);
	error = tpm_checkpoint_local_valid(view);
	if (error != 0)
		return (error);
	total = TPM_CHECKPOINT_HEADER_SIZE + view->intf_length +
	    view->ppi_length;
	for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
		error = tpm_swtpm_control_blob_validate(i + 1,
		    view->blobs[i].data, view->blobs[i].length,
		    view->blobs[i].flags);
		if (error != 0)
			return (error);
		if (view->blobs[i].length > UINT32_MAX - total)
			return (EOVERFLOW);
		total += view->blobs[i].length;
	}
	*size = total;
	return (0);
}

int
tpm_checkpoint_state_encode(const struct tpm_checkpoint_view *view,
    uint8_t *wire, size_t wire_size)
{
	size_t total, offset;
	int error;

	if (wire == NULL)
		return (EINVAL);
	error = tpm_checkpoint_state_size(view, &total);
	if (error != 0)
		return (error);
	if (wire_size < total)
		return (EMSGSIZE);
	memcpy(wire, "BHYTPM03", 8);
	le32enc(wire + 8, total);
	le32enc(wire + 12, TPM_CHECKPOINT_BACKEND_SWTPM);
	le32enc(wire + 16, TPM_CHECKPOINT_VERSION_2_0);
	le32enc(wire + 20, view->intf_length);
	le32enc(wire + 24, view->ppi_length);
	for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
		le32enc(wire + 28 + i * 8, view->blobs[i].flags);
		le32enc(wire + 32 + i * 8, view->blobs[i].length);
	}
	memcpy(wire + 52, view->storage_id,
	    TPM_CHECKPOINT_STORAGE_ID_SIZE);
	memcpy(wire + 68, view->key_id, TPM_CHECKPOINT_KEY_ID_SIZE);
	offset = TPM_CHECKPOINT_HEADER_SIZE;
	memcpy(wire + offset, view->intf, view->intf_length);
	offset += view->intf_length;
	memcpy(wire + offset, view->ppi, view->ppi_length);
	offset += view->ppi_length;
	for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
		if (view->blobs[i].length != 0)
			memcpy(wire + offset, view->blobs[i].data,
			    view->blobs[i].length);
		offset += view->blobs[i].length;
	}
	return (offset == total ? 0 : EPROTO);
}

int
tpm_checkpoint_state_decode(const uint8_t *wire, size_t wire_size,
    struct tpm_checkpoint_view *view)
{
	struct tpm_checkpoint_view candidate = { 0 };
	size_t offset, length;
	int error;

	if (wire == NULL || view == NULL ||
	    wire_size < TPM_CHECKPOINT_HEADER_SIZE ||
	    memcmp(wire, "BHYTPM03", 8) != 0 ||
	    le32dec(wire + 8) != wire_size ||
	    le32dec(wire + 12) != TPM_CHECKPOINT_BACKEND_SWTPM ||
	    le32dec(wire + 16) != TPM_CHECKPOINT_VERSION_2_0)
		return (EINVAL);
	candidate.intf_length = le32dec(wire + 20);
	candidate.ppi_length = le32dec(wire + 24);
	memcpy(candidate.storage_id, wire + 52,
	    TPM_CHECKPOINT_STORAGE_ID_SIZE);
	memcpy(candidate.key_id, wire + 68, TPM_CHECKPOINT_KEY_ID_SIZE);
	if (candidate.intf_length != TPM_CRB_LOCAL_STATE_SIZE ||
	    candidate.ppi_length != TPM_PPI_LOCAL_STATE_SIZE ||
	    !tpm_checkpoint_storage_id_valid(candidate.storage_id) ||
	    !tpm_checkpoint_storage_id_valid(candidate.key_id))
		return (EINVAL);
	offset = TPM_CHECKPOINT_HEADER_SIZE;
	if (candidate.intf_length > wire_size - offset)
		return (EINVAL);
	candidate.intf = wire + offset;
	offset += candidate.intf_length;
	if (candidate.ppi_length > wire_size - offset)
		return (EINVAL);
	candidate.ppi = wire + offset;
	offset += candidate.ppi_length;
	for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
		candidate.blobs[i].flags = le32dec(wire + 28 + i * 8);
		length = le32dec(wire + 32 + i * 8);
		if (length > SWTPM_CONTROL_MAX_BLOB ||
		    length > wire_size - offset)
			return (EINVAL);
		candidate.blobs[i].length = length;
		candidate.blobs[i].data = length == 0 ? NULL : wire + offset;
		error = tpm_swtpm_control_blob_validate(i + 1,
		    candidate.blobs[i].data, candidate.blobs[i].length,
		    candidate.blobs[i].flags);
		if (error != 0)
			return (error);
		offset += length;
	}
	if (offset != wire_size)
		return (EINVAL);
	error = tpm_checkpoint_local_valid(&candidate);
	if (error != 0)
		return (error);
	*view = candidate;
	return (0);
}
