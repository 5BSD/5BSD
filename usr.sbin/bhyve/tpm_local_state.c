/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "tpm_local_state.h"

#define TPM_LOCAL_HEADER_SIZE 12U

static bool
tpm_crb_fields_valid(const struct tpm_crb_local_state *state)
{

	return ((state->loc_state == 0x81U && state->loc_sts == 0) ||
	    (state->loc_state == 0x83U && state->loc_sts == 1)) &&
	    (state->ctrl_sts & ~0x3U) == 0;
}

static int
tpm_local_header_decode(const uint8_t *wire, size_t wire_size,
    const char magic[8], size_t expected_size)
{

	if (wire == NULL || wire_size != expected_size ||
	    memcmp(wire, magic, 8) != 0 ||
	    le32dec(wire + 8) != expected_size)
		return (EINVAL);
	return (0);
}

int
tpm_crb_local_state_encode(const struct tpm_crb_local_state *state,
    uint8_t *wire, size_t wire_size)
{
	size_t off;

	if (state == NULL || wire == NULL ||
	    wire_size < TPM_CRB_LOCAL_STATE_SIZE)
		return (EINVAL);
	if (!tpm_crb_fields_valid(state))
		return (EINVAL);
	memcpy(wire, "TPMCRB01", 8);
	le32enc(wire + 8, TPM_CRB_LOCAL_STATE_SIZE);
	off = TPM_LOCAL_HEADER_SIZE;
	le32enc(wire + off, state->loc_state);
	off += 4;
	le32enc(wire + off, state->loc_sts);
	off += 4;
	le32enc(wire + off, state->ctrl_sts);
	off += 4;
	le32enc(wire + off, state->cmd_size);
	off += 4;
	le64enc(wire + off, state->cmd_addr);
	off += 8;
	le32enc(wire + off, state->rsp_size);
	off += 4;
	le64enc(wire + off, state->rsp_addr);
	off += 8;
	memcpy(wire + off, state->data, sizeof(state->data));
	return (0);
}

int
tpm_crb_local_state_decode(const uint8_t *wire, size_t wire_size,
    struct tpm_crb_local_state *state)
{
	struct tpm_crb_local_state candidate;
	size_t off;
	int error;

	if (state == NULL)
		return (EINVAL);
	error = tpm_local_header_decode(wire, wire_size, "TPMCRB01",
	    TPM_CRB_LOCAL_STATE_SIZE);
	if (error != 0)
		return (error);
	off = TPM_LOCAL_HEADER_SIZE;
	candidate.loc_state = le32dec(wire + off);
	off += 4;
	candidate.loc_sts = le32dec(wire + off);
	off += 4;
	candidate.ctrl_sts = le32dec(wire + off);
	off += 4;
	candidate.cmd_size = le32dec(wire + off);
	off += 4;
	candidate.cmd_addr = le64dec(wire + off);
	off += 8;
	candidate.rsp_size = le32dec(wire + off);
	off += 4;
	candidate.rsp_addr = le64dec(wire + off);
	off += 8;
	if (!tpm_crb_fields_valid(&candidate))
		return (EINVAL);
	memcpy(candidate.data, wire + off, sizeof(candidate.data));
	*state = candidate;
	return (0);
}

int
tpm_ppi_local_state_encode(const uint8_t *state, size_t state_size,
    uint8_t *wire, size_t wire_size)
{

	if (state == NULL || state_size != TPM_PPI_LOCAL_DATA_SIZE ||
	    wire == NULL || wire_size < TPM_PPI_LOCAL_STATE_SIZE)
		return (EINVAL);
	memcpy(wire, "TPMPPI01", 8);
	le32enc(wire + 8, TPM_PPI_LOCAL_STATE_SIZE);
	memcpy(wire + TPM_LOCAL_HEADER_SIZE, state, state_size);
	return (0);
}

int
tpm_ppi_local_state_decode(const uint8_t *wire, size_t wire_size,
    uint8_t *state, size_t state_size)
{
	int error;

	if (state == NULL || state_size != TPM_PPI_LOCAL_DATA_SIZE)
		return (EINVAL);
	error = tpm_local_header_decode(wire, wire_size, "TPMPPI01",
	    TPM_PPI_LOCAL_STATE_SIZE);
	if (error != 0)
		return (error);
	memcpy(state, wire + TPM_LOCAL_HEADER_SIZE, state_size);
	return (0);
}
