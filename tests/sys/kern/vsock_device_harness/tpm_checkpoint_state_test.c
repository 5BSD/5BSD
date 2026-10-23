/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../usr.sbin/bhyve/tpm_local_state.c"
#include "../../../../usr.sbin/bhyve/tpm_swtpm_control.c"
#include "../../../../usr.sbin/bhyve/tpm_checkpoint_state.c"

static void
make_migration_blob(uint8_t blob[92], uint8_t fill)
{

	memset(blob, fill, 92);
	blob[0] = 2;
	blob[1] = 1;
	be16enc(blob + 2, 10);
	be16enc(blob + 4, 6);
	be32enc(blob + 6, 92);
	be16enc(blob + 10, 5);
	be32enc(blob + 12, 16);
	be16enc(blob + 32, 3);
	be32enc(blob + 34, 32);
	be16enc(blob + 70, 7);
	be32enc(blob + 72, 16);
}

ATF_TC_WITHOUT_HEAD(bundle_roundtrip_and_preflight);
ATF_TC_BODY(bundle_roundtrip_and_preflight, tc)
{
	struct tpm_crb_local_state crb = { 0 };
	struct tpm_checkpoint_view input = { 0 }, output = { 0 };
	uint8_t intf[TPM_CRB_LOCAL_STATE_SIZE];
	uint8_t ppi[TPM_PPI_LOCAL_STATE_SIZE];
	uint8_t ppi_data[TPM_PPI_LOCAL_DATA_SIZE] = { 0 };
	uint8_t permanent[92];
	uint8_t volatile_blob[92];
	uint8_t *wire;
	size_t size;

	(void)tc;
	make_migration_blob(permanent, 0xa5);
	make_migration_blob(volatile_blob, 0x5a);
	crb.loc_state = 0x81;
	crb.ctrl_sts = 2;
	crb.cmd_size = TPM_CRB_LOCAL_DATA_SIZE;
	crb.cmd_addr = UINT64_C(0xfed40080);
	crb.rsp_size = TPM_CRB_LOCAL_DATA_SIZE;
	crb.rsp_addr = UINT64_C(0xfed40080);
	crb.data[0] = 0xa5;
	ppi_data[0x101] = 0x5a;
	ATF_REQUIRE_EQ(tpm_crb_local_state_encode(&crb, intf,
	    sizeof(intf)), 0);
	ATF_REQUIRE_EQ(tpm_ppi_local_state_encode(ppi_data,
	    sizeof(ppi_data), ppi, sizeof(ppi)), 0);
	input.intf = intf;
	input.intf_length = sizeof(intf);
	input.ppi = ppi;
	input.ppi_length = sizeof(ppi);
	ATF_REQUIRE_EQ(tpm_checkpoint_storage_id_parse(
	    "0123456789abcdef0123456789abcdef", input.storage_id), 0);
	ATF_REQUIRE_EQ(tpm_checkpoint_storage_id_parse(
	    "fedcba9876543210fedcba9876543210", input.key_id), 0);
	input.blobs[0].data = permanent;
	input.blobs[0].length = sizeof(permanent);
	input.blobs[0].flags = 0;
	input.blobs[1].data = volatile_blob;
	input.blobs[1].length = sizeof(volatile_blob);
	input.blobs[1].flags = 0;
	{
		uint8_t key_id[TPM_CHECKPOINT_KEY_ID_SIZE];

		memcpy(key_id, input.key_id, sizeof(key_id));
		memset(input.key_id, 0, sizeof(input.key_id));
		ATF_CHECK_EQ(tpm_checkpoint_state_size(&input, &size), EINVAL);
		memcpy(input.key_id, key_id, sizeof(key_id));
	}
	input.blobs[0].flags = SWTPM_CONTROL_STATE_ENCRYPTED;
	ATF_CHECK_EQ(tpm_checkpoint_state_size(&input, &size), EINVAL);
	input.blobs[0].flags = 0;
	input.blobs[0].length = 0;
	ATF_CHECK_EQ(tpm_checkpoint_state_size(&input, &size), EINVAL);
	input.blobs[0].length = sizeof(permanent);
	input.blobs[1].length = 0;
	ATF_CHECK_EQ(tpm_checkpoint_state_size(&input, &size), EINVAL);
	input.blobs[1].length = sizeof(volatile_blob);
	ATF_REQUIRE_EQ(tpm_checkpoint_state_size(&input, &size), 0);
	ATF_CHECK_EQ(size, 84 + sizeof(intf) + sizeof(ppi) +
	    sizeof(permanent) + sizeof(volatile_blob));
	wire = malloc(size);
	ATF_REQUIRE(wire != NULL);
	ATF_REQUIRE_EQ(tpm_checkpoint_state_encode(&input, wire, size), 0);
	ATF_CHECK_EQ(memcmp(wire, "BHYTPM03", 8), 0);
	ATF_CHECK_EQ(le32dec(wire + 8), size);
	ATF_CHECK_EQ(le32dec(wire + 12), 1);
	ATF_CHECK_EQ(le32dec(wire + 16), 2);
	ATF_CHECK_EQ(memcmp(wire + 52, input.storage_id,
	    sizeof(input.storage_id)), 0);
	ATF_CHECK_EQ(memcmp(wire + 68, input.key_id,
	    sizeof(input.key_id)), 0);
	ATF_REQUIRE_EQ(tpm_checkpoint_state_decode(wire, size, &output), 0);
	ATF_CHECK_EQ(memcmp(output.storage_id, input.storage_id,
	    sizeof(input.storage_id)), 0);
	ATF_CHECK_EQ(memcmp(output.key_id, input.key_id,
	    sizeof(input.key_id)), 0);
	ATF_CHECK_EQ(output.intf_length, sizeof(intf));
	ATF_CHECK_EQ(output.ppi_length, sizeof(ppi));
	ATF_CHECK_EQ(output.blobs[0].length, sizeof(permanent));
	ATF_CHECK_EQ(memcmp(output.blobs[0].data, permanent,
	    sizeof(permanent)), 0);
	ATF_CHECK_EQ(output.blobs[1].flags, 0);
	ATF_CHECK_EQ(output.blobs[2].length, 0);
	ATF_CHECK(output.blobs[2].data == NULL);
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size - 1,
	    &output), EINVAL);
	le32enc(wire + 32, 0);
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	le32enc(wire + 32, input.blobs[0].length);
	le32enc(wire + 40, 0);
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	le32enc(wire + 40, input.blobs[1].length);
	wire[28] = 4;
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	wire[28] = SWTPM_CONTROL_STATE_ENCRYPTED;
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	wire[28] = 0;
	wire[TPM_CHECKPOINT_HEADER_SIZE + sizeof(intf) + sizeof(ppi) + 5] = 4;
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EPROTO);
	wire[TPM_CHECKPOINT_HEADER_SIZE + sizeof(intf) + sizeof(ppi) + 5] = 6;
	wire[TPM_CHECKPOINT_HEADER_SIZE + sizeof(intf) + sizeof(ppi)] = 3;
	wire[TPM_CHECKPOINT_HEADER_SIZE + sizeof(intf) + sizeof(ppi) + 1] = 3;
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EPROTO);
	wire[TPM_CHECKPOINT_HEADER_SIZE + sizeof(intf) + sizeof(ppi)] = 2;
	wire[TPM_CHECKPOINT_HEADER_SIZE + sizeof(intf) + sizeof(ppi) + 1] = 1;
	wire[12] = 2;
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	wire[12] = 1;
	memset(wire + 52, 0, TPM_CHECKPOINT_STORAGE_ID_SIZE);
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	memcpy(wire + 52, input.storage_id,
	    TPM_CHECKPOINT_STORAGE_ID_SIZE);
	memset(wire + 68, 0, TPM_CHECKPOINT_KEY_ID_SIZE);
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	memcpy(wire + 68, input.key_id, TPM_CHECKPOINT_KEY_ID_SIZE);
	wire[7] = '2';
	ATF_CHECK_EQ(tpm_checkpoint_state_decode(wire, size,
	    &output), EINVAL);
	explicit_bzero(wire, size);
	free(wire);
}

ATF_TC_WITHOUT_HEAD(storage_id_parse);
ATF_TC_BODY(storage_id_parse, tc)
{
	uint8_t id[TPM_CHECKPOINT_STORAGE_ID_SIZE];
	uint8_t original[TPM_CHECKPOINT_STORAGE_ID_SIZE];

	(void)tc;
	memset(id, 0x5a, sizeof(id));
	memcpy(original, id, sizeof(id));
	ATF_CHECK_EQ(tpm_checkpoint_storage_id_parse(
	    "0123456789abcdef0123456789abcdef", id), 0);
	ATF_CHECK_EQ(id[0], 0x01);
	ATF_CHECK_EQ(id[15], 0xef);
	memcpy(id, original, sizeof(id));
	ATF_CHECK_EQ(tpm_checkpoint_storage_id_parse(
	    "0123456789abcdef0123456789abcde", id), EINVAL);
	ATF_CHECK_EQ(memcmp(id, original, sizeof(id)), 0);
	ATF_CHECK_EQ(tpm_checkpoint_storage_id_parse(
	    "0123456789abcdef0123456789abcdef0", id), EINVAL);
	ATF_CHECK_EQ(tpm_checkpoint_storage_id_parse(
	    "0123456789abcdef0123456789abcdeF", id), EINVAL);
	ATF_CHECK_EQ(tpm_checkpoint_storage_id_parse(
	    "00000000000000000000000000000000", id), EINVAL);
	ATF_CHECK_EQ(memcmp(id, original, sizeof(id)), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bundle_roundtrip_and_preflight);
	ATF_TP_ADD_TC(tp, storage_id_parse);
	return (atf_no_error());
}
