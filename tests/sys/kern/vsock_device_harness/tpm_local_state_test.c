/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "../../../../usr.sbin/bhyve/tpm_local_state.c"

ATF_TC_WITHOUT_HEAD(crb_roundtrip_and_rejection);
ATF_TC_BODY(crb_roundtrip_and_rejection, tc)
{
	struct tpm_crb_local_state source, decoded, previous;
	uint8_t wire[TPM_CRB_LOCAL_STATE_SIZE];
	size_t i;

	(void)tc;
	memset(&source, 0, sizeof(source));
	source.loc_state = 0x83;
	source.loc_sts = 1;
	source.ctrl_sts = 2;
	source.cmd_size = 0xf80;
	source.cmd_addr = UINT64_C(0xfed40080);
	source.rsp_size = 0xf80;
	source.rsp_addr = UINT64_C(0xfed40080);
	for (i = 0; i < sizeof(source.data); i++)
		source.data[i] = (uint8_t)i;
	ATF_REQUIRE_EQ(tpm_crb_local_state_encode(&source, wire,
	    sizeof(wire)), 0);
	memset(&decoded, 0, sizeof(decoded));
	ATF_REQUIRE_EQ(tpm_crb_local_state_decode(wire, sizeof(wire),
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.loc_state, source.loc_state);
	ATF_CHECK_EQ(decoded.cmd_addr, source.cmd_addr);
	ATF_CHECK_EQ(decoded.rsp_addr, source.rsp_addr);
	ATF_CHECK_EQ(memcmp(decoded.data, source.data,
	    sizeof(source.data)), 0);
	previous = decoded;
	ATF_CHECK_EQ(tpm_crb_local_state_decode(wire, sizeof(wire) - 1,
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &previous, sizeof(decoded)), 0);
	wire[12] |= 0x20;
	ATF_CHECK_EQ(tpm_crb_local_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &previous, sizeof(decoded)), 0);
	wire[12] &= ~0x20;
	wire[12] = 0x81;
	ATF_CHECK_EQ(tpm_crb_local_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
	wire[12] = 0x83;
	wire[0] = 'X';
	ATF_CHECK_EQ(tpm_crb_local_state_decode(wire, sizeof(wire),
	    &decoded), EINVAL);
}

ATF_TC_WITHOUT_HEAD(ppi_roundtrip_and_rejection);
ATF_TC_BODY(ppi_roundtrip_and_rejection, tc)
{
	uint8_t source[TPM_PPI_LOCAL_DATA_SIZE];
	uint8_t decoded[TPM_PPI_LOCAL_DATA_SIZE];
	uint8_t wire[TPM_PPI_LOCAL_STATE_SIZE];
	size_t i;

	(void)tc;
	for (i = 0; i < sizeof(source); i++)
		source[i] = (uint8_t)(i ^ 0xa5);
	ATF_REQUIRE_EQ(tpm_ppi_local_state_encode(source, sizeof(source),
	    wire, sizeof(wire)), 0);
	memset(decoded, 0, sizeof(decoded));
	ATF_REQUIRE_EQ(tpm_ppi_local_state_decode(wire, sizeof(wire),
	    decoded, sizeof(decoded)), 0);
	ATF_CHECK_EQ(memcmp(decoded, source, sizeof(source)), 0);
	wire[8]++;
	ATF_CHECK_EQ(tpm_ppi_local_state_decode(wire, sizeof(wire),
	    decoded, sizeof(decoded)), EINVAL);
	ATF_CHECK_EQ(memcmp(decoded, source, sizeof(source)), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, crb_roundtrip_and_rejection);
	ATF_TP_ADD_TC(tp, ppi_roundtrip_and_rejection);
	return (atf_no_error());
}
