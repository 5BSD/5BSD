/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include "oes_broker_protocol.h"

static struct oes_broker_message
request(void)
{
	return ((struct oes_broker_message){ .magic = OES_BROKER_MAGIC,
	    .version = OES_BROKER_VERSION, .operation = OES_BROKER_OPEN_NOTIFY });
}
ATF_TC_WITHOUT_HEAD(attachment_contract);
ATF_TC_BODY(attachment_contract, tc)
{
	struct oes_broker_message m = request();
	ATF_CHECK_EQ(0, oes_broker_validate(&m, sizeof(m), 0, false));
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 1, false));
	ATF_CHECK_EQ(0, oes_broker_validate(&m, sizeof(m), 1, true));
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, true));
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 2, true));
	m.status = EPERM;
	ATF_CHECK_EQ(0, oes_broker_validate(&m, sizeof(m), 0, true));
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 1, true));
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, false));
	m.status = -EPERM;
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, true));
	m.status = ELAST + 1;
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, true));
}
ATF_TC_WITHOUT_HEAD(malformed_frames);
ATF_TC_BODY(malformed_frames, tc)
{
	struct oes_broker_message m = request();
	ATF_CHECK_ERRNO(EPROTO, oes_broker_validate(NULL, sizeof(m), 0, false) == -1);
	for (size_t n = 0; n < sizeof(m); n++)
		ATF_CHECK_ERRNO(EPROTO, oes_broker_validate(&m, n, 0, false) == -1);
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m)+1, 0, false));
	m.magic ^= 1;
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, false));
	m = request(); m.version++;
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, false));
	m = request(); m.operation++;
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, false));
	m = request(); m.reserved = 1;
	ATF_CHECK_EQ(-1, oes_broker_validate(&m, sizeof(m), 0, false));
}
ATF_TC_WITHOUT_HEAD(unaligned_frame);
ATF_TC_BODY(unaligned_frame, tc)
{
	struct oes_broker_message m = request();
	unsigned char buffer[sizeof(m)+1];
	memcpy(buffer+1, &m, sizeof(m));
	ATF_CHECK_EQ(0, oes_broker_validate(buffer+1, sizeof(m), 0, false));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, attachment_contract);
	ATF_TP_ADD_TC(tp, malformed_frames);
	ATF_TP_ADD_TC(tp, unaligned_frame);
	return (atf_no_error());
}
