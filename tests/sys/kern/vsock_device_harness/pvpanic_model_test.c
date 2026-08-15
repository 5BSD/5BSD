/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Rootless model test for the bhyve pvpanic event register ABI and host
 * reaction policy.  Exercises the pure logic shared with pvpanic.c via
 * pvpanic_model.h: the supported-events read, event-write decode, invalid
 * writes, the fatal-event gate, action parsing, and the snapshot config codec.
 */

#include <sys/param.h>

#include <atf-c.h>

#include "pvpanic_model.h"

ATF_TC_WITHOUT_HEAD(read_returns_supported_mask);
ATF_TC_BODY(read_returns_supported_mask, tc)
{

	(void)tc;
	/* A read of the event register yields exactly PANICKED|CRASHLOADED. */
	ATF_CHECK_EQ(pvpanic_supported_events(),
	    PVPANIC_PANICKED | PVPANIC_CRASHLOADED);
	ATF_CHECK_EQ(pvpanic_supported_events(), 0x03);
}

ATF_TC_WITHOUT_HEAD(write_decodes_known_events);
ATF_TC_BODY(write_decodes_known_events, tc)
{

	(void)tc;
	ATF_CHECK_EQ(pvpanic_decode_event(PVPANIC_PANICKED), PVPANIC_PANICKED);
	ATF_CHECK_EQ(pvpanic_decode_event(PVPANIC_CRASHLOADED),
	    PVPANIC_CRASHLOADED);
	ATF_CHECK_EQ(pvpanic_decode_event(PVPANIC_PANICKED | PVPANIC_CRASHLOADED),
	    PVPANIC_PANICKED | PVPANIC_CRASHLOADED);
}

ATF_TC_WITHOUT_HEAD(write_ignores_unknown_bits);
ATF_TC_BODY(write_ignores_unknown_bits, tc)
{

	(void)tc;
	/* Unknown high bits are masked off; a pure-noise write decodes to 0. */
	ATF_CHECK_EQ(pvpanic_decode_event(0x00), 0);
	ATF_CHECK_EQ(pvpanic_decode_event(0xFC), 0);
	ATF_CHECK_EQ(pvpanic_decode_event(0xFF),
	    PVPANIC_PANICKED | PVPANIC_CRASHLOADED);
	/* PANICKED plus noise still decodes to just PANICKED. */
	ATF_CHECK_EQ(pvpanic_decode_event(PVPANIC_PANICKED | 0x80),
	    PVPANIC_PANICKED);
}

ATF_TC_WITHOUT_HEAD(only_panicked_is_fatal);
ATF_TC_BODY(only_panicked_is_fatal, tc)
{

	(void)tc;
	ATF_CHECK(pvpanic_event_is_fatal(PVPANIC_PANICKED));
	ATF_CHECK(pvpanic_event_is_fatal(PVPANIC_PANICKED | PVPANIC_CRASHLOADED));
	/* A crashloaded guest is not dead: it must not trigger a lifecycle change. */
	ATF_CHECK(!pvpanic_event_is_fatal(PVPANIC_CRASHLOADED));
	ATF_CHECK(!pvpanic_event_is_fatal(0));
}

ATF_TC_WITHOUT_HEAD(action_parsing);
ATF_TC_BODY(action_parsing, tc)
{
	enum pvpanic_action act;

	(void)tc;
	act = PVPANIC_ACT_RESET;
	ATF_REQUIRE(pvpanic_parse_action("none", &act));
	ATF_CHECK_EQ(act, PVPANIC_ACT_NONE);
	ATF_REQUIRE(pvpanic_parse_action("log", &act));
	ATF_CHECK_EQ(act, PVPANIC_ACT_NONE);
	ATF_REQUIRE(pvpanic_parse_action("poweroff", &act));
	ATF_CHECK_EQ(act, PVPANIC_ACT_POWEROFF);
	ATF_REQUIRE(pvpanic_parse_action("reset", &act));
	ATF_CHECK_EQ(act, PVPANIC_ACT_RESET);
	ATF_REQUIRE(pvpanic_parse_action("halt", &act));
	ATF_CHECK_EQ(act, PVPANIC_ACT_HALT);

	/* Unknown values are rejected and leave the output untouched. */
	act = PVPANIC_ACT_HALT;
	ATF_CHECK(!pvpanic_parse_action("explode", &act));
	ATF_CHECK_EQ(act, PVPANIC_ACT_HALT);
	ATF_CHECK(!pvpanic_parse_action(NULL, &act));
	ATF_CHECK(!pvpanic_parse_action("reset", NULL));
}

ATF_TC_WITHOUT_HEAD(snapshot_codec_roundtrips);
ATF_TC_BODY(snapshot_codec_roundtrips, tc)
{
	static const enum pvpanic_action actions[] = {
		PVPANIC_ACT_NONE, PVPANIC_ACT_POWEROFF,
		PVPANIC_ACT_RESET, PVPANIC_ACT_HALT,
	};
	bool enabled;
	enum pvpanic_action action;
	uint8_t byte;

	(void)tc;
	for (unsigned i = 0; i < nitems(actions); i++) {
		for (int en = 0; en <= 1; en++) {
			byte = pvpanic_config_encode(en != 0, actions[i]);
			enabled = !en;
			action = PVPANIC_ACT_NONE;
			ATF_REQUIRE(pvpanic_config_decode(byte, &enabled,
			    &action));
			ATF_CHECK_EQ(enabled, en != 0);
			ATF_CHECK_EQ(action, actions[i]);
		}
	}

	/* A byte carrying a reserved action value is rejected. */
	ATF_CHECK(!pvpanic_config_decode(0x07, &enabled, &action));
	ATF_CHECK(!pvpanic_config_decode(0x85, &enabled, &action));
	/* A byte with reserved bits (3:6) set is likewise rejected. */
	ATF_CHECK(!pvpanic_config_decode(0x08, &enabled, &action));
	ATF_CHECK(!pvpanic_config_decode(0x40, &enabled, &action));
	ATF_CHECK(!pvpanic_config_decode(0x88, &enabled, &action));
}

ATF_TC_WITHOUT_HEAD(snapshot_rejects_topology_change);
ATF_TC_BODY(snapshot_rejects_topology_change, tc)
{

	ATF_CHECK(pvpanic_topology_matches(false, false));
	ATF_CHECK(pvpanic_topology_matches(true, true));
	ATF_CHECK(!pvpanic_topology_matches(false, true));
	ATF_CHECK(!pvpanic_topology_matches(true, false));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, read_returns_supported_mask);
	ATF_TP_ADD_TC(tp, write_decodes_known_events);
	ATF_TP_ADD_TC(tp, write_ignores_unknown_bits);
	ATF_TP_ADD_TC(tp, only_panicked_is_fatal);
	ATF_TP_ADD_TC(tp, action_parsing);
	ATF_TP_ADD_TC(tp, snapshot_codec_roundtrips);
	ATF_TP_ADD_TC(tp, snapshot_rejects_topology_change);
	return (atf_no_error());
}
