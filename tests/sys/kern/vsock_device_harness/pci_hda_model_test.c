/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "pci_hda_model.h"

ATF_TC_WITHOUT_HEAD(cmd_ctl_invariants);
ATF_TC_BODY(cmd_ctl_invariants, tc)
{

	/* Quiescent ring. */
	ATF_CHECK(hda_snapshot_cmd_ctl_valid(0, 0, 0, 0));
	/* Running rings at each guest-selectable geometry. */
	ATF_CHECK(hda_snapshot_cmd_ctl_valid(1, 0, 1, 2));
	ATF_CHECK(hda_snapshot_cmd_ctl_valid(1, 5, 12, 16));
	ATF_CHECK(hda_snapshot_cmd_ctl_valid(1, 255, 0, 256));
	/* A command error stops the DMA engine but keeps stale geometry. */
	ATF_CHECK(hda_snapshot_cmd_ctl_valid(0, 3, 7, 16));

	/* run is a boolean. */
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(2, 0, 0, 256));
	/* A running ring must have a geometry. */
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(1, 0, 0, 0));
	/* Only the architectural ring sizes exist. */
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(1, 0, 0, 3));
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(0, 0, 0, 512));
	/* Cursors must stay inside the ring. */
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(1, 16, 0, 16));
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(1, 0, 16, 16));
	/* A zero-sized ring cannot retain cursors. */
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(0, 1, 0, 0));
	ATF_CHECK(!hda_snapshot_cmd_ctl_valid(0, 0, 1, 0));
}

ATF_TC_WITHOUT_HEAD(stream_invariants);
ATF_TC_BODY(stream_invariants, tc)
{

	/* Stopped descriptors only carry a bounded tag. */
	ATF_CHECK(hda_snapshot_stream_valid(0, 0, 0, 0, 0, 0, 0, 0));
	ATF_CHECK(hda_snapshot_stream_valid(7, 1, 0, 15, 0, 0, 0, 0));
	ATF_CHECK(!hda_snapshot_stream_valid(0, 0, 0, 16, 0, 0, 0, 0));

	/* Running input stream (descriptor 0..3 is dir 0). */
	ATF_CHECK(hda_snapshot_stream_valid(1, 0, 1, 3, 8, 0, 2, 64));
	/* Running output stream (descriptor 4..7 is dir 1). */
	ATF_CHECK(hda_snapshot_stream_valid(5, 1, 1, 2, 0, 1, 2, 128));

	/* Descriptor index out of range. */
	ATF_CHECK(!hda_snapshot_stream_valid(8, 1, 1, 2, 0, 0, 1, 4));
	/* Direction must match the descriptor's side of the split. */
	ATF_CHECK(!hda_snapshot_stream_valid(1, 1, 1, 3, 0, 0, 1, 4));
	ATF_CHECK(!hda_snapshot_stream_valid(5, 0, 1, 2, 0, 0, 1, 4));
	/* Stream tag 0 never runs. */
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 0, 0, 0, 1, 4));
	/* BDL shape bounds. */
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 3, 0, 0, 0, 4));
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 3, 0, 0, 257, 4));
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 3, 0, 2, 2, 4));
	/* Cyclic buffer length and cursors are dword-granular and non-zero. */
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 3, 0, 0, 1, 0));
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 3, 0, 0, 1, 6));
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 1, 3, 2, 0, 1, 8));
	/* run/dir are booleans. */
	ATF_CHECK(!hda_snapshot_stream_valid(1, 0, 2, 3, 0, 0, 1, 4));
	ATF_CHECK(!hda_snapshot_stream_valid(1, 2, 1, 3, 0, 0, 1, 4));
}

ATF_TC_WITHOUT_HEAD(stream_map_invariants);
ATF_TC_BODY(stream_map_invariants, tc)
{
	uint8_t map[2][HDA_SNAPSHOT_STREAM_TAGS_CNT];
	uint8_t dir[HDA_SNAPSHOT_IOSS_NO];
	uint8_t run[HDA_SNAPSHOT_IOSS_NO];
	uint8_t stream[HDA_SNAPSHOT_IOSS_NO];

	memset(map, UINT8_MAX, sizeof(map));
	memset(dir, 0, sizeof(dir));
	memset(run, 0, sizeof(run));
	memset(stream, 0, sizeof(stream));

	/* Empty map with no running streams. */
	ATF_CHECK(hda_snapshot_stream_map_valid(map, dir, run, stream));

	/* Consistent running input (ind 1, tag 3) and output (ind 5, tag 2). */
	dir[1] = 0; run[1] = 1; stream[1] = 3; map[0][3] = 1;
	dir[5] = 1; run[5] = 1; stream[5] = 2; map[1][2] = 5;
	ATF_CHECK(hda_snapshot_stream_map_valid(map, dir, run, stream));

	/* A running stream must be reachable through its tag. */
	map[1][2] = UINT8_MAX;
	ATF_CHECK(!hda_snapshot_stream_map_valid(map, dir, run, stream));
	map[1][2] = 5;

	/* A mapped tag must name a running descriptor. */
	map[0][4] = 2;
	ATF_CHECK(!hda_snapshot_stream_map_valid(map, dir, run, stream));
	map[0][4] = UINT8_MAX;

	/* Map entries are descriptor indices. */
	map[0][5] = HDA_SNAPSHOT_IOSS_NO;
	ATF_CHECK(!hda_snapshot_stream_map_valid(map, dir, run, stream));
	map[0][5] = UINT8_MAX;

	/* The mapped descriptor must carry the same tag and direction. */
	map[0][6] = 1;
	ATF_CHECK(!hda_snapshot_stream_map_valid(map, dir, run, stream));
	map[0][6] = UINT8_MAX;
	map[1][3] = 1;
	ATF_CHECK(!hda_snapshot_stream_map_valid(map, dir, run, stream));
	map[1][3] = UINT8_MAX;

	ATF_CHECK(hda_snapshot_stream_map_valid(map, dir, run, stream));
}

ATF_TC_WITHOUT_HEAD(codec_stream_invariants);
ATF_TC_BODY(codec_stream_invariants, tc)
{

	/* Reset defaults: muted at full step count. */
	ATF_CHECK(hda_codec_snapshot_stream_valid(0, 0, 0x4a, 0x4a, 0x80,
	    0x80));
	/* Active converter. */
	ATF_CHECK(hda_codec_snapshot_stream_valid(1, 5, 0x7f, 0, 0, 0));

	/* 4-bit tag fields. */
	ATF_CHECK(!hda_codec_snapshot_stream_valid(0x10, 0, 0, 0, 0, 0));
	ATF_CHECK(!hda_codec_snapshot_stream_valid(0, 0x10, 0, 0, 0, 0));
	/* 7-bit gains. */
	ATF_CHECK(!hda_codec_snapshot_stream_valid(0, 0, 0x80, 0, 0, 0));
	ATF_CHECK(!hda_codec_snapshot_stream_valid(0, 0, 0, 0x80, 0, 0));
	/* Mute is the dedicated bit or clear. */
	ATF_CHECK(!hda_codec_snapshot_stream_valid(0, 0, 0, 0, 0x01, 0));
	ATF_CHECK(!hda_codec_snapshot_stream_valid(0, 0, 0, 0, 0, 0x40));
}

ATF_TC_WITHOUT_HEAD(codec_get_parameter_bounds);
ATF_TC_BODY(codec_get_parameter_bounds, tc)
{
	const uint32_t nodes = 6; /* HDA_CODEC_NODES_COUNT */

	/* In-range node and parameter indices are accepted. */
	ATF_CHECK(hda_codec_get_parameter_valid(0, nodes, 0));
	ATF_CHECK(hda_codec_get_parameter_valid(nodes - 1, nodes,
	    HDA_CODEC_MODEL_PARAMS_COUNT - 1));

	/*
	 * Regression: the GET_PARAMETER verb payload is a 16-bit guest field
	 * used to index a fixed-width row.  A parameter id at or past the row
	 * width must be rejected regardless of node id -- a playback-only codec
	 * with a valid node is still exposed to the out-of-bounds read.
	 */
	ATF_CHECK(!hda_codec_get_parameter_valid(0, nodes,
	    HDA_CODEC_MODEL_PARAMS_COUNT));
	ATF_CHECK(!hda_codec_get_parameter_valid(2, nodes, 0xffff));

	/* Node id at or past the node count is rejected. */
	ATF_CHECK(!hda_codec_get_parameter_valid(nodes, nodes, 0));
	ATF_CHECK(!hda_codec_get_parameter_valid(0xff, nodes, 0));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, cmd_ctl_invariants);
	ATF_TP_ADD_TC(tp, stream_invariants);
	ATF_TP_ADD_TC(tp, stream_map_invariants);
	ATF_TP_ADD_TC(tp, codec_stream_invariants);
	ATF_TP_ADD_TC(tp, codec_get_parameter_bounds);
	return (atf_no_error());
}
