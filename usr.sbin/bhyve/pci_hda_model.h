/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _PCI_HDA_MODEL_H_
#define	_PCI_HDA_MODEL_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * Architecture-neutral invariants for the HDA controller checkpoint record.
 * The controller geometry is fixed by the emulation; a restore record which
 * disagrees with it was not produced by this device model.
 */
#define	HDA_SNAPSHOT_ISS_NO		0x04U
#define	HDA_SNAPSHOT_OSS_NO		0x04U
#define	HDA_SNAPSHOT_IOSS_NO						\
	(HDA_SNAPSHOT_ISS_NO + HDA_SNAPSHOT_OSS_NO)
#define	HDA_SNAPSHOT_STREAM_TAGS_CNT	0x10U
#define	HDA_SNAPSHOT_BDL_MAX_LEN	0x100U
#define	HDA_SNAPSHOT_DMA_ACCESS_LEN	4U

/*
 * Number of per-node parameter slots the codec's GET_PARAMETER tables carry.
 * Must equal hda_codec.c's HDA_CODEC_PARAMS_COUNT; a _Static_assert there ties
 * the two together so this model check cannot drift from the real table shape.
 */
#define	HDA_CODEC_MODEL_PARAMS_COUNT	0x14U

/*
 * Bound a GET_PARAMETER verb before it indexes get_parameters[nid][param].
 * A guest command carries an 8-bit node id and a 16-bit parameter id, both
 * attacker-controlled and both used as array indices.  The parameter id is
 * independent of which table (play-only, record-only, or duplex) the codec
 * selected, so a playback-only codec is exactly as exposed as a duplex one: an
 * out-of-range parameter read past the fixed-width row either way.
 */
static inline bool
hda_codec_get_parameter_valid(uint32_t nid, uint32_t no_nodes, uint32_t param)
{

	return (nid < no_nodes && param < HDA_CODEC_MODEL_PARAMS_COUNT);
}

/*
 * A CORB/RIRB ring is either quiescent or sized to one of the guest-selectable
 * ring geometries with in-range cursors.  A stopped ring may retain its stale
 * geometry (a command error stops the DMA engine without clearing it), so only
 * the cursor/size relationship is enforced, not an all-zero shape.
 */
static inline bool
hda_snapshot_cmd_ctl_valid(uint8_t run, uint16_t rp, uint16_t wp,
    uint16_t size)
{

	if (run != 0 && run != 1)
		return (false);
	if (size != 0 && size != 2 && size != 16 && size != 256)
		return (false);
	if (run != 0 && size == 0)
		return (false);
	if (size != 0 && (rp >= size || wp >= size))
		return (false);
	if (size == 0 && (rp != 0 || wp != 0))
		return (false);
	return (true);
}

/*
 * Stream descriptor cursors are only meaningful while the stream runs; a
 * running descriptor must describe a non-empty, dword-granular cyclic buffer
 * with in-range buffer-entry and byte cursors, on the correct side of the
 * input/output split for its descriptor index.
 */
static inline bool
hda_snapshot_stream_valid(uint32_t stream_ind, uint8_t dir, uint8_t run,
    uint8_t stream, uint32_t bp, uint32_t be, uint32_t bdl_cnt, uint32_t cbl)
{

	if (stream_ind >= HDA_SNAPSHOT_IOSS_NO)
		return (false);
	if ((run != 0 && run != 1) || (dir != 0 && dir != 1))
		return (false);
	if (stream >= HDA_SNAPSHOT_STREAM_TAGS_CNT)
		return (false);
	if (run == 0)
		return (true);
	if (dir != (stream_ind >= HDA_SNAPSHOT_ISS_NO ? 1 : 0))
		return (false);
	if (stream == 0)
		return (false);
	if (bdl_cnt == 0 || bdl_cnt > HDA_SNAPSHOT_BDL_MAX_LEN ||
	    be >= bdl_cnt)
		return (false);
	if (cbl == 0 || cbl % HDA_SNAPSHOT_DMA_ACCESS_LEN != 0)
		return (false);
	if (bp % HDA_SNAPSHOT_DMA_ACCESS_LEN != 0)
		return (false);
	return (true);
}

/*
 * The stream-tag map and the stream descriptors must agree bidirectionally:
 * a mapped tag names a running descriptor which carries that tag in that
 * direction, and every running descriptor is reachable through its tag.
 * stream_map is [2][HDA_SNAPSHOT_STREAM_TAGS_CNT], flattened row-major with
 * direction as the major index; descriptor fields are parallel arrays.
 */
static inline bool
hda_snapshot_stream_map_valid(
    const uint8_t map[2][HDA_SNAPSHOT_STREAM_TAGS_CNT],
    const uint8_t *dir, const uint8_t *run, const uint8_t *stream)
{
	uint32_t d, tag, ind;
	uint8_t entry;

	for (d = 0; d < 2; d++) {
		for (tag = 0; tag < HDA_SNAPSHOT_STREAM_TAGS_CNT; tag++) {
			entry = map[d][tag];
			if (entry == UINT8_MAX)
				continue;
			if (entry >= HDA_SNAPSHOT_IOSS_NO)
				return (false);
			if (run[entry] != 1 || dir[entry] != d ||
			    stream[entry] != tag)
				return (false);
		}
	}
	for (ind = 0; ind < HDA_SNAPSHOT_IOSS_NO; ind++) {
		if (run[ind] != 1)
			continue;
		if (dir[ind] > 1 ||
		    stream[ind] >= HDA_SNAPSHOT_STREAM_TAGS_CNT)
			return (false);
		if (map[dir[ind]][stream[ind]] != ind)
			return (false);
	}
	return (true);
}

/*
 * Codec converter state published through SET_AMP_GAIN_MUTE and
 * SET_CONV_STREAM_CHAN: gains are 7-bit steps, mute is the dedicated bit,
 * and stream/channel tags are 4-bit fields.
 */
static inline bool
hda_codec_snapshot_stream_valid(uint8_t channel, uint8_t stream,
    uint8_t left_gain, uint8_t right_gain, uint8_t left_mute,
    uint8_t right_mute)
{

	if (channel > 0x0f || stream > 0x0f)
		return (false);
	if (left_gain > 0x7f || right_gain > 0x7f)
		return (false);
	if ((left_mute != 0 && left_mute != 0x80) ||
	    (right_mute != 0 && right_mute != 0x80))
		return (false);
	return (true);
}

#endif /* _PCI_HDA_MODEL_H_ */
