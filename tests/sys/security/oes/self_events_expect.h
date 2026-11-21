/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * self_events_test expectations.  S1 pinned the behaviour before the reader
 * rule (descendants 1, unmute 0 then 1, sysctl present, inverted 1,
 * receiver 1, not flagged, no OES_IOC_JOIN); the reader rule (S2) gives
 * these: a reader never receives its own events, whatever the scope, mute
 * inversion or how it got the descriptor, and is flagged as a client.
 */
#ifndef _SELF_EVENTS_EXPECT_H_
#define	_SELF_EVENTS_EXPECT_H_

/* Own opens a descendants-scoped client delivers to its opener (N2). */
#define	SELF_EVENTS_DESCENDANTS	0
/* errno of unmuting OES_MUTE_SELF (N3), and own opens afterwards. */
#define	SELF_UNMUTE_ERRNO	EINVAL
#define	SELF_EVENTS_UNMUTED	0
/* security.oes.default_self_mute exists (N4). */
#define	SELF_MUTE_SYSCTL	false
/* Own opens delivered with process mutes inverted (N5). */
#define	SELF_EVENTS_INVERTED	0
/* A passed client's reader's own opens delivered to it (N6). */
#define	SELF_EVENTS_RECEIVER	0
/* That reader is flagged EP_FLAG_OES_CLIENT in other clients (N13). */
#define	SELF_READER_FLAGGED	true
/* The 'E' ioctl number OES_IOC_JOIN takes (N7): the next free one. */
#define	SELF_JOIN_NR		45

#endif
