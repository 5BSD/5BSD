/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * self_events_test expectations: the behaviour before the reader rule
 * (oes-no-self-events.md S1 pins).  The reader-rule commit changes each
 * value and says why.
 */
#ifndef _SELF_EVENTS_EXPECT_H_
#define	_SELF_EVENTS_EXPECT_H_

/* Own opens a descendants-scoped client delivers to its opener (N2). */
#define	SELF_EVENTS_DESCENDANTS	1
/* errno of unmuting OES_MUTE_SELF (N3), and own opens afterwards. */
#define	SELF_UNMUTE_ERRNO	0
#define	SELF_EVENTS_UNMUTED	1
/* security.oes.default_self_mute exists (N4). */
#define	SELF_MUTE_SYSCTL	true
/* Own opens delivered with process mutes inverted (N5). */
#define	SELF_EVENTS_INVERTED	1
/* A passed client's reader's own opens delivered to it (N6). */
#define	SELF_EVENTS_RECEIVER	1
/* That reader is flagged EP_FLAG_OES_CLIENT in other clients (N13). */
#define	SELF_READER_FLAGGED	false
/* The 'E' ioctl number OES_IOC_JOIN takes (N7): the next free one. */
#define	SELF_JOIN_NR		45

#endif
