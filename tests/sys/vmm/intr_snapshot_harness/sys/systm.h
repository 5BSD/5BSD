/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of the kernel <sys/systm.h>.  Provides the
 * assertion, uptime, and callout surface the vmm interrupt/timer device
 * models rely on.  Uptime is fully test-controlled through 'kmock_uptime'
 * so snapshot/restore tests can model a destination host whose uptime
 * differs arbitrarily from the source.  The callout mock records the last
 * absolute deadline so tests can assert the reanchored target.
 */
#ifndef _KMOCK_SYS_SYSTM_H_
#define	_KMOCK_SYS_SYSTM_H_

#include <sys/types.h>
#include <sys/time.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define	KASSERT(exp, msg)	do {					\
	if (!(exp))							\
		abort();						\
} while (0)

#define	panic(...)		do {					\
	fprintf(stderr, __VA_ARGS__);					\
	abort();							\
} while (0)

#ifndef CTASSERT
#define	CTASSERT(x)		_Static_assert((x), #x)
#endif

/* Kernel <sys/cdefs.h> spelling; userspace cdefs.h lacks it. */
#ifndef __diagused
#define	__diagused		__unused
#endif

/* Test-controlled monotonic uptime. */
extern struct bintime kmock_uptime;

static inline void
binuptime(struct bintime *bt)
{

	*bt = kmock_uptime;
}

static inline sbintime_t
sbinuptime(void)
{

	return (bttosbt(kmock_uptime));
}

/*
 * bin2bcd_data[] is declared by <sys/libkern.h> (pulled in by the kernel's
 * <sys/systm.h>) and defined in libkern.  vrtc.c indexes it directly; the
 * test program provides the table.
 */
extern u_char const bin2bcd_data[];

/* kern_tc.c precision exponent; fixed by the test program. */
extern int tc_precexp;

/* FREQ2BT is kernel-only in <sys/time.h>; mirror the kernel definition. */
#ifndef FREQ2BT
#define	FREQ2BT(freq, bt)						\
{									\
	(bt)->sec = 0;							\
	(bt)->frac = ((uint64_t)0x8000000000000000 / (freq)) << 1;	\
}
#endif

/*
 * Callout mock.  Arming records the absolute sbintime deadline and
 * precision; kmock_callout_fire() emulates softclock dispatch (clear
 * pending, run the handler, which is expected to callout_deactivate()).
 */
struct callout {
	sbintime_t	c_sbt;		/* last absolute deadline */
	sbintime_t	c_precision;
	void		(*c_func)(void *);
	void		*c_arg;
	int		c_kmock_flags;
	int		c_active;
	int		c_pending;
	u_int		c_resets;	/* number of arm operations */
};

#define	C_ABSOLUTE	0x0200

static inline void
callout_init(struct callout *c, int mpsafe __unused)
{

	memset(c, 0, sizeof(*c));
}

static inline int
callout_reset_sbt(struct callout *c, sbintime_t sbt, sbintime_t precision,
    void (*func)(void *), void *arg, int flags)
{
	int pending;

	pending = c->c_pending;
	c->c_sbt = sbt;
	c->c_precision = precision;
	c->c_func = func;
	c->c_arg = arg;
	c->c_kmock_flags = flags;
	c->c_active = 1;
	c->c_pending = 1;
	c->c_resets++;
	return (pending);
}

static inline int
callout_stop(struct callout *c)
{
	int pending;

	pending = c->c_pending;
	c->c_active = 0;
	c->c_pending = 0;
	return (pending);
}

static inline int
callout_drain(struct callout *c)
{

	return (callout_stop(c));
}

#define	callout_active(c)	((c)->c_active)
#define	callout_pending(c)	((c)->c_pending)
#define	callout_deactivate(c)	((c)->c_active = 0)

static inline void
kmock_callout_fire(struct callout *c)
{

	c->c_pending = 0;
	c->c_func(c->c_arg);
}

#endif /* !_KMOCK_SYS_SYSTM_H_ */
