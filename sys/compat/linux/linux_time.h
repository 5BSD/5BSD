/*-
 * Copyright (c) 2014 Bjoern A. Zeeb
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249
 * ("MRC2"), as part of the DARPA MRC research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_LINUX_TIME_H
#define	_LINUX_TIME_H

#ifndef	__LINUX_ARCH_SIGEV_PREAMBLE_SIZE
#define	__LINUX_ARCH_SIGEV_PREAMBLE_SIZE	\
	(sizeof(l_int) * 2 + sizeof(l_sigval_t))
#endif

#define	LINUX_SIGEV_MAX_SIZE			64
#define	LINUX_SIGEV_PAD_SIZE			\
	((LINUX_SIGEV_MAX_SIZE - __LINUX_ARCH_SIGEV_PREAMBLE_SIZE) / \
	sizeof(l_int))

#define	LINUX_CLOCK_REALTIME			0
#define	LINUX_CLOCK_MONOTONIC			1
#define	LINUX_CLOCK_PROCESS_CPUTIME_ID		2
#define	LINUX_CLOCK_THREAD_CPUTIME_ID		3
#define	LINUX_CLOCK_MONOTONIC_RAW		4
#define	LINUX_CLOCK_REALTIME_COARSE		5
#define	LINUX_CLOCK_MONOTONIC_COARSE		6
#define	LINUX_CLOCK_BOOTTIME			7
#define	LINUX_CLOCK_REALTIME_ALARM		8
#define	LINUX_CLOCK_BOOTTIME_ALARM		9
#define	LINUX_CLOCK_SGI_CYCLE			10
#define	LINUX_CLOCK_TAI				11

#define	LINUX_CPUCLOCK_PERTHREAD_MASK		4
#define	LINUX_CPUCLOCK_MASK			3
#define	LINUX_CPUCLOCK_WHICH(clock)		\
	((clock) & (clockid_t) LINUX_CPUCLOCK_MASK)
#define	LINUX_CPUCLOCK_PROF			0
#define	LINUX_CPUCLOCK_VIRT			1
#define	LINUX_CPUCLOCK_SCHED			2
#define	LINUX_CPUCLOCK_MAX			3
#define	LINUX_CLOCKFD				LINUX_CPUCLOCK_MAX
#define	LINUX_CLOCKFD_MASK			\
	(LINUX_CPUCLOCK_PERTHREAD_MASK|LINUX_CPUCLOCK_MASK)

#define	LINUX_CPUCLOCK_ID(clock)		((pid_t) ~((clock) >> 3))
#define	LINUX_CPUCLOCK_PERTHREAD(clock)		\
	(((clock) & (clockid_t) LINUX_CPUCLOCK_PERTHREAD_MASK) != 0)

#define	LINUX_TIMER_ABSTIME			0x01

#define	L_SIGEV_SIGNAL				0
#define	L_SIGEV_NONE				1
#define	L_SIGEV_THREAD				2
#define	L_SIGEV_THREAD_ID			4

struct l_sigevent {
	l_sigval_t sigev_value;
	l_int sigev_signo;
	l_int sigev_notify;
	union {
		l_int _pad[LINUX_SIGEV_PAD_SIZE];
		l_int _tid;
		struct {
			l_uintptr_t _function;
			l_uintptr_t _attribute;
		} _l_sigev_thread;
	} _l_sigev_un;
}
#if defined(__amd64__) && defined(COMPAT_LINUX32)
__packed
#endif
;

struct l_itimerspec {
	struct l_timespec it_interval;
	struct l_timespec it_value;
};

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
struct l_itimerspec64 {
	struct l_timespec64 it_interval;
	struct l_timespec64 it_value;
};
#endif

int native_to_linux_timespec(struct l_timespec *,
				     struct timespec *);
int linux_to_native_timespec(struct timespec *,
				     struct l_timespec *);
int linux_put_timespec(struct timespec *,
				     struct l_timespec *);
int linux_get_timespec(struct timespec *,
				     const struct l_timespec *);
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int native_to_linux_timespec64(struct l_timespec64 *,
				     struct timespec *);
int linux_to_native_timespec64(struct timespec *,
				     struct l_timespec64 *);
int linux_put_timespec64(struct timespec *,
				     struct l_timespec64 *);
int linux_get_timespec64(struct timespec *,
				    const  struct l_timespec64 *);
#endif
int linux_to_native_clockid(clockid_t *, clockid_t);
int native_to_linux_itimerspec(struct l_itimerspec *,
				     struct itimerspec *);
int linux_to_native_itimerspec(struct itimerspec *,
				     struct l_itimerspec *);
#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int native_to_linux_itimerspec64(struct l_itimerspec64 *,
				     struct itimerspec *);
int linux_to_native_itimerspec64(struct itimerspec *,
				     struct l_itimerspec64 *);
#endif

int linux_convert_l_sigevent(const struct l_sigevent *l_sig, struct sigevent *sig);
int linux_to_native_timerflags(int *, int);

/*
 * adjtimex(2)/clock_adjtime(2), <uapi/linux/timex.h>.  With l_long and
 * l_int this yields both the 64-bit layout (208 bytes, natural padding
 * after modes, status and shift) and the 32-bit adjtimex layout used by
 * i386/COMPAT_LINUX32 (128 bytes).  The 32-bit clock_adjtime64(2), which
 * takes the 64-bit __kernel_timex, is a separate syscall and not this.
 */
struct l_timex {
	l_uint		modes;
	l_long		offset;
	l_long		freq;
	l_long		maxerror;
	l_long		esterror;
	l_int		status;
	l_long		constant;
	l_long		precision;
	l_long		tolerance;
	l_timeval	time;
	l_long		tick;
	l_long		ppsfreq;
	l_long		jitter;
	l_int		shift;
	l_long		stabil;
	l_long		jitcnt;
	l_long		calcnt;
	l_long		errcnt;
	l_long		stbcnt;
	l_int		tai;
	l_int		_pad[11];
};

/* Linux timex mode bits. */
#define	LINUX_ADJ_OFFSET		0x0001
#define	LINUX_ADJ_FREQUENCY		0x0002
#define	LINUX_ADJ_MAXERROR		0x0004
#define	LINUX_ADJ_ESTERROR		0x0008
#define	LINUX_ADJ_STATUS		0x0010
#define	LINUX_ADJ_TIMECONST		0x0020
#define	LINUX_ADJ_TAI			0x0080
#define	LINUX_ADJ_SETOFFSET		0x0100
#define	LINUX_ADJ_MICRO			0x1000
#define	LINUX_ADJ_NANO			0x2000
#define	LINUX_ADJ_TICK			0x4000
#define	LINUX_ADJ_ADJTIME		0x8000
#define	LINUX_ADJ_OFFSET_SINGLESHOT	0x8001
#define	LINUX_ADJ_OFFSET_READONLY	0x2000
#define	LINUX_ADJ_OFFSET_SS_READ	0xa001

#endif	/* _LINUX_TIME_H */
