/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BIN_ZSH_TRACE_PRESSURE_H
#define BIN_ZSH_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_FORK_START(a0) \
	DTRACE_PROBE1(zsh, fork__start, (a0))
#else
#define ZSH_TRACE_FORK_START(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_FORK_DONE(a0, a1) \
	DTRACE_PROBE2(zsh, fork__done, (a0), (a1))
#else
#define ZSH_TRACE_FORK_DONE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_JOB_LIMIT(a0) \
	DTRACE_PROBE1(zsh, job__limit, (a0))
#else
#define ZSH_TRACE_JOB_LIMIT(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_EXEC_ATTEMPT(a0) \
	DTRACE_PROBE1(zsh, exec__attempt, (a0))
#else
#define ZSH_TRACE_EXEC_ATTEMPT(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_EXEC_FAILURE(a0, a1) \
	DTRACE_PROBE2(zsh, exec__failure, (a0), (a1))
#else
#define ZSH_TRACE_EXEC_FAILURE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_PIPELINE_START(a0, a1) \
	DTRACE_PROBE2(zsh, pipeline__start, (a0), (a1))
#else
#define ZSH_TRACE_PIPELINE_START(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_PIPELINE_DONE(a0, a1, a2) \
	DTRACE_PROBE3(zsh, pipeline__done, (a0), (a1), (a2))
#else
#define ZSH_TRACE_PIPELINE_DONE(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_WAIT_START(a0, a1) \
	DTRACE_PROBE2(zsh, wait__start, (a0), (a1))
#else
#define ZSH_TRACE_WAIT_START(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ZSH_TRACE_WAIT_DONE(a0, a1) \
	DTRACE_PROBE2(zsh, wait__done, (a0), (a1))
#else
#define ZSH_TRACE_WAIT_DONE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif
