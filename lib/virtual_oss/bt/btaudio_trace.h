/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BTAUDIO_TRACE_H
#define BTAUDIO_TRACE_H
#ifdef WITH_DTRACE
#include <errno.h>
#include "btaudio_provider.h"
#define BTAUDIO_TRACE(name, ...) do { \
	if (BTAUDIO_##name##_ENABLED()) { \
		int trace_saved_errno = errno; \
		BTAUDIO_##name(__VA_ARGS__); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define BTAUDIO_TRACE(name, ...) ((void)0)
#endif
#endif
