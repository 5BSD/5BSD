/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _GZIPSTREAM_TRACE_H_
#define _GZIPSTREAM_TRACE_H_
#ifdef WITH_COVERAGE_DTRACE
#include <errno.h>
#include <gzipstream_provider.h>
#define TRACE_INFLATE__START(a0, a1) do { \
	if (GZIPSTREAM_INFLATE_START_ENABLED()) { \
		int saved_trace_errno = errno; \
		GZIPSTREAM_INFLATE_START((unsigned int)(a0), (unsigned int)(a1)); \
		errno = saved_trace_errno; \
	} \
} while (0)
#define TRACE_INFLATE__DONE(a0, a1, a2) do { \
	if (GZIPSTREAM_INFLATE_DONE_ENABLED()) { \
		int saved_trace_errno = errno; \
		GZIPSTREAM_INFLATE_DONE((int)(a0), (unsigned int)(a1), (unsigned int)(a2)); \
		errno = saved_trace_errno; \
	} \
} while (0)
#define TRACE_DECODE__ERROR(a0, a1) do { \
	if (GZIPSTREAM_DECODE_ERROR_ENABLED()) { \
		int saved_trace_errno = errno; \
		GZIPSTREAM_DECODE_ERROR((int)(a0), (long long)(a1)); \
		errno = saved_trace_errno; \
	} \
} while (0)
static int
trace_inflate(z_streamp stream, int flush)
{
	int result, error;

	TRACE_INFLATE__START(stream->avail_in, stream->avail_out);
	result = inflate(stream, flush);
	error = errno;
	TRACE_INFLATE__DONE(result, stream->avail_in, stream->avail_out);
	errno = error;
	return (result);
}

#else
#define TRACE_DECODE__ERROR(a0, a1) do { } while (0)
#define TRACE_INFLATE__START(a0, a1) do { } while (0)
#define TRACE_INFLATE__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
