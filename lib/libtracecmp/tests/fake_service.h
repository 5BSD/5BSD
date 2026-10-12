/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TRACECMP_FAKE_SERVICE_H_
#define _TRACECMP_FAKE_SERVICE_H_
/* Provider counters the fake service reports in a Stats reply. */
#define	FAKE_STATS_OPENED	7
#define	FAKE_STATS_REJECTED	3
enum fake_reply_mode {
	FAKE_REPLY_NORMAL,
	FAKE_REPLY_NO_FEATURE,		/* features 0 */
	FAKE_REPLY_BAD_FEATURES,	/* an unknown feature bit */
	FAKE_REPLY_FUTURE_VERSION,	/* wire version 2 */
	FAKE_REPLY_BAD_ERRNO,		/* Open error 0 (not an errno) */
	FAKE_REPLY_CLOSE_ON_OPEN,	/* close instead of answering Open */
	FAKE_REPLY_LEGACY		/* a pre-FIDL provider */
};
void fake_service_reset(void);
void fake_service_fail_connect(int);
void fake_service_fail_call(int);
void fake_service_reply_mode(enum fake_reply_mode);
unsigned fake_service_created(void);
unsigned fake_service_closed(void);
unsigned fake_service_max_concurrent(void);
#endif
