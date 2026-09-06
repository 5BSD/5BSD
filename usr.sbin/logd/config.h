/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LOGCMP_CONFIG_H_
#define _LOGCMP_CONFIG_H_

#include <stdint.h>

#include <logcmp_protocol.h>

#include "store.h"

#define	LOGCMP_CONFIG_NAME	"logd.conf"
/*
 * Default config path for the logctl(8) operator tool's `configtest` with no
 * explicit argument: the config installed inside the Log.cap bundle.  The
 * daemon itself receives its config through the bundle at launch and does not
 * consult this path.
 */
#define	LOGCMP_CONFIG_PATH \
	"/Capabilities/System/Log.cap/Units/logd.unit/Config/" LOGCMP_CONFIG_NAME
#define	LOGCMP_CONFIG_MAX_SIZE		(64U * 1024)
#define	LOGCMP_RING_SIZE_DEFAULT	(256U * 1024)
#define	LOGCMP_RING_SIZE_MIN		(64U * 1024)
#define	LOGCMP_RING_SIZE_MAX		(64U * 1024 * 1024)
#define	LOGCMP_DRAIN_MS_DEFAULT		1000U
#define	LOGCMP_DRAIN_MS_MIN		1U
#define	LOGCMP_DRAIN_MS_MAX		1000U
#define	LOGCMP_SEGMENT_SIZE_DEFAULT	(16U * 1024 * 1024)
#define	LOGCMP_SEGMENT_SIZE_MIN		LOGCMP_STORE_SEGMENT_MIN
#define	LOGCMP_SEGMENT_SIZE_MAX		(1024U * 1024 * 1024)
#define	LOGCMP_MAX_SEGMENTS_DEFAULT	LOGCMP_STORE_SEGMENTS_DEFAULT
#define	LOGCMP_MAX_SEGMENTS_MIN		LOGCMP_STORE_SEGMENTS_MIN
#define	LOGCMP_MAX_SEGMENTS_MAX		LOGCMP_STORE_SEGMENTS_MAX
#define	LOGCMP_MINIMUM_SEVERITY_DEFAULT	LOGCMP_SEVERITY_TRACE
#define	LOGCMP_RATE_INTERVAL_MS_DEFAULT	30000U
#define	LOGCMP_RATE_INTERVAL_MS_MAX	3600000U
#define	LOGCMP_RATE_BURST_DEFAULT	10000U
#define	LOGCMP_RATE_BURST_MAX		1000000U
#define	LOGCMP_INGRESS_SHARDS_DEFAULT	4U
#define	LOGCMP_INGRESS_SHARDS_MIN	1U
#define	LOGCMP_INGRESS_SHARDS_MAX	64U
#define	LOGCMP_MAX_SESSIONS_DEFAULT	65536U
#define	LOGCMP_MAX_SESSIONS_MIN		64U
#define	LOGCMP_MAX_SESSIONS_MAX		262144U
#define	LOGCMP_DRAIN_BATCH_DEFAULT	256U
#define	LOGCMP_DRAIN_BATCH_MIN		1U
#define	LOGCMP_DRAIN_BATCH_MAX		4096U

struct logcmp_config {
	uint32_t ring_size;
	uint32_t fallback_drain_ms;
	uint64_t segment_size;
	uint32_t max_segments;
	uint32_t minimum_severity;
	uint32_t rate_limit_interval_ms;
	uint32_t rate_limit_burst;
	uint32_t ingress_shards;
	uint32_t max_sessions;
	uint32_t drain_batch;
};

void	logcmp_config_default(struct logcmp_config *);
int	logcmp_config_parse(const char *, struct logcmp_config *);
int	logcmp_config_load(const char *, struct logcmp_config *);
int	logcmp_config_load_fd(int, struct logcmp_config *);

#endif
