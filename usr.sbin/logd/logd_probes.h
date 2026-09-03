/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifdef WITH_DTRACE
#include "logd_provider.h"
#define	LOGD_PROBE_POOL_START(shard, capacity, result) \
	LOGD_POOL_START(shard, capacity, result)
#define	LOGD_PROBE_POOL_ADMIT(shard, label, active, result) \
	LOGD_POOL_ADMIT(shard, __DECONST(char *, label), active, result)
#define	LOGD_PROBE_POOL_SHUTDOWN(shard, active, result) \
	LOGD_POOL_SHUTDOWN(shard, active, result)
#define	LOGD_PROBE_SESSION(label, instance, result) \
	LOGD_SESSION_START(__DECONST(char *, label), instance, result)
#define	LOGD_PROBE_SESSION_END(label, instance, result) \
	LOGD_SESSION_END(__DECONST(char *, label), instance, result)
#define	LOGD_PROBE_RECORD(label, severity, length, result) \
	LOGD_RECORD_WRITE(__DECONST(char *, label), severity, length, \
	    result)
#define	LOGD_PROBE_DROP(label, sequence, error) \
	LOGD_RECORD_DROP(__DECONST(char *, label), sequence, error)
#define	LOGD_PROBE_WAKE(label, instance, result) \
	LOGD_WAKEUP_RECEIVE(__DECONST(char *, label), instance, result)
#define	LOGD_PROBE_BATCH(label, instance, reason, records, result) \
	LOGD_BATCH_DRAIN(__DECONST(char *, label), instance, \
	    __DECONST(char *, reason), records, result)
#define	LOGD_PROBE_FLUSH(label, instance, records, duration, result) \
	LOGD_FLUSH_COMPLETE(__DECONST(char *, label), instance, \
	    records, duration, result)
#define	LOGD_PROBE_PERSIST(label, generation, offset, length, result) \
	LOGD_STORAGE_PERSIST(__DECONST(char *, label), generation, \
	    offset, length, result)
#define	LOGD_PROBE_ROTATE(generation, result) \
	LOGD_STORAGE_ROTATE(generation, result)
#define	LOGD_PROBE_CORRUPTION(generation, offset, error) \
	LOGD_STORAGE_CORRUPTION(generation, offset, error)
#define	LOGD_PROBE_QUARANTINE(generation, error) \
	LOGD_STORAGE_QUARANTINE(generation, error)
#define	LOGD_PROBE_QUERY(label, generation, offset, severity, length, result) \
	LOGD_QUERY_COMPLETE(__DECONST(char *, label), generation, \
	    offset, severity, length, result)
#else
#define	LOGD_PROBE_POOL_START(shard, capacity, result) \
	do { (void)(shard); (void)(capacity); (void)(result); } while (0)
#define	LOGD_PROBE_POOL_ADMIT(shard, label, active, result) \
	do { (void)(shard); (void)(label); (void)(active); \
	    (void)(result); } while (0)
#define	LOGD_PROBE_POOL_SHUTDOWN(shard, active, result) \
	do { (void)(shard); (void)(active); (void)(result); } while (0)
#define	LOGD_PROBE_SESSION(label, instance, result) \
	do { (void)(label); (void)(instance); (void)(result); } while (0)
#define	LOGD_PROBE_SESSION_END(label, instance, result) \
	do { (void)(label); (void)(instance); (void)(result); } while (0)
#define	LOGD_PROBE_RECORD(label, severity, length, result) \
	do { (void)(label); (void)(severity); (void)(length); \
	    (void)(result); } while (0)
#define	LOGD_PROBE_DROP(label, sequence, error) \
	do { (void)(label); (void)(sequence); (void)(error); } while (0)
#define	LOGD_PROBE_WAKE(label, instance, result) \
	do { (void)(label); (void)(instance); (void)(result); } while (0)
#define	LOGD_PROBE_BATCH(label, instance, reason, records, result) \
	do { (void)(label); (void)(instance); (void)(reason); \
	    (void)(records); (void)(result); } while (0)
#define	LOGD_PROBE_FLUSH(label, instance, records, duration, result) \
	do { (void)(label); (void)(instance); (void)(records); \
	    (void)(duration); (void)(result); } while (0)
#define	LOGD_PROBE_PERSIST(label, generation, offset, length, result) \
	do { (void)(label); (void)(generation); (void)(offset); \
	    (void)(length); (void)(result); } while (0)
#define	LOGD_PROBE_ROTATE(generation, result) \
	do { (void)(generation); (void)(result); } while (0)
#define	LOGD_PROBE_CORRUPTION(generation, offset, error) \
	do { (void)(generation); (void)(offset); (void)(error); } while (0)
#define	LOGD_PROBE_QUARANTINE(generation, error) \
	do { (void)(generation); (void)(error); } while (0)
#define	LOGD_PROBE_QUERY(label, generation, offset, severity, length, result) \
	do { (void)(label); (void)(generation); (void)(offset); \
	    (void)(severity); (void)(length); (void)(result); } while (0)
#endif
