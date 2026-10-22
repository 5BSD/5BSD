/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>

typedef struct dtrace_ecb dtrace_ecb_t;
typedef struct dtrace_probe dtrace_probe_t;
typedef struct dtrace_provider dtrace_provider_t;
typedef struct dtrace_predicate dtrace_predicate_t;

struct dtrace_predicate {
	int dtp_cacheid;
};
struct dtrace_ecb {
	dtrace_probe_t *dte_probe;
	dtrace_ecb_t *dte_next;
	dtrace_predicate_t *dte_predicate;
};
struct dtrace_probe {
	uint16_t dtpr_vmid;
	int dtpr_provid;
	int dtpr_id;
	void *dtpr_arg;
	void *dtpr_provider;
	dtrace_ecb_t *dtpr_ecb;
	dtrace_ecb_t *dtpr_ecb_last;
	int dtpr_predcache;
};
struct dtrace_provider {
	struct {
		void (*dtps_enable)(void *, int, void *);
	} dtpv_pops;
	void *dtpv_arg;
};

static int cpu_lock, dtrace_lock, sync_count, backend_result;
static int backend_calls, host_calls;
static int (*hypertrace_enable)(uint16_t, int);
#define ASSERT(v) assert(v)
#define MUTEX_HELD(v) ((void)(v), 1)

static void
dtrace_sync(void)
{
	sync_count++;
}

static int
backend_enable(uint16_t vmid, int id)
{
	assert(vmid == 7 && id == 11);
	backend_calls++;
	return (backend_result);
}

static void
host_enable(void *arg, int id, void *probe_arg)
{
	assert(arg == (void *)&host_calls);
	assert(id == 11 && probe_arg == (void *)&host_calls);
	host_calls++;
}

/* PRODUCTION_ENABLE */

int
main(void)
{
	dtrace_probe_t probe = { .dtpr_vmid = 7, .dtpr_provid = 1,
	    .dtpr_id = 11 };
	dtrace_predicate_t predicate = { .dtp_cacheid = 42 };
	dtrace_ecb_t first = { .dte_probe = &probe,
	    .dte_predicate = &predicate };
	dtrace_ecb_t second = { .dte_probe = &probe };
	dtrace_provider_t host = { .dtpv_pops.dtps_enable = host_enable,
	    .dtpv_arg = &host_calls };
	dtrace_probe_t host_probe = { .dtpr_provid = 1, .dtpr_id = 11,
	    .dtpr_arg = &host_calls, .dtpr_provider = &host };
	dtrace_ecb_t host_ecb = { .dte_probe = &host_probe };
	dtrace_ecb_t null_ecb = { 0 };

	assert(dtrace_ecb_enable(&null_ecb) == 0);
	assert(dtrace_ecb_enable(&first) == ENXIO);
	assert(probe.dtpr_ecb == NULL);
	hypertrace_enable = backend_enable;
	backend_result = ESRCH;
	assert(dtrace_ecb_enable(&first) == ESRCH);
	assert(probe.dtpr_ecb == NULL && probe.dtpr_ecb_last == NULL);
	backend_result = -ESRCH;
	assert(dtrace_ecb_enable(&first) == ESRCH);
	assert(probe.dtpr_ecb == NULL);
	backend_result = 0;
	assert(dtrace_ecb_enable(&first) == 0);
	assert(probe.dtpr_ecb == &first && probe.dtpr_ecb_last == &first);
	assert(probe.dtpr_predcache == 42);
	assert(dtrace_ecb_enable(&second) == 0);
	assert(first.dte_next == &second && probe.dtpr_ecb_last == &second);
	assert(probe.dtpr_predcache == 0 && sync_count == 1);
	assert(backend_calls == 3);
	assert(dtrace_ecb_enable(&host_ecb) == 0);
	assert(host_calls == 1 && host_probe.dtpr_ecb == &host_ecb);
	return (0);
}
