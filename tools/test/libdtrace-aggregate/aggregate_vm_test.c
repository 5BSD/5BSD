/* Exercise production aggregation and joined walks without a DTrace device.
 * Only kernel metadata/snapshot I/O and allocation failure are simulated.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "dt_aggregate.c"

static dtrace_aggdesc_t *descs[3];
static dtrace_eprobedesc_t *enabled[3];
static dtrace_probedesc_t probes[3];
static uint64_t samples[3][4];
static void *owned[256];
static int calls, fail_at, fail_epid, rows;
static int expected_cols;

void *
dt_alloc(dtrace_hdl_t *dtp, size_t size)
{
	void *p;
	int i;
	if (++calls == fail_at) {
		dtp->dt_errno = EDT_NOMEM;
		return (NULL);
	}
	p = malloc(size);
	assert(p != NULL);
	for (i = 0; owned[i] != NULL; i++)
		assert(i < 255);
	owned[i] = p;
	return (p);
}
void *
dt_zalloc(dtrace_hdl_t *dtp, size_t size)
{
	void *p = dt_alloc(dtp, size);
	if (p != NULL)
		memset(p, 0, size);
	return (p);
}
void
dt_free(dtrace_hdl_t *dtp, void *p)
{
	int i;
	(void)dtp;
	if (p == NULL)
		return;
	for (i = 0; i < 256 && owned[i] != p; i++)
		;
	assert(i < 256); /* Never free borrowed cached metadata. */
	owned[i] = NULL;
	free(p);
}
int
dt_ioctl(dtrace_hdl_t *dtp, u_long cmd, void *arg)
{
	dtrace_bufdesc_t *b = *(dtrace_bufdesc_t **)arg;
	(void)dtp;
	assert(cmd == DTRACEIOC_AGGSNAP);
	b->dtbd_data = (char *)samples;
	b->dtbd_size = sizeof(samples);
	b->dtbd_drops = 0;
	return (0);
}
int
dt_aggid_lookup(dtrace_hdl_t *dtp, dtrace_aggid_t id,
    dtrace_aggdesc_t **out)
{
	(void)dtp;
	if (id < 1 || id > 3)
		return (-1);
	*out = descs[id - 1];
	return (0);
}
int
dt_epid_lookup(dtrace_hdl_t *dtp, dtrace_epid_t id,
    dtrace_eprobedesc_t **out, dtrace_probedesc_t **p)
{
	(void)dtp;
	assert(id >= 1 && id <= 3);
	if (fail_epid)
		return (-1);
	*out = enabled[id - 1];
	*p = &probes[id - 1];
	return (0);
}
static void
init(dtrace_hdl_t *dtp, int split_var)
{
	memset(dtp, 0, sizeof(*dtp));
	for (size_t i = 0; i < nitems(dtp->dt_options); i++)
		dtp->dt_options[i] = DTRACEOPT_UNSET;
	for (int i = 0; i < 3; i++) {
		dtrace_aggdesc_t *d = descs[i];
		memset(d, 0, sizeof(*d) + 2 * sizeof(dtrace_recdesc_t));
		d->dtagd_id = i + 1;
		d->dtagd_epid = i + 1;
		d->dtagd_varid = split_var && i == 2 ? 43 : 42;
		d->dtagd_size = 32;
		d->dtagd_nrecs = 3;
		d->dtagd_rec[0].dtrd_offset = 8;
		d->dtagd_rec[0].dtrd_size = 8;
		d->dtagd_rec[0].dtrd_action = DTRACEACT_DIFEXPR;
		d->dtagd_rec[1].dtrd_offset = 16;
		d->dtagd_rec[1].dtrd_size = 8;
		d->dtagd_rec[1].dtrd_action = DTRACEACT_DIFEXPR;
		d->dtagd_rec[2].dtrd_offset = 24;
		d->dtagd_rec[2].dtrd_size = 8;
		d->dtagd_rec[2].dtrd_action = DTRACEAGG_COUNT;
		enabled[i]->dtepd_nrecs = 2;
		enabled[i]->dtepd_rec[0].dtrd_size = 8;
		enabled[i]->dtepd_rec[1].dtrd_offset = 24;
		enabled[i]->dtepd_vmid = i == 1 ? 2 : 1;
		probes[i].dtpd_vmid = enabled[i]->dtepd_vmid;
		samples[i][0] = i + 1;
		samples[i][1] = d->dtagd_varid;
		samples[i][2] = 77;
		samples[i][3] = i + 5;
	}
}
static void
clear(dtrace_hdl_t *dtp)
{
	dt_ahash_t *hash = &dtp->dt_aggregate.dtat_hash;
	for (dt_ahashent_t *h = hash->dtah_all, *next; h; h = next) {
		next = h->dtahe_nextall;
		free(h->dtahe_data.dtada_data);
		free(h);
	}
	free(hash->dtah_hash);
}
static int
joined(const dtrace_aggdata_t **data, int n, void *arg)
{
	unsigned vm = data[0]->dtada_edesc->dtepd_vmid;
	(void)arg;
	assert(vm == 1 || vm == 2);
	assert(n == expected_cols + 1);
	for (int i = 1; i < n; i++) {
		uint64_t value = ((uint64_t *)data[i]->dtada_data)[3];
		assert(data[i]->dtada_edesc->dtepd_vmid == vm);
		assert(data[i]->dtada_edesc->dtepd_nrecs == 2);
		assert(data[i]->dtada_edesc->dtepd_rec[0].dtrd_size == 8);
		assert(data[i]->dtada_edesc->dtepd_rec[1].dtrd_offset == 24);
		assert(data[i]->dtada_pdesc->dtpd_vmid == vm);
		if (i == 1)
			assert(value == (vm == 1 ? 5 : 6));
		else if (i == n - 1 && expected_cols == 4)
			assert(value == 0); /* Globally absent variable. */
		else
			assert(value == (vm == 1 ? 7 : 0));
	}
	rows++;
	return (0);
}
int
main(void)
{
	dtrace_hdl_t dtp;
	dtrace_aggvarid_t vars[] = {42, 43, 43, 44};
	uint64_t totals[3] = {0};
	int entries = 0, rc, allocation_count;

	for (int i = 0; i < 3; i++) {
		descs[i] = calloc(1, sizeof(*descs[i]) + 2 * sizeof(dtrace_recdesc_t));
		assert(descs[i] != NULL);
		enabled[i] = calloc(1, sizeof(*enabled[i]) + sizeof(dtrace_recdesc_t));
		assert(enabled[i] != NULL);
	}
	init(&dtp, 0);
	assert(dt_aggregate_snap_cpu(&dtp, 0) == 0);
	for (dt_ahashent_t *h = dtp.dt_aggregate.dtat_hash.dtah_all; h;
	    h = h->dtahe_nextall) {
		entries++;
		totals[h->dtahe_data.dtada_edesc->dtepd_vmid] +=
		    ((uint64_t *)h->dtahe_data.dtada_data)[3];
	}
	printf("entries=%d vm1=%ju vm2=%ju\n", entries,
	    (uintmax_t)totals[1], (uintmax_t)totals[2]);
	if (entries != 2 || totals[1] != 12 || totals[2] != 6)
		return (1);
	clear(&dtp);

	/* Different VM/key pairs with equal hash sums still stay separate. */
	init(&dtp, 0);
	samples[1][2] = 76;
	assert(dt_aggregate_snap_cpu(&dtp, 0) == 0);
	entries = 0;
	for (dt_ahashent_t *h = dtp.dt_aggregate.dtat_hash.dtah_all; h;
	    h = h->dtahe_nextall)
		entries++;
	assert(entries == 2);
	clear(&dtp);
	/* Host VMID0 retains traditional tuple merging. */
	init(&dtp, 0);
	for (int i = 0; i < 3; i++)
		enabled[i]->dtepd_vmid = probes[i].dtpd_vmid = 0;
	assert(dt_aggregate_snap_cpu(&dtp, 0) == 0);
	assert(dtp.dt_aggregate.dtat_hash.dtah_all->dtahe_nextall == NULL);
	assert(((uint64_t *)dtp.dt_aggregate.dtat_hash.dtah_all->
	    dtahe_data.dtada_data)[3] == 18);
	clear(&dtp);

	init(&dtp, 1);
	assert(dt_aggregate_snap_cpu(&dtp, 0) == 0);
	for (expected_cols = 2; expected_cols <= 4; expected_cols++) {
		rows = calls = 0;
		assert(dtrace_aggregate_walk_joined(&dtp, vars,
		    expected_cols, joined, NULL) == 0);
		assert(rows == 2);
	}
	allocation_count = calls;
	/* Fail each allocation in the widest joined walk; no borrowed frees. */
	expected_cols = 4;
	for (fail_at = 1; fail_at <= allocation_count; fail_at++) {
		calls = rows = 0;
		rc = dtrace_aggregate_walk_joined(&dtp, vars, 4, joined, NULL);
		assert(rc == -1);
		for (int i = 0; i < 256; i++)
			assert(owned[i] == NULL);
	}
	fail_at = 0;
	/* Missing global column needs metadata lookup: failure must clean up. */
	fail_epid = 1;
	assert(dtrace_aggregate_walk_joined(&dtp, vars, 4, joined, NULL) == -1);
	for (int i = 0; i < 256; i++)
		assert(owned[i] == NULL);
	fail_epid = 0;
	for (int i = 0; i < 3; i++) {
		assert(enabled[i]->dtepd_vmid == (i == 1 ? 2 : 1));
		assert(probes[i].dtpd_vmid == enabled[i]->dtepd_vmid);
	}
	clear(&dtp);
	init(&dtp, 0);
	fail_epid = 1;
	assert(dt_aggregate_snap_cpu(&dtp, 0) == -1);
	clear(&dtp);
	for (int i = 0; i < 3; i++) {
		free(descs[i]);
		free(enabled[i]);
	}
	puts("PASS VM separation, same-VM merge, joined zero/remap/absent columns, allocation and descriptor errors");
	return (0);
}
