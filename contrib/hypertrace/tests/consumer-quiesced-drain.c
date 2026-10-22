// SPDX-License-Identifier: BSD-2-Clause
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

enum { DTRACEOPT_BUFPOLICY, DTRACEOPT_TEMPORAL };
enum { DTRACEOPT_UNSET = -1, DTRACEOPT_BUFPOLICY_SWITCH = 1,
    DTRACEOPT_BUFPOLICY_RING = 2, DTRACEOPT_BUFPOLICY_FILL = 3 };
typedef struct dt_idhash { unsigned long count; } dt_idhash_t;
typedef struct dtrace_hdl {
    int64_t dt_options[2];
    int64_t dt_lastswitch;
    int64_t dt_lastagg;
    int dt_active;
    int dt_drain_final;
    int dt_oformat;
    int error;
    dt_idhash_t *dt_aggs;
    struct { struct { void *dtah_all; } dtat_hash; } dt_aggregate;
} dtrace_hdl_t;
typedef struct dtrace_consumer { int unused; } dtrace_consumer_t;

static int snapshots, consumed, fail_snapshot, fail_consume, abort_consume;
static int materialize_aggregate;
static int drain_checks, speculative, fail_second_check;
#define DTRACEIOC_DRAINABLE 22
static int
dt_ioctl(dtrace_hdl_t *dtp, int command, void *arg)
{
    assert(dtp != NULL && command == DTRACEIOC_DRAINABLE && arg == NULL);
    drain_checks++;
    if (speculative || (fail_second_check && (drain_checks & 1) == 0)) {
        errno = speculative ? EOPNOTSUPP : EIO;
        return (-1);
    }
    return (0);
}
static unsigned long
dt_idhash_size(const dt_idhash_t *hash)
{
    return (hash->count);
}
static int
dt_set_errno(dtrace_hdl_t *dtp, int error)
{
    dtp->error = error;
    return (-1);
}
static int
dtrace_aggregate_snap(dtrace_hdl_t *dtp)
{
    assert(dtp->dt_lastswitch == 0 && dtp->dt_lastagg == 0);
    snapshots++;
    if (materialize_aggregate)
        dtp->dt_aggregate.dtat_hash.dtah_all = &materialize_aggregate;
    return (fail_snapshot ? dt_set_errno(dtp, EIO) : 0);
}
static int
dtrace_consume_consumer(dtrace_hdl_t *dtp, FILE *fp,
    dtrace_consumer_t *con, void *arg)
{
    assert(con != NULL && arg == NULL);
    /* The drain consumes with the final flag set, whatever the ordering
     * option, so a temporal queue emits every retained record. */
    assert(dtp->dt_drain_final == 1);
    consumed++;
    if (fail_consume)
        return (dt_set_errno(dtp, EIO));
    if (abort_consume)
        return (1);
    assert(fputs("drained", fp) >= 0);
    return (0);
}

#include "consumer-quiesced-drain.inc"

int
main(void)
{
    dtrace_hdl_t dtp = { .dt_options = {
        DTRACEOPT_BUFPOLICY_SWITCH, DTRACEOPT_UNSET },
        .dt_active = 1, .dt_lastswitch = 42, .dt_lastagg = 43 };
    dtrace_consumer_t con = { 0 };
    dt_idhash_t aggs = { 0 };
    FILE *fp = tmpfile();
    struct stat st;
    assert(fp != NULL);
    dtp.dt_aggs = &aggs;

    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == 0);
    assert(snapshots == 1 && consumed == 1 && drain_checks == 2);
    assert(fstat(fileno(fp), &st) == 0 && st.st_size == 7);
    assert(dtp.dt_lastswitch == 0 && dtp.dt_lastagg == 0);

    aggs.count = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 1 && consumed == 1);
    aggs.count = 0;
    dtp.dt_aggregate.dtat_hash.dtah_all = &aggs;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 1 && consumed == 1);
    dtp.dt_aggregate.dtat_hash.dtah_all = NULL;
    materialize_aggregate = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 2 && consumed == 1);
    materialize_aggregate = 0;
    dtp.dt_aggregate.dtat_hash.dtah_all = NULL;

    dtp.dt_options[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_RING;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 2);
    dtp.dt_options[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_FILL;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 2);
    dtp.dt_options[DTRACEOPT_BUFPOLICY] = DTRACEOPT_BUFPOLICY_SWITCH;
    dtp.dt_oformat = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 2);
    dtp.dt_oformat = 0;
    /* Temporal ordering no longer refuses the drain: the snapshot is consumed
     * with dt_drain_final set and the flag is clear again afterwards. */
    dtp.dt_options[DTRACEOPT_TEMPORAL] = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == 0 &&
        snapshots == 3 && consumed == 2 && dtp.dt_drain_final == 0);
    dtp.dt_options[DTRACEOPT_TEMPORAL] = DTRACEOPT_UNSET;
    dtp.dt_active = 0;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EINVAL && snapshots == 3);
    dtp.dt_active = 1;
    fail_snapshot = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EIO && snapshots == 4 && consumed == 2);
    fail_snapshot = 0;
    fail_consume = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EIO && snapshots == 5 && consumed == 3);
    /* A failed consume still clears the final flag. */
    assert(dtp.dt_drain_final == 0);
    fail_consume = 0;
    abort_consume = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == ECANCELED && snapshots == 6 && consumed == 4);
    abort_consume = 0;
    speculative = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EOPNOTSUPP && snapshots == 6 && consumed == 4);
    speculative = 0;
    drain_checks = 0;
    fail_second_check = 1;
    assert(dtrace_consume_quiesced(&dtp, fp, &con, NULL) == -1 &&
        dtp.error == EIO && snapshots == 7 && consumed == 4 &&
        drain_checks == 2);
    assert(dtrace_consume_quiesced(NULL, fp, &con, NULL) == -1);
    assert(dtrace_consume_quiesced(&dtp, fp, NULL, NULL) == -1);
    assert(fclose(fp) == 0);
    return (0);
}
