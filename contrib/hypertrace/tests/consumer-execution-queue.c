/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dtraced_wire.h"

typedef struct dtd_arg { uint8_t rx_session[16]; } dtd_arg_t;
typedef struct dt_pgplist {
	int execution_done;
	int execution_ok;
} dt_pgplist_t;
typedef struct dt_execution_notice {
	struct dt_execution_notice *next;
	dtraced_consumer_ack_t result;
	dt_pgplist_t *wait_for;
} dt_execution_notice_t;

static dt_execution_notice_t *g_execution_notices;
static size_t g_execution_notice_count;
static int g_execution_receiver_done;
static int g_execution_reporting;
static pthread_mutex_t g_pgplistmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_pgpcond = PTHREAD_COND_INITIALIZER;
static _Atomic int g_intr, g_impatient;
static _Atomic int g_session_stop;
static dtraced_consumer_ack_t reported[4];
static unsigned nreported;

static void
fatal(const char *format, ...)
{
	(void)format;
	abort();
}

static int
report_identified_execution(const dtd_arg_t *connection,
    const dtraced_consumer_ack_t *result)
{
	(void)connection;
	pthread_mutex_lock(&g_pgplistmtx);
	assert(nreported < 4);
	reported[nreported++] = *result;
	pthread_cond_broadcast(&g_pgpcond);
	pthread_mutex_unlock(&g_pgplistmtx);
	return (0);
}

/* FUNCTIONS */

static void
wait_for_count(unsigned count)
{
	for (int i = 0; i < 1000; i++) {
		pthread_mutex_lock(&g_pgplistmtx);
		unsigned current = nreported;
		pthread_mutex_unlock(&g_pgplistmtx);
		if (current == count)
			return;
		usleep(1000);
	}
	abort();
}

int
main(void)
{
	dtd_arg_t connection = {};
	dt_pgplist_t dependent = {};
	dt_pgplist_t failed = { .execution_done = 1 };
	dtraced_hdr_t header = { .msg_type = DTRACED_MSG_ELF };
	pthread_t reporter;

	assert(pthread_create(&reporter, NULL,
	    report_identified_executions, &connection) == 0);
	header.elf.delivery_id = 9;
	header.elf.vmid = 3;
	header.elf.epoch = 7;
	header.elf.program_id[0] = 0xa1;
	header.elf.source_id[0] = 0xb2;
	header.installed.delivery_id = header.elf.delivery_id;
	header.installed.vmid = header.elf.vmid;
	header.installed.epoch = header.elf.epoch;
	header.installed.program_id[0] = header.elf.program_id[0];
	header.installed.source_id[0] = header.elf.source_id[0];
	header.installed.name[0] = 0xc3;
	assert(identified_ingress_header_valid(&header));
	header.installed.epoch++;
	assert(!identified_ingress_header_valid(&header));
	header.installed.epoch--;
	header.installed.name[0] = 0;
	assert(!identified_ingress_header_valid(&header));
	header.installed.name[0] = 0xc3;
	queue_identified_execution(&header,
	    DTRACED_CONSUMER_ACK_DERIVED, &dependent);
	usleep(10000);
	assert(nreported == 0);
	header.elf.delivery_id = 10;
	header.installed.delivery_id = 10;
	queue_identified_execution(&header,
	    DTRACED_CONSUMER_ACK_NO_DERIVED, NULL);
	wait_for_count(1);
	assert(reported[0].delivery_id == 10 &&
	    reported[0].outcome == DTRACED_CONSUMER_ACK_NO_DERIVED);
	pthread_mutex_lock(&g_pgplistmtx);
	dependent.execution_done = dependent.execution_ok = 1;
	pthread_cond_broadcast(&g_pgpcond);
	pthread_mutex_unlock(&g_pgplistmtx);
	wait_for_count(2);
	assert(reported[1].delivery_id == 9 &&
	    reported[1].outcome == DTRACED_CONSUMER_ACK_DERIVED &&
	    reported[1].program_id[0] == 0xa1 &&
	    reported[1].source_id[0] == 0xb2 &&
	    reported[1].ingress_session[0] == 0xc3 &&
	    reported[1].vmid == 3 && reported[1].epoch == 7);
	header.elf.delivery_id = 11;
	header.installed.delivery_id = 11;
	queue_identified_execution(&header,
	    DTRACED_CONSUMER_ACK_NO_DERIVED, &failed);
	usleep(10000);
	assert(nreported == 2);
	header.elf.delivery_id = 12;
	header.installed.delivery_id = 12;
	queue_identified_execution(&header,
	    DTRACED_CONSUMER_ACK_NO_DERIVED, NULL);
	pthread_mutex_lock(&g_pgplistmtx);
	g_execution_receiver_done = 1;
	pthread_cond_broadcast(&g_pgpcond);
	pthread_mutex_unlock(&g_pgplistmtx);
	assert(pthread_join(reporter, NULL) == 0);
	assert(nreported == 3 && reported[2].delivery_id == 12);
	assert(g_execution_notices == NULL && g_execution_notice_count == 0);
	atomic_store(&g_session_stop, 1);
	queue_identified_execution(&header,
	    DTRACED_CONSUMER_ACK_NO_DERIVED, NULL);
	assert(pthread_create(&reporter, NULL, report_identified_executions,
	    &connection) == 0);
	assert(pthread_join(reporter, NULL) == 0);
	assert(nreported == 3 && !g_execution_reporting &&
	    g_execution_notice_count == 1);
	free(g_execution_notices);
	g_execution_notices = NULL;
	g_execution_notice_count = 0;
	puts("PASS: identified execution queue waits, skips, and preserves identity");
	return (0);
}
