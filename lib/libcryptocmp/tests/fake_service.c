/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Scripted system.Crypto provider for the libcryptocmp client tests.  It
 * replaces libservice's service_open(): each call creates a real capability
 * channel and serves the provider end with a bsd.crypto.v1 server on its own
 * thread, so the client library runs over the native transport.  Each
 * scripted fault or status applies to the next operation (not negotiation).
 */
#include <sys/param.h>
#include <sys/types.h>

#include <assert.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.crypto.v1/c/bsd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cryptocmp.h>

#include "fake_service.h"

int service_open(const char *, int *);
int service_budget_timeout(uint32_t *);

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static enum fake_service_fault next_fault;
static unsigned calls, closed, created;
static int next_status, last_fd = -1;

void
fake_service_reset(void)
{

	pthread_mutex_lock(&lock);
	/* Let earlier sessions' servers notice their clients left. */
	while (closed < created)
		pthread_cond_wait(&changed, &lock);
	next_fault = FAKE_SERVICE_FAULT_NONE;
	next_status = 0;
	if (last_fd >= 0)
		close(last_fd);
	last_fd = -1;
	calls = closed = created = 0;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fault_next(enum fake_service_fault fault)
{

	pthread_mutex_lock(&lock);
	next_fault = fault;
	pthread_mutex_unlock(&lock);
}

void
fake_service_status_next(int status)
{

	pthread_mutex_lock(&lock);
	next_status = status;
	pthread_mutex_unlock(&lock);
}

int
fake_service_last_fd(void)
{
	int fd;

	pthread_mutex_lock(&lock);
	fd = last_fd;
	pthread_mutex_unlock(&lock);
	return (fd);
}

#define COUNTER(name, value)                                                  \
unsigned                                                                      \
name(void)                                                                    \
{                                                                             \
	unsigned result;                                                      \
	pthread_mutex_lock(&lock);                                            \
	result = value;                                                       \
	pthread_mutex_unlock(&lock);                                          \
	return (result);                                                      \
}
COUNTER(fake_service_calls, calls)
COUNTER(fake_service_created, created)

/* Sessions whose server saw its client leave (waits briefly for them). */
unsigned
fake_service_closed(void)
{
	struct timespec deadline;
	unsigned result;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 2;
	pthread_mutex_lock(&lock);
	while (closed < created &&
	    pthread_cond_timedwait(&changed, &lock, &deadline) == 0)
		;
	result = closed;
	pthread_mutex_unlock(&lock);
	return (result);
}

/* Callers' RPC budgets are not under test here. */
int
service_budget_timeout(uint32_t *ms)
{
	return (ms == NULL ? (errno = EINVAL, -1) : 0);
}

/* The scripted outcome for the next operation. */
static void
take(enum fake_service_fault *fault, int *status)
{

	pthread_mutex_lock(&lock);
	calls++;
	*fault = next_fault;
	*status = next_status;
	next_fault = FAKE_SERVICE_FAULT_NONE;
	next_status = 0;
	pthread_mutex_unlock(&lock);
}

/* Map the script to an error value, or 0 for a normal reply. */
static uint32_t
scripted_error(enum fake_service_fault fault, int status)
{

	if (fault == FAKE_SERVICE_FAULT_ZERO_ERRNO)
		return (0xffffffffU);	/* sentinel: send err = 0 */
	if (fault == FAKE_SERVICE_FAULT_RANGE_ERRNO)
		return (ELAST + 1);
	return ((uint32_t)status);
}

#define REPLY_ERROR(method)                                                   \
	do {                                                                  \
		struct bsd_crypto_v1_Crypto_##method##_Result e = {           \
			.tag = bsd_crypto_v1_Crypto_##method##_Result_err_tag \
		};                                                            \
		e.value.err = err == 0xffffffffU ? 0 : err;                   \
		assert(bsd_crypto_v1_Crypto_##method##_reply(c, r, &e) == 0); \
		return;                                                       \
	} while (0)

#define PROLOGUE(method)                                                      \
	enum fake_service_fault fault;                                        \
	int status;                                                           \
	uint32_t err;                                                         \
	(void)x;                                                              \
	take(&fault, &status);                                                \
	if (fault == FAKE_SERVICE_FAULT_CALL) {                               \
		fidl_bsd_connection_close(c, ECONNRESET);                     \
		return;                                                       \
	}                                                                     \
	err = scripted_error(fault, status);                                  \
	if (err != 0)                                                         \
		REPLY_ERROR(method);

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_crypto_v1_ProtocolInfo v = { CRYPTOCMP_WIRE_VERSION };
	(void)x;
	(void)e;
	pthread_mutex_lock(&lock);
	if (next_fault == FAKE_SERVICE_FAULT_FUTURE_VERSION) {
		v.wire_version++;
		next_fault = FAKE_SERVICE_FAULT_NONE;
	}
	pthread_mutex_unlock(&lock);
	assert(bsd_crypto_v1_Crypto_GetProtocolInfo_reply(c, r, &v) == 0);
}

static int
null_fd(void)
{
	int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	assert(fd >= 0);
	return (fd);
}

static void
generate(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_GenerateParams *q)
{
	struct bsd_crypto_v1_Crypto_Generate_Result v = {
		.tag = bsd_crypto_v1_Crypto_Generate_Result_response_tag
	};
	PROLOGUE(Generate)
	(void)q;
	v.value.response.descriptor = null_fd();
	assert(bsd_crypto_v1_Crypto_Generate_reply(c, r, &v) == 0);
	close(v.value.response.descriptor);
}

static void
generate_key(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_KeyParams *q)
{
	struct bsd_crypto_v1_Crypto_GenerateKey_Result v = {
		.tag = bsd_crypto_v1_Crypto_GenerateKey_Result_response_tag
	};
	PROLOGUE(GenerateKey)
	(void)q;
	v.value.response.descriptor = null_fd();
	memset(v.value.response.public_key, 0xa5,
	    sizeof(v.value.response.public_key));
	assert(bsd_crypto_v1_Crypto_GenerateKey_reply(c, r, &v) == 0);
	close(v.value.response.descriptor);
}

#define GENERATION(name, method, request)                                     \
static void                                                                   \
name(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,      \
    struct request *q)                                                        \
{                                                                             \
	struct bsd_crypto_v1_Crypto_##method##_Result v = {                   \
		.tag = bsd_crypto_v1_Crypto_##method##_Result_response_tag    \
	};                                                                    \
	PROLOGUE(method)                                                      \
	(void)q;                                                              \
	v.value.response.generation =                                         \
	    fault == FAKE_SERVICE_FAULT_NAMED_GENERATION ? 0 : 42;            \
	assert(bsd_crypto_v1_Crypto_##method##_reply(c, r, &v) == 0);         \
}
GENERATION(named_create, NamedCreate, bsd_crypto_v1_NamedCreateRequest)
GENERATION(named_rotate, NamedRotate, bsd_crypto_v1_NamedControlRequest)
GENERATION(named_delete, NamedDelete, bsd_crypto_v1_NamedControlRequest)

static void
named_lease(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_NamedLeaseRequest *q)
{
	struct bsd_crypto_v1_Crypto_NamedLease_Result v = {
		.tag = bsd_crypto_v1_Crypto_NamedLease_Result_response_tag
	};
	int ends[2];
	PROLOGUE(NamedLease)
	(void)q;
	/* Deliver a pipe's write end so a test can tell whether it closed. */
	assert(pipe(ends) == 0);
	pthread_mutex_lock(&lock);
	if (last_fd >= 0)
		close(last_fd);
	last_fd = ends[0];
	pthread_mutex_unlock(&lock);
	v.value.response.descriptor = ends[1];
	v.value.response.generation =
	    fault == FAKE_SERVICE_FAULT_LEASE_GENERATION ? 0 : 42;
	assert(bsd_crypto_v1_Crypto_NamedLease_reply(c, r, &v) == 0);
	close(ends[1]);
}

static void
digest(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_DigestParams *q)
{
	struct bsd_crypto_v1_Crypto_Digest_Result v = {
		.tag = bsd_crypto_v1_Crypto_Digest_Result_response_tag
	};
	PROLOGUE(Digest)
	(void)q;
	v.value.response.descriptor = null_fd();
	assert(bsd_crypto_v1_Crypto_Digest_reply(c, r, &v) == 0);
	close(v.value.response.descriptor);
}

static void
random_bytes(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_RandomRequest *q)
{
	struct bsd_crypto_v1_Crypto_Random_Result v = {
		.tag = bsd_crypto_v1_Crypto_Random_Result_response_tag
	};
	uint8_t data[CRYPTOCMP_MAX_RANDOM_BYTES + 1];
	PROLOGUE(Random)
	memset(data, 0x5a, sizeof(data));
	v.value.response.data = data;
	v.value.response.data_size = q->nbytes +
	    (fault == FAKE_SERVICE_FAULT_RANDOM_SIZE ? 1 : 0);
	assert(bsd_crypto_v1_Crypto_Random_reply(c, r, &v) == 0);
}

static void
named_stat(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_NamedControlRequest *q)
{
	struct bsd_crypto_v1_Crypto_NamedStat_Result v = {
		.tag = bsd_crypto_v1_Crypto_NamedStat_Result_response_tag
	};
	PROLOGUE(NamedStat)
	(void)q;
	v.value.response.generation =
	    fault == FAKE_SERVICE_FAULT_STAT_GENERATION ? 0 : 42;
	v.value.response.rights =
	    fault == FAKE_SERVICE_FAULT_STAT_RIGHTS ? 0 : 3;
	v.value.response.cipher = 11;
	v.value.response.keylen = 32;
	assert(bsd_crypto_v1_Crypto_NamedStat_reply(c, r, &v) == 0);
}

static void
named_list(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct bsd_crypto_v1_NamedListRequest *q)
{
	struct bsd_crypto_v1_Crypto_NamedList_Result v = {
		.tag = bsd_crypto_v1_Crypto_NamedList_Result_response_tag
	};
	struct bsd_crypto_v1_NamedEntry entries[2] = {
		{ "alpha", 5, 10, 3 },
		{ "beta", 4, 11, 3 },
	};
	PROLOGUE(NamedList)
	switch (fault) {
	case FAKE_SERVICE_FAULT_LIST_CURSOR:
		v.value.response.next_cursor = q->cursor;
		break;
	case FAKE_SERVICE_FAULT_LIST_NAME:
		entries[0].name = "al/pha";
		entries[0].name_size = 6;
		break;
	case FAKE_SERVICE_FAULT_LIST_GENERATION:
		entries[0].generation = 0;
		break;
	case FAKE_SERVICE_FAULT_LIST_RIGHTS:
		entries[0].rights = 0;
		break;
	default:
		break;
	}
	v.value.response.entries = entries;
	v.value.response.entries_size = 2;
	assert(bsd_crypto_v1_Crypto_NamedList_reply(c, r, &v) == 0);
}

static void *
serve(void *argument)
{
	struct bsd_crypto_v1_Crypto_server handlers = {
		.GetProtocolInfo = info,
		.Generate = generate,
		.GenerateKey = generate_key,
		.NamedCreate = named_create,
		.NamedLease = named_lease,
		.NamedRotate = named_rotate,
		.NamedDelete = named_delete,
		.Digest = digest,
		.Random = random_bytes,
		.NamedStat = named_stat,
		.NamedList = named_list
	};
	struct fidl_bsd_connection *connection;
	int fd = (int)(intptr_t)argument;

	assert(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER,
	    &connection) == 0);
	assert(bsd_crypto_v1_Crypto_bind(connection, &handlers, NULL) == 0);
	while (fidl_bsd_connection_poll(connection, 10000) == 0)
		;
	fidl_bsd_connection_destroy(connection);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_cond_broadcast(&changed);
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int
service_open(const char *name, int *fd)
{
	pthread_t thread;
	int ends[2];

	if (name == NULL || strcmp(name, CRYPTOCMP_INTERFACE) != 0 ||
	    fd == NULL)
		return (errno = EINVAL, -1);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	assert(pthread_create(&thread, NULL, serve,
	    (void *)(intptr_t)ends[1]) == 0);
	assert(pthread_detach(thread) == 0);
	pthread_mutex_lock(&lock);
	created++;
	pthread_mutex_unlock(&lock);
	*fd = ends[0];
	return (0);
}
