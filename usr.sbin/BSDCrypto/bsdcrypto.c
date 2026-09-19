/*- SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/types.h>
#include <sys/cryptodesc.h>
#include <auditcmp.h>
#include <auditcmp_server.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <capreclaim.h>
#include <channel.h>
#include <cryptodesc.h>
#include <cryptocmp_protocol.h>
#include <libservice.h>
#include <logcmp.h>

#include "policy.h"
#include "crypto_probes.h"
#ifdef BSDCRYPTO_TESTING
#include "bsdcrypto_test.h"
#endif

#define CRYPTOCMP_NAME "system.Crypto"

static int control_fd;
struct crypto_worker {
	char	owner[CRYPTODESC_KEY_OWNER_MAX];
	char	actor[64];
	struct auditcmp_client *audit;
};

static int
harden_control_descriptor(bool worker)
{
	static const unsigned long commands[] = {
		CIOCGCRYPTODESCGENERATE,
		CIOCGCRYPTOKEYDESC,
		CIOCGCRYPTONAMEDKEY,
		CIOCGCRYPTONAMEDLEASE,
		CIOCCRYPTONAMEDROTATE,
		CIOCCRYPTONAMEDDELETE,
		CIOCGCRYPTONAMEDSTAT,
		CIOCGCRYPTONAMEDLIST,
		CIOCGCRYPTOOWNERLIST,
	};
	cap_rights_t rights;

	if (cap_xfer_limit(control_fd, CAP_XFER_NONE) == -1 ||
	    (worker && cap_clofork_limit(control_fd, CAP_CLOFORK_LOCKED) == -1) ||
	    cap_cloexec_limit(control_fd, CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_ioctls_limit(control_fd, commands, nitems(commands)) == -1)
		return (-1);
	cap_rights_init(&rights, CAP_IOCTL);
	return (cap_rights_limit(control_fd, &rights));
}

static void
audit_operation(struct crypto_worker *worker, const char *operation, int error)
{

	if (worker->audit != NULL)
		(void)auditcmp_submit(worker->audit, worker->actor, operation, error);
}
static void
request(struct channel *c __unused, struct channel_message *m, void *arg __unused)
{
	const struct cryptocmp_msg *in;
	const struct cryptocmp_generate *generate;
	const struct cryptocmp_key_generate *key_generate;
	const struct cryptocmp_named_create *named_create;
	const struct cryptocmp_named_lease *named_lease;
	const struct cryptocmp_named_control *named_control;
	const struct cryptocmp_named_stat *named_stat;
	const struct cryptocmp_named_list *named_list;
	const struct cryptocmp_digest *digest;
	const struct cryptocmp_random *random_request;
	struct cryptocmp_msg out;
	struct cryptocmp_key_reply key_out;
	struct cryptocmp_named_reply named_out;
	struct cryptocmp_named_stat_reply stat_out;
	struct cryptocmp_named_list_reply list_out;
	struct cryptocmp_random_reply random_out;
	struct cryptodesc_named_stat stat;
	struct cryptodesc_named_list_entry list_entries[CRYPTODESC_NAMED_LIST_MAX];
	uint32_t list_count, list_next_cursor;
	struct session2_op session;
	struct crypto_worker *worker;
	const char *operation;
	const void *reply_data;
	size_t reply_length;
	uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE];
	uint64_t generation;
	uint32_t random_bytes;
	int fd, error, deliver_fd;

	fd = -1;
	error = EPROTO;
	operation = "malformed-request";
	in = channel_message_data(m);
	memset(&out, 0, sizeof(out));
	memset(&key_out, 0, sizeof(key_out));
	memset(&named_out, 0, sizeof(named_out));
	memset(&stat_out, 0, sizeof(stat_out));
	memset(&list_out, 0, sizeof(list_out));
	memset(&random_out, 0, sizeof(random_out));
	memset(&stat, 0, sizeof(stat));
	memset(list_entries, 0, sizeof(list_entries));
	list_count = 0;
	list_next_cursor = 0;
	memset(public_key, 0, sizeof(public_key));
	generation = 0;
	random_bytes = 0;
	worker = arg;
	if (channel_message_length(m) >= sizeof(*in) &&
	    channel_message_fd_count(m) == 0 &&
	    in->magic == CRYPTOCMP_MAGIC &&
	    in->version == CRYPTOCMP_VERSION &&
	    in->opcode >= CRYPTOCMP_OP_GENERATE &&
	    in->opcode <= CRYPTOCMP_OP_NAMED_LIST) {
		out.opcode = in->opcode;
		if (in->opcode == CRYPTOCMP_OP_GENERATE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*generate)) {
			operation = "descriptor-generate";
			generate = (const struct cryptocmp_generate *)(in + 1);
			if (cryptocmp_policy_validate(generate) != 0) {
				error = errno;
				goto reply;
			}
			memset(&session, 0, sizeof(session));
			session.cipher = generate->cipher;
			session.mac = generate->mac;
			session.keylen = generate->keylen;
			session.key = NULL;
			session.mackeylen = generate->mackeylen;
			session.mackey = NULL;
			session.crid = generate->crid;
			session.ivlen = generate->ivlen;
			session.maclen = generate->maclen;
			if (cryptodesc_mint_generated(control_fd, &session,
			    generate->rights, generate->ttl, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_GENERATE_KEY &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*key_generate)) {
			operation = "key-generate";
			key_generate = (const struct cryptocmp_key_generate *)(in + 1);
			if (cryptocmp_key_policy_validate(key_generate) != 0) {
				error = errno;
				goto reply;
			}
			if (cryptodesc_mint_key(control_fd, key_generate->type,
			    key_generate->rights, key_generate->ttl, public_key, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_CREATE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_create)) {
			operation = "named-create";
			named_create = (const struct cryptocmp_named_create *)(in + 1);
			if (cryptocmp_named_create_policy_validate(named_create) != 0) {
				error = errno;
				goto reply;
			}
			memset(&session, 0, sizeof(session));
			session.cipher = named_create->generate.cipher;
			session.mac = named_create->generate.mac;
			session.keylen = named_create->generate.keylen;
			session.mackeylen = named_create->generate.mackeylen;
			session.crid = named_create->generate.crid;
			session.ivlen = named_create->generate.ivlen;
			session.maclen = named_create->generate.maclen;
			if (cryptodesc_named_create(control_fd, named_create->name,
			    worker->owner, &session, named_create->generate.rights,
			    &generation) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_LEASE &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_lease)) {
			operation = "named-lease";
			named_lease = (const struct cryptocmp_named_lease *)(in + 1);
			if (cryptocmp_named_lease_policy_validate(named_lease) != 0) {
				error = errno;
				goto reply;
			}
			if (cryptodesc_named_lease(control_fd, named_lease->name,
			    worker->owner, named_lease->rights, named_lease->ttl,
			    &generation, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if ((in->opcode == CRYPTOCMP_OP_NAMED_ROTATE ||
		    in->opcode == CRYPTOCMP_OP_NAMED_DELETE) &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_control)) {
			operation = in->opcode == CRYPTOCMP_OP_NAMED_ROTATE ?
			    "named-rotate" : "named-delete";
			named_control = (const struct cryptocmp_named_control *)(in + 1);
			if (cryptocmp_named_control_policy_validate(named_control) != 0) {
				error = errno;
				goto reply;
			}
			if ((in->opcode == CRYPTOCMP_OP_NAMED_ROTATE ?
			    cryptodesc_named_rotate(control_fd, named_control->name,
			    worker->owner, &generation) : cryptodesc_named_delete(control_fd,
			    named_control->name, worker->owner, &generation)) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_STAT &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_stat)) {
			operation = "named-stat";
			named_stat = (const struct cryptocmp_named_stat *)(in + 1);
			if (cryptocmp_named_stat_policy_validate(named_stat) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * Read-only introspection: resolve the key owner-scoped
			 * on worker->owner (never a wire-supplied owner) and copy
			 * out its metadata.  No descriptor is minted and the key
			 * is not mutated; a miss is ENOENT.
			 */
			if (cryptodesc_named_stat(control_fd, named_stat->name,
			    worker->owner, &stat) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_NAMED_LIST &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*named_list)) {
			operation = "named-list";
			named_list = (const struct cryptocmp_named_list *)(in + 1);
			if (cryptocmp_named_list_policy_validate(named_list) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * Owner-scoped enumeration: resolve the walk on
			 * worker->owner (never a wire-supplied owner) and copy
			 * out only names/generations/rights.  No descriptor is
			 * minted, no key is mutated, and no key material leaves
			 * the kernel; an out-of-range cursor is an empty page.
			 */
			if (cryptodesc_named_list(control_fd, worker->owner,
			    named_list->cursor, list_entries,
			    CRYPTODESC_NAMED_LIST_MAX, &list_count,
			    &list_next_cursor) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_DIGEST &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*digest)) {
			operation = "digest";
			digest = (const struct cryptocmp_digest *)(in + 1);
			if (cryptocmp_digest_policy_validate(digest) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * An unkeyed hash is an ordinary DIGEST-mode session with
			 * no cipher and no MAC key.  It reuses the generated-session
			 * mint path (which randomises nothing when both key lengths
			 * are zero) and is delivered as a DTYPE_CRYPTO descriptor the
			 * client streams data through; CRYPTODESC_RIGHT_AUTH is the
			 * right the kernel requires to compute a digest.
			 */
			memset(&session, 0, sizeof(session));
			session.cipher = 0;
			session.mac = digest->alg;
			session.keylen = 0;
			session.key = NULL;
			session.mackeylen = 0;
			session.mackey = NULL;
			session.crid = 0;
			session.ivlen = 0;
			session.maclen = 0;
			if (cryptodesc_mint_generated(control_fd, &session,
			    CRYPTODESC_RIGHT_AUTH, digest->ttl, &fd) == 0)
				error = 0;
			else
				error = errno;
		} else if (in->opcode == CRYPTOCMP_OP_RANDOM &&
		    channel_message_length(m) == sizeof(*in) + sizeof(*random_request)) {
			operation = "random";
			random_request = (const struct cryptocmp_random *)(in + 1);
			if (cryptocmp_random_policy_validate(random_request) != 0) {
				error = errno;
				goto reply;
			}
			/*
			 * CSPRNG bytes are not secret-key material to confine, so
			 * they are returned inline; the reply buffer is scrubbed
			 * after the send regardless.
			 */
			random_bytes = random_request->nbytes;
			arc4random_buf(random_out.data, random_bytes);
			error = 0;
		}
	}

reply:
	out.magic = CRYPTOCMP_MAGIC;
	out.version = CRYPTOCMP_VERSION;
	out.status = error == 0 ? 0 : -error;
	key_out.msg = out;
	named_out.msg = out;
	named_out.generation = generation;
	stat_out.msg = out;
	if (error == 0 && out.opcode == CRYPTOCMP_OP_NAMED_STAT) {
		stat_out.info.generation = stat.cd_generation;
		stat_out.info.rights = stat.cd_rights;
		stat_out.info.cipher = stat.cd_cipher;
		stat_out.info.mac = stat.cd_mac;
		stat_out.info.keylen = stat.cd_keylen;
		stat_out.info.mackeylen = stat.cd_mackeylen;
	}
	list_out.msg = out;
	if (error == 0 && out.opcode == CRYPTOCMP_OP_NAMED_LIST) {
		uint32_t i;

		list_out.count = list_count;
		list_out.next_cursor = list_next_cursor;
		for (i = 0; i < list_count && i < CRYPTOCMP_NAMED_LIST_MAX; i++) {
			strlcpy(list_out.entries[i].name, list_entries[i].cd_name,
			    sizeof(list_out.entries[i].name));
			list_out.entries[i].generation =
			    list_entries[i].cd_generation;
			list_out.entries[i].rights = list_entries[i].cd_rights;
		}
	}
	CRYPTO_PROBE_NAMED_LIST(worker->owner, list_count, error);
	random_out.msg = out;
	random_out.nbytes = error == 0 ? random_bytes : 0;
	audit_operation(worker, operation, error);
	if (out.opcode == CRYPTOCMP_OP_GENERATE_KEY)
		memcpy(key_out.public_key, public_key, sizeof(key_out.public_key));
	/*
	 * Select the reply shape by opcode: keyed-descriptor replies carry the
	 * public key, named-key replies carry the generation, a random reply
	 * carries a variable-length inline payload, and everything else (plain
	 * descriptor mints and malformed requests) uses the bare header.  A
	 * delivered descriptor accompanies only the successful mint/lease ops.
	 */
	switch (out.opcode) {
	case CRYPTOCMP_OP_GENERATE_KEY:
		reply_data = &key_out;
		reply_length = sizeof(key_out);
		break;
	case CRYPTOCMP_OP_NAMED_CREATE:
	case CRYPTOCMP_OP_NAMED_LEASE:
	case CRYPTOCMP_OP_NAMED_ROTATE:
	case CRYPTOCMP_OP_NAMED_DELETE:
		reply_data = &named_out;
		reply_length = sizeof(named_out);
		break;
	case CRYPTOCMP_OP_NAMED_STAT:
		reply_data = &stat_out;
		reply_length = sizeof(stat_out);
		break;
	case CRYPTOCMP_OP_NAMED_LIST:
		reply_data = &list_out;
		reply_length = sizeof(list_out);
		break;
	case CRYPTOCMP_OP_RANDOM:
		reply_data = &random_out;
		reply_length = offsetof(struct cryptocmp_random_reply, data) +
		    (error == 0 ? random_bytes : 0);
		break;
	default:
		reply_data = &out;
		reply_length = sizeof(out);
		break;
	}
	deliver_fd = error == 0 && (out.opcode == CRYPTOCMP_OP_GENERATE ||
	    out.opcode == CRYPTOCMP_OP_GENERATE_KEY ||
	    out.opcode == CRYPTOCMP_OP_NAMED_LEASE ||
	    out.opcode == CRYPTOCMP_OP_DIGEST) ? 1 : 0;
	(void)channel_send_reply(m, &(struct channel_outgoing){
	    .size = sizeof(struct channel_outgoing),
	    .data = reply_data,
	    .length = reply_length,
	    .fds = deliver_fd != 0 ? &fd : NULL,
	    .nfds = deliver_fd });
	if (fd >= 0)
		close(fd);
	explicit_bzero(public_key, sizeof(public_key));
	explicit_bzero(&key_out, sizeof(key_out));
	explicit_bzero(&named_out, sizeof(named_out));
	explicit_bzero(&stat_out, sizeof(stat_out));
	explicit_bzero(&list_out, sizeof(list_out));
	explicit_bzero(list_entries, sizeof(list_entries));
	explicit_bzero(&random_out, sizeof(random_out));
	channel_message_free(m);
}

/*
 * The owner-scoped request/channel core.  The immutable owner label (bound to
 * the unforgeable channel peer identity by the caller) is threaded into every
 * named-key operation via crypto_worker::owner, so a session can only reach the
 * keys minted under its own label.  Both the production worker and the test
 * entrypoint drive this same path; only the surrounding sandbox setup differs.
 */
static int
serve_session(int fd, const char *owner, const char *actor, struct auditcmp_client *audit)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct crypto_worker state;
	struct channel *channel;
	int ready, result, wants_write;

	memset(&state, 0, sizeof(state));
	strlcpy(state.owner, owner, sizeof(state.owner));
	strlcpy(state.actor, actor, sizeof(state.actor));
	state.audit = audit;
	channel = NULL;
	result = 1;
	if (channel_create(fd, &options, &channel) == -1)
		goto out;
	if (channel_set_request_handler(channel, request, &state) == -1) {
		goto out;
	}
	/*
	 * A provider-side fault (wait/flush failure) is a meaningful error and is
	 * reflected in the exit status; a read/dispatch break is the ordinary case
	 * of the client disconnecting and terminates the worker cleanly.
	 */
	result = 0;
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1) {
			result = 1;
			break;
		}
		ready = channel_wait(channel, wants_write, -1);
		if (ready == -1) {
			result = 1;
			break;
		}
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) {
			result = 1;
			break;
		}
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
	}
out:
	if (channel != NULL)
		channel_destroy(channel);
	return (result);
}

/*
 * The connecting unit's bundle -- the reclaim key -- is the first component of
 * the container "<bundle>/<unit>" switchboard stamps on the channel.  Empty when
 * the client has no bundle (a session), which then holds no named keys, and
 * empty (never truncated) when the component would not fit the key.
 */
static void
bundle_of(const char *container, char *out, size_t outsz)
{
	const char *slash;
	size_t n;

	out[0] = '\0';
	if (container == NULL)
		return;
	slash = strchr(container, '/');
	n = slash != NULL ? (size_t)(slash - container) : strlen(container);
	if (n == 0 || n >= outsz)
		return;
	memcpy(out, container, n);
	out[n] = '\0';
}

#ifdef BSDCRYPTO_TESTING
/* Test seam: the reclaim key derived from a stamped container. */
void
bsdcrypto_test_bundle_of(const char *container, char *out, size_t outsz)
{
	bundle_of(container, out, outsz);
}

/*
 * Test entrypoint: run the real owner-scoped serve path against a caller-owned
 * channel descriptor with a caller-supplied owner label.  It opens and hardens
 * the /dev/crypto control descriptor exactly as production does but omits the
 * switchboard-only sandbox wrappers (worker protect/authority-drop/cap_enter) and
 * the audit client, which require a live plane.  Named-key ownership is enforced
 * by the kernel key store keyed on (name, owner), so this exercises the true
 * isolation property.
 */
int
bsdcrypto_test_serve(int fd, const char *owner_label)
{

	if (fd < 0 || owner_label == NULL ||
	    strnlen(owner_label, CRYPTODESC_KEY_OWNER_MAX) == 0 ||
	    strnlen(owner_label, CRYPTODESC_KEY_OWNER_MAX) ==
	    CRYPTODESC_KEY_OWNER_MAX)
		return (errno = EINVAL, -1);
	control_fd = open("/dev/crypto", O_RDWR);
	if (control_fd < 0)
		return (-1);
	if (harden_control_descriptor(true) == -1)
		return (1);
	return (serve_session(fd, owner_label, owner_label, NULL));
}
#endif /* BSDCRYPTO_TESTING */

#ifndef BSDCRYPTO_TESTING

/*
 * Container-model key reclaim (docs/capability-container-model.md, keys in the
 * kernel).  Named keys are owned by the connecting unit's bundle; a forked
 * reconcile child compares the keystore's owners against the installed bundles
 * (System/, Apps/) and drops the keys of any bundle that is gone.
 */
#define	CRYPTO_SYSTEM_DIR	"/Capabilities/System"
#define	CRYPTO_APPS_DIR		"/Capabilities/Apps"
#define	CRYPTO_RUN_LIVE_DIR	"/Capabilities/Run/live"	/* running markers */
#define	CRYPTO_RECLAIM_INTERVAL	300	/* grace window for the timer passes */
#define	CRYPTO_RECLAIM_POLL	3	/* while awaiting the first pass */
#define	CRYPTO_RECLAIM_INTERVAL_MIN	10
#define	CRYPTO_RECLAIM_INTERVAL_MAX	86400

/*
 * The reconcile cadence (== grace window) may be set through the unit's
 * manifest environment, CRYPTO_RECLAIM_INTERVAL, within bounds; anything
 * else keeps the default.
 */
static unsigned
reclaim_interval(void)
{
	const char *s = getenv("CRYPTO_RECLAIM_INTERVAL");
	char *end;
	long v;

	if (s == NULL || *s == '\0')
		return (CRYPTO_RECLAIM_INTERVAL);
	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < CRYPTO_RECLAIM_INTERVAL_MIN ||
	    v > CRYPTO_RECLAIM_INTERVAL_MAX)
		return (CRYPTO_RECLAIM_INTERVAL);
	return ((unsigned)v);
}
#define	CRYPTO_RECLAIM_MAX_ROUNDS 4096	/* deletion renumbers; bound the re-list */

/*
 * Drop every named key owned by `owner`.  Re-list from cursor zero each round
 * because deletion renumbers the owner-filtered set.  Returns the number
 * reclaimed, or -1 on a hard list failure.
 */
static int
drop_owner_keys(const char *owner)
{
	struct cryptodesc_named_list_entry entries[CRYPTODESC_NAMED_LIST_MAX];
	uint64_t generation;
	uint32_t count, next_cursor, i, reclaimed, rounds;
	int deleted_this_round;

	if (owner == NULL || owner[0] == '\0' ||
	    strnlen(owner, CRYPTODESC_KEY_OWNER_MAX) == CRYPTODESC_KEY_OWNER_MAX)
		return (0);
	reclaimed = 0;
	for (rounds = 0; rounds < CRYPTO_RECLAIM_MAX_ROUNDS; rounds++) {
		count = 0;
		next_cursor = 0;
		memset(entries, 0, sizeof(entries));
		if (cryptodesc_named_list(control_fd, owner, 0, entries,
		    CRYPTODESC_NAMED_LIST_MAX, &count, &next_cursor) != 0)
			return (-1);
		if (count == 0)
			return ((int)reclaimed);
		deleted_this_round = 0;
		for (i = 0; i < count; i++) {
			generation = 0;
			if (cryptodesc_named_delete(control_fd, entries[i].cd_name,
			    owner, &generation) == 0) {
				reclaimed++;
				deleted_this_round = 1;
			}
		}
		if (deleted_this_round == 0)
			break;
	}
	return ((int)reclaimed);
}

/* libcapreclaim enumerate: emit each distinct owner (bundle) holding keys. */
static int
crypto_enumerate(void *arg __unused,
    void (*emit)(void *emit_arg, const char *owner), void *emit_arg)
{
	char owners[CRYPTODESC_OWNER_LIST_MAX][CRYPTODESC_KEY_OWNER_MAX];
	uint32_t cursor, count, next_cursor, i;

	cursor = 0;
	do {
		if (cryptodesc_owner_list(control_fd, cursor, owners,
		    CRYPTODESC_OWNER_LIST_MAX, &count, &next_cursor) != 0)
			return (-1);
		for (i = 0; i < count; i++)
			emit(emit_arg, owners[i]);
		cursor = next_cursor;
	} while (next_cursor != 0);
	return (0);
}

/* libcapreclaim destroy: drop a gone bundle's keys. */
static int
crypto_destroy(void *arg __unused, const char *owner)
{
	int n;

	n = drop_owner_keys(owner);
	CRYPTO_PROBE_RECLAIM_DROP(owner, n, n < 0 ? errno : 0);
	if (n > 0)
		logcmp_log(LOG_NOTICE,
		    "reclaim: dropped %d key(s) for uninstalled bundle %s", n,
		    owner);
	else if (n < 0)
		logcmp_log(LOG_WARNING,
		    "reclaim: dropping keys for uninstalled bundle %s: %m", owner);
	return (n < 0 ? -1 : 0);
}

/*
 * The reconcile loop.  Runs in a forked child that holds only the retained
 * control descriptor and the switchboard-delivered install-directory
 * descriptors (manifest directories = [...]) and never accepts client input.
 * The provider is born in capability mode, so the install roots are read via
 * those delivered descriptors -- a path open would fail ECAPMODE and silently
 * disable reclaim.  Reaps immediately on the first settled boot pass and
 * seen-gone-twice thereafter; System/ existing is the readiness gate, so a
 * missing/undelivered install root reaps nothing.
 */
static void __dead2
crypto_reaper_loop(void)
{
	struct capreclaim r = CAPRECLAIM_INIT;
	struct capreclaim_stats stats;
	enum capreclaim_when when = CAPRECLAIM_BOOT;
	unsigned nap;
	int sys_fd, apps_fd, run_fd;

	setproctitle("[CRYPTO] capability component [reclaim]");
	r.enumerate = crypto_enumerate;
	r.destroy = crypto_destroy;
	r.stats = &stats;
	r.status_dirfd = capreclaim_status_dir();	/* -1 if unavailable: no record */
	r.status_name = "Crypto";
	if (service_resource_dir(CRYPTO_SYSTEM_DIR, &sys_fd) == -1)
		sys_fd = -1;
	if (service_resource_dir(CRYPTO_APPS_DIR, &apps_fd) == -1)
		apps_fd = -1;
	if (service_resource_dir(CRYPTO_RUN_LIVE_DIR, &run_fd) == -1)
		run_fd = -1;
	for (;;) {
		if (sys_fd != -1) {
			int n;

			r.sources[0].fd = sys_fd;
			r.sources[0].strip_cap = true;
			r.sources[1].fd = apps_fd;	/* -1 if absent: skipped */
			r.sources[1].strip_cap = true;
			r.sources[2].fd = run_fd;	/* Run/live/<bundle>: running */
			r.sources[2].strip_cap = false;
			r.nsources = 3;
			n = capreclaim_run(&r, when);
			CRYPTO_PROBE_RECLAIM_PASS((int)when, stats.nlive,
			    stats.nowned, stats.norphans, stats.ndestroyed,
			    stats.nfailed);
			if (n == -1)
				logcmp_log(LOG_WARNING,
				    "reclaim: %s pass failed: %m",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer");
			else if (n > 0 || stats.nfailed > 0)
				logcmp_log(LOG_NOTICE,
				    "reclaim: %s pass dropped keys of %d bundle%s "
				    "(%u live, %u owned, %u orphaned, %u failed)",
				    when == CAPRECLAIM_BOOT ? "boot" : "timer",
				    n, n == 1 ? "" : "s", stats.nlive, stats.nowned,
				    stats.norphans, stats.nfailed);
			/* A floored pass saw nothing: the boot pass is still owed. */
			if (n >= 0 && !stats.floored)
				when = CAPRECLAIM_TIMER;
		}
		nap = (when == CAPRECLAIM_BOOT) ? CRYPTO_RECLAIM_POLL :
		    reclaim_interval();
		(void)sleep(nap);
	}
}

/*
 * Fork the key-reclaim child.  Called after the control descriptor is retained
 * and hardened, so the child inherits control_fd along with the delivered
 * install-directory descriptors.  Non-fatal: a fork failure just defers
 * cleanup.
 */
static void
start_reaper(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		logcmp_log(LOG_WARNING, "reclaim: fork: %m");
		return;
	}
	if (pid == 0) {
		(void)signal(SIGCHLD, SIG_DFL);
		crypto_reaper_loop();
		/* NOTREACHED */
	}
}

static int
worker(int fd, int audit_fd, const char *owner, const char *actor)
{
	struct auditcmp_client *audit;
	int result;

	audit = NULL;
	if (auditcmp_client_adopt(audit_fd, &audit) == -1 ||
	    harden_control_descriptor(true) == -1) {
		auditcmp_client_close(audit);
		return (1);
	}
	if (service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1) {
		auditcmp_client_close(audit);
		return (1);
	}
	result = serve_session(fd, owner, actor, audit);
	auditcmp_client_close(audit);
	return (result);
}

static int
start_session(int fd, const char *peer_label, const char *actor)
{
	int audit_fd;
	pid_t pid;
	char owner[CRYPTODESC_KEY_OWNER_MAX];

	audit_fd = -1;
	/*
	 * `owner` is the connecting unit's bundle (the reclaim key); it may be
	 * empty for a client with no bundle (e.g. a session), which then holds no
	 * named keys -- the named-key ops reject an empty owner on their own.  An
	 * over-length owner is malformed.
	 */
	if (strnlen(peer_label, sizeof(owner)) == sizeof(owner))
		return (errno = EINVAL, -1);
	strlcpy(owner, peer_label, sizeof(owner));
	if (auditcmp_client_prepare(&audit_fd) == -1)
		return (-1);
	pid = fork();
	if (pid == -1) {
		close(audit_fd);
		return (-1);
	}
	if (pid == 0)
		_exit(worker(fd, audit_fd, owner, actor));
	close(audit_fd);
	return (0);
}

/* Distinct startup exit codes make pre-readiness failures diagnosable in
 * switchboard's service-exit log, even before the logging provider is reachable. */
#define STARTUP_CHECK(test, code) do { if ((test) == -1) { \
    logcmp_log(LOG_ERR, "startup step %d failed: %m", code); \
    return (code); } } while (0)

int
main(void)
{
	struct service_context *ctx = NULL;
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	char bundle[CRYPTODESC_KEY_OWNER_MAX];
	int fd;

	setproctitle("[CRYPTO] capability component");
	openlog("bsdcrypto", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * /dev/crypto is provided by the cryptodev module.  Ensure it is loaded
	 * before opening the control device: bsdextension owns kernel-module loading
	 * (system.SystemExtension), so [CRYPTO] self-serves the module by name
	 * rather than relying on PID 1 or switchboard to load it.  This is done
	 * before becoming a provider and entering capability mode.
	 */
	STARTUP_CHECK(service_acquire(&ctx), 10);
	STARTUP_CHECK(service_ensure_extension(ctx, "cryptodev"), 11);
	service_release(ctx);

	/*
	 * Born in capability mode: switchboard delivered /dev as a directory
	 * descriptor (manifest directories = ["/dev"]); open the control node
	 * beneath it with openat(2) rather than a global path.
	 */
	{
		int devdir;

		STARTUP_CHECK(service_resource_dir("/dev", &devdir), 12);
		control_fd = openat(devdir, "crypto", O_RDWR);
	}
	/*
	 * Self-harden the long-lived accept/fork parent.  It must still pdfork
	 * workers and receive connection descriptors, so NOFORK/NOFDRECV are not
	 * applied; NOPRIVS is safe because the /dev/crypto control descriptor is
	 * already open (mirrors bsdnetwork's parent protect mask).
	 */
	STARTUP_CHECK(control_fd, 13);
	STARTUP_CHECK(harden_control_descriptor(false), 14);
	/*
	 * Start the key-reclaim child now: control_fd is retained and hardened
	 * (its ioctl allow-list includes owner/named list + delete), so the child
	 * inherits it along with the switchboard-delivered install directories.
	 */
	start_reaper();
	STARTUP_CHECK(service_provider_create(&provider), 16);
	STARTUP_CHECK(service_provider_authorize_capabilities(provider), 17);
	STARTUP_CHECK(service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC), 18);
	STARTUP_CHECK(service_provider_expose(provider, CRYPTOCMP_NAME, &listener), 19);
	STARTUP_CHECK(service_provider_enter_capability_mode(provider), 20);
	STARTUP_CHECK(service_provider_ready(provider), 21);

	for (;;) {
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (1);
		bundle_of(id.container, bundle, sizeof(bundle));
		if (start_session(fd, bundle, id.client_label) == -1)
			logcmp_log(LOG_WARNING, "session for %s rejected: %m",
			    id.client_label);
		close(fd);
	}
}
#endif /* !BSDCRYPTO_TESTING */
