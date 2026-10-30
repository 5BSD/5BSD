/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int quota_daemon_main(void);
/* Fault injection at the storage boundary; grant() itself is production code. */
#define bsdfilesystem_destroy_tree quota_destroy
#define tzfs_get_one_prop quota_getprop
#define tzfs_set_prop_string quota_setstring
#define tzfs_promote quota_promote
#define tzfs_rename quota_rename
#define tzfs_snapshot quota_snapshot
#define tzfs_clone quota_clone
#define bsdfilesystem_count_snapshots quota_snapshots
#define tzfs_openat quota_openat
#define tzfs_derive quota_derive
#define tzfs_mount quota_mount
#define tzfs_unmount quota_unmount
#define tzfs_set_prop_uint64 quota_setprop
#define tzfs_limit_dataset_ioctls_by_rights quota_limit
#define bsdfilesystem_ensure_path quota_ensure
#define bsdfilesystem_count_children quota_children
#define main quota_daemon_main
#include "../request.c"
#undef main

static int mount_error;
static int property_error, property_calls, mount_calls, open_calls;
static int issued[16], issued_count;
static bool missing_leaf;
static int child_count, count_error, count_calls, ensure_calls;
static int snapshot_calls, snapshot_error, clone_calls;
static uint64_t property_value;
static int marker_error, marker_calls, promote_calls, rename_calls;
static int origin_error, destroy_calls;
static const char *origin_value = "records";

int quota_destroy(int fd, const char *name)
{
	ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
	ATF_REQUIRE(name[0] != '\0');
	destroy_calls++;
	return (errno = ENOTSUP, -1);
}

int
quota_getprop(int fd, const char *name, char *value, size_t length,
    uint64_t *number, int *is_string, uint32_t *source)
{
	ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
	ATF_CHECK_STREQ(BSDFILESYSTEM_TXN_BASE_PROP, name);
	if (origin_error != 0)
		return (errno = origin_error, -1);
	strlcpy(value, origin_value, length);
	*number = 0;
	*is_string = 1;
	*source = 0;
	return (0);
}
int
quota_setstring(int fd, const char *name, const char *value)
{
	ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
	ATF_CHECK_STREQ(BSDFILESYSTEM_TXN_BASE_PROP, name);
	ATF_CHECK_STREQ("", value);
	marker_calls++;
	return (marker_error == 0 ? 0 : (errno = marker_error, -1));
}
int quota_promote(int fd __unused)
{
	promote_calls++;
	return (errno = ENOTSUP, -1);
}
int quota_rename(int fd __unused, const char *from __unused, const char *to __unused)
{
	rename_calls++;
	return (errno = ENOTSUP, -1);
}


static int
quota_fd(void)
{
	int fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(issued_count < (int)nitems(issued));
	issued[issued_count++] = fd;
	return (fd);
}
int
quota_openat(int fd __unused, const char *name __unused,
    uint64_t rights __unused, uint32_t flags __unused)
{
	open_calls++;
	if (missing_leaf && open_calls == 1)
		return (errno = ENOENT, -1);
	return (quota_fd());
}
int quota_derive(int fd __unused, uint64_t rights __unused) { return (quota_fd()); }
int
quota_ensure(int fd __unused, const char *name __unused, uint64_t rights __unused)
{
	ensure_calls++;
	return (quota_fd());
}
int
quota_children(int fd)
{
	ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
	count_calls++;
	return (count_error != 0 ? (errno = count_error, -1) : child_count);
}
int quota_snapshots(int fd) { return (quota_children(fd)); }
int
quota_snapshot(int fd, const char *name)
{
	ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
	ATF_REQUIRE(name[0] != '\0');
	snapshot_calls++;
	return (snapshot_error == 0 ? 0 : (errno = snapshot_error, -1));
}
int
quota_clone(int fd __unused, int origin __unused,
    const char *snapshot __unused, const char *name __unused)
{
	clone_calls++;
	return (errno = ENOTSUP, -1);
}
int
quota_setprop(int fd, const char *name, uint64_t value)
{
	ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
	ATF_CHECK_STREQ("refquota", name);
	property_calls++;
	property_value = value;
	return (property_error == 0 ? 0 : (errno = property_error, -1));
}
int
quota_mount(int fd __unused, bool ro __unused)
{
	mount_calls++;
	if (mount_error != 0) return (errno = mount_error, -1);
	return (quota_fd());
}
int quota_unmount(int fd __unused) { return (0); }
int quota_limit(int fd __unused, uint64_t rights __unused, uint32_t flags __unused)
{ return (0); }

static void
quota_setup(struct bsdfilesystem_state *st, struct tzfs_conn *conn,
    struct bsdfilesystem_request *rq)
{
	memset(st, 0, sizeof(*st));
	memset(conn, 0, sizeof(*conn));
	/* Open logging before tracking descriptors: a lazy syslog socket can
	 * reuse a correctly closed fixture fd and invalidate the F_GETFD test. */
	openlog("quota_test", LOG_NDELAY, LOG_USER);
	memset(rq, 0, sizeof(*rq));
	st->boot_fd = 42; /* Never dereferenced by the injected storage boundary. */
	st->cfg.default_refquota = BSDFILESYSTEM_MIN_REFQUOTA;
	strlcpy(st->cfg.ephemeral, "selected/ephemeral", sizeof(st->cfg.ephemeral));
	strlcpy(st->boot_name, "boot", sizeof(st->boot_name));
	strlcpy(conn->client, "org.test.quota.client", sizeof(conn->client));
	strlcpy(rq->dataset, "records", sizeof(rq->dataset));
	rq->lifetime = BSDFILESYSTEM_BOOT;
	rq->rights = ZH_MOUNT;
	rq->deliver = BSDFILESYSTEM_DELIVER_MOUNTED;
	property_error = property_calls = mount_calls = open_calls = issued_count = 0;
	property_value = 0;
	marker_error = marker_calls = promote_calls = rename_calls = 0;
	origin_error = destroy_calls = 0;
	origin_value = "records";
	snapshot_calls = snapshot_error = clone_calls = 0;
	missing_leaf = false;
	child_count = count_error = count_calls = ensure_calls = 0;
	mount_error = 0;
}

ATF_TC_WITHOUT_HEAD(commit_marker_failure);
ATF_TC_BODY(commit_marker_failure, tc)
{
	struct bsdfilesystem_state st;
	struct tzfs_conn conn;
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_version_request version;
	struct tzfs_msg message;
	char ns[BSDFILESYSTEM_MAXPATH];
	const int errors[] = { EPERM, ENOSPC, EIO, 0 };

	for (unsigned i = 0; i < nitems(errors); i++) {
		quota_setup(&st, &conn, &rq);
		conn_anchors_init(&conn);
		st.persistent_fd = 42;
		strlcpy(st.cfg.persistent, "selected/persistent", sizeof(st.cfg.persistent));
		strlcpy(conn.container, "org.test.quota/client", sizeof(conn.container));
		memset(&version, 0, sizeof(version));
		version.op = BSDFILESYSTEM_OP_TXN_COMMIT;
		version.lifetime = BSDFILESYSTEM_PERSISTENT;
		version.scope = BSDFILESYSTEM_SCOPE_UNIT;
		strlcpy(version.dataset, "records", sizeof(version.dataset));
		gen_version_id(version.version, sizeof(version.version));
		ATF_REQUIRE(storage_namespace_scope(conn.container, (const char (*)[64])conn.groups,
		    version.scope, version.group, version.lifetime, ns, sizeof(ns)));
		for (unsigned j = 0; j < 2; j++) {
			conn.anchors[j].fd = quota_fd();
			snprintf(conn.anchors[j].dataset, sizeof(conn.anchors[j].dataset),
			    "%s/%s/%s", st.cfg.persistent, ns,
			    j == 0 ? version.dataset : version.version);
		}
		memset(&message, 0, sizeof(message));
		message.reply_fd = -1;
		marker_error = errors[i];
		bsdfilesystem_serve_version(&st, &conn, &version, &message);
		ATF_REQUIRE(message.replied);
		ATF_CHECK_EQ(sizeof(struct bsdfilesystem_reply), message.reply_length);
		ATF_CHECK_EQ(-1, message.reply_fd);
		ATF_CHECK_EQ(errors[i] != 0 ? errors[i] : ENOTSUP, message.reply.rp.status);
		ATF_CHECK_EQ(1, marker_calls);
		ATF_CHECK_EQ(errors[i] == 0 ? 1 : 0, promote_calls);
		ATF_CHECK_EQ(0, rename_calls);
		for (int j = 0; j < issued_count; j++) {
			if (j < 2 && errors[i] != 0) {
				ATF_CHECK_EQ(issued[j], conn.anchors[j].fd);
				ATF_CHECK(fcntl(issued[j], F_GETFD) >= 0);
				close(issued[j]);
			} else
				ATF_CHECK_ERRNO(EBADF, fcntl(issued[j], F_GETFD) == -1);
		}
	}
}

ATF_TC_WITHOUT_HEAD(abort_origin_binding);
ATF_TC_BODY(abort_origin_binding, tc)
{
	struct bsdfilesystem_state st;
	struct tzfs_conn conn;
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_version_request version;
	struct tzfs_msg message;
	char ns[BSDFILESYSTEM_MAXPATH];
	const char *origins[] = { "other", "", "records", "records" };

	for (unsigned i = 0; i < nitems(origins); i++) {
		quota_setup(&st, &conn, &rq);
		conn_anchors_init(&conn);
		st.persistent_fd = 42;
		strlcpy(st.cfg.persistent, "selected/persistent", sizeof(st.cfg.persistent));
		strlcpy(conn.container, "org.test.quota/client", sizeof(conn.container));
		memset(&version, 0, sizeof(version));
		version.op = BSDFILESYSTEM_OP_TXN_ABORT;
		version.lifetime = BSDFILESYSTEM_PERSISTENT;
		version.scope = BSDFILESYSTEM_SCOPE_UNIT;
		strlcpy(version.dataset, "records", sizeof(version.dataset));
		gen_version_id(version.version, sizeof(version.version));
		ATF_REQUIRE(storage_namespace_scope(conn.container, (const char (*)[64])conn.groups,
		    version.scope, version.group, version.lifetime, ns, sizeof(ns)));
		conn.anchors[0].fd = quota_fd();
		snprintf(conn.anchors[0].dataset, sizeof(conn.anchors[0].dataset),
		    "%s/%s/%s", st.cfg.persistent, ns, version.version);
		origin_value = origins[i];
		origin_error = i == 2 ? EIO : 0;
		memset(&message, 0, sizeof(message));
		message.reply_fd = -1;
		bsdfilesystem_serve_version(&st, &conn, &version, &message);
		ATF_REQUIRE(message.replied);
		ATF_CHECK_EQ(sizeof(struct bsdfilesystem_reply), message.reply_length);
		ATF_CHECK_EQ(-1, message.reply_fd);
		ATF_CHECK_EQ(i == 3 ? ENOTSUP : (i == 2 ? EIO : EINVAL),
		    message.reply.rp.status);
		ATF_CHECK_EQ(i == 3 ? 1 : 0, destroy_calls);
		for (int j = 0; j < issued_count; j++) {
			if (j == 0 && i != 3) {
				ATF_CHECK_EQ(issued[j], conn.anchors[0].fd);
				ATF_CHECK(fcntl(issued[j], F_GETFD) >= 0);
				close(issued[j]);
			} else
				ATF_CHECK_ERRNO(EBADF, fcntl(issued[j], F_GETFD) == -1);
		}
	}
}

ATF_TC_WITHOUT_HEAD(version_count_admission);
ATF_TC_BODY(version_count_admission, tc)
{
	struct bsdfilesystem_state st;
	struct tzfs_conn conn;
	struct bsdfilesystem_request rq;
	struct bsdfilesystem_version_request version;
	struct tzfs_msg message;
	const int errors[] = { EIO, EINVAL, ENOMEM, 0, 0 };

	for (unsigned transaction = 0; transaction < 2; transaction++) {
		for (unsigned i = 0; i < nitems(errors); i++) {
			quota_setup(&st, &conn, &rq);
			st.persistent_fd = 42;
			strlcpy(conn.container, "org.test.quota/client", sizeof(conn.container));
			memset(&version, 0, sizeof(version));
			version.op = transaction ? BSDFILESYSTEM_OP_TXN_BEGIN :
			    BSDFILESYSTEM_OP_SNAPSHOT;
			version.lifetime = BSDFILESYSTEM_PERSISTENT;
			version.scope = BSDFILESYSTEM_SCOPE_UNIT;
			strlcpy(version.dataset, "records", sizeof(version.dataset));
			memset(&message, 0, sizeof(message));
			message.reply_fd = -1;
			count_error = errors[i];
			child_count = (transaction ? BSDFILESYSTEM_NS_MAX_CLAIMS :
			    BSDFILESYSTEM_MAX_SNAPSHOTS) - (i == 4 ? 1 : 0);
			/* Below-limit transactions reach snapshot, then stop there.
			 * No fixture operation pretends to create a real ZFS clone. */
			snapshot_error = transaction ? ENOTSUP : 0;
			bsdfilesystem_serve_version(&st, &conn, &version, &message);
			ATF_REQUIRE(message.replied);
			ATF_CHECK_EQ(sizeof(message.reply.vrp), message.reply_length);
			ATF_CHECK_EQ(-1, message.reply_fd);
			ATF_CHECK_EQ(i < 3 ? errors[i] : i == 3 ? EDQUOT :
			    transaction ? ENOTSUP : 0, message.reply.vrp.status);
			ATF_CHECK_EQ(1, count_calls);
			ATF_CHECK_EQ(i == 4 ? 1 : 0, snapshot_calls);
			ATF_CHECK_EQ(0, clone_calls);
			ATF_CHECK_EQ(0, mount_calls);
			ATF_CHECK_EQ(0, property_calls);
			if (i != 4 || transaction)
				ATF_CHECK_STREQ("", message.reply.vrp.version);
			else
				ATF_CHECK(message.reply.vrp.version[0] != '\0');
			for (int j = 0; j < issued_count; j++)
				ATF_CHECK_ERRNO(EBADF, fcntl(issued[j], F_GETFD) == -1);
		}
	}
}

ATF_TC_WITHOUT_HEAD(claim_count_admission);
ATF_TC_BODY(claim_count_admission, tc)
{
	struct bsdfilesystem_state st;
	struct tzfs_conn conn;
	struct bsdfilesystem_request rq;
	char dataset[BSDFILESYSTEM_MAXPATH];
	int keep, result, saved;
	const int errors[] = { EIO, EINVAL, ENOMEM, 0, 0, EIO };

	for (unsigned i = 0; i < nitems(errors); i++) {
		quota_setup(&st, &conn, &rq);
		missing_leaf = i != 5;
		count_error = errors[i];
		child_count = i == 3 ? BSDFILESYSTEM_NS_MAX_CLAIMS :
		    BSDFILESYSTEM_NS_MAX_CLAIMS - 1;
		result = grant(&st, &conn, &rq, dataset, sizeof(dataset), &keep);
		saved = errno;
		if (i < 4) {
			ATF_CHECK_EQ(-1, result);
			ATF_CHECK_EQ(i == 3 ? EDQUOT : errors[i], saved);
			ATF_CHECK_EQ(-1, keep);
			ATF_CHECK_EQ(1, ensure_calls); /* Namespace only; no new leaf. */
			ATF_CHECK_EQ(0, property_calls);
			ATF_CHECK_EQ(0, mount_calls);
		} else {
			ATF_REQUIRE_MSG(result >= 0, "grant: %s", strerror(saved));
			ATF_REQUIRE(keep >= 0);
			ATF_CHECK_EQ(i == 4 ? 2 : 1, ensure_calls);
			ATF_CHECK_EQ(1, property_calls);
			ATF_CHECK_EQ(1, mount_calls);
			close(result);
			close(keep);
		}
		/* Existing claims never need a new-object count. */
		ATF_CHECK_EQ(i == 5 ? 0 : 1, count_calls);
		for (int j = 0; j < issued_count; j++)
			ATF_CHECK_ERRNO(EBADF, fcntl(issued[j], F_GETFD) == -1);
	}
}

ATF_TC_WITHOUT_HEAD(refquota_failure_denies_delivery);
ATF_TC_BODY(refquota_failure_denies_delivery, tc)
{
	const int failures[] = { EPERM, ENOSPC, EIO };
	struct bsdfilesystem_state st;
	struct tzfs_conn conn;
	struct bsdfilesystem_request rq;
	char dataset[BSDFILESYSTEM_MAXPATH];
	int keep, result;

	for (unsigned mode = 0; mode < 2; mode++) {
		for (unsigned i = 0; i < nitems(failures); i++) {
			quota_setup(&st, &conn, &rq);
			rq.deliver = mode == 0 ? BSDFILESYSTEM_DELIVER_HANDLE :
			    BSDFILESYSTEM_DELIVER_MOUNTED;
			property_error = failures[i];
			result = grant(&st, &conn, &rq, dataset, sizeof(dataset), &keep);
			ATF_CHECK_EQ(-1, result);
			ATF_CHECK_EQ(failures[i], errno);
			ATF_CHECK_EQ(-1, keep);
			ATF_CHECK_EQ(1, property_calls);
			ATF_CHECK_EQ(st.cfg.default_refquota, property_value);
			ATF_CHECK_EQ(0, mount_calls);
			/* Only the provisioning open; no delivered handle reopen. */
			ATF_CHECK_EQ(1, open_calls);
			for (int j = 0; j < issued_count; j++)
				ATF_CHECK_ERRNO(EBADF, fcntl(issued[j], F_GETFD) == -1);
		}
	}
}

ATF_TC_WITHOUT_HEAD(refquota_success_and_readonly_recovery);
ATF_TC_BODY(refquota_success_and_readonly_recovery, tc)
{
	struct bsdfilesystem_state st;
	struct tzfs_conn conn;
	struct bsdfilesystem_request rq;
	char dataset[BSDFILESYSTEM_MAXPATH];
	int keep, result;

	for (unsigned mode = 0; mode < 3; mode++) {
		quota_setup(&st, &conn, &rq);
		if (mode == 1) {
			rq.deliver = BSDFILESYSTEM_DELIVER_MOUNTED_RO;
			property_error = ENOSPC;
		} else if (mode == 2) {
			st.cfg.default_refquota = 0;
		} else {
			rq.quota = 2 * BSDFILESYSTEM_MIN_REFQUOTA;
		}
		result = grant(&st, &conn, &rq, dataset, sizeof(dataset), &keep);
		ATF_REQUIRE_MSG(result >= 0, "grant: %s", strerror(errno));
		ATF_REQUIRE(keep >= 0);
		ATF_CHECK_EQ(mode == 0 ? 1 : 0, property_calls);
		if (mode == 0)
			ATF_CHECK_EQ(rq.quota, property_value);
		ATF_CHECK_EQ(1, mount_calls);
		close(result);
		close(keep);
		for (int j = 0; j < issued_count; j++)
			ATF_CHECK_ERRNO(EBADF, fcntl(issued[j], F_GETFD) == -1);
	}
}

ATF_TC_WITHOUT_HEAD(client_quota);
ATF_TC_BODY(client_quota, tc)
{
	struct fs_worker entries[FS_MAX_LABEL_WORKERS];
	struct fs_worker *head = NULL;

	memset(entries, 0, sizeof(entries));
	for (unsigned i = 0; i < nitems(entries); i++) {
		ATF_REQUIRE(fs_worker_admit(head, "org.test.busy"));
		strlcpy(entries[i].label, "org.test.busy", sizeof(entries[i].label));
		entries[i].next = head;
		head = &entries[i];
	}
	ATF_CHECK(!fs_worker_admit(head, "org.test.busy"));
	ATF_CHECK(fs_worker_admit(head, "org.test.peer"));
	/* Removing the exiting session returns its client's admission slot. */
	head = head->next;
	ATF_CHECK(fs_worker_admit(head, "org.test.busy"));
	ATF_CHECK(fs_worker_admit(head, "org.test.peer"));
}
ATF_TC_WITHOUT_HEAD(worker_shutdown);
ATF_TC_BODY(worker_shutdown, tc)
{
	struct fs_worker *head = NULL, *entry;
	int descriptors[2], status;
	pid_t children[2];

	for (unsigned i = 0; i < nitems(descriptors); i++) {
		entry = calloc(1, sizeof(*entry));
		ATF_REQUIRE(entry != NULL);
		children[i] = pdfork(&entry->pd, PD_CLOEXEC | PD_NOWAITPID);
		ATF_REQUIRE_MSG(children[i] >= 0,
		    "pdfork(PD_CLOEXEC | PD_NOWAITPID): %s (errno %d)",
		    strerror(errno), errno);
		if (children[i] == 0)
			for (;;)
				pause();
		descriptors[i] = entry->pd;
		entry->next = head;
		head = entry;
	}
	ATF_REQUIRE_EQ(0, fs_workers_stop(&head));
	ATF_CHECK(head == NULL);
	for (unsigned i = 0; i < nitems(descriptors); i++) {
		ATF_CHECK_ERRNO(EBADF, fcntl(descriptors[i], F_GETFD) == -1);
		ATF_CHECK_ERRNO(ECHILD, waitpid(children[i], &status, WNOHANG) == -1);
	}
	ATF_CHECK_EQ(0, fs_workers_stop(&head));
}
ATF_TC_WITHOUT_HEAD(sender_required);
ATF_TC_BODY(sender_required, tc)
{
	struct bsdfilesystem_state st = {0};
	struct tzfs_conn conn = {.st = &st, .uid = 123, .gid = 456};
	struct bsdfilesystem_request request = {.op = BSDFILESYSTEM_OP_PING};
	struct channel_sender sender = {.uid = 789, .gid = 987};
	struct tzfs_msg message;
	/* Missing attribution must fail before parsing any request variant.
	 * NULL payload makes accidental dispatch observable rather than letting
	 * a later request validator accidentally satisfy this test. */
	const size_t lengths[] = {sizeof(struct bsdfilesystem_request),
	    sizeof(struct bsdfilesystem_open_request),
	    sizeof(struct bsdfilesystem_list_request),
	    sizeof(struct bsdfilesystem_version_request)};

	for (unsigned i = 0; i < nitems(lengths); i++) {
		memset(&message, 0, sizeof(message));
		message.length = lengths[i];
		message.reply_fd = -1;
		tzfs_request(&conn, &message);
		ATF_CHECK(message.replied);
		ATF_CHECK_EQ(EACCES, message.reply.rp.status);
		ATF_CHECK_EQ(-1, message.reply_fd);
		ATF_CHECK_EQ(123, conn.uid);
		ATF_CHECK_EQ(456, conn.gid);
	}
	memset(&message, 0, sizeof(message));
	message.data = &request;
	message.length = sizeof(request);
	message.sender = &sender;
	message.reply_fd = -1;
	tzfs_request(&conn, &message);
	ATF_CHECK(message.replied);
	ATF_CHECK_EQ(0, message.reply.rp.status);
	ATF_CHECK_EQ(789, conn.uid);
	ATF_CHECK_EQ(987, conn.gid);
}

ATF_TC_WITHOUT_HEAD(sender_invocation_attribution);
ATF_TC_BODY(sender_invocation_attribution, tc)
{
	struct bsdfilesystem_state st = {0};
	struct tzfs_conn conn = {.st = &st, .uid = 123, .gid = 456};
	struct bsdfilesystem_request request = {.op = BSDFILESYSTEM_OP_PING};
	struct channel_sender sender = {.uid = 789, .gid = 987, .nonce = 101};
	struct channel_process_identity process = {.identity = 202};
	struct cap_authority_stamp stamp = {.issuer = 303, .identity = 404,
	    .generation = 505, .kind = CAP_AUTH_MANAGED, .valid = 1};
	struct tzfs_msg message;
	/* Metadata is attribution, not a BIP prerequisite for a health request.
	 * Missing kernel sender credentials still reject before dispatch. */
	for (unsigned bad = 0; bad < 11; bad++) {
		struct channel_sender who = sender;
		struct channel_process_identity proc = process;
		struct cap_authority_stamp auth = stamp;
		conn.uid = 123; conn.gid = 456;
		message = (struct tzfs_msg){.data = &request, .length = sizeof(request),
		    .reply_fd = -1, .sender = &who, .process = &proc, .authority = &auth};
		switch (bad) {
		case 0: message.sender = NULL; break;
		case 1: message.process = NULL; break;
		case 2: message.authority = NULL; break;
		case 3: proc.identity = 0; break;
		case 4: who.nonce = 0; break;
		case 5: auth.valid = 0; break;
		case 6: auth.issuer = 0; break;
		case 7: auth.identity = 0; break;
		case 8: auth.generation = 0; break;
		case 9: auth.kind = CAP_AUTH_RETIRED_USER; break;
		case 10: auth.reserved = 1; break;
		}
		conn.actor.valid = true;
		conn.actor.process_identity = 999;
		tzfs_request(&conn, &message);
		ATF_CHECK(message.replied);
		ATF_CHECK_EQ(bad == 0 ? EACCES : 0, message.reply.rp.status);
		ATF_CHECK_EQ(-1, message.reply_fd);
		ATF_CHECK(!conn.actor.valid);
		ATF_CHECK_EQ(0, conn.actor.process_identity);
		ATF_CHECK_EQ(bad == 0 ? 123 : sender.uid, conn.uid);
		ATF_CHECK_EQ(bad == 0 ? 456 : sender.gid, conn.gid);
	}
	/* Capture each actual invocation, not the first connection identity.
	 * Attribution uid intentionally differs from mutable sender uid. */
	for (unsigned i = 0; i < 2; i++) {
		message = (struct tzfs_msg){.data = &request, .length = sizeof(request),
		    .sender = &sender, .process = &process, .authority = &stamp, .reply_fd = -1};
		tzfs_request(&conn, &message);
		ATF_CHECK(message.replied); ATF_CHECK_EQ(0, message.reply.rp.status);
		ATF_CHECK(conn.actor.valid);
		ATF_CHECK_EQ(process.identity, conn.actor.process_identity);
		ATF_CHECK_EQ(sender.nonce, conn.actor.execution_nonce);
		ATF_CHECK_EQ(stamp.identity, conn.actor.authority.identity);
		ATF_CHECK_EQ(stamp.generation, conn.actor.authority.generation);
		ATF_CHECK_EQ(sender.uid, conn.uid); ATF_CHECK_EQ(sender.gid, conn.gid);
		process.identity++; sender.nonce++; stamp.identity++; stamp.generation++;
		ATF_CHECK(conn.actor.authority.identity != stamp.identity);
	}
	/* The FIDL adapter rejects malformed representation before dispatch. */
	ATF_CHECK_EQ(EINVAL, fs_run(&conn, NULL, NULL, 0, false, &message));
	ATF_CHECK(!conn.actor.valid);
	ATF_CHECK_EQ(0, conn.actor.process_identity);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sender_required);
	ATF_TP_ADD_TC(tp, sender_invocation_attribution);
	ATF_TP_ADD_TC(tp, commit_marker_failure);
	ATF_TP_ADD_TC(tp, abort_origin_binding);
	ATF_TP_ADD_TC(tp, version_count_admission);
	ATF_TP_ADD_TC(tp, claim_count_admission);
	ATF_TP_ADD_TC(tp, refquota_failure_denies_delivery);
	ATF_TP_ADD_TC(tp, refquota_success_and_readonly_recovery);
	ATF_TP_ADD_TC(tp, client_quota);
	ATF_TP_ADD_TC(tp, worker_shutdown);
	return (atf_no_error());
}
