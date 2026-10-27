/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise real NLMv4 pending-request matching in an isolated test guest. */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <rpc/rpc.h>
#include <rpcsvc/nlm_prot.h>

#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static CLIENT *client;
static AUTH *auth;
static nlm4_lock locks[3];
static fhandle_t handles[3];
static int files[3] = { -1, -1, -1 };
static unsigned int nfiles;
static bool cleanup_needed;
static unsigned int failures;
static struct timeval timeout = { 5, 0 };

static int
request(rpcproc_t procedure, unsigned int file, bool report)
{
	nlm4_testargs test = { 0 };
	nlm4_testres test_result = { 0 };
	nlm4_lockargs lock = { 0 };
	nlm4_cancargs cancel = { 0 };
	nlm4_unlockargs unlock = { 0 };
	nlm4_res result = { 0 };
	xdrproc_t encode, decode;
	void *argument, *response;
	enum clnt_stat status;
	int value;

	decode = (xdrproc_t)xdr_nlm4_res;
	response = &result;
	switch (procedure) {
	case NLM4_TEST:
		test.exclusive = TRUE;
		test.alock = locks[file];
		/* A different remote owner must observe a granted lock as busy. */
		test.alock.svid++;
		encode = (xdrproc_t)xdr_nlm4_testargs;
		argument = &test;
		decode = (xdrproc_t)xdr_nlm4_testres;
		response = &test_result;
		break;
	case NLM4_NM_LOCK:
		lock.block = TRUE;
		lock.exclusive = TRUE;
		lock.alock = locks[file];
		encode = (xdrproc_t)xdr_nlm4_lockargs;
		argument = &lock;
		break;
	case NLM4_CANCEL:
		cancel.block = TRUE;
		cancel.exclusive = TRUE;
		cancel.alock = locks[file];
		encode = (xdrproc_t)xdr_nlm4_cancargs;
		argument = &cancel;
		break;
	case NLM4_UNLOCK:
		unlock.alock = locks[file];
		encode = (xdrproc_t)xdr_nlm4_unlockargs;
		argument = &unlock;
		break;
	default:
		abort();
	}
	status = clnt_call(client, procedure, encode, argument,
	    decode, response, timeout);
	value = status == RPC_SUCCESS ? (int)(procedure == NLM4_TEST ?
	    test_result.stat.stat : result.stat.stat) : -1;
	if (status != RPC_SUCCESS && report)
		clnt_perror(client, "NLM request");
	xdr_free(decode, response);
	return (value);
}

static void
cleanup(void)
{
	unsigned int i;

	if (cleanup_needed) {
		/* Cancel pending requests before releasing the local blocker. */
		for (i = 0; i < nfiles; i++) {
			int cancelled = request(NLM4_CANCEL, i, true);
			int unlocked = request(NLM4_UNLOCK, i, true);

			if ((cancelled != nlm4_granted && cancelled != nlm4_denied) ||
			    unlocked != nlm4_granted) {
				warnx("cleanup unconfirmed for file %u", i);
				failures++;
			}
		}
	}
	cleanup_needed = false;
	if (client != NULL) {
		clnt_destroy(client);
		client = NULL;
	}
	if (auth != NULL) {
		auth_destroy(auth);
		auth = NULL;
	}
	for (i = 0; i < nfiles; i++) {
		if (files[i] != -1)
			close(files[i]);
		files[i] = -1;
	}
}

static void
expect(const char *name, rpcproc_t procedure, unsigned int file, int wanted)
{
	int actual;

	actual = request(procedure, file, true);
	if (actual != wanted) {
		fprintf(stderr, "FAIL %s: status=%d expected=%d\n", name,
		    actual, wanted);
		failures++;
	} else
		printf("PASS %s\n", name);
}

int
main(int argc, char **argv)
{
	struct stat st[3];
	char *original, *alias;
	struct flock blocker = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
	    .l_start = 0, .l_len = 1 };
	unsigned int i;
	int status;

	if (argc != 5 && argc != 6)
		errx(2, "usage: %s server unique-caller-name file-A file-B [hard-link-to-A]", argv[0]);
	nfiles = (unsigned int)argc - 3;
	if (*argv[2] == '\0' || strlen(argv[2]) > MAXNAMELEN)
		errx(2, "invalid caller name");
	if (atexit(cleanup) != 0)
		err(2, "atexit");
	for (i = 0; i < nfiles; i++) {
		files[i] = open(argv[3 + i], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
		if (files[i] == -1 || fstat(files[i], &st[i]) == -1)
			err(2, "open/stat test file");
		if (!S_ISREG(st[i].st_mode))
			errx(2, "test files must be regular files");
		if (getfh(argv[3 + i], &handles[i]) == -1)
			err(2, "getfh");
		locks[i].caller_name = argv[2];
		locks[i].fh.n_len = sizeof(handles[i]);
		locks[i].fh.n_bytes = (char *)&handles[i];
		locks[i].svid = (u_int32_t)getpid();
		locks[i].l_offset = 0;
		locks[i].l_len = 1;
	}
	if (st[0].st_dev == st[1].st_dev && st[0].st_ino == st[1].st_ino)
		errx(2, "file A and B must be different objects");
	if (nfiles == 3) {
		if (st[0].st_dev != st[2].st_dev || st[0].st_ino != st[2].st_ino ||
		    st[0].st_nlink < 2)
			errx(2, "alias must be a hard link to file A");
		original = realpath(argv[3], NULL);
		alias = realpath(argv[5], NULL);
		if (original == NULL || alias == NULL)
			err(2, "resolve alias paths");
		if (strcmp(original, alias) == 0)
			errx(2, "alias must name a distinct directory entry");
		free(original);
		free(alias);
	}
	if (fcntl(files[0], F_SETLK, &blocker) == -1)
		err(2, "local blocker");
	client = clnt_create_timed(argv[1], NLM_PROG, NLM_VERS4, "tcp",
	    &timeout);
	if (client == NULL) {
		clnt_pcreateerror(argv[1]);
		return (2);
	}
	auth = authunix_create_default();
	if (auth == NULL)
		errx(2, "cannot create RPC credentials");
	client->cl_auth = auth;
	cleanup_needed = true;
	status = request(NLM4_NM_LOCK, 0, true);
	if (status != nlm4_blocked)
		errx(1, "required queued A lock not established: status=%d", status);
	expect("B initially unlocked", NLM4_TEST, 1, nlm4_granted);
	expect("B lock is independent of queued A", NLM4_NM_LOCK, 1, nlm4_granted);
	expect("B lock excludes another owner", NLM4_TEST, 1, nlm4_denied);
	expect("cancel B does not match queued A", NLM4_CANCEL, 1, nlm4_denied);
	expect("duplicate A remains queued", NLM4_NM_LOCK, 0, nlm4_blocked);
	expect("release B", NLM4_UNLOCK, 1, nlm4_granted);
	expect("B unlocked after release", NLM4_TEST, 1, nlm4_granted);
	if (nfiles == 3) {
		expect("hard-link alias matches queued A", NLM4_NM_LOCK, 2, nlm4_blocked);
		expect("cancel A through hard-link alias", NLM4_CANCEL, 2, nlm4_granted);
		expect("original A no longer queued", NLM4_CANCEL, 0, nlm4_denied);
	} else
		expect("cancel A", NLM4_CANCEL, 0, nlm4_granted);
	/* Cleanup failures must also prevent a successful result. */
	cleanup();
	return (failures == 0 ? 0 : 1);
}
