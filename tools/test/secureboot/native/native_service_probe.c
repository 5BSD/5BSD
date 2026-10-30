/* SPDX-License-Identifier: BSD-2-Clause */
/* Runs only in the disposable authenticated boot fixture's rc subtree. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/cryptodesc.h>
#include <cryptocmp.h>
#include <sys/wait.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <errno.h>
#include <fcntl.h>
#include <notify.h>
#include <libservice.h>
#include <service_runtime.h>
#include <libservice_session.h>
#include <switchboard_svc_proto.h>
#include <switchboard_ctl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { \
	if (!(test)) { \
		printf("NATIVE_SERVICE_FAIL line=%d errno=%d\n", __LINE__, errno); \
		return (1); \
	} \
	printf("NATIVE_SERVICE_CHECK %s\n", #test); \
} while (0)

static int
control_request(int fd, uint32_t operation, int expected_status)
{
	struct service_session *session;
	struct sctl_request request = { .op = operation };
	union { max_align_t align; char bytes[sizeof(struct sctl_reply) +
	    SWITCHBOARD_CTL_SUMMARY_MAX]; } response;
	struct service_message message = { .size = sizeof(message),
	    .data = &request, .length = sizeof(request) };
	struct service_reply reply = { .size = sizeof(reply),
	    .data = response.bytes, .capacity = sizeof(response.bytes) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	const struct sctl_reply *header;

	CHECK(service_session_create(fd, &session) == 0);
	options.timeout_ms = 5000;
	CHECK(service_session_call(session, &message, &reply, &options) == 0);
	CHECK(reply.length >= sizeof(*header));
	header = (const struct sctl_reply *)response.bytes;
	CHECK(header->status == (uint32_t)expected_status &&
	    reply.length == sizeof(*header) + header->flags && reply.nfds == 0);
	service_session_close(session);
	return (0);
}

static int
control_binding(void)
{
	struct mac_capability_info_args info;
	int fd, status, fresh;
	pid_t child;

	CHECK(service_open(SWITCHBOARD_CONTROL_NAME, &fd) == 0);
	CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	child = fork(); CHECK(child >= 0);
	if (child == 0) {
		/* Use the raw kernel interface, bypassing libservice's PID guard. */
		CHECK(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == -1 && errno == EPERM);
		close(fd);
		/* The child may request its own read-only connection. */
		CHECK(service_open(SWITCHBOARD_CONTROL_NAME, &fresh) == 0);
		_exit(control_request(fresh, SCTL_OP_STATUS, 0));
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
	CHECK(control_request(fd, SCTL_OP_STATUS, 0) == 0);
	CHECK(service_open(SWITCHBOARD_CONTROL_NAME, &fd) == 0);
	CHECK(control_request(fd, SCTL_OP_RELOAD, EPERM) == 0);
	return (0);
}

static int
crypto_operation(void)
{
	struct cryptocmp_client *client = NULL;
	struct cryptocmp_key_generate request = {
	    .type = CRYPTODESC_KEY_ED25519,
	    .rights = CRYPTODESC_RIGHT_SIGN | CRYPTODESC_RIGHT_VERIFY,
	    .ttl = 30,
	};
	const unsigned char message[] = "BIP Crypto bootstrap operation";
	unsigned char public_key[32], signature[CRYPTODESC_ED25519_SIGNATURE_SIZE];
	struct cryptodesc_sign sign = {
	    .cd_data = message, .cd_data_len = sizeof(message) - 1,
	    .cd_signature = signature, .cd_signature_len = sizeof(signature),
	};
	struct cryptodesc_verify verify = {
	    .cd_data = message, .cd_data_len = sizeof(message) - 1,
	    .cd_signature = signature, .cd_signature_len = sizeof(signature),
	};
	struct cryptoctl_derive escalation = { .scope = CRYPTOCTL_SCOPE_OWNER,
	    .rights = CRYPTOCTL_WORKER_RIGHTS };
	int fd, control;

	/* Even root must use the authorized provider rather than reopen control. */
	control = open("/dev/crypto", O_RDWR);
	CHECK(control == -1 && errno == EPERM);
	CHECK(cryptocmp_open(&client) == 0);
	CHECK(cryptocmp_generate_key(client, &request, public_key, &fd) == 0);
	CHECK(ioctl(fd, CIOCCRYPTOSIGN, &sign) == 0);
	CHECK(ioctl(fd, CIOCCRYPTOVERIFY, &verify) == 0);
	signature[0] ^= 1;
	CHECK(ioctl(fd, CIOCCRYPTOVERIFY, &verify) == -1 && errno == EBADMSG);
	CHECK(ioctl(fd, CIOCGCRYPTOCONTROL, &escalation) == -1 && errno == ENOTTY);
	close(fd);
	cryptocmp_close(client);
	/* Keep each complete marker in one write on the shared guest console. */
	const char result[] = "\nCRYPTO_BOOTSTRAP_PASS provider sign/verify, corrupt signature and control escalation denied\n";
	CHECK(write(STDOUT_FILENO, result, sizeof(result) - 1) ==
	    (ssize_t)(sizeof(result) - 1));
	return (0);
}

static int
crypto_unavailable(void)
{
	struct cryptocmp_client *client = NULL;
	struct notify_client *notify = NULL;
	int fd;

	/* The authorized client and another real provider must work. */
	CHECK(notify_client_open(&notify) == 0);
	CHECK(notify_publish(notify, "user.secureboot.crypto-denial",
	    "probe", sizeof("probe")) == 0);
	notify_client_close(notify);
	fd = open("/dev/crypto", O_RDWR);
	CHECK(fd == -1 && errno == EPERM);
	CHECK(cryptocmp_open(&client) == -1 && errno == ECONNRESET);
	CHECK(client == NULL);
	/* Keep each complete marker in one write on the shared guest console. */
	const char result[] = "\nCRYPTO_BOOTSTRAP_DENIED provider unavailable, independent provider operational, direct control denied\n";
	CHECK(write(STDOUT_FILENO, result, sizeof(result) - 1) ==
	    (ssize_t)(sizeof(result) - 1));
	return (0);
}

int
main(int argc, char **argv)
{
	struct notify_client *client = NULL, *gated = NULL;
	struct notify_event *event;
	struct stat st;
	const char topic[] = "user.secureboot.probe";
	const char payload[] = "authenticated service round trip";
	union { max_align_t align; unsigned char bytes[NOTIFY_MAX_MESSAGE]; } buffer;
	ssize_t length;
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(30);
	if (argc == 2 && strcmp(argv[1], "--crypto-unavailable") == 0)
		return (crypto_unavailable());
	CHECK(argc == 1);
	CHECK(getuid() == 0 && geteuid() == 0);
	CHECK(stat("/etc/capability/require-signatures", &st) == 0 &&
	    S_ISREG(st.st_mode) && st.st_size == 0);
	CHECK(stat("/etc/spwd.db", &st) == 0 && (st.st_mode & 0777) == 0600);
	fd = open("/Capabilities/System/Notify.cap/Units/bsdnotify.unit/bin/BSDNotify", O_WRONLY);
	CHECK(fd == -1 && errno == EROFS);
	CHECK(notify_client_open(&client) == 0);
	CHECK(notify_subscribe(client, topic) == 0);
	CHECK(notify_publish(client, topic, payload, sizeof(payload)) == 0);
	length = notify_next(client, (struct notify_event *)buffer.bytes, sizeof(buffer.bytes), 5000);
	CHECK(length >= (ssize_t)sizeof(*event));
	event = (struct notify_event *)buffer.bytes;
	CHECK(event->type == NOTIFY_EVENT_PUBLISH &&
	    event->topic_length == strlen(topic) && event->payload_length == sizeof(payload));
	CHECK((size_t)length == sizeof(*event) + event->publisher_length +
	    event->topic_length + event->payload_length);
	CHECK(memcmp(event->data + event->publisher_length, topic, strlen(topic)) == 0);
	CHECK(memcmp(event->data + event->publisher_length + event->topic_length,
	    payload, sizeof(payload)) == 0);
	CHECK(notify_publish(client, "system.secureboot.probe", payload, sizeof(payload)) == -1 &&
	    (errno == EACCES || errno == EPERM));
	CHECK(notify_state_set(client, "system.secureboot.probe", 1) == -1 &&
	    (errno == EACCES || errno == EPERM));
	/* Discovery hides endpoints outside this scoped grant. */
	CHECK(notify_client_open_system(&gated) == -1 &&
	    (errno == ENOENT || errno == EACCES || errno == EPERM));
	CHECK(gated == NULL);
	/* The real broker and router run as the staged service account in
	 * capability mode. Only the broker inherits the launch OOM setting. */
	{
		struct passwd *account = getpwnam("capability");
		struct kinfo_proc *processes;
		size_t size = 0;
		unsigned count = 0, excluded = 0;
		int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_UID, 0};

		CHECK(account != NULL);
		mib[3] = account->pw_uid;
		CHECK(sysctl(mib, nitems(mib), NULL, &size, NULL, 0) == 0 && size > 0);
		processes = malloc(size);
		CHECK(processes != NULL);
		CHECK(sysctl(mib, nitems(mib), processes, &size, NULL, 0) == 0 &&
		    size % sizeof(*processes) == 0);
		for (size_t i = 0; i < size / sizeof(*processes); i++) {
			CHECK(processes[i].ki_uid == account->pw_uid);
			CHECK(processes[i].ki_cr_flags & KI_CRF_CAPABILITY_MODE);
			CHECK(ptrace(PT_ATTACH, processes[i].ki_pid, NULL, 0) == -1 &&
			    (errno == EACCES || errno == EPERM));
			CHECK(kill(processes[i].ki_pid, SIGCONT) == -1 &&
			    (errno == EACCES || errno == EPERM));
			count++;
			if (processes[i].ki_flag & P_PROTECTED)
				excluded++;
		}
		free(processes);
		CHECK(count == 2 && excluded == 1);
	}
	notify_client_close(client);
	CHECK(control_binding() == 0);
	/* Retired BIP opcode 16 must remain unsupported. */
	{
		uint32_t request = 16;
		struct svc_reply response;
		struct service_session *session;
		struct service_message message = { .size = sizeof(message), .data = &request, .length = sizeof(request) };
		struct service_reply reply = { .size = sizeof(reply), .data = &response, .capacity = sizeof(response) };
		struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
		fd = service_ambient_lookup_fd(); CHECK(fd >= 0);
		CHECK(service_session_create(fd, &session) == 0);
		options.timeout_ms = 5000;
		CHECK(service_session_call(session, &message, &reply, &options) == 0);
		CHECK(reply.length == sizeof(response) && reply.nfds == 0 && response.status == ENOTSUP);
		service_session_close(session);
	}

	CHECK(crypto_operation() == 0);
	alarm(0);
	puts("NATIVE_SOFTWARE_SERVICE_PASS signed providers, notification round trip, control gates");
	return (0);
}
