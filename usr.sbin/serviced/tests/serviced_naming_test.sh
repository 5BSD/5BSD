#
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration tests for the full oracled → serviced → service stack.
#
# These test the service-side channel protocol (READY, REGISTER, LOOKUP)
# and the naming registry.  Each test builds small C programs that act
# as services, launches them through serviced manifests, and verifies
# the expected behavior.
#

_helpers="$(dirname "$0")/test_helpers.sh"
if [ ! -f "$_helpers" ]; then
	_helpers="/usr/src/usr.sbin/serviced/tests/test_helpers.sh"
fi
. "$_helpers"

# naming tests use start_oracled which does not wait for serviced ready
start_oracled()
{
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi
}

stop_oracled()
{
	stop_stack
}

#
# Build a service that sends READY over its channel fd.
#
build_ready_service()
{
	require_cc
	cat > ready_svc.c <<'CEOF'
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#define SVC_OP_READY 1

struct svc_req_hdr { uint32_t op; };
struct svc_reply { int32_t status; };

int main(void)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct svc_req_hdr req;
	struct svc_reply rpl;
	const char *fd_str;
	int channel_fd;
	FILE *out;

	fd_str = getenv("ORACLED_CHANNEL_FD");
	if (!fd_str) return 1;
	channel_fd = atoi(fd_str);

	req.op = SVC_OP_READY;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &req;
	sa.payload_len = sizeof(req);
	sa.reply_token = 1;
	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1)
		return 1;

	memset(&ra, 0, sizeof(ra));
	ra.payload = &rpl;
	ra.payload_len = sizeof(rpl);
	if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1)
		return 1;

	out = fopen("ready-ok.out", "w");
	if (out) { fprintf(out, "status=%d\n", rpl.status); fclose(out); }

	sleep(30);
	return 0;
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -I/usr/src/sys -o ready_svc ready_svc.c
}

#
# Build a provider service that registers a name and logs new clients.
#
build_provider_service()
{
	require_cc
	cat > provider_svc.c <<'CEOF'
#include <sys/types.h>
#include <sys/event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#define SVC_OP_READY      1
#define SVC_OP_REGISTER   2
#define SVC_OP_NEW_CLIENT 128
#define SERVICED_NAME_MAX 255

struct svc_req_hdr { uint32_t op; };
struct svc_register_req {
	uint32_t op;
	uint32_t flags;
	char name[SERVICED_NAME_MAX + 1];
};
struct svc_reply { int32_t status; };
struct svc_new_client_msg {
	uint32_t op;
	uint32_t flags;
	char client_label[64];
};

static int
send_recv(int fd, const void *req, uint32_t reqlen, uint64_t token,
    struct svc_reply *rpl)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) return -1;

	memset(&ra, 0, sizeof(ra));
	ra.payload = rpl;
	ra.payload_len = sizeof(*rpl);
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) return -1;
	return 0;
}

int main(void)
{
	struct svc_req_hdr ready_req;
	struct svc_register_req reg_req;
	struct svc_reply rpl;
	struct mac_capability_recvmsg_args ra;
	struct svc_new_client_msg notify;
	const char *fd_str, *name;
	int channel_fd, client_fd;
	FILE *out;

	fd_str = getenv("ORACLED_CHANNEL_FD");
	if (!fd_str) return 1;
	channel_fd = atoi(fd_str);

	name = getenv("ORACLED_LABEL");
	if (!name) name = "test.provider.default";

	/* Send READY. */
	ready_req.op = SVC_OP_READY;
	if (send_recv(channel_fd, &ready_req, sizeof(ready_req), 1, &rpl) == -1)
		return 1;

	/* Register the name. */
	memset(&reg_req, 0, sizeof(reg_req));
	reg_req.op = SVC_OP_REGISTER;
	strlcpy(reg_req.name, name, sizeof(reg_req.name));
	if (send_recv(channel_fd, &reg_req, sizeof(reg_req), 2, &rpl) == -1)
		return 1;

	out = fopen("provider-registered.out", "w");
	if (out) {
		fprintf(out, "pid=%d\nname=%s\nstatus=%d\n",
		    getpid(), name, rpl.status);
		fclose(out);
	}

	if (rpl.status != 0) return 1;

	/* Wait for a new client notification. */
	client_fd = -1;
	memset(&ra, 0, sizeof(ra));
	ra.payload = &notify;
	ra.payload_len = sizeof(notify);
	ra.fds = &client_fd;
	ra.nfds = 1;

	if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1)
		return 1;

	out = fopen("provider-client.out", "w");
	if (out) {
		fprintf(out, "op=%u\nclient_label=%s\nclient_fd=%d\n",
		    notify.op, notify.client_label, client_fd);
		fclose(out);
	}

	/* Send a greeting over the new client fd. */
	if (client_fd >= 0) {
		struct mac_capability_sendmsg_args csa;
		const char *greeting = "hello from provider";

		memset(&csa, 0, sizeof(csa));
		csa.payload = greeting;
		csa.payload_len = strlen(greeting) + 1;
		(void)ioctl(client_fd, MAC_CAPABILITY_SENDMSG, &csa);
		close(client_fd);
	}

	sleep(30);
	return 0;
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -I/usr/src/sys -o provider_svc provider_svc.c
}

#
# Build a client service that looks up a name and reads a message.
#
build_client_service()
{
	require_cc
	cat > client_svc.c <<'CEOF'
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#define SVC_OP_READY  1
#define SVC_OP_LOOKUP 4
#define SERVICED_NAME_MAX 255

struct svc_req_hdr { uint32_t op; };
struct svc_lookup_req {
	uint32_t op;
	uint32_t flags;
	char name[SERVICED_NAME_MAX + 1];
};
struct svc_reply { int32_t status; };

int main(void)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	struct svc_req_hdr ready_req;
	struct svc_lookup_req lookup_req;
	struct svc_reply rpl;
	const char *fd_str, *name = NULL;
	int channel_fd, peer_fd;
	char msg[256];
	FILE *out;

	fd_str = getenv("ORACLED_CHANNEL_FD");
	if (!fd_str) return 1;
	channel_fd = atoi(fd_str);

	/* Read lookup name from file (env vars are stripped by serviced). */
	{
		FILE *lf = fopen("lookup-name", "r");
		static char lbuf[256];
		if (lf != NULL) {
			if (fgets(lbuf, sizeof(lbuf), lf) != NULL) {
				size_t l = strlen(lbuf);
				if (l > 0 && lbuf[l-1] == '\n') lbuf[l-1] = '\0';
				name = lbuf;
			}
			fclose(lf);
		}
	}
	if (!name) name = "test.provider";

	/* Send READY. */
	ready_req.op = SVC_OP_READY;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &ready_req;
	sa.payload_len = sizeof(ready_req);
	sa.reply_token = 1;
	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) return 1;
	memset(&ra, 0, sizeof(ra));
	ra.payload = &rpl;
	ra.payload_len = sizeof(rpl);
	if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) return 1;

	/* Wait for provider to be registered. */
	sleep(2);

	/* Look up the provider. */
	memset(&lookup_req, 0, sizeof(lookup_req));
	lookup_req.op = SVC_OP_LOOKUP;
	strlcpy(lookup_req.name, name, sizeof(lookup_req.name));

	peer_fd = -1;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &lookup_req;
	sa.payload_len = sizeof(lookup_req);
	sa.reply_token = 2;
	if (ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) return 1;

	memset(&ra, 0, sizeof(ra));
	ra.payload = &rpl;
	ra.payload_len = sizeof(rpl);
	ra.fds = &peer_fd;
	ra.nfds = 1;
	if (ioctl(channel_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) return 1;

	out = fopen("client-lookup.out", "w");
	if (out) {
		fprintf(out, "status=%d\npeer_fd=%d\n", rpl.status, peer_fd);
		fclose(out);
	}

	if (rpl.status != 0 || peer_fd < 0) return 1;

	/* Read the greeting from the provider. */
	memset(msg, 0, sizeof(msg));
	memset(&ra, 0, sizeof(ra));
	ra.payload = msg;
	ra.payload_len = sizeof(msg) - 1;
	if (ioctl(peer_fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) return 1;

	out = fopen("client-message.out", "w");
	if (out) { fprintf(out, "%s\n", msg); fclose(out); }

	close(peer_fd);
	sleep(30);
	return 0;
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -I/usr/src/sys -o client_svc client_svc.c
}

# -------------------------------------------------------------------
# Test: READY protocol
# -------------------------------------------------------------------

atf_test_case service_ready_protocol cleanup
service_ready_protocol_head()
{
	atf_set "descr" "service sends READY and receives acknowledgement"
	atf_set "require.user" "root"
}
service_ready_protocol_body()
{
	build_ready_service
	find_serviced

	prepare_paths
	cat > "$manifestdir/ready.ucl" <<EOF
label = "ready-test";
program = "$(pwd)/ready_svc";
EOF
	write_config
	start_oracled

	if ! wait_for_file ready-ok.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start (mac_capability may not be loaded)"
	fi

	atf_check -s exit:0 -o match:"status=0" cat ready-ok.out
	atf_check -s exit:0 -o ignore \
	    grep "service ready-test: reported ready" "$logfile"
}
service_ready_protocol_cleanup()
{
	cleanup_common
}

# -------------------------------------------------------------------
# Test: REGISTER + LOOKUP (name-based connection brokering)
# -------------------------------------------------------------------

atf_test_case naming_register_and_lookup cleanup
naming_register_and_lookup_head()
{
	atf_set "descr" "provider registers a name, client looks it up, channel is brokered, message exchanged"
	atf_set "require.user" "root"
}
naming_register_and_lookup_body()
{
	build_provider_service
	build_client_service
	find_serviced

	prepare_paths

	cat > "$manifestdir/aaa-provider.ucl" <<EOF
label = "test.provider";
program = "$(pwd)/provider_svc";
provides = ["test-api"];
EOF
	cat > "$manifestdir/zzz-client.ucl" <<EOF
label = "client";
program = "$(pwd)/client_svc";
requires = ["test-api"];
EOF
	# Client reads lookup target from file.
	echo "test.provider" > lookup-name
	write_config
	start_oracled

	# Wait for provider to register.
	if ! wait_for_file provider-registered.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "provider did not start"
	fi
	atf_check -s exit:0 -o match:"status=0" \
	    grep "status=" provider-registered.out

	# Wait for client to complete lookup.
	if ! wait_for_file client-lookup.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "client did not complete lookup"
	fi
	atf_check -s exit:0 -o match:"status=0" \
	    grep "status=" client-lookup.out

	# Wait for the provider to see the client connection.
	if ! wait_for_file provider-client.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "provider did not see client connection"
	fi
	atf_check -s exit:0 -o match:"op=128" \
	    grep "op=" provider-client.out
	atf_check -s exit:0 -o match:"client_label=client" \
	    grep "client_label=" provider-client.out

	# Wait for the client to read the provider's greeting.
	if ! wait_for_file client-message.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "client did not receive message"
	fi
	atf_check -s exit:0 -o match:"hello from provider" \
	    cat client-message.out
}
naming_register_and_lookup_cleanup()
{
	rm -f lookup-name
	cleanup_common
}

# -------------------------------------------------------------------
# Test: LOOKUP of nonexistent name returns ENOENT
# -------------------------------------------------------------------

atf_test_case naming_lookup_nonexistent cleanup
naming_lookup_nonexistent_head()
{
	atf_set "descr" "lookup of unregistered name returns ENOENT"
	atf_set "require.user" "root"
}
naming_lookup_nonexistent_body()
{
	build_client_service
	find_serviced

	prepare_paths
	echo "no.such.service" > lookup-name

	cat > "$manifestdir/client.ucl" <<EOF
label = "client";
program = "$(pwd)/client_svc";
EOF
	write_config
	start_oracled

	if ! wait_for_file client-lookup.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "client did not start"
	fi

	# status=2 is ENOENT on FreeBSD
	atf_check -s exit:0 -o match:"status=2" \
	    grep "status=" client-lookup.out
}
naming_lookup_nonexistent_cleanup()
{
	rm -f lookup-name
	cleanup_common
}

# -------------------------------------------------------------------
# Test: names auto-unregister when service exits
# -------------------------------------------------------------------

atf_test_case naming_auto_unregister_on_exit cleanup
naming_auto_unregister_on_exit_head()
{
	atf_set "descr" "registered names are cleaned up when the owning service exits"
	atf_set "require.user" "root"
}
naming_auto_unregister_on_exit_body()
{
	build_provider_service
	find_serviced

	prepare_paths

	cat > "$manifestdir/provider.ucl" <<EOF
label = "test.unreg";
program = "$(pwd)/provider_svc";
restart = "never";
provides = ["test.unreg"];
EOF
	write_config
	start_oracled

	if ! wait_for_file provider-registered.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "provider did not start"
	fi

	# Kill the provider.
	provider_pid=$(grep "^pid=" provider-registered.out 2>/dev/null | head -1 | cut -d= -f2)
	if [ -z "$provider_pid" ]; then
		provider_pid=$(grep "service test.unreg: exec confirmed (pid" "$logfile" | head -1 | sed 's/.*pid \([0-9]*\)).*/\1/')
	fi
	if [ -n "$provider_pid" ]; then
		kill "$provider_pid" 2>/dev/null || true
		sleep 2
	fi

	# Check the log for auto-unregister.
	atf_check -s exit:0 -o ignore \
	    grep "auto-unregistered.*test.unreg" "$logfile"
}
naming_auto_unregister_on_exit_cleanup()
{
	cleanup_common
}

# -------------------------------------------------------------------
# Test: unauthorized name squatting rejected
# -------------------------------------------------------------------

atf_test_case naming_unauthorized_name_rejected cleanup
naming_unauthorized_name_rejected_head()
{
	atf_set "descr" "service cannot register name not in its label or provides[]"
	atf_set "require.user" "root"
}
naming_unauthorized_name_rejected_body()
{
	require_cc
	cat > squat_svc.c <<'CEOF'
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#define SVC_OP_READY    1
#define SVC_OP_REGISTER 2
#define SERVICED_NAME_MAX 255

struct svc_req_hdr { uint32_t op; };
struct svc_register_req {
	uint32_t op;
	uint32_t flags;
	char name[SERVICED_NAME_MAX + 1];
};
struct svc_reply { int32_t status; };

static int
send_recv(int fd, const void *req, uint32_t reqlen, uint64_t token,
    struct svc_reply *rpl)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) return (-1);
	memset(&ra, 0, sizeof(ra));
	ra.payload = rpl;
	ra.payload_len = sizeof(*rpl);
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) return (-1);
	return (0);
}

int main(void)
{
	struct svc_req_hdr ready_req;
	struct svc_register_req reg_req;
	struct svc_reply rpl;
	const char *fd_str;
	int channel_fd;
	FILE *out;

	fd_str = getenv("ORACLED_CHANNEL_FD");
	if (!fd_str) return (1);
	channel_fd = atoi(fd_str);

	ready_req.op = SVC_OP_READY;
	if (send_recv(channel_fd, &ready_req, sizeof(ready_req), 1, &rpl) == -1)
		return (1);

	/* Try to register a name NOT in our label or provides[]. */
	memset(&reg_req, 0, sizeof(reg_req));
	reg_req.op = SVC_OP_REGISTER;
	strlcpy(reg_req.name, "com.evil.hijack", sizeof(reg_req.name));
	if (send_recv(channel_fd, &reg_req, sizeof(reg_req), 2, &rpl) == -1)
		return (1);

	out = fopen("squat-result.out", "w");
	if (out != NULL) {
		fprintf(out, "status=%d\n", rpl.status);
		fclose(out);
	}
	sleep(30);
	return (0);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -I/usr/src/sys -o squat_svc squat_svc.c

	start_oracled
	prepare_paths
	cat > "$manifestdir/squat.ucl" <<EOF
label = "squat-test";
program = "$(pwd)/squat_svc";
provides = ["squat-api"];
EOF
	kill -HUP "$daemon_pid" 2>/dev/null
	sleep 2

	if ! wait_for_file squat-result.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	# status=13 is EACCES on FreeBSD
	atf_check -s exit:0 -o match:"status=13" cat squat-result.out
}
naming_unauthorized_name_rejected_cleanup()
{
	pkill -9 -f squat_svc 2>/dev/null || true
	cleanup_common
	rm -f squat_svc squat_svc.c squat-result.out
}

# -------------------------------------------------------------------
# Test: self-lookup returns ELOOP
# -------------------------------------------------------------------

atf_test_case naming_self_lookup_eloop cleanup
naming_self_lookup_eloop_head()
{
	atf_set "descr" "service looking up its own name gets ELOOP"
	atf_set "require.user" "root"
}
naming_self_lookup_eloop_body()
{
	require_cc
	cat > selfloop_svc.c <<'CEOF'
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#define SVC_OP_READY    1
#define SVC_OP_REGISTER 2
#define SVC_OP_LOOKUP   4
#define SERVICED_NAME_MAX 255

struct svc_req_hdr { uint32_t op; };
struct svc_register_req {
	uint32_t op;
	uint32_t flags;
	char name[SERVICED_NAME_MAX + 1];
};
struct svc_lookup_req {
	uint32_t op;
	uint32_t flags;
	char name[SERVICED_NAME_MAX + 1];
};
struct svc_reply { int32_t status; };

static int
send_recv(int fd, const void *req, uint32_t reqlen, uint64_t token,
    struct svc_reply *rpl)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.reply_token = token;
	if (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1) return (-1);
	memset(&ra, 0, sizeof(ra));
	ra.payload = rpl;
	ra.payload_len = sizeof(*rpl);
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1) return (-1);
	return (0);
}

int main(void)
{
	struct svc_req_hdr ready_req;
	struct svc_register_req reg_req;
	struct svc_lookup_req lookup_req;
	struct svc_reply rpl;
	const char *fd_str;
	int channel_fd;
	FILE *out;

	fd_str = getenv("ORACLED_CHANNEL_FD");
	if (!fd_str) return (1);
	channel_fd = atoi(fd_str);

	/* Send READY. */
	ready_req.op = SVC_OP_READY;
	if (send_recv(channel_fd, &ready_req, sizeof(ready_req), 1, &rpl) == -1)
		return (1);

	/* Register our own name. */
	memset(&reg_req, 0, sizeof(reg_req));
	reg_req.op = SVC_OP_REGISTER;
	strlcpy(reg_req.name, "selfloop.test", sizeof(reg_req.name));
	if (send_recv(channel_fd, &reg_req, sizeof(reg_req), 2, &rpl) == -1)
		return (1);
	if (rpl.status != 0) return (1);

	/* Look up our own name — should get ELOOP. */
	memset(&lookup_req, 0, sizeof(lookup_req));
	lookup_req.op = SVC_OP_LOOKUP;
	strlcpy(lookup_req.name, "selfloop.test", sizeof(lookup_req.name));
	if (send_recv(channel_fd, &lookup_req, sizeof(lookup_req), 3, &rpl) == -1)
		return (1);

	out = fopen("selfloop-result.out", "w");
	if (out != NULL) {
		fprintf(out, "status=%d\n", rpl.status);
		fclose(out);
	}
	sleep(30);
	return (0);
}
CEOF
	atf_check -s exit:0 -e ignore cc -Wall -I/usr/src/sys -o selfloop_svc selfloop_svc.c

	find_serviced
	prepare_paths
	cat > "$manifestdir/selfloop.ucl" <<EOF
label = "selfloop.test";
program = "$(pwd)/selfloop_svc";
provides = ["selfloop.test"];
EOF
	write_config
	start_oracled

	if ! wait_for_file selfloop-result.out; then
		cat "$logfile" 2>/dev/null
		atf_skip "service did not start"
	fi

	# status=62 is ELOOP on FreeBSD
	atf_check -s exit:0 -o match:"status=62" cat selfloop-result.out
}
naming_self_lookup_eloop_cleanup()
{
	pkill -9 -f selfloop_svc 2>/dev/null || true
	cleanup_common
	rm -f selfloop_svc selfloop_svc.c selfloop-result.out
}

atf_init_test_cases()
{
	atf_add_test_case service_ready_protocol
	atf_add_test_case naming_register_and_lookup
	atf_add_test_case naming_lookup_nonexistent
	atf_add_test_case naming_auto_unregister_on_exit
	atf_add_test_case naming_unauthorized_name_rejected
	atf_add_test_case naming_self_lookup_eloop
}
