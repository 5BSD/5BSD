/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "protected_crypto.h"
#include "gates.h"

/* Allocation failures are injected only at storage-table allocation sizes. */
static size_t fail_storage_malloc;
static bool fail_storage_calloc;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t);
void *__wrap_calloc(size_t, size_t);

void *
__wrap_malloc(size_t size)
{
	if (fail_storage_malloc != 0 && size == fail_storage_malloc) {
		fail_storage_malloc = 0;
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

void *
__wrap_calloc(size_t count, size_t size)
{
	if (fail_storage_calloc && size == sizeof(struct capsule_storage)) {
		fail_storage_calloc = false;
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(count, size));
}

static int
input_fd(const void *data, size_t length)
{
	char name[] = "policy.XXXXXX";
	int fd = mkstemp(name);

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, unlink(name));
	ATF_REQUIRE_EQ((ssize_t)length, write(fd, data, length));
	return (fd);
}

static int
load(struct capsule_config *cfg, const char *text)
{

	return (config_load_fd(cfg, input_fd(text, strlen(text))));
}

ATF_TC_WITHOUT_HEAD(selected_inputs);
ATF_TC_BODY(selected_inputs, tc)
{
	struct capsule_config cfg = {0};

	config_free(&cfg);
	config_init_defaults(&cfg);
	ATF_REQUIRE_EQ(0, load(&cfg, "pidfile=\"/selected/pid\"; "
	    "control_socket=\"/selected/control\"; control_socket_mode=\"0710\"; "
	    "service_manager=\"/selected/manager\"; integrity {visible=true; ptrace=false;} "
	    "claims {system=[reboot,settime]; network=[{port=443; protocol=tcp; "
	    "direction=connect; address=\"2001:db8::1/64\";}];}"));
	ATF_CHECK_STREQ("/selected/pid", cfg.pidfile);
	ATF_CHECK_STREQ("/selected/control", cfg.control_socket);
	ATF_CHECK_STREQ("/selected/manager", cfg.service_manager);
	ATF_CHECK_EQ(0710, cfg.control_socket_mode);
	ATF_CHECK_EQ(CP_SF_VISIBLE, cfg.integrity_flags & CP_SF_VISIBLE);
	ATF_CHECK_EQ(0, cfg.integrity_flags & CP_SF_PTRACE);
	ATF_CHECK_EQ(SYS_GATE_REBOOT | SYS_GATE_SETTIME, cfg.claim_system_policy);
	ATF_REQUIRE_EQ(1, cfg.nclaim_net);
	ATF_CHECK_EQ(443, cfg.claim_net[0].port_min);
	ATF_CHECK_EQ(443, cfg.claim_net[0].port_max);
	ATF_CHECK_EQ(IPPROTO_TCP, cfg.claim_net[0].protocol);
	ATF_CHECK_EQ(AF_INET6, cfg.claim_net[0].domain);
	ATF_CHECK_EQ(64, cfg.claim_net[0].prefix);
	ATF_CHECK_EQ(CLAIM_SOURCE_POLICY, cfg.claim_net_source[0]);
	ATF_CHECK(cfg.loaded_from_file);
	ATF_REQUIRE_EQ(0, load(&cfg, "service_manager=\"\"; control_socket_mode=\"700\"; "
	    "claims {network=[]; system=[];} integrity {signal=false; sigkill=false; sigcont=false;}"));
	ATF_CHECK_STREQ("", cfg.service_manager);
	ATF_CHECK_EQ(0700, cfg.control_socket_mode);
	ATF_CHECK_EQ(0, cfg.nclaim_net);
	ATF_CHECK_EQ(0, cfg.claim_system);
	ATF_CHECK_EQ(CAPSULE_REQUIRED_INTEGRITY_FLAGS,
	    cfg.integrity_flags & CAPSULE_REQUIRED_INTEGRITY_FLAGS);
	ATF_REQUIRE_EQ(0, load(&cfg, "# explicit defaults\n"));
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(invalid_policy_is_atomic);
ATF_TC_BODY(invalid_policy_is_atomic, tc)
{
	static const char *const invalid[] = {
	    "unexpected=true;", "pidfile=first; pidfile=second;",
	    "pidfile=\"/changed\"; claims {system=[reboot,unknown];}",
	    "\"pidfile\\u0000hidden\"=\"/changed\";", "pidfile=42;",
	    "pidfile=\"a\\u0000b\";", "service_manager=\"a\\nb\";",
	    "control_socket_mode=700;", "control_socket_mode=\"\";",
	    "control_socket_mode=\"0x700\";", "control_socket_mode=\"0780\";",
	    "control_socket_mode=\"10000\";", "integrity=[];",
	    "integrity {ptrace=maybe;}", "integrity {ptrace=true; ptrace=false;}",
	    "integrity {prtrace=false;}", "claims=[];", "claims {paths=[];}", "claims {files=[];}",
	    "claims {system=reboot;}", "claims {system=[unknown];}",
	    "claims {system=[reboot,reboot];}", "claims {system=[true];}",
	    "claims {network={port=22;};}", "claims {network=[true];}",
	    "claims {network=[{protcol=tcp;}];}",
	    "claims {network=[{protocol=6;}];}",
	    "claims {network=[{direction=true;}];}",
	    "claims {network=[{address=123;}];}",
	    "claims {network=[{domain=2;}];}",
	    "claims {network=[{port=22; ports=23;}];}",
	    "claims {network=[{port=-1;}];}",
	    "claims {network=[{port=70000;}];}",
	    "claims {network=[{port=\"0-\";}];}",
	    "claims {network=[{address=\"10.0.0.1/\";}];}",
	    "claims {network=[{domain=inet; address=\"::1\";}];}",
	    "claims {network=[{domain=inet6; address=\"10.0.0.1\";}];}",
	    "claims {network=[{prefix=33;}];}",
	    "claims {network=[{port=22;},{port=22;}];}",
	    "claims {network=[{port=22;},{protocol=invalid;}];}",
	    ".include \"missing-policy\";", "[true]"
	};
	struct capsule_config cfg = {0}, before;
	char *text;

	config_free(&cfg);
	config_init_defaults(&cfg);
	ATF_REQUIRE_EQ(0, load(&cfg, "service_manager=\"/accepted\";"));
	before = cfg;
	for (size_t i = 0; i < nitems(invalid); i++) {
		text = strdup(invalid[i]);
		ATF_REQUIRE(text != NULL);
		ATF_CHECK_MSG(load(&cfg, text) == -1, "accepted invalid input: %s", invalid[i]);
		ATF_CHECK_MSG(memcmp(&cfg, &before, sizeof(cfg)) == 0,
		    "partial policy applied for: %s", invalid[i]);
		cfg = before;
		free(text);
	}
	text = malloc(PATH_MAX + 64);
	ATF_REQUIRE(text != NULL);
	memset(text, 'a', PATH_MAX + 63);
	memcpy(text, "pidfile=\"", 9);
	strcpy(text + PATH_MAX + 9, "\";");
	ATF_CHECK_EQ(-1, load(&cfg, text));
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	free(text);
	/* Overflow must reject the complete policy, not retain its first 32 claims. */
	FILE *f = fopen("many.conf", "w");
	ATF_REQUIRE(f != NULL);
	fputs("claims {network=[", f);
	for (unsigned i = 1; i <= CAPSULE_MAX_NET_CLAIMS + 1; i++)
		fprintf(f, "{port=%u;},", i);
	fputs("];}", f);
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_CHECK_EQ(-1, config_load_fd(&cfg, open("many.conf", O_RDONLY)));
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(no_external_inputs);
ATF_TC_BODY(no_external_inputs, tc)
{
	struct capsule_config cfg = {0};
	FILE *f = fopen("included.conf", "w");

	ATF_REQUIRE(f != NULL);
	fputs("service_manager=\"/external\";", f);
	ATF_REQUIRE_EQ(0, fclose(f));
	config_free(&cfg);
	config_init_defaults(&cfg);
	ATF_CHECK_EQ(-1, load(&cfg, ".include \"included.conf\";"));
	ATF_REQUIRE_EQ(0, setenv("CAPSULE_TEST_MANAGER", "/external", 1));
	ATF_REQUIRE_EQ(0, load(&cfg, "service_manager=\"${CAPSULE_TEST_MANAGER}\";"));
	ATF_CHECK_STREQ("${CAPSULE_TEST_MANAGER}", cfg.service_manager);
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(descriptor_inputs);
ATF_TC_BODY(descriptor_inputs, tc)
{
	struct capsule_config cfg = {0}, before;
	const char raw[] = "pidfile=\"a\";\0service_manager=\"b\";";
	int fd;

	config_free(&cfg);
	config_init_defaults(&cfg);
	fd = input_fd("", 0);
	ATF_REQUIRE_EQ(0, config_load_fd(&cfg, fd));
	before = cfg;
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	ATF_CHECK_EQ(-1, config_load_fd(&cfg, input_fd(raw, sizeof(raw)-1)));
	fd = input_fd("", 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 1024 * 1024 + 1));
	ATF_CHECK_EQ(-1, config_load_fd(&cfg, fd));
	ATF_CHECK_EQ(-1, config_load_fd(&cfg, open(".", O_RDONLY)));
	fd = input_fd("", 0);
	ATF_REQUIRE_EQ(0, fchmod(fd, 0666));
	ATF_CHECK_EQ(-1, config_load_fd(&cfg, fd));
	ATF_CHECK_EQ(-1, config_load_fd(&cfg, -1));
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	ATF_CHECK_EQ(-1, config_load(&cfg, "absent-explicit-policy"));
	fd = open("target.conf", O_CREAT | O_WRONLY, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, symlink("target.conf", "alias.conf"));
	ATF_CHECK_EQ(-1, config_load(&cfg, "alias.conf"));
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(shipped_policy);
ATF_TC_BODY(shipped_policy, tc)
{
	struct capsule_config cfg = {0};
	char path[PATH_MAX];

	config_free(&cfg);
	config_init_defaults(&cfg);
	snprintf(path, sizeof(path), "%s/capsule-daemon.conf", atf_tc_get_config_var(tc, "srcdir"));
	ATF_REQUIRE_EQ(0, config_load_fd(&cfg, open(path, O_RDONLY)));
	ATF_CHECK(cfg.loaded_from_file);
	ATF_CHECK_STREQ(CAPSULE_DEFAULT_SVC_MANAGER, cfg.service_manager);
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(shipped_examples);
ATF_TC_BODY(shipped_examples, tc)
{
	static const char *const names[] = { "desktop", "server", "embedded", "broker" };
	struct capsule_config cfg = {0};
	char path[PATH_MAX];

	for (size_t i = 0; i < nitems(names); i++) {
		config_free(&cfg);
		config_init_defaults(&cfg);
		snprintf(path, sizeof(path), "%s/%s.conf",
		    atf_tc_get_config_var(tc, "srcdir"), names[i]);
		ATF_REQUIRE_EQ_MSG(0, config_load_fd(&cfg, open(path, O_RDONLY)),
		    "invalid shipped example: %s", path);
		if (strcmp(names[i], "server") == 0 || strcmp(names[i], "embedded") == 0) {
			ATF_REQUIRE_EQ(1, cfg.nclaim_net);
			ATF_CHECK_EQ(0, cfg.claim_net[0].port_min);
			ATF_CHECK_EQ(1023, cfg.claim_net[0].port_max);
		}
	}
	config_free(&cfg);
}


static void
storage_policy(char *out, size_t length, const char *recipient, const char *pool_guid,
    const char *dataset, const char *dataset_guid, const char *devices, const char *rights)
{
	snprintf(out, length, "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fe\"; storage=[{recipient=\"%s\"; pool=\"data\"; "
	    "pool_guid=%s; dataset=\"%s\"; dataset_guid=%s; devices=%s; rights=%s;}];",
	    recipient, pool_guid, dataset, dataset_guid, devices, rights);
}

ATF_TC_WITHOUT_HEAD(storage_inputs);
ATF_TC_BODY(storage_inputs, tc)
{
	struct capsule_config cfg = {0}, same, before;
	char text[4096];
	const char *const guids[] = { "0", "01", "-1", "+1", "1.0", "1x", "18446744073709551616" };
	const char *const datasets[] = { "data", "other/state", "data/../state", "data//state", "data/state@snap" };
	const char *const devices[] = { "[]", "[\"/tmp/vdev\"]", "[\"/dev/../tmp/vdev\"]", "[\"/dev/disk\",\"/dev/disk\"]" };
	const char *const rights[] = { "[]", "[all]", "[props_read]", "[props_read,event,event]", "[props_read,event,unknown]" };

	config_free(&cfg);
	config_init_defaults(&cfg);
	ATF_CHECK_EQ(0, cfg.nstorage);
	storage_policy(text, sizeof(text), "site.Store/provider", "\"18446744073709551615\"",
	    "data/service", "\"42\"", "[\"/dev/gpt/b\",\"/dev/gpt/a\"]", "[props_read,event,mount]");
	ATF_REQUIRE_EQ(0, load(&cfg, text));
	ATF_REQUIRE_EQ(1, cfg.nstorage);
	ATF_CHECK_EQ(UINT64_MAX, cfg.storage[0].pool_guid);
	ATF_CHECK_EQ(42, cfg.storage[0].dataset_guid);
	ATF_CHECK_STREQ("site.Store/provider", cfg.storage[0].recipient);
	ATF_CHECK_STREQ("/dev/gpt/a", cfg.storage[0].devices[0]);
	before = cfg;
	config_init_defaults(&same);
	storage_policy(text, sizeof(text), "site.Store/provider", "\"18446744073709551615\"",
	    "data/service", "\"42\"", "[\"/dev/gpt/a\",\"/dev/gpt/b\"]", "[mount,event,props_read]");
	ATF_REQUIRE_EQ(0, load(&same, text));
	ATF_CHECK(config_boot_policy_equal(&cfg, &same));
	same.storage[0].dataset_guid++;
	ATF_CHECK(!config_boot_policy_equal(&cfg, &same));
	for (unsigned i = 0; i < sizeof(guids)/sizeof(guids[0]); i++) {
		char guid[128];
		snprintf(guid, sizeof(guid), "\"%s\"", guids[i]);
		storage_policy(text, sizeof(text), "site.Store/provider", guid,
		    "data/service", "\"42\"", "[\"/dev/disk\"]", "[props_read,event]");
		ATF_CHECK_EQ(-1, load(&cfg, text));
		ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	}
	for (unsigned group = 0; group < 3; group++) {
		unsigned count = group == 0 ? sizeof(datasets)/sizeof(datasets[0]) :
		    group == 1 ? sizeof(devices)/sizeof(devices[0]) : sizeof(rights)/sizeof(rights[0]);
		for (unsigned i = 0; i < count; i++) {
			storage_policy(text, sizeof(text), "site.Store/provider", "\"1\"",
			    group == 0 ? datasets[i] : "data/service", "\"42\"",
			    group == 1 ? devices[i] : "[\"/dev/disk\"]",
			    group == 2 ? rights[i] : "[props_read,event]");
			ATF_CHECK_EQ(-1, load(&cfg, text));
			ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
		}
	}
	storage_policy(text, sizeof(text), "site.Store/provider", "1",
	    "data/service", "\"42\"", "[\"/dev/disk\"]", "[props_read,event]");
	ATF_CHECK_EQ(-1, load(&cfg, text)); /* GUIDs must be full-width strings. */
	ATF_REQUIRE_EQ(0, load(&cfg, "storage=[];"));
	ATF_CHECK_EQ(0, cfg.nstorage);
	ATF_CHECK(!config_boot_policy_equal(&cfg, &before));
	config_free(&cfg);
	config_free(&same);
}

ATF_TC_WITHOUT_HEAD(storage_conflicts);
ATF_TC_BODY(storage_conflicts, tc)
{
	struct capsule_config cfg = {0};
	char text[4096];
	const char *const seconds[] = {
	    "recipient=\"site.One/unit\"; dataset=\"data/two\"; dataset_guid=\"3\";",
	    "recipient=\"site.Two/unit\"; dataset=\"data/one/child\"; dataset_guid=\"3\";",
	    "recipient=\"site.Two/unit\"; dataset=\"data/one\"; dataset_guid=\"3\";",
	    "recipient=\"site.Two/unit\"; dataset=\"data/two\"; dataset_guid=\"2\";"
	};
	for (unsigned i = 0; i < sizeof(seconds)/sizeof(seconds[0]); i++) {
		config_free(&cfg);
		config_init_defaults(&cfg);
		snprintf(text, sizeof(text), "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fe\"; storage=[{recipient=\"site.One/unit\"; pool=data; pool_guid=\"1\"; "
		    "dataset=\"data/one\"; dataset_guid=\"2\"; devices=[\"/dev/disk\"]; rights=[props_read,event];},"
		    "{pool=data; pool_guid=\"1\"; devices=[\"/dev/disk\"]; rights=[props_read,event]; %s}];", seconds[i]);
		ATF_CHECK_EQ(-1, load(&cfg, text));
		ATF_CHECK_EQ(0, cfg.nstorage);
	}
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(host_identity);
ATF_TC_BODY(host_identity, tc)
{
	const char *uuid = "57061ee3-7587-4a12-9447-2ac2b0e947fe";
	const char *const invalid[] = {
	    "hostuuid=42;", "hostuuid=\"\";", "hostuuid=\"not-a-uuid\";",
	    "hostuuid=\"00000000-0000-0000-0000-000000000000\";",
	    "hostuuid=\"57061EE3-7587-4a12-9447-2ac2b0e947fe\";",
	    "hostuuid=\"57061ee3_7587-4a12-9447-2ac2b0e947fe\";",
	    "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fg\";",
	    "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fe0\";",
	    "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fe\\u0000hidden\";",
	    "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fe\"; hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947ff\";"
	};
	struct capsule_config cfg = {0}, before, changed = {0};
	unsigned long id;
	char text[4096];
	(void)tc;

	/* Known answer calculated with the existing rc.d/hostid convention. */
	ATF_REQUIRE(config_hostid(uuid, &id));
	ATF_CHECK_EQ(0x6e6521a3UL, id);
	ATF_CHECK(!config_hostid(NULL, &id));
	ATF_CHECK(!config_hostid(uuid, NULL));
	config_free(&cfg);
	config_init_defaults(&cfg);
	snprintf(text, sizeof(text), "hostuuid=\"%s\";", uuid);
	ATF_REQUIRE_EQ(0, load(&cfg, text));
	ATF_CHECK_STREQ(uuid, cfg.hostuuid);
	before = cfg;
	for (unsigned i = 0; i < nitems(invalid); i++) {
		ATF_CHECK_MSG(load(&cfg, invalid[i]) == -1, "accepted %s", invalid[i]);
		ATF_CHECK_EQ(0, memcmp(&before, &cfg, sizeof(cfg)));
	}
	ATF_REQUIRE_EQ(0, config_copy(&changed, &cfg));
	ATF_REQUIRE_EQ(0, load(&changed,
	    "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947ff\";"));
	ATF_CHECK(!config_boot_policy_equal(&cfg, &changed));
	ATF_REQUIRE_EQ(0, load(&cfg, "# manager restart keeps identity\n"));
	ATF_CHECK(config_boot_policy_equal(&before, &cfg));
	config_free(&cfg);
	config_init_defaults(&cfg);
	before = cfg;
	storage_policy(text, sizeof(text), "site.Store/provider", "\"1\"",
	    "data/service", "\"42\"", "[\"/dev/disk\"]", "[props_read,event]");
	ATF_REQUIRE(strstr(text, "storage=") != NULL);
	ATF_CHECK_EQ(-1, load(&cfg, strstr(text, "storage=")));
	ATF_CHECK_EQ(0, memcmp(&before, &cfg, sizeof(cfg)));
	config_free(&cfg);
	config_free(&changed);
}

ATF_TC_WITHOUT_HEAD(installation_policy);
ATF_TC_BODY(installation_policy, tc)
{
	struct capsule_config cfg = {0};
	char guid[32];
	int fd;

	if (!atf_tc_has_config_var(tc, "installation_policy"))
		atf_tc_skip("explicit installation policy and expected identities required");
	fd = open(atf_tc_get_config_var(tc, "installation_policy"),
	    O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	config_free(&cfg);
	config_init_defaults(&cfg);
	ATF_REQUIRE_EQ(0, config_load_fd(&cfg, fd));
	if (atf_tc_has_config_var(tc, "crypto_recipient"))
		ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "crypto_recipient"),
		    cfg.crypto_recipient);
	ATF_REQUIRE_EQ(1, cfg.nstorage);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "hostuuid"), cfg.hostuuid);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "recipient"), cfg.storage[0].recipient);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "pool"), cfg.storage[0].pool);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "dataset"), cfg.storage[0].dataset);
	(void)snprintf(guid, sizeof(guid), "%" PRIu64, cfg.storage[0].pool_guid);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "pool_guid"), guid);
	(void)snprintf(guid, sizeof(guid), "%" PRIu64, cfg.storage[0].dataset_guid);
	ATF_REQUIRE_STREQ(atf_tc_get_config_var(tc, "dataset_guid"), guid);
	config_free(&cfg);
}

ATF_TC_WITHOUT_HEAD(crypto_boot_policy);
ATF_TC_BODY(crypto_boot_policy, tc)
{
	static const char *bad[] = {
	    "crypto_recipient = 1;", "crypto_recipient = [];",
	    "crypto_recipient = \"single\";", "crypto_recipient = \"a/b/c\";",
	    "crypto_recipient = \"a/..\";", "crypto_recipient = \"a/\";",
	    "crypto_recipient = \"a/b\"; crypto_recipient = \"a/c\";"
	};
	struct capsule_config cfg = {0}, before, changed = {0};

	config_free(&cfg);
	config_init_defaults(&cfg);
	ATF_CHECK_STREQ("", cfg.crypto_recipient);
	ATF_REQUIRE_EQ(0, load(&cfg, "crypto_recipient = \"example.Crypto/service\";"));
	ATF_CHECK_STREQ("example.Crypto/service", cfg.crypto_recipient);
	before = cfg;
	for (size_t i = 0; i < nitems(bad); i++) {
		ATF_CHECK_ERRNO(EINVAL, load(&cfg, bad[i]) == -1);
		ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	}
	ATF_REQUIRE_EQ(0, config_copy(&changed, &cfg));
	ATF_REQUIRE_EQ(0, load(&changed, "crypto_recipient = \"example.Other/service\";"));
	ATF_CHECK(!config_boot_policy_equal(&cfg, &changed));
	ATF_REQUIRE_EQ(0, load(&changed, "crypto_recipient = \"\";"));
	ATF_CHECK(!config_boot_policy_equal(&cfg, &changed));
	ATF_CHECK(config_boot_policy_equal(&cfg, &before));
	/* UID zero is insufficient: only original PID 1 may acquire the grant. */
	ATF_REQUIRE(getpid() != 1);
	ATF_CHECK_ERRNO(EPERM, protected_crypto_prepare(&cfg) == -1);
	ATF_CHECK_ERRNO(EPERM, protected_crypto_open(cfg.crypto_recipient) == -1);
	config_free(&cfg);
	config_free(&changed);
}

static int
load_data(struct capsule_config *cfg, const char *data)
{
	char *text;
	int result;

	ATF_REQUIRE(asprintf(&text, "hostuuid=\"f58f0973-3fa8-4c62-991a-d26a1f9a7b76\"; "
	    "storage=[{recipient=example.Store/service; pool=tank; pool_guid=\"1\"; "
	    "dataset=\"tank/state\"; dataset_guid=\"2\"; devices=[\"/dev/vtbd1\"]; "
	    "rights=[props_read,event]; %s }];", data) > 0);
	result = load(cfg, text);
	free(text);
	return (result);
}

ATF_TC_WITHOUT_HEAD(storage_policy_file);

ATF_TC_BODY(storage_policy_file, tc)
{
	struct capsule_config cfg = {0}, before;
	const char *retired[] = {"policy=\"/Config/custom storage.ucl\";",
	    "policy=relative;", "policy=\"\";", "policy=12;",
	    "management={operations=[info];subtree=true;require_lease=true;properties=[];};",
	    "data={operations=[read];subtree=true;require_lease=true;};",
	    "attachment=/state;", "content=ordinary;", "content=protected;"};
	(void)tc;
	config_init_defaults(&cfg);
	ATF_REQUIRE_EQ(0, load_data(&cfg, ""));
	before = cfg;
	for (size_t i = 0; i < nitems(retired); i++) {
		ATF_CHECK_EQ(-1, load_data(&cfg, retired[i]));
		ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	}
	config_free(&cfg);
}


static char *
many_storage(unsigned count)
{
	char *text = NULL;
	size_t length = 0;
	FILE *stream = open_memstream(&text, &length);

	ATF_REQUIRE(stream != NULL);
	fprintf(stream, "hostuuid=\"57061ee3-7587-4a12-9447-2ac2b0e947fe\";storage=[");
	for (unsigned i = 0; i < count; i++)
		fprintf(stream, "%s{pool=tank;pool_guid=\"1\";dataset=tank/s%u;"
		    "dataset_guid=\"%u\";devices=[\"/dev/vtbd1\"];"
		    "rights=[props_read,event];recipient=site.Store/unit%u;}",
		    i == 0 ? "" : ",", i, i + 2, i);
	fprintf(stream, "];");
	ATF_REQUIRE_EQ(0, fclose(stream));
	return (text);
}

ATF_TC_WITHOUT_HEAD(storage_dynamic_lifetime);
ATF_TC_BODY(storage_dynamic_lifetime, tc)
{
	struct capsule_config cfg = {0}, copy = {0}, before;
	struct capsule_storage first;
	char *text;
	(void)tc;

	config_init_defaults(&cfg);
	text = many_storage(31);
	ATF_REQUIRE_EQ(0, load(&cfg, text));
	free(text);
	ATF_REQUIRE_EQ(31, cfg.nstorage);
	ATF_REQUIRE_EQ(0, config_copy(&copy, &cfg));
	ATF_CHECK(copy.storage != cfg.storage);
	ATF_CHECK(config_boot_policy_equal(&copy, &cfg));
	before = cfg;
	first = cfg.storage[0];
	ATF_CHECK_EQ(-1, load(&cfg, "storage=[{content=ordinary}];"));
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	ATF_CHECK_EQ(0, memcmp(&cfg.storage[0], &first, sizeof(first)));
	text = many_storage(CAPSULE_STORAGE_MAX + 1);
	ATF_CHECK_EQ(-1, load(&cfg, text));
	free(text);
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	ATF_REQUIRE_EQ(0, load(&cfg, "# preserve omitted storage"));
	ATF_CHECK(config_boot_policy_equal(&copy, &cfg));
	ATF_REQUIRE_EQ(0, load(&cfg, "storage=[];"));
	ATF_CHECK_EQ(0, cfg.nstorage);
	ATF_CHECK(cfg.storage == NULL);
	config_free(&cfg);
	ATF_CHECK_EQ(31, copy.nstorage);
	ATF_CHECK_STREQ("tank/s30", copy.storage[30].dataset);
	config_free(&copy);
	config_free(&copy);
}

ATF_TC_WITHOUT_HEAD(storage_allocation_failure);
ATF_TC_BODY(storage_allocation_failure, tc)
{
	struct capsule_config cfg = {0}, copy = {0}, before, copy_before;
	struct capsule_storage first;
	char *text = many_storage(11);
	(void)tc;

	config_init_defaults(&cfg);
	ATF_REQUIRE_EQ(0, load(&cfg, text));
	ATF_REQUIRE_EQ(0, config_copy(&copy, &cfg));
	before = cfg;
	copy_before = copy;
	first = cfg.storage[0];
	fail_storage_malloc = cfg.nstorage * sizeof(*cfg.storage);
	ATF_CHECK_ERRNO(ENOMEM, config_copy(&copy, &cfg) == -1);
	ATF_CHECK_EQ(0, fail_storage_malloc);
	ATF_CHECK_EQ(0, memcmp(&copy, &copy_before, sizeof(copy)));
	ATF_CHECK(config_boot_policy_equal(&copy, &cfg));
	fail_storage_malloc = cfg.nstorage * sizeof(*cfg.storage);
	ATF_CHECK_ERRNO(ENOMEM, load(&cfg, text) == -1);
	ATF_CHECK_EQ(0, fail_storage_malloc);
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	fail_storage_calloc = true;
	ATF_CHECK_EQ(-1, load(&cfg, text));
	ATF_CHECK(!fail_storage_calloc);
	ATF_CHECK_EQ(0, memcmp(&cfg, &before, sizeof(cfg)));
	ATF_CHECK_EQ(0, memcmp(&cfg.storage[0], &first, sizeof(first)));
	config_free(&copy);
	config_free(&cfg);
	free(text);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, storage_allocation_failure);
	ATF_TP_ADD_TC(tp, storage_dynamic_lifetime);
	ATF_TP_ADD_TC(tp, storage_policy_file);
	ATF_TP_ADD_TC(tp, crypto_boot_policy);
	ATF_TP_ADD_TC(tp, installation_policy);
	ATF_TP_ADD_TC(tp, host_identity);
	ATF_TP_ADD_TC(tp, storage_inputs);
	ATF_TP_ADD_TC(tp, storage_conflicts);
	ATF_TP_ADD_TC(tp, selected_inputs);
	ATF_TP_ADD_TC(tp, invalid_policy_is_atomic);
	ATF_TP_ADD_TC(tp, no_external_inputs);
	ATF_TP_ADD_TC(tp, descriptor_inputs);
	ATF_TP_ADD_TC(tp, shipped_policy);
	ATF_TP_ADD_TC(tp, shipped_examples);
	return (atf_no_error());
}
