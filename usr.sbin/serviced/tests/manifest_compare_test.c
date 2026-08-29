/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <string.h>

#include "manifest_compare.h"

static struct svc_manifest
sample_manifest(void)
{
	struct svc_manifest m;

	memset(&m, 0, sizeof(m));
	strlcpy(m.label, "org.test.bundle/program", sizeof(m.label));
	strlcpy(m.program, "/Capabilities/Test.cap/bin/program",
	    sizeof(m.program));
	strlcpy(m.user, "capability", sizeof(m.user));
	strlcpy(m.group, "capability", sizeof(m.group));
	strlcpy(m.arguments[0], "argument", sizeof(m.arguments[0]));
	m.narguments = 1;
	strlcpy(m.environment[0], "KEY=value", sizeof(m.environment[0]));
	m.nenvironment = 1;
	strlcpy(m.provides[0], "org.test.endpoint", sizeof(m.provides[0]));
	m.nprovides = 1;
	strlcpy(m.kmod_requires[0], "testmod", sizeof(m.kmod_requires[0]));
	m.nkmod_requires = 1;
	strlcpy(m.cap_paths[0], "/tmp", sizeof(m.cap_paths[0]));
	m.ncap_paths = 1;
	strlcpy(m.cap_files[0].path, "/tmp/file",
	    sizeof(m.cap_files[0].path));
	m.cap_files[0].actions = 1;
	m.ncap_files = 1;
	m.cap_net[0].domain = 2;
	m.ncap_net = 1;
	m.cap_jail[0].jid = 7;
	m.ncap_jail = 1;
	m.cap_vsock[0].cid = 3;
	m.ncap_vsock = 1;
	strlcpy(m.cap_storage[0].name, "data",
	    sizeof(m.cap_storage[0].name));
	strlcpy(m.cap_storage[0].dataset, "u-test",
	    sizeof(m.cap_storage[0].dataset));
	strlcpy(m.cap_storage[0].flavor, "native",
	    sizeof(m.cap_storage[0].flavor));
	m.cap_storage[0].rights = 1;
	m.cap_storage[0].scope = ORT_STORAGE_SCOPE_UNIT;
	m.ncap_storage = 1;
	strlcpy(m.cap_services[0], "identity", sizeof(m.cap_services[0]));
	m.ncap_services = 1;
	m.cap_system = 1;
	m.has_jail = true;
	strlcpy(m.jail_name, "testjail", sizeof(m.jail_name));
	strlcpy(m.jail_path, "/jails/test", sizeof(m.jail_path));
	strlcpy(m.jail_hostname, "test.invalid", sizeof(m.jail_hostname));
	strlcpy(m.jail_ip4_addr, "192.0.2.1", sizeof(m.jail_ip4_addr));
	m.restart = 1;
	m.stop_timeout = 5;
	m.max_failures = 10;
	return (m);
}

#define CHECK_CHANGE(statement) do { \
	a = sample_manifest(); \
	b = a; \
	statement; \
	ATF_CHECK(!serviced_manifest_equal(&a, &b)); \
} while (0)

ATF_TC_WITHOUT_HEAD(equal_and_unused_tail);
ATF_TC_BODY(equal_and_unused_tail, tc)
{
	struct svc_manifest a, b;

	a = sample_manifest();
	b = a;
	ATF_REQUIRE(serviced_manifest_equal(&a, &b));
	strlcpy(b.arguments[1], "unused", sizeof(b.arguments[1]));
	strlcpy(b.cap_storage[1].name, "unused",
	    sizeof(b.cap_storage[1].name));
	ATF_CHECK(serviced_manifest_equal(&a, &b));
}

ATF_TC_WITHOUT_HEAD(identity_and_execution_changes);
ATF_TC_BODY(identity_and_execution_changes, tc)
{
	struct svc_manifest a, b;

	CHECK_CHANGE(b.label[0] = 'x');
	CHECK_CHANGE(b.program[0] = 'x');
	CHECK_CHANGE(b.user[0] = 'x');
	CHECK_CHANGE(b.group[0] = 'x');
	CHECK_CHANGE(b.arguments[0][0] = 'x');
	CHECK_CHANGE(b.environment[0][0] = 'x');
	CHECK_CHANGE(b.restart++);
	CHECK_CHANGE(b.stop_timeout++);
	CHECK_CHANGE(b.max_failures++);
	CHECK_CHANGE(b.provides[0][0] = 'x');
	CHECK_CHANGE(b.kmod_requires[0][0] = 'x');
	CHECK_CHANGE(b.has_jail = false);
	CHECK_CHANGE(b.jail_name[0] = 'x');
	CHECK_CHANGE(b.jail_path[0] = 'x');
	CHECK_CHANGE(b.jail_hostname[0] = 'x');
	CHECK_CHANGE(b.jail_ip4_addr[0] = 'x');
}

ATF_TC_WITHOUT_HEAD(authority_changes);
ATF_TC_BODY(authority_changes, tc)
{
	struct svc_manifest a, b;

	CHECK_CHANGE(b.cap_paths[0][1] = 'x');
	CHECK_CHANGE(b.cap_files[0].actions++);
	CHECK_CHANGE(b.cap_net[0].domain++);
	CHECK_CHANGE(b.cap_jail[0].jid++);
	CHECK_CHANGE(b.cap_vsock[0].cid++);
	CHECK_CHANGE(b.cap_storage[0].rights++);
	CHECK_CHANGE(b.cap_storage[0].name[0] = 'x');
	CHECK_CHANGE(b.cap_storage[0].dataset[0] = 'x');
	CHECK_CHANGE(b.cap_storage[0].flavor[0] = 'x');
	CHECK_CHANGE(b.cap_storage[0].lifetime++);
	CHECK_CHANGE(b.cap_storage[0].scope++);
	CHECK_CHANGE(b.cap_services[0][0] = 'x');
	CHECK_CHANGE(b.cap_system++);
	CHECK_CHANGE(b.protect_flags++);
	CHECK_CHANGE(b.ncap_paths = 0);
	CHECK_CHANGE(b.ncap_files = 0);
	CHECK_CHANGE(b.ncap_net = 0);
	CHECK_CHANGE(b.ncap_jail = 0);
	CHECK_CHANGE(b.ncap_vsock = 0);
	CHECK_CHANGE(b.ncap_storage = 0);
	CHECK_CHANGE(b.ncap_services = 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, equal_and_unused_tail);
	ATF_TP_ADD_TC(tp, identity_and_execution_changes);
	ATF_TP_ADD_TC(tp, authority_changes);
	return (atf_no_error());
}
