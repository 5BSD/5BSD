/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "management_policy.h"

static const char fixture[] =
    "version=1; subjects=["
    "{uid=1001; attributes={deployment=lab; subsystem=network;};},"
    "{uid=1002; attributes={deployment=other; subsystem=network;};}];"
    "targets=[{label=\"test.network\"; attributes={deployment=lab; subsystem=network;};},"
    "{label=\"test.storage\"; attributes={deployment=lab; subsystem=storage;};}];"
    "rules=[{id=maintenance; effect=allow; operations=[start,stop];"
    "target={class=system;}; equal=[{subject=deployment; target=deployment;},"
    "{subject=subsystem; target=subsystem;}];}];";

static int
evaluate_bytes(const char *text, size_t len, uid_t uid, const char *label,
    const char *class, const char *op, char *reason)
{
	char path[] = "policy.XXXXXX";
	int fd, error;

	fd = mkstemp(path);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, text, len));
	error = svc_management_policy_fd(fd, uid, label, class, op, reason, 64);
	close(fd);
	unlink(path);
	return (error);
}

static int
evaluate(const char *text, uid_t uid, const char *label, const char *class,
    const char *op, char *reason)
{
	return (evaluate_bytes(text, strlen(text), uid, label, class, op, reason));
}

ATF_TC_WITHOUT_HEAD(scoped_operations);
ATF_TC_BODY(scoped_operations, tc)
{
	char reason[64];

	ATF_CHECK_EQ(0, evaluate(fixture, 1001, "test.network", "system", "start", reason));
	ATF_CHECK_STREQ("maintenance", reason);
	ATF_CHECK_EQ(0, evaluate(fixture, 1001, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1001, "test.storage", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1002, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 0, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1001, "system.switchboard", "manager", "reload", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1001, "test.network", "system", "unknown", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1001, "test.network", "core", "stop", reason));
	ATF_CHECK_STREQ("core-invariant", reason);
	ATF_CHECK_EQ(EINVAL, evaluate(fixture, (uid_t)-1, "test.network", "system", "stop", reason));
}

ATF_TC_WITHOUT_HEAD(deny_overrides);
ATF_TC_BODY(deny_overrides, tc)
{
	const char *prefix = "version=1; subjects=[]; targets=[]; rules=[";
	const char *allow = "{id=permit; effect=allow; operations=[stop];}";
	const char *deny = "{id=refuse; effect=deny; operations=[stop]; subject={uid=\"1001\";};}";
	char text[1024], reason[64];
	unsigned i;

	for (i = 0; i < 2; i++) {
		snprintf(text, sizeof(text), "%s%s,%s];", prefix,
		    i == 0 ? allow : deny, i == 0 ? deny : allow);
		ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "test.network", "system", "stop", reason));
		ATF_CHECK_STREQ("refuse", reason);
		ATF_CHECK_EQ(0, evaluate(text, 1002, "test.network", "system", "stop", reason));
		ATF_CHECK_EQ(EACCES, evaluate(text, 1002, "test.network", "core", "stop", reason));
	}
}

ATF_TC_WITHOUT_HEAD(malformed_fails_closed);
ATF_TC_BODY(malformed_fails_closed, tc)
{
	const char *bad[] = {
	    "",
	    "version=2; subjects=[]; targets=[]; rules=[];",
	    "version=1; version=1; subjects=[]; targets=[]; rules=[];",
	    "version=1; subjects=[]; targets=[]; rules=[]; typo=true;",
	    "version=1; subjects=[{uid=0;attributes={uid=\"1001\";};}];targets=[];rules=[];",
	    "version=1; subjects=[{uid=0;},{uid=0;}];targets=[];rules=[];",
	    "version=1; subjects=[];targets=[{label=x;},{label=x;}];rules=[];",
	    "version=1; subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[stop];},"
	    "{id=x;effect=deny;operations=[stop];}];",
	    "version=1; subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[stop];},"
	    "{id=y;effect=allow;operations=[erase];}];",
	    "version=1; subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[stop]; fresh=true;}];",
	    "version=1; subjects=[{uid=1001;attributes={deployment=lab;deployment=lab;};}];targets=[];rules=[];",
	    "version=1; subjects=[{uid=1001;attributes={deployment=true;};}];targets=[];rules=[];",
	    "version=1; subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[stop];equal=[{}];}];",
	    "version=1; subjects=[{uid=-1;}];targets=[];rules=[];"
	};
	char reason[64];
	unsigned i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		ATF_CHECK_EQ_MSG(EINVAL, evaluate(bad[i], 1001, "test.network",
		    "system", "stop", reason), "accepted invalid policy %u", i);
	ATF_CHECK_EQ(EINVAL, svc_management_policy_fd(-1, 1001,
	    "test.network", "system", "stop", reason, sizeof(reason)));
}

ATF_TC_WITHOUT_HEAD(missing_attributes);
ATF_TC_BODY(missing_attributes, tc)
{
	char reason[64];

	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1003, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(fixture, 1001, "unassigned", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate("version=1;subjects=[];targets=[];rules=["
	    "{id=x;effect=allow;operations=[stop];equal=[{subject=missing;target=missing;}];}];",
	    1001, "test.network", "system", "stop", reason));
}

ATF_TC_WITHOUT_HEAD(policy_replacement);
ATF_TC_BODY(policy_replacement, tc)
{
	char reason[64];

	/* No permission cache: the same authenticated identity is re-evaluated. */
	ATF_CHECK_EQ(0, evaluate(fixture, 1001, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate("version=1;subjects=[];targets=[];rules=[];",
	    1001, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EINVAL, evaluate("broken", 1001, "test.network", "system", "stop", reason));
}


ATF_TC_WITHOUT_HEAD(file_size_boundary);
ATF_TC_BODY(file_size_boundary, tc)
{
	char *text, reason[64];

	text = malloc(65537);
	ATF_REQUIRE(text != NULL);
	memset(text, ' ', 65537);
	memcpy(text, fixture, strlen(fixture));
	ATF_CHECK_EQ(0, evaluate_bytes(text, 65536, 1001,
	    "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EINVAL, evaluate_bytes(text, 65537, 1001,
	    "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(EINVAL, evaluate_bytes(text, 0, 1001,
	    "test.network", "system", "stop", reason));
	free(text);
}

ATF_TC_WITHOUT_HEAD(collection_bounds);
ATF_TC_BODY(collection_bounds, tc)
{
	FILE *stream;
	char *text, reason[64];
	size_t length;
	unsigned kind, n, i, column;
	const char *names[] = { "subjects", "targets", "rules" };

	for (kind = 0; kind < 3; kind++) {
		for (n = 128; n <= 129; n++) {
			stream = open_memstream(&text, &length);
			ATF_REQUIRE(stream != NULL);
			fprintf(stream, "version=1;");
			for (column = 0; column < 3; column++) {
				fprintf(stream, "%s=[", names[column]);
				if (column == kind) {
					for (i = 0; i < n; i++) {
						if (i != 0) fprintf(stream, ",");
						if (kind == 0)
							fprintf(stream, "{uid=%u;}", 1000 + i);
						else if (kind == 1)
							fprintf(stream, "{label=\"target%u\";}", i);
						else
							fprintf(stream, "{id=r%u;effect=allow;operations=[stop];}", i);
					}
				} else if (column == 2)
					fprintf(stream, "{id=permit;effect=allow;operations=[stop];}");
				fprintf(stream, "];");
			}
			ATF_REQUIRE_EQ(0, fclose(stream));
			ATF_CHECK_EQ_MSG(n == 128 ? 0 : EINVAL,
			    evaluate(text, 1001, "test.network", "system", "stop", reason),
			    "collection %s size %u", names[kind], n);
			free(text);
		}
	}
}

ATF_TC_WITHOUT_HEAD(attribute_bounds);
ATF_TC_BODY(attribute_bounds, tc)
{
	FILE *stream;
	char *text, reason[64], key[65], value[257], policy[2048];
	size_t length;
	unsigned n, i, keylen, valuelen;

	for (n = 16; n <= 17; n++) {
		stream = open_memstream(&text, &length);
		ATF_REQUIRE(stream != NULL);
		fprintf(stream, "version=1;subjects=[{uid=1001;attributes={");
		for (i = 0; i < n; i++) fprintf(stream, "a%u=lab;", i);
		fprintf(stream, "};}];targets=[];rules=[{id=permit;effect=allow;operations=[stop];}];");
		ATF_REQUIRE_EQ(0, fclose(stream));
		ATF_CHECK_EQ(n == 16 ? 0 : EINVAL,
		    evaluate(text, 1001, "test.network", "system", "stop", reason));
		free(text);
	}
	memset(key, 'k', sizeof(key) - 1); key[64] = '\0';
	memset(value, 'v', sizeof(value) - 1); value[256] = '\0';
	for (keylen = 63; keylen <= 64; keylen++) {
		for (valuelen = 255; valuelen <= 256; valuelen++) {
			snprintf(policy, sizeof(policy), "version=1;subjects=[{uid=1001;"
			    "attributes={\"%.*s\"=\"%.*s\";};}];targets=[];"
			    "rules=[{id=permit;effect=allow;operations=[stop];}];",
			    keylen, key, valuelen, value);
			ATF_CHECK_EQ(keylen == 63 && valuelen == 255 ? 0 : EINVAL,
			    evaluate(policy, 1001, "test.network", "system", "stop", reason));
		}
	}
}

ATF_TC_WITHOUT_HEAD(equality_bounds);
ATF_TC_BODY(equality_bounds, tc)
{
	FILE *stream;
	char *text, reason[64];
	size_t length;
	unsigned n, i;

	for (n = 16; n <= 17; n++) {
		stream = open_memstream(&text, &length);
		ATF_REQUIRE(stream != NULL);
		fprintf(stream, "version=1;subjects=[];targets=[];rules=["
		    "{id=permit;effect=allow;operations=[stop];equal=[");
		for (i = 0; i < n; i++)
			fprintf(stream, "%s{subject=uid;target=uid;}", i ? "," : "");
		fprintf(stream, "];}];");
		ATF_REQUIRE_EQ(0, fclose(stream));
		/* Even valid equality lists cannot match a missing target uid. */
		ATF_CHECK_EQ(n == 16 ? EACCES : EINVAL,
		    evaluate(text, 1001, "test.network", "system", "stop", reason));
		free(text);
	}
}

ATF_TC_WITHOUT_HEAD(reserved_attributes);
ATF_TC_BODY(reserved_attributes, tc)
{
	const char *reserved[] = { "uid", "label", "class" };
	char text[1024], reason[64];
	unsigned i, target;

	for (i = 0; i < 3; i++) {
		for (target = 0; target < 2; target++) {
			snprintf(text, sizeof(text), "version=1;%s=[{%s;"
			    "attributes={%s=\"forged\";};}];%s=[];"
			    "rules=[{id=permit;effect=allow;operations=[stop];}];",
			    target ? "targets" : "subjects",
			    target ? "label=\"test.network\"" : "uid=1001",
			    reserved[i], target ? "subjects" : "targets");
			ATF_CHECK_EQ(EINVAL,
			    evaluate(text, 1001, "test.network", "system", "stop", reason));
		}
	}
}

ATF_TC_WITHOUT_HEAD(literal_matching);
ATF_TC_BODY(literal_matching, tc)
{
	const char *text = "version=1;subjects=[];targets=[];rules=["
	    "{id=literal;effect=allow;operations=[stop];"
	    "subject={uid=\"1001\";};target={label=\"test.*\";class=system;};}];";
	char reason[64];

	ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "test.network", "system", "stop", reason));
	ATF_CHECK_EQ(0, evaluate(text, 1001, "test.*", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(text, 1002, "test.*", "system", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "test.*", "user", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "test.*", "system", "start", reason));
	ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "test.*", "system", "STOP", reason));
}

ATF_TC_WITHOUT_HEAD(reload_scoping);
ATF_TC_BODY(reload_scoping, tc)
{
	const char *text = "version=1;subjects=[];targets=[];rules=["
	    "{id=reload-only;effect=allow;operations=[reload];subject={uid=\"1001\";};"
	    "target={label=\"system.switchboard\";class=manager;};}];";
	char reason[64];

	ATF_CHECK_EQ(0, evaluate(text, 1001, "system.switchboard", "manager", "reload", reason));
	ATF_CHECK_STREQ("reload-only", reason);
	ATF_CHECK_EQ(EACCES, evaluate(text, 0, "system.switchboard", "manager", "reload", reason));
	ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "system.switchboard", "manager", "stop", reason));
	ATF_CHECK_EQ(EACCES, evaluate(text, 1001, "test.network", "system", "reload", reason));
}

ATF_TC_WITHOUT_HEAD(invalid_encodings);
ATF_TC_BODY(invalid_encodings, tc)
{
	const char *bad[] = {
	    "version=1;subjects=[];targets=[];rules=[{id=\"ok\\u0000hidden\";effect=allow;operations=[stop];}];",
	    "version=1;subjects=[];targets=[];rules=[{id=ok;effect=\"allow\\u0000deny\";operations=[stop];}];",
	    "version=1;subjects=[{uid=4294967295;}];targets=[];rules=[];",
	    "version=1;subjects=[{uid=4294967296;}];targets=[];rules=[];",
	    "version=1;subjects=[{uid=1.5;}];targets=[];rules=[];",
	    "version=1;subjects=[{uid=\"1001\";}];targets=[];rules=[];",
	    "version=1;subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[\"*\"];}];",
	    "version=1;subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[];}];",
	    "version=1;subjects=[];targets=[];rules=[{id=x;effect=allow;operations=[stop];subject={uid=1001;};}];"
	};
	char reason[64];
	unsigned i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		ATF_CHECK_EQ_MSG(EINVAL,
		    evaluate(bad[i], 1001, "test.network", "system", "stop", reason),
		    "invalid encoding %u was accepted", i);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, scoped_operations);
	ATF_TP_ADD_TC(tp, deny_overrides);
	ATF_TP_ADD_TC(tp, malformed_fails_closed);
	ATF_TP_ADD_TC(tp, missing_attributes);
	ATF_TP_ADD_TC(tp, policy_replacement);
	ATF_TP_ADD_TC(tp, file_size_boundary);
	ATF_TP_ADD_TC(tp, collection_bounds);
	ATF_TP_ADD_TC(tp, attribute_bounds);
	ATF_TP_ADD_TC(tp, equality_bounds);
	ATF_TP_ADD_TC(tp, reserved_attributes);
	ATF_TP_ADD_TC(tp, literal_matching);
	ATF_TP_ADD_TC(tp, reload_scoping);
	ATF_TP_ADD_TC(tp, invalid_encodings);
	return (atf_no_error());
}
