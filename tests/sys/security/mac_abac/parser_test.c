/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "mac_abacd.h"

#define DEFINE_OPERATION_CASES(name, value)                                \
ATF_TC(line_allow_##name);                                                  \
ATF_TC_HEAD(line_allow_##name, tc)                                          \
{                                                                           \
	atf_tc_set_md_var(tc, "descr", "parse allow " #name);               \
}                                                                           \
ATF_TC_BODY(line_allow_##name, tc)                                          \
{                                                                           \
	struct abac_rule_io rule;                                             \
	char text[256];                                                       \
	(void)tc;                                                             \
	snprintf(text, sizeof(text), "allow " #name                           \
	    " type=source -> type=target");                                  \
	ATF_REQUIRE_EQ(0, mac_abacd_parse_line(text, &rule));                  \
	ATF_REQUIRE_EQ((uint32_t)(value), rule.vr_operations);                 \
	ATF_REQUIRE_EQ(ABAC_ACTION_ALLOW, rule.vr_action);                     \
}                                                                           \
ATF_TC(line_deny_##name);                                                   \
ATF_TC_HEAD(line_deny_##name, tc)                                           \
{                                                                           \
	atf_tc_set_md_var(tc, "descr", "parse deny " #name);                \
}                                                                           \
ATF_TC_BODY(line_deny_##name, tc)                                           \
{                                                                           \
	struct abac_rule_io rule;                                             \
	char text[256];                                                       \
	(void)tc;                                                             \
	snprintf(text, sizeof(text), "deny " #name " * -> *");              \
	ATF_REQUIRE_EQ(0, mac_abacd_parse_line(text, &rule));                  \
	ATF_REQUIRE_EQ((uint32_t)(value), rule.vr_operations);                 \
	ATF_REQUIRE_EQ(ABAC_ACTION_DENY, rule.vr_action);                      \
}                                                                           \
ATF_TC(line_casefold_##name);                                               \
ATF_TC_HEAD(line_casefold_##name, tc)                                       \
{                                                                           \
	atf_tc_set_md_var(tc, "descr", "operation names are case-insensitive");\
}                                                                           \
ATF_TC_BODY(line_casefold_##name, tc)                                       \
{                                                                           \
	struct abac_rule_io rule;                                             \
	char opname[64] = #name;                                              \
	char text[256];                                                       \
	size_t i;                                                             \
	(void)tc;                                                             \
	for (i = 0; opname[i] != '\0'; i++)                                  \
		opname[i] = (char)toupper((unsigned char)opname[i]);            \
	snprintf(text, sizeof(text), "allow %s * -> *", opname);             \
	ATF_REQUIRE_EQ(0, mac_abacd_parse_line(text, &rule));                  \
	ATF_REQUIRE_EQ((uint32_t)(value), rule.vr_operations);                 \
}                                                                           \
ATF_TC(line_subject_context_##name);                                        \
ATF_TC_HEAD(line_subject_context_##name, tc)                                \
{                                                                           \
	atf_tc_set_md_var(tc, "descr", "parse subject context for " #name); \
}                                                                           \
ATF_TC_BODY(line_subject_context_##name, tc)                                \
{                                                                           \
	struct abac_rule_io rule;                                             \
	char text[256];                                                       \
	(void)tc;                                                             \
	snprintf(text, sizeof(text), "allow " #name                           \
	    " * ctx:uid=42,gid=7 -> *");                                    \
	ATF_REQUIRE_EQ(0, mac_abacd_parse_line(text, &rule));                  \
	ATF_REQUIRE_EQ(ABAC_CTX_UID | ABAC_CTX_GID,                            \
	    rule.vr_subj_context.vc_flags);                                   \
	ATF_REQUIRE_EQ(42, rule.vr_subj_context.vc_uid);                       \
	ATF_REQUIRE_EQ(7, rule.vr_subj_context.vc_gid);                        \
}                                                                           \
ATF_TC(line_object_context_set_##name);                                     \
ATF_TC_HEAD(line_object_context_set_##name, tc)                             \
{                                                                           \
	atf_tc_set_md_var(tc, "descr", "parse object context and max set"); \
}                                                                           \
ATF_TC_BODY(line_object_context_set_##name, tc)                             \
{                                                                           \
	struct abac_rule_io rule;                                             \
	char text[320];                                                       \
	(void)tc;                                                             \
	snprintf(text, sizeof(text), "allow " #name                           \
	    " !type=bad -> key=* ctx:jail=host,tty=true set 65535");         \
	ATF_REQUIRE_EQ(0, mac_abacd_parse_line(text, &rule));                  \
	ATF_REQUIRE_EQ(65535, rule.vr_set);                                    \
	ATF_REQUIRE_EQ(ABAC_MATCH_NEGATE, rule.vr_subject.vp_flags);           \
	ATF_REQUIRE_EQ(ABAC_CTX_JAIL | ABAC_CTX_HAS_TTY,                       \
	    rule.vr_obj_context.vc_flags);                                    \
}

ABAC_OPERATION_LIST(DEFINE_OPERATION_CASES)

#define INVALID_CASE(name, text)                                           \
ATF_TC(invalid_##name);                                                     \
ATF_TC_HEAD(invalid_##name, tc)                                             \
{                                                                           \
	atf_tc_set_md_var(tc, "descr", "reject malformed rule: " #name);    \
}                                                                           \
ATF_TC_BODY(invalid_##name, tc)                                             \
{                                                                           \
	struct abac_rule_io rule;                                             \
	(void)tc;                                                             \
	ATF_REQUIRE(mac_abacd_parse_line((text), &rule) < 0);                  \
}

INVALID_CASE(action, "permit read * -> *")
INVALID_CASE(operation, "allow frobnicate * -> *")
INVALID_CASE(empty_operation, "allow , * -> *")
INVALID_CASE(operation_trailing_comma, "allow read, * -> *")
INVALID_CASE(operation_double_comma, "allow read,,write * -> *")
INVALID_CASE(subject, "allow read type -> *")
INVALID_CASE(subject_empty_pair, "allow read type=a,,domain=b -> *")
INVALID_CASE(subject_duplicate_key, "allow read type=a,type=b -> *")
INVALID_CASE(pattern_trailing_comma, "allow read type=a, -> *")
INVALID_CASE(missing_arrow, "allow read * *")
INVALID_CASE(second_arrow, "allow read * -> * -> *")
INVALID_CASE(missing_object, "allow read * ->")
INVALID_CASE(context_key, "allow read * ctx:nope=1 -> *")
INVALID_CASE(context_empty, "allow read * ctx: -> *")
INVALID_CASE(context_trailing_comma, "allow read * ctx:uid=1, -> *")
INVALID_CASE(context_double_comma, "allow read * ctx:uid=1,,gid=2 -> *")
INVALID_CASE(context_duplicate, "allow read * ctx:uid=1,uid=2 -> *")
INVALID_CASE(context_uid_ruid, "allow read * ctx:uid=1,ruid=1 -> *")
INVALID_CASE(context_range, "allow read * ctx:uid=4294967296 -> *")
INVALID_CASE(set_negative, "allow read * -> * set -1")
INVALID_CASE(set_range, "allow read * -> * set 65536")
INVALID_CASE(set_duplicate, "allow read * -> * set 1 set 2")
INVALID_CASE(transition_operation, "transition read * -> * => type=new")
INVALID_CASE(transition_label, "transition exec * -> * => type")
INVALID_CASE(allow_newlabel, "allow exec * -> * => type=new")
INVALID_CASE(duplicate_newlabel,
    "transition exec * -> * => type=a => type=b")

#define ADD_OPERATION_CASES(name, value)                                    \
	ATF_TP_ADD_TC(tp, line_allow_##name);                                 \
	ATF_TP_ADD_TC(tp, line_deny_##name);                                  \
	ATF_TP_ADD_TC(tp, line_casefold_##name);                              \
	ATF_TP_ADD_TC(tp, line_subject_context_##name);                       \
	ATF_TP_ADD_TC(tp, line_object_context_set_##name);

#define ADD_INVALID_CASE(name) ATF_TP_ADD_TC(tp, invalid_##name)

ATF_TP_ADD_TCS(tp)
{
	ABAC_OPERATION_LIST(ADD_OPERATION_CASES)
	ADD_INVALID_CASE(action);
	ADD_INVALID_CASE(operation);
	ADD_INVALID_CASE(empty_operation);
	ADD_INVALID_CASE(operation_trailing_comma);
	ADD_INVALID_CASE(operation_double_comma);
	ADD_INVALID_CASE(subject);
	ADD_INVALID_CASE(subject_empty_pair);
	ADD_INVALID_CASE(subject_duplicate_key);
	ADD_INVALID_CASE(pattern_trailing_comma);
	ADD_INVALID_CASE(missing_arrow);
	ADD_INVALID_CASE(second_arrow);
	ADD_INVALID_CASE(missing_object);
	ADD_INVALID_CASE(context_key);
	ADD_INVALID_CASE(context_empty);
	ADD_INVALID_CASE(context_trailing_comma);
	ADD_INVALID_CASE(context_double_comma);
	ADD_INVALID_CASE(context_duplicate);
	ADD_INVALID_CASE(context_uid_ruid);
	ADD_INVALID_CASE(context_range);
	ADD_INVALID_CASE(set_negative);
	ADD_INVALID_CASE(set_range);
	ADD_INVALID_CASE(set_duplicate);
	ADD_INVALID_CASE(transition_operation);
	ADD_INVALID_CASE(transition_label);
	ADD_INVALID_CASE(allow_newlabel);
	ADD_INVALID_CASE(duplicate_newlabel);
	return (atf_no_error());
}
