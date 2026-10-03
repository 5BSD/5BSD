/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Attribute policy for authenticated SwitchBoard control operations.
 * This does not mediate exec, POSIX access, or internal supervisor work.
 * Every operation evaluates one complete policy snapshot, so a retained
 * control descriptor is not a retained administrative authorization.
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <kenv.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ucl.h>

#include "management_policy.h"
#ifndef MANAGEMENT_POLICY_TESTING
#include <syslog.h>
#include "switchboard.h"
#include "management.h"
#include "switchboard_audit.h"
#endif

#define POLICY_PATH "/Capabilities/Config/switchboard/management-policy.ucl"
#define POLICY_MAX (64 * 1024)
#define ITEMS_MAX 128
#define ATTR_MAX 16
#define NAME_MAXLEN 63
#define VALUE_MAXLEN 255

static bool
text_valid(const ucl_object_t *o, size_t max)
{
	const char *s;

	if (o == NULL || ucl_object_type(o) != UCL_STRING)
		return (false);
	s = ucl_object_tostring(o);
	return (s != NULL && o->len != 0 && o->len <= max &&
	    strlen(s) == o->len);
}

/* Closed schemas and duplicate rejection, including duplicates in objects. */
static bool
keys(const ucl_object_t *o, const char *const *allowed)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *v;
	unsigned i;

	if (o == NULL || ucl_object_type(o) != UCL_OBJECT)
		return (false);
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		if (v->next != NULL || strlen(ucl_object_key(v)) != v->keylen)
			return (false);
		for (i = 0; allowed[i] != NULL; i++)
			if (strcmp(ucl_object_key(v), allowed[i]) == 0)
				break;
		if (allowed[i] == NULL)
			return (false);
	}
	return (true);
}

static bool
attributes(const ucl_object_t *o, bool assigned)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *v;
	const char *k;
	unsigned n = 0;

	if (o == NULL)
		return (true);
	if (ucl_object_type(o) != UCL_OBJECT)
		return (false);
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		k = ucl_object_key(v);
		if (++n > ATTR_MAX || v->next != NULL || k == NULL ||
		    strlen(k) == 0 || strlen(k) != v->keylen ||
		    strlen(k) > NAME_MAXLEN ||
		    !text_valid(v, VALUE_MAXLEN))
			return (false);
		/* Runtime facts can be matched, but never assigned by metadata. */
		if (assigned && (strcmp(k, "uid") == 0 ||
		    strcmp(k, "class") == 0 || strcmp(k, "label") == 0))
			return (false);
	}
	return (true);
}

static bool
array_valid(const ucl_object_t *o)
{
	return (o != NULL && ucl_object_type(o) == UCL_ARRAY &&
	    ucl_array_size(o) <= ITEMS_MAX);
}

static bool
operation_valid(const ucl_object_t *o)
{
	const char *s;

	if (!text_valid(o, NAME_MAXLEN))
		return (false);
	s = ucl_object_tostring(o);
	return (strcmp(s, "start") == 0 || strcmp(s, "stop") == 0 ||
	    strcmp(s, "reload") == 0);
}

static bool
validate(const ucl_object_t *root)
{
	static const char *const root_keys[] = {
	    "version", "subjects", "targets", "rules", NULL };
	static const char *const subject_keys[] = { "uid", "attributes", NULL };
	static const char *const target_keys[] = { "label", "attributes", NULL };
	static const char *const rule_keys[] = {
	    "id", "effect", "operations", "subject", "target", "equal", NULL };
	static const char *const equal_keys[] = { "subject", "target", NULL };
	const ucl_object_t *a, *b, *v, *w, *ops, *equal;
	const char *s;
	unsigned i, j, k;
	int64_t uid;

	if (!keys(root, root_keys))
		return (false);
	v = ucl_object_lookup(root, "version");
	if (v == NULL || ucl_object_type(v) != UCL_INT ||
	    ucl_object_toint(v) != 1)
		return (false);
	for (k = 0; k < 2; k++) {
		a = ucl_object_lookup(root, k == 0 ? "subjects" : "targets");
		if (!array_valid(a))
			return (false);
		for (i = 0; i < ucl_array_size(a); i++) {
			b = ucl_array_find_index(a, i);
			if (!keys(b, k == 0 ? subject_keys : target_keys) ||
			    !attributes(ucl_object_lookup(b, "attributes"), true))
				return (false);
			v = ucl_object_lookup(b, k == 0 ? "uid" : "label");
			if (k == 0) {
				if (v == NULL || ucl_object_type(v) != UCL_INT)
					return (false);
				uid = ucl_object_toint(v);
				if (uid < 0 || (uint64_t)uid >= (uint64_t)(uid_t)-1)
					return (false);
			} else if (!text_valid(v, VALUE_MAXLEN))
				return (false);
			for (j = 0; j < i; j++) {
				w = ucl_object_lookup(ucl_array_find_index(a, j),
				    k == 0 ? "uid" : "label");
				if ((k == 0 && ucl_object_toint(v) == ucl_object_toint(w)) ||
				    (k != 0 && strcmp(ucl_object_tostring(v),
				    ucl_object_tostring(w)) == 0))
					return (false);
			}
		}
	}
	a = ucl_object_lookup(root, "rules");
	if (!array_valid(a))
		return (false);
	for (i = 0; i < ucl_array_size(a); i++) {
		b = ucl_array_find_index(a, i);
		if (!keys(b, rule_keys) ||
		    !text_valid(ucl_object_lookup(b, "id"), NAME_MAXLEN) ||
		    !attributes(ucl_object_lookup(b, "subject"), false) ||
		    !attributes(ucl_object_lookup(b, "target"), false))
			return (false);
		v = ucl_object_lookup(b, "effect");
		if (!text_valid(v, NAME_MAXLEN))
			return (false);
		s = ucl_object_tostring(v);
		if (strcmp(s, "allow") != 0 && strcmp(s, "deny") != 0)
			return (false);
		for (j = 0; j < i; j++)
			if (strcmp(ucl_object_tostring(ucl_object_lookup(b, "id")),
			    ucl_object_tostring(ucl_object_lookup(
			    ucl_array_find_index(a, j), "id"))) == 0)
				return (false);
		ops = ucl_object_lookup(b, "operations");
		if (!array_valid(ops) || ucl_array_size(ops) == 0)
			return (false);
		for (j = 0; j < ucl_array_size(ops); j++)
			if (!operation_valid(ucl_array_find_index(ops, j)))
				return (false);
		equal = ucl_object_lookup(b, "equal");
		if (equal == NULL)
			continue;
		if (!array_valid(equal) || ucl_array_size(equal) > ATTR_MAX)
			return (false);
		for (j = 0; j < ucl_array_size(equal); j++) {
			v = ucl_array_find_index(equal, j);
			if (!keys(v, equal_keys) ||
			    !text_valid(ucl_object_lookup(v, "subject"), NAME_MAXLEN) ||
			    !text_valid(ucl_object_lookup(v, "target"), NAME_MAXLEN))
				return (false);
		}
	}
	return (true);
}

static const char *
attribute(const ucl_object_t *attrs, const char *key, const char *uid,
    const char *label, const char *class)
{
	const ucl_object_t *v;

	if (strcmp(key, "uid") == 0)
		return (uid);
	if (strcmp(key, "label") == 0)
		return (label);
	if (strcmp(key, "class") == 0)
		return (class);
	v = attrs == NULL ? NULL : ucl_object_lookup(attrs, key);
	return (v == NULL ? NULL : ucl_object_tostring(v));
}

static bool
matches(const ucl_object_t *pattern, const ucl_object_t *attrs,
    const char *uid, const char *label, const char *class)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *v;
	const char *s;

	if (pattern == NULL)
		return (true);
	while ((v = ucl_object_iterate(pattern, &it, true)) != NULL) {
		s = attribute(attrs, ucl_object_key(v), uid, label, class);
		if (s == NULL || strcmp(s, ucl_object_tostring(v)) != 0)
			return (false);
	}
	return (true);
}

int
svc_management_policy_fd(int fd, uid_t uid, const char *label,
    const char *class, const char *operation, char *reason, size_t reasonlen)
{
	struct stat sb;
	struct ucl_parser *parser = NULL;
	ucl_object_t *root = NULL;
	const ucl_object_t *a, *b, *attrs, *subject = NULL, *target = NULL;
	const ucl_object_t *rules, *rule, *ops;
	const char *x, *y, *allowed = NULL;
	char uidstr[32];
	unsigned char *buf = NULL;
	unsigned i, j;
	bool match;
	int error = EINVAL;

	strlcpy(reason, "invalid-policy", reasonlen);
	if (label == NULL || class == NULL || operation == NULL ||
	    uid == (uid_t)-1 || fstat(fd, &sb) == -1 ||
	    !S_ISREG(sb.st_mode) || sb.st_size <= 0 || sb.st_size > POLICY_MAX)
		goto out;
	buf = malloc((size_t)sb.st_size);
	if (buf == NULL)
		goto out;
	if (pread(fd, buf, (size_t)sb.st_size, 0) != sb.st_size)
		goto out;
	parser = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_FILEVARS);
	if (parser == NULL || !ucl_parser_add_chunk(parser, buf, sb.st_size) ||
	    ucl_parser_get_error(parser) != NULL)
		goto out;
	root = ucl_parser_get_object(parser);
	if (!validate(root))
		goto out;
	error = EACCES;
	strlcpy(reason, "default-deny", reasonlen);
	if (strcmp(class, "core") == 0) {
		strlcpy(reason, "core-invariant", reasonlen);
		goto out;
	}
	snprintf(uidstr, sizeof(uidstr), "%ju", (uintmax_t)uid);
	for (j = 0; j < 2; j++) {
		a = ucl_object_lookup(root, j == 0 ? "subjects" : "targets");
		for (i = 0; i < ucl_array_size(a); i++) {
			b = ucl_array_find_index(a, i);
			attrs = ucl_object_lookup(b, "attributes");
			if (j == 0 && ucl_object_toint(ucl_object_lookup(b, "uid")) == uid)
				subject = attrs;
			if (j == 1 && strcmp(ucl_object_tostring(
			    ucl_object_lookup(b, "label")), label) == 0)
				target = attrs;
		}
	}
	rules = ucl_object_lookup(root, "rules");
	for (i = 0; i < ucl_array_size(rules); i++) {
		rule = ucl_array_find_index(rules, i);
		ops = ucl_object_lookup(rule, "operations");
		match = false;
		for (j = 0; j < ucl_array_size(ops); j++)
			if (strcmp(ucl_object_tostring(ucl_array_find_index(ops, j)),
			    operation) == 0)
				match = true;
		if (!match || !matches(ucl_object_lookup(rule, "subject"),
		    subject, uidstr, NULL, NULL) ||
		    !matches(ucl_object_lookup(rule, "target"), target,
		    NULL, label, class))
			continue;
		a = ucl_object_lookup(rule, "equal");
		for (j = 0; a != NULL && j < ucl_array_size(a); j++) {
			b = ucl_array_find_index(a, j);
			x = attribute(subject, ucl_object_tostring(ucl_object_lookup(b,
			    "subject")), uidstr, NULL, NULL);
			y = attribute(target, ucl_object_tostring(ucl_object_lookup(b,
			    "target")), NULL, label, class);
			if (x == NULL || y == NULL || strcmp(x, y) != 0)
				break;
		}
		if (a != NULL && j != ucl_array_size(a))
			continue;
		x = ucl_object_tostring(ucl_object_lookup(rule, "id"));
		if (strcmp(ucl_object_tostring(ucl_object_lookup(rule, "effect")),
		    "deny") == 0) {
			strlcpy(reason, x, reasonlen);
			goto out;
		}
		if (allowed == NULL)
			allowed = x;
	}
	if (allowed != NULL) {
		error = 0;
		strlcpy(reason, allowed, reasonlen);
	}
out:
	if (root != NULL)
		ucl_object_unref(root);
	if (parser != NULL)
		ucl_parser_free(parser);
	free(buf);
	return (error);
}

#ifndef MANAGEMENT_POLICY_TESTING
static bool policy_enabled;

void
svc_management_policy_init(void)
{
	char value[32] = { 0 };
	int n;

	/* Any configured value except explicit NO enables fail-closed policy. */
	errno = 0;
	n = kenv(KENV_GET, "switchboard_management_policy", value, sizeof(value) - 1);
	policy_enabled = n < 0 ? errno != ENOENT : strcasecmp(value, "NO") != 0;
	syslog(LOG_INFO, "management authorization: %s",
	    policy_enabled ? "attribute policy" : "legacy compatibility");
}

int
svc_management_authorize(const struct svc_runtime *svc, const char *operation,
    uid_t uid, bool is_operator)
{
	struct stat sb;
	const char *label, *class;
	char reason[NAME_MAXLEN + 1];
	int fd, error;

	if (!policy_enabled)
		return (svc == NULL ? (is_operator ? 0 : EPERM) :
		    svc_management_check_op(svc, operation, uid, is_operator));
	/* Preserve self-management; policy never promotes a caller over CORE. */
	if (svc != NULL && svc->manifest.management == SVC_MGMT_CORE)
		return (EPERM);
	if (svc != NULL && svc->manifest.management == SVC_MGMT_USER &&
	    uid != (uid_t)-1 && uid == svc->owner_uid)
		return (0);
	label = svc == NULL ? "system.switchboard" : svc->manifest.label;
	class = svc == NULL ? "manager" :
	    svc_management_name(svc->manifest.management);
	fd = open(POLICY_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_VERIFY);
	if (fd != -1 && (fstat(fd, &sb) == -1 || sb.st_uid != 0 ||
	    (sb.st_mode & (S_IWGRP | S_IWOTH)) != 0)) {
		error = EACCES;
		strlcpy(reason, "untrusted-policy-file", sizeof(reason));
	} else
		error = svc_management_policy_fd(fd, uid, label, class, operation,
		    reason, sizeof(reason));
	if (fd != -1)
		close(fd);
	switchboard_audit(AUE_SWITCHBOARD_CTL, uid, error,
	    "attribute-policy op=%s target=%s rule=%s", operation, label, reason);
	return (error == 0 ? 0 : EPERM);
}
#endif
