/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Bounded, data-only parsers for the software-authority policies:
 * the temporary rc authority (boot-authority.ucl), the lasting grants of
 * adopted rc.d services (service-authority.ucl), and the read-only endpoints
 * of UID 0 sessions without authority (root-query.ucl).
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ucl.h>
#include <libcapbundle.h>
#include "switchboard.h"
#include "authority.h"

/* Read the whole descriptor once, refusing changes during the read. */
static int
policy_root(int fd, struct ucl_parser **parserp, ucl_object_t **rootp)
{
	struct ucl_parser *parser;
	ucl_object_t *root = NULL;
	struct stat st, after;
	unsigned char *text = NULL, extra;
	size_t offset = 0;
	ssize_t length;
	int error = EINVAL;

	*parserp = NULL;
	*rootp = NULL;
	if (fstat(fd, &st) == -1)
		return (errno);
	if (!S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > 65536)
		return (EINVAL);
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL)
		return (ENOMEM);
	text = malloc((size_t)st.st_size + 1);
	if (text == NULL) {
		error = ENOMEM;
		goto out;
	}
	while (offset < (size_t)st.st_size) {
		length = pread(fd, text + offset, (size_t)st.st_size - offset, offset);
		if (length < 0 && errno == EINTR)
			continue;
		if (length < 0) {
			error = errno;
			goto out;
		}
		if (length == 0)
			goto out;
		offset += (size_t)length;
	}
	do {
		length = pread(fd, &extra, 1, st.st_size);
	} while (length < 0 && errno == EINTR);
	if (length < 0) {
		error = errno;
		goto out;
	}
	if (length != 0 || memchr(text, '\0', offset) != NULL)
		goto out;
	if (fstat(fd, &after) == -1) {
		error = errno;
		goto out;
	}
	if (after.st_size != st.st_size || after.st_mode != st.st_mode ||
	    after.st_uid != st.st_uid || after.st_gid != st.st_gid ||
	    timespeccmp(&after.st_mtim, &st.st_mtim, !=) ||
	    timespeccmp(&after.st_ctim, &st.st_ctim, !=) ||
	    !ucl_parser_add_chunk_full(parser, text, offset, 0,
	    UCL_DUPLICATE_ERROR, UCL_PARSE_UCL))
		goto out;
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT)
		goto out;
	error = 0;
out:
	free(text);
	if (error != 0) {
		if (root != NULL)
			ucl_object_unref(root);
		ucl_parser_free(parser);
		return (error);
	}
	*parserp = parser;
	*rootp = root;
	return (0);
}

static bool
valid_key(const ucl_object_t *entry, const char **keyp)
{
	const char *key = ucl_object_key(entry);

	*keyp = key;
	return (key != NULL && strlen(key) == entry->keylen);
}

/* Append one unique, valid service name to an endpoint scope. */
static bool
add_endpoint(struct svc_authority_scope *scope, const ucl_object_t *value)
{
	const char *name = ucl_object_tostring(value);
	size_t i;

	if (ucl_object_type(value) != UCL_STRING || name == NULL ||
	    value->len != strlen(name) ||
	    !capbundle_valid_service_name(name, SVC_ANOINT_NAME_MAX))
		return (false);
	for (i = 0; i < scope->count; i++)
		if (strcmp(scope->endpoints[i], name) == 0)
			return (false);
	if (scope->count == SVC_AUTHORITY_SCOPE_MAX)
		return (false);
	strlcpy(scope->endpoints[scope->count++], name,
	    sizeof(scope->endpoints[0]));
	return (true);
}

int
svc_authority_parse_boot(int fd, struct svc_domain *domain,
    struct svc_authority_scope *scope)
{
	struct svc_domain candidate = { .kind = SVC_DOMAIN_SYSTEM };
	struct svc_authority_scope endpoints = { 0 };
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *entry, *value;
	ucl_object_iter_t it = NULL, items;
	size_t i;
	unsigned seen = 0, bit;
	int error;
	bool endpoint;

	memset(domain, 0, sizeof(*domain));
	memset(scope, 0, sizeof(*scope));
	error = policy_root(fd, &parser, &root);
	if (error != 0)
		return (errno = error, -1);
	error = EINVAL;
	while ((entry = ucl_object_iterate(root, &it, true)) != NULL) {
		const char *key;

		if (!valid_key(entry, &key))
			goto out;
		if (strcmp(key, "admin_rights") == 0)
			bit = 1;
		else if (strcmp(key, "endpoints") == 0)
			bit = 2;
		else if (strcmp(key, "attributes") == 0)
			bit = 4;
		else
			goto out;
		if ((seen & bit) != 0 || entry->next != NULL)
			goto out;
		seen |= bit;
		if (bit == 1) {
			if (ucl_object_type(entry) != UCL_BOOLEAN)
				goto out;
			candidate.anoint.admin_rights = ucl_object_toboolean(entry);
			continue;
		}
		if (ucl_object_type(entry) != UCL_ARRAY)
			goto out;
		endpoint = bit == 2;
		items = NULL;
		while ((value = ucl_object_iterate(entry, &items, true)) != NULL) {
			const char *name = ucl_object_tostring(value);

			if (endpoint) {
				if (!add_endpoint(&endpoints, value))
					goto out;
				continue;
			}
			if (ucl_object_type(value) != UCL_STRING ||
			    name == NULL || value->len != strlen(name) ||
			    !capbundle_valid_service_name(name, SVC_ANOINT_NAME_MAX))
				goto out;
			for (i = 0; i < candidate.anoint.n; i++)
				if (strcmp(candidate.anoint.names[i], name) == 0)
					goto out;
			if (candidate.anoint.n == SVC_ANOINT_MAX)
				goto out;
			strlcpy(candidate.anoint.names[candidate.anoint.n++],
			    name, sizeof(candidate.anoint.names[0]));
		}
	}
	if (endpoints.count == 0)
		goto out;
	*domain = candidate;
	*scope = endpoints;
	error = 0;
out:
	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (error == 0 ? 0 : (errno = error, -1));
}

/* An rc.d service name, as rc_adopt.conf uses it: [A-Za-z0-9_-], no dots. */
static bool
valid_rc_label(const char *label, size_t len)
{
	size_t i;

	if (len == 0 || len >= SWITCHBOARD_LABEL_MAX)
		return (false);
	for (i = 0; i < len; i++) {
		char c = label[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_'))
			return (false);
	}
	return (true);
}

/*
 * An executable image a lasting service grant may survive exec into: an
 * absolute, normalized path without "." or ".." components.  The issuer opens
 * and pins each image when it issues the grant; this only checks syntax.
 */
static bool
valid_image_path(const char *path, size_t len)
{
	const char *p, *component;

	if (len < 2 || len >= SVC_SERVICE_IMAGE_MAX || path[0] != '/' ||
	    path[len - 1] == '/' || strstr(path, "//") != NULL)
		return (false);
	for (p = path + 1; *p != '\0'; ) {
		component = p;
		while (*p != '\0' && *p != '/')
			p++;
		if ((p - component == 1 && component[0] == '.') ||
		    (p - component == 2 && component[0] == '.' &&
		    component[1] == '.'))
			return (false);
		if (*p == '/')
			p++;
	}
	return (true);
}

/*
 * service-authority.ucl: one object per adopted rc.d service label, each with
 * a non-empty "endpoints" list and a non-empty "images" list.  The grant
 * carries no attributes and no administrative rights; the format has no key
 * for either.
 */
int
svc_authority_parse_services(int fd, struct svc_service_authority *out,
    unsigned max, unsigned *countp)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *service, *entry, *value;
	ucl_object_iter_t it = NULL, fields, items;
	struct svc_service_authority *candidate = NULL;
	unsigned count = 0, seen, i;
	int error;

	*countp = 0;
	if (out == NULL || max == 0)
		return (errno = EINVAL, -1);
	memset(out, 0, sizeof(*out) * max);
	error = policy_root(fd, &parser, &root);
	if (error != 0)
		return (errno = error, -1);
	candidate = calloc(max, sizeof(*candidate));
	if (candidate == NULL) {
		error = ENOMEM;
		goto out;
	}
	error = EINVAL;
	while ((service = ucl_object_iterate(root, &it, true)) != NULL) {
		struct svc_service_authority *s;
		const char *label;

		if (!valid_key(service, &label) || service->next != NULL ||
		    ucl_object_type(service) != UCL_OBJECT ||
		    !valid_rc_label(label, service->keylen) ||
		    count == max)
			goto out;
		for (i = 0; i < count; i++)
			if (strcmp(candidate[i].label, label) == 0)
				goto out;
		s = &candidate[count];
		strlcpy(s->label, label, sizeof(s->label));
		seen = 0;
		fields = NULL;
		while ((entry = ucl_object_iterate(service, &fields, true)) != NULL) {
			const char *key;
			unsigned bit;

			if (!valid_key(entry, &key))
				goto out;
			if (strcmp(key, "endpoints") == 0)
				bit = 1;
			else if (strcmp(key, "images") == 0)
				bit = 2;
			else
				goto out;
			if ((seen & bit) != 0 || entry->next != NULL ||
			    ucl_object_type(entry) != UCL_ARRAY)
				goto out;
			seen |= bit;
			items = NULL;
			while ((value = ucl_object_iterate(entry, &items,
			    true)) != NULL) {
				const char *path = ucl_object_tostring(value);

				if (bit == 1) {
					if (!add_endpoint(&s->scope, value))
						goto out;
					continue;
				}
				if (ucl_object_type(value) != UCL_STRING ||
				    path == NULL || value->len != strlen(path) ||
				    !valid_image_path(path, value->len) ||
				    s->nimages == SVC_SERVICE_IMAGES_MAX)
					goto out;
				for (i = 0; i < s->nimages; i++)
					if (strcmp(s->images[i], path) == 0)
						goto out;
				strlcpy(s->images[s->nimages++], path,
				    sizeof(s->images[0]));
			}
		}
		if (seen != 3 || s->scope.count == 0 || s->nimages == 0)
			goto out;
		count++;
	}
	memcpy(out, candidate, sizeof(*out) * count);
	*countp = count;
	error = 0;
out:
	free(candidate);
	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (error == 0 ? 0 : (errno = error, -1));
}

/*
 * root-query.ucl: exactly one key, "endpoints", a non-empty list of unique
 * service names.  The format has no key for attributes, rights or users.
 */
int
svc_authority_parse_root_query(int fd, struct svc_authority_scope *scope)
{
	struct svc_authority_scope candidate = { 0 };
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *entry, *value;
	ucl_object_iter_t it = NULL, items;
	int error;
	bool seen = false;

	memset(scope, 0, sizeof(*scope));
	error = policy_root(fd, &parser, &root);
	if (error != 0)
		return (errno = error, -1);
	error = EINVAL;
	while ((entry = ucl_object_iterate(root, &it, true)) != NULL) {
		const char *key;

		if (!valid_key(entry, &key) || strcmp(key, "endpoints") != 0 ||
		    seen || entry->next != NULL ||
		    ucl_object_type(entry) != UCL_ARRAY)
			goto out;
		seen = true;
		items = NULL;
		while ((value = ucl_object_iterate(entry, &items, true)) != NULL)
			if (!add_endpoint(&candidate, value))
				goto out;
	}
	if (candidate.count == 0)
		goto out;
	*scope = candidate;
	error = 0;
out:
	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (error == 0 ? 0 : (errno = error, -1));
}
