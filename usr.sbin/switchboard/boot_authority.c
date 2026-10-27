/* SPDX-License-Identifier: BSD-2-Clause */
/* Bounded, data-only parser for the temporary rc software authority. */
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

int
svc_authority_parse_boot(int fd, struct svc_domain *domain,
    struct svc_authority_scope *scope)
{
	struct svc_domain candidate = { .kind = SVC_DOMAIN_SYSTEM };
	struct svc_authority_scope endpoints = { 0 };
	struct ucl_parser *parser;
	ucl_object_t *root = NULL;
	const ucl_object_t *entry, *value;
	ucl_object_iter_t it = NULL, items;
	struct stat st, after;
	unsigned char *text = NULL, extra;
	size_t offset = 0, i;
	ssize_t length;
	unsigned seen = 0, bit;
	int error = EINVAL;
	bool endpoint;

	memset(domain, 0, sizeof(*domain));
	memset(scope, 0, sizeof(*scope));
	if (fstat(fd, &st) == -1)
		return (-1);
	if (!S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > 65536)
		return (errno = EINVAL, -1);
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL)
		return (errno = ENOMEM, -1);
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
	while ((entry = ucl_object_iterate(root, &it, true)) != NULL) {
		const char *key = ucl_object_key(entry);

		if (key == NULL || strlen(key) != entry->keylen)
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

			if (ucl_object_type(value) != UCL_STRING ||
			    name == NULL || value->len != strlen(name) ||
			    !capbundle_valid_service_name(name, SVC_ANOINT_NAME_MAX))
				goto out;
			if (endpoint) {
				for (i = 0; i < endpoints.count; i++)
					if (strcmp(endpoints.endpoints[i], name) == 0)
						goto out;
				if (endpoints.count == SVC_AUTHORITY_SCOPE_MAX)
					goto out;
				strlcpy(endpoints.endpoints[endpoints.count++], name,
				    sizeof(endpoints.endpoints[0]));
			} else {
				for (i = 0; i < candidate.anoint.n; i++)
					if (strcmp(candidate.anoint.names[i], name) == 0)
						goto out;
				if (candidate.anoint.n == SVC_ANOINT_MAX)
					goto out;
				strlcpy(candidate.anoint.names[candidate.anoint.n++],
				    name, sizeof(candidate.anoint.names[0]));
			}
		}
	}
	if (endpoints.count == 0)
		goto out;
	*domain = candidate;
	*scope = endpoints;
	error = 0;
out:
	free(text);
	if (root != NULL)
		ucl_object_unref(root);
	ucl_parser_free(parser);
	return (error == 0 ? 0 : (errno = error, -1));
}
