/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "libcapbundle_internal.h"

static int
policy_error(char *errbuf, size_t errlen, const char *message)
{

	if (errbuf != NULL && errlen != 0)
		strlcpy(errbuf, message, errlen);
	errno = EINVAL;
	return (-1);
}

static bool
valid_name(const char *name, size_t maximum)
{
	const unsigned char *p;

	if (name == NULL || name[0] == '\0' || strlen(name) >= maximum)
		return (false);
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		if (!(('a' <= *p && *p <= 'z') ||
		    ('A' <= *p && *p <= 'Z') ||
		    ('0' <= *p && *p <= '9') || *p == '.' || *p == '_' ||
		    *p == '-'))
			return (false);
	return (true);
}

static bool
valid_semver(const char *version)
{
	unsigned fields;
	bool digit;

	if (version == NULL || version[0] == '\0' ||
	    strlen(version) >= SERVICED_COMPONENT_VERSION_MAX)
		return (false);
	fields = 1;
	digit = false;
	for (; *version != '\0'; version++) {
		if ('0' <= *version && *version <= '9') {
			digit = true;
			continue;
		}
		if (*version != '.' || !digit || fields == 3)
			return (false);
		fields++;
		digit = false;
	}
	return (fields == 3 && digit);
}

static int
read_policy(const char *path, unsigned char **datap, size_t *sizep,
    char *errbuf, size_t errlen)
{
	struct stat st;
	unsigned char *data;
	ssize_t nread;
	size_t offset;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1) {
		if (errbuf != NULL && errlen != 0)
			snprintf(errbuf, errlen, "%s: %s", path, strerror(errno));
		return (-1);
	}
	if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > CAPBUNDLE_MAX_UCL_SIZE) {
		close(fd);
		return (policy_error(errbuf, errlen,
		    "policy must be a non-empty regular file no larger than 1 MB"));
	}
	data = malloc((size_t)st.st_size);
	if (data == NULL) {
		close(fd);
		return (-1);
	}
	offset = 0;
	while (offset < (size_t)st.st_size) {
		nread = read(fd, data + offset, (size_t)st.st_size - offset);
		if (nread == -1 && errno == EINTR)
			continue;
		if (nread <= 0) {
			free(data);
			close(fd);
			if (nread == 0)
				errno = EIO;
			return (-1);
		}
		offset += (size_t)nread;
	}
	close(fd);
	*datap = data;
	*sizep = offset;
	return (0);
}

static bool
known_top_key(const char *key)
{

	return (strcmp(key, "schema") == 0 ||
	    strcmp(key, "schema_version") == 0 ||
	    strcmp(key, "provider_defaults") == 0 ||
	    strcmp(key, "service_overrides") == 0);
}

int
capbundle_policy_open(const char *path, struct capbundle_policy **pp,
    char *errbuf, size_t errlen)
{
	struct capbundle_policy *policy;
	struct ucl_parser *parser;
	const ucl_object_t *root, *object, *entry, *value, *components, *choice;
	ucl_object_iter_t it, jt, kt;
	unsigned char *data;
	const char *key, *string;
	size_t size;
	unsigned seen_schema, seen_version, seen_defaults, seen_overrides;

	if (path == NULL || pp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*pp = NULL;
	if (read_policy(path, &data, &size, errbuf, errlen) == -1)
		return (-1);
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
	if (parser == NULL) {
		free(data);
		return (-1);
	}
	if (!ucl_parser_add_chunk_full(parser, data, size, 0,
	    UCL_DUPLICATE_ERROR, UCL_PARSE_UCL)) {
		if (errbuf != NULL && errlen != 0)
			snprintf(errbuf, errlen, "%s: %s", path,
			    ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		free(data);
		errno = EINVAL;
		return (-1);
	}
	free(data);
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		ucl_parser_free(parser);
		return (policy_error(errbuf, errlen,
		    "policy root must be an object"));
	}
	seen_schema = 0;
	seen_version = 0;
	seen_defaults = 0;
	seen_overrides = 0;
	it = NULL;
	while ((entry = ucl_object_iterate(root, &it, true)) != NULL) {
		key = ucl_object_key(entry);
		if (key == NULL || !known_top_key(key)) {
			if (errbuf != NULL && errlen != 0)
				snprintf(errbuf, errlen,
				    "policy: unknown key '%s'",
				    key != NULL ? key : "");
			ucl_parser_free(parser);
			errno = EINVAL;
			return (-1);
		}
		if ((strcmp(key, "schema") == 0 && ++seen_schema != 1) ||
		    (strcmp(key, "schema_version") == 0 &&
		    ++seen_version != 1) ||
		    (strcmp(key, "provider_defaults") == 0 &&
		    ++seen_defaults != 1) ||
		    (strcmp(key, "service_overrides") == 0 &&
		    ++seen_overrides != 1)) {
			if (errbuf != NULL && errlen != 0)
				snprintf(errbuf, errlen,
				    "policy: duplicate key '%s'", key);
			ucl_parser_free(parser);
			errno = EINVAL;
			return (-1);
		}
	}
	object = ucl_object_lookup(root, "schema");
	if (object == NULL || ucl_object_type(object) != UCL_STRING ||
	    strcmp(ucl_object_tostring(object),
	    "org.5bsd.serviced.policy") != 0) {
		ucl_parser_free(parser);
		return (policy_error(errbuf, errlen,
		    "policy schema must be 'org.5bsd.serviced.policy'"));
	}
	object = ucl_object_lookup(root, "schema_version");
	if (object == NULL || ucl_object_type(object) != UCL_STRING ||
	    strcmp(ucl_object_tostring(object), "1.0.0") != 0) {
		ucl_parser_free(parser);
		return (policy_error(errbuf, errlen,
		    "policy schema_version must be '1.0.0'"));
	}
	policy = calloc(1, sizeof(*policy));
	if (policy == NULL) {
		ucl_parser_free(parser);
		return (-1);
	}

	object = ucl_object_lookup(root, "provider_defaults");
	if (object != NULL && ucl_object_type(object) != UCL_OBJECT)
		goto bad_defaults;
	it = NULL;
	while (object != NULL &&
	    (entry = ucl_object_iterate(object, &it, true)) != NULL) {
		unsigned i;
		unsigned nprovider, nversion;

		if (policy->ndefaults >= CAPBUNDLE_POLICY_MAX_DEFAULTS)
			goto too_many_defaults;
		key = ucl_object_key(entry);
		if (!valid_name(key, SERVICED_COMPONENT_INTERFACE_MAX) ||
		    ucl_object_type(entry) != UCL_OBJECT)
			goto bad_defaults;
		value = ucl_object_lookup(entry, "version");
		choice = ucl_object_lookup(entry, "provider");
		if (value == NULL || ucl_object_type(value) != UCL_STRING ||
		    !valid_semver(ucl_object_tostring(value)) ||
		    choice == NULL || ucl_object_type(choice) != UCL_STRING ||
		    !valid_name(ucl_object_tostring(choice),
		    SERVICED_COMPONENT_PROVIDER_MAX))
			goto bad_defaults;
		nprovider = 0;
		nversion = 0;
		jt = NULL;
		while ((components = ucl_object_iterate(entry, &jt, true)) != NULL) {
			string = ucl_object_key(components);
			if (string == NULL || (strcmp(string, "version") != 0 &&
			    strcmp(string, "provider") != 0))
				goto bad_defaults;
			if ((strcmp(string, "version") == 0 && ++nversion != 1) ||
			    (strcmp(string, "provider") == 0 &&
			    ++nprovider != 1))
				goto bad_defaults;
		}
		for (i = 0; i < policy->ndefaults; i++)
			if (strcmp(policy->defaults[i].interface, key) == 0 &&
			    strcmp(policy->defaults[i].version,
			    ucl_object_tostring(value)) == 0) {
				string = "duplicate provider_defaults entry";
				goto bad;
			}
		strlcpy(policy->defaults[policy->ndefaults].interface, key,
		    sizeof(policy->defaults[0].interface));
		strlcpy(policy->defaults[policy->ndefaults].version,
		    ucl_object_tostring(value),
		    sizeof(policy->defaults[0].version));
		strlcpy(policy->defaults[policy->ndefaults].provider,
		    ucl_object_tostring(choice),
		    sizeof(policy->defaults[0].provider));
		policy->ndefaults++;
	}

	object = ucl_object_lookup(root, "service_overrides");
	if (object != NULL && ucl_object_type(object) != UCL_OBJECT)
		goto bad_overrides;
	it = NULL;
	while (object != NULL &&
	    (entry = ucl_object_iterate(object, &it, true)) != NULL) {
		const char *service = ucl_object_key(entry);
		unsigned ncomponents;

		if (!valid_name(service, SERVICED_LABEL_MAX) ||
		    ucl_object_type(entry) != UCL_OBJECT)
			goto bad_overrides;
		ncomponents = 0;
		jt = NULL;
		while ((value = ucl_object_iterate(entry, &jt, true)) != NULL) {
			key = ucl_object_key(value);
			if (key == NULL || strcmp(key, "components") != 0 ||
			    ++ncomponents != 1)
				goto bad_overrides;
		}
		components = ucl_object_lookup(entry, "components");
		if (components == NULL ||
		    ucl_object_type(components) != UCL_OBJECT)
			goto bad_overrides;
		jt = NULL;
		choice = ucl_object_iterate(components, &jt, true);
		if (choice == NULL)
			goto bad_overrides;
		do {
			const char *component = ucl_object_key(choice);
			unsigned i;
			unsigned nprovider;

			if (policy->noverrides >=
			    CAPBUNDLE_POLICY_MAX_OVERRIDES)
				goto too_many_overrides;
			if (!valid_name(component, SERVICED_COMPONENT_NAME_MAX) ||
			    ucl_object_type(choice) != UCL_OBJECT)
				goto bad_overrides;
			value = ucl_object_lookup(choice, "provider");
			if (value == NULL || ucl_object_type(value) != UCL_STRING ||
			    !valid_name(ucl_object_tostring(value),
			    SERVICED_COMPONENT_PROVIDER_MAX))
				goto bad_overrides;
			nprovider = 0;
			kt = NULL;
			while ((root = ucl_object_iterate(choice, &kt, true)) != NULL)
				if (ucl_object_key(root) == NULL ||
				    strcmp(ucl_object_key(root), "provider") != 0 ||
				    ++nprovider != 1)
					goto bad_overrides;
			for (i = 0; i < policy->noverrides; i++)
				if (strcmp(policy->overrides[i].service,
				    service) == 0 &&
				    strcmp(policy->overrides[i].component,
				    component) == 0) {
					string = "duplicate service component override";
					goto bad;
				}
			strlcpy(policy->overrides[policy->noverrides].service,
			    service, sizeof(policy->overrides[0].service));
			strlcpy(policy->overrides[policy->noverrides].component,
			    component, sizeof(policy->overrides[0].component));
			strlcpy(policy->overrides[policy->noverrides].provider,
			    ucl_object_tostring(value),
			    sizeof(policy->overrides[0].provider));
			policy->noverrides++;
		} while ((choice = ucl_object_iterate(components, &jt,
		    true)) != NULL);
	}
	ucl_parser_free(parser);
	*pp = policy;
	return (0);

bad_defaults:
	string = "policy provider_defaults entries require only version and provider";
	goto bad;
too_many_defaults:
	string = "policy has too many provider_defaults";
	goto bad;
bad_overrides:
	string = "policy service_overrides entries require components.<name>.provider";
	goto bad;
too_many_overrides:
	string = "policy has too many service component overrides";
bad:
	free(policy);
	ucl_parser_free(parser);
	return (policy_error(errbuf, errlen, string));
}

void
capbundle_policy_close(struct capbundle_policy *policy)
{

	free(policy);
}
