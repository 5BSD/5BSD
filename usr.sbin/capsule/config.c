/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * UCL configuration file parser for capsule.
 *
 * Reads /etc/capsule.conf (or a path given with -f) and populates
 * struct capsule_config.  Only an absent default file outside BIP permits defaults.
 * Supplied policy is bounded, data-only, strictly validated and applied atomically.
 */

#include <sys/socket.h>
#include <sys/zfshandle.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include <dev/mac_capability/mac_capability_capprotect_proto.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

#include "claim_parse.h"
#include "config.h"
#include "gates.h"
#include "capsule_ctl.h"

/* UCL keys and strings are length-delimited; reject C-string aliases. */
static bool
cfg_keys(const ucl_object_t *obj, const char *const *keys, size_t count)
{
	const ucl_object_t *v;
	ucl_object_iter_t it = NULL;
	size_t i;

	if (obj == NULL || ucl_object_type(obj) != UCL_OBJECT)
		return (false);
	while ((v = ucl_object_iterate(obj, &it, true)) != NULL) {
		if (v->key == NULL || strlen(v->key) != v->keylen ||
		    v->next != NULL)
			return (false);
		for (i = 0; i < count; i++)
			if (strcmp(v->key, keys[i]) == 0)
				break;
		if (i == count)
			return (false);
	}
	return (true);
}

static bool
cfg_text(const ucl_object_t *obj)
{
	const unsigned char *text;

	if (obj == NULL || ucl_object_type(obj) != UCL_STRING)
		return (false);
	text = (const unsigned char *)ucl_object_tostring(obj);
	if (text == NULL || strlen((const char *)text) != obj->len)
		return (false);
	for (; *text != '\0'; text++)
		if (*text < 0x20 || *text == 0x7f)
			return (false);
	return (true);
}

/*
 * Parse a single UCL network claim object into an ort_net_claim.
 * Returns 0 on success or -1 for an invalid claim. The caller must reject
 * the complete configuration on failure.
 */
int
parse_ucl_net_claim(const ucl_object_t *elem, struct ort_net_claim *nc,
    const char *label)
{
	const ucl_object_t *v;
	const char *s;

	static const char *const keys[] = {
	    "port", "ports", "protocol", "direction", "domain", "address", "prefix"
	};
	static const char *const strings[] = {
	    "protocol", "direction", "domain", "address"
	};

	if (!cfg_keys(elem, keys, nitems(keys)) ||
	    (ucl_object_lookup(elem, "port") != NULL &&
	    ucl_object_lookup(elem, "ports") != NULL))
		return (-1);
	for (size_t i = 0; i < nitems(strings); i++) {
		v = ucl_object_lookup(elem, strings[i]);
		if (v != NULL && !cfg_text(v))
			return (-1);
	}
	v = ucl_object_lookup(elem, "port");
	if (v == NULL)
		v = ucl_object_lookup(elem, "ports");
	if (v != NULL && ucl_object_type(v) == UCL_STRING && !cfg_text(v))
		return (-1);
	memset(nc, 0, sizeof(*nc));
	nc->port_min = 0;
	nc->port_max = UINT16_MAX;

	v = ucl_object_lookup(elem, "port");
	if (v == NULL)
		v = ucl_object_lookup(elem, "ports");
	if (v != NULL) {
		if (parse_port_range_obj(v, &nc->port_min,
		    &nc->port_max) != 0) {
			syslog(LOG_WARNING, "%s: invalid port range", label);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "protocol");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (parse_net_protocol_string(s, &nc->protocol) != 0) {
			syslog(LOG_ERR, "%s: unknown protocol: %s",
			    label, s);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "direction");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "bind") == 0)
			nc->direction = ORT_NET_DIR_BIND;
		else if (strcmp(s, "connect") == 0)
			nc->direction = ORT_NET_DIR_CONNECT;
		else if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->direction = ORT_NET_DIR_ANY;
		else {
			syslog(LOG_ERR, "%s: unknown direction: %s",
			    label, s);
			return (-1);
		}
	}
	if (nc->direction == 0)
		nc->direction = ORT_NET_DIR_BIND;

	nc->domain = AF_INET;
	v = ucl_object_lookup(elem, "domain");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (strcmp(s, "inet") == 0)
			nc->domain = AF_INET;
		else if (strcmp(s, "inet6") == 0)
			nc->domain = AF_INET6;
		else if (strcmp(s, "bluetooth") == 0)
			nc->domain = AF_BLUETOOTH;
		else if (strcmp(s, "*") == 0 || strcmp(s, "any") == 0)
			nc->domain = 0;
		else {
			syslog(LOG_ERR, "%s: unknown domain: %s",
			    label, s);
			return (-1);
		}
	}

	v = ucl_object_lookup(elem, "address");
	if (v != NULL && ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		if (nc->domain == AF_BLUETOOTH) {
			/* BD_ADDR literal or "*"; sets prefix 0 (any) or 48. */
			if (parse_bdaddr_string(s, nc->addr,
			    &nc->prefix) != 0) {
				syslog(LOG_ERR, "%s: invalid bluetooth "
				    "address: %s", label, s);
				return (-1);
			}
		} else {
			int addr_domain = 0;
			if (parse_address_string(s, nc->addr, &nc->prefix,
			    &addr_domain) != 0) {
				syslog(LOG_ERR, "%s: invalid address: %s",
				    label, s);
				return (-1);
			}
			if (addr_domain != 0) {
				if (ucl_object_lookup(elem, "domain") != NULL &&
				    nc->domain != addr_domain)
					return (-1);
				nc->domain = addr_domain;
			}
		}
	}

	v = ucl_object_lookup(elem, "prefix");
	if (v != NULL) {
		int64_t pfx;

		if (ucl_object_type(v) != UCL_INT) {
			syslog(LOG_ERR, "%s: invalid prefix", label);
			return (-1);
		}
		pfx = ucl_object_toint(v);
		if (nc->domain == AF_BLUETOOTH) {
			/* BD_ADDR match is all-or-nothing: 0=any, 48=exact. */
			if (pfx != 0 && pfx != 48) {
				syslog(LOG_ERR, "%s: invalid bluetooth "
				    "prefix: %jd", label, (intmax_t)pfx);
				return (-1);
			}
		} else if (pfx < 0 || pfx > 128 ||
		    (nc->domain == AF_INET && pfx > 32)) {
			syslog(LOG_ERR, "%s: invalid prefix: %jd",
			    label, (intmax_t)pfx);
			return (-1);
		}
		nc->prefix = (uint8_t)pfx;
	}

	return (0);
}

void
config_init_defaults(struct capsule_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->pidfile, CAPSULE_DEFAULT_PIDFILE,
	    sizeof(cfg->pidfile));
	strlcpy(cfg->control_socket, CAPSULE_CTL_SOCK,
	    sizeof(cfg->control_socket));
	cfg->control_socket_mode = CAPSULE_DEFAULT_CTLMODE;

	strlcpy(cfg->service_manager, CAPSULE_DEFAULT_SVC_MANAGER,
	    sizeof(cfg->service_manager));

	/* rc(8) administers Capsule through its root-only control socket. */
	cfg->integrity_flags = CP_SF_PTRACE | CP_SF_WAIT | CP_SF_SCHED |
	    CP_SF_KTRACE | CAPSULE_REQUIRED_INTEGRITY_FLAGS;
}

void
config_free(struct capsule_config *cfg)
{

	free(cfg->storage);
	cfg->storage = NULL;
	cfg->nstorage = 0;
}

int
config_copy(struct capsule_config *dst, const struct capsule_config *src)
{
	struct capsule_config copy;

	if (src->nstorage > CAPSULE_STORAGE_MAX ||
	    (src->nstorage != 0 && src->storage == NULL))
		return (errno = EINVAL, -1);
	if (dst == src)
		return (0);
	copy = *src;
	copy.storage = NULL;
	if (src->nstorage != 0) {
		copy.storage = malloc(src->nstorage * sizeof(*copy.storage));
		if (copy.storage == NULL)
			return (-1);
		memcpy(copy.storage, src->storage,
		    src->nstorage * sizeof(*copy.storage));
	}
	config_free(dst);
	*dst = copy;
	return (0);
}

static int
cfg_string(const ucl_object_t *obj, const char *key,
    char *buf, size_t bufsz)
{
	const ucl_object_t *o;

	o = ucl_object_lookup(obj, key);
	if (o == NULL)
		return (0);
	if (!cfg_text(o) || o->len >= bufsz)
		return (-1);
	strlcpy(buf, ucl_object_tostring(o), bufsz);
	return (0);
}

static int
cfg_mode(const ucl_object_t *root, struct capsule_config *cfg)
{
	const ucl_object_t *o;
	const char *text;
	unsigned mode = 0;

	o = ucl_object_lookup(root, "control_socket_mode");
	if (o == NULL)
		return (0);
	if (!cfg_text(o) || o->len == 0)
		return (-1);
	text = ucl_object_tostring(o);
	for (; *text != '\0'; text++) {
		if (*text < '0' || *text > '7' || mode > 0777)
			return (-1);
		mode = mode * 8 + (*text - '0');
	}
	cfg->control_socket_mode = (mode_t)mode;
	return (0);
}

static const struct {
	const char	*name;
	uint32_t	 flag;
} integrity_cfg_map[] = {
	{ "ptrace",	CP_SF_PTRACE },
	{ "signal",	CP_SF_SIGNAL },
	{ "sigkill",	CP_SF_SIGKILL },
	{ "sigcont",	CP_SF_SIGCONT },
	{ "visible",	CP_SF_VISIBLE },
	{ "wait",	CP_SF_WAIT },
	{ "sched",	CP_SF_SCHED },
	{ "core",	CP_SF_CORE },
	{ "ktrace",	CP_SF_KTRACE },
};

static int
cfg_integrity(const ucl_object_t *root, struct capsule_config *cfg)
{
	const ucl_object_t *sec, *o;
	ucl_object_iter_t it = NULL;
	unsigned i;

	sec = ucl_object_lookup(root, "integrity");
	if (sec == NULL)
		return (0);
	if (ucl_object_type(sec) != UCL_OBJECT)
		return (-1);
	while ((o = ucl_object_iterate(sec, &it, true)) != NULL) {
		if (o->key == NULL || strlen(o->key) != o->keylen ||
		    o->next != NULL || ucl_object_type(o) != UCL_BOOLEAN)
			return (-1);
		for (i = 0; i < nitems(integrity_cfg_map); i++)
			if (strcmp(o->key, integrity_cfg_map[i].name) == 0)
				break;
		if (i == nitems(integrity_cfg_map))
			return (-1);
		if (ucl_object_toboolean(o))
			cfg->integrity_flags |= integrity_cfg_map[i].flag;
		else if ((integrity_cfg_map[i].flag &
		    CAPSULE_REQUIRED_INTEGRITY_FLAGS) != 0)
			fprintf(stderr, "capsule: integrity.%s=false ignored; "
			    "ambient signal protection is mandatory\n", o->key);
		else
			cfg->integrity_flags &= ~integrity_cfg_map[i].flag;
	}
	return (0);
}

static int
cfg_claims(const ucl_object_t *root, struct capsule_config *cfg)
{
	static const char *const keys[] = { "network", "system" };
	const ucl_object_t *sec, *arr, *elem;
	ucl_object_iter_t it;
	unsigned i;

	sec = ucl_object_lookup(root, "claims");
	if (sec == NULL)
		return (0);
	if (!cfg_keys(sec, keys, nitems(keys)))
		return (-1);
	arr = ucl_object_lookup(sec, "network");
	if (arr != NULL) {
		if (ucl_object_type(arr) != UCL_ARRAY)
			return (-1);
		cfg->nclaim_net = 0;
		memset(cfg->claim_net, 0, sizeof(cfg->claim_net));
		memset(cfg->claim_net_source, 0, sizeof(cfg->claim_net_source));
		memset(cfg->claim_net_refcount, 0, sizeof(cfg->claim_net_refcount));
		it = NULL;
		while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
			if (cfg->nclaim_net == CAPSULE_MAX_NET_CLAIMS ||
			    parse_ucl_net_claim(elem,
			    &cfg->claim_net[cfg->nclaim_net], "config") != 0)
				return (-1);
			for (i = 0; i < cfg->nclaim_net; i++)
				if (memcmp(&cfg->claim_net[i],
				    &cfg->claim_net[cfg->nclaim_net],
				    sizeof(cfg->claim_net[i])) == 0)
					return (-1);
			cfg->claim_net_source[cfg->nclaim_net++] = CLAIM_SOURCE_POLICY;
		}
	}
	arr = ucl_object_lookup(sec, "system");
	if (arr != NULL) {
		if (ucl_object_type(arr) != UCL_ARRAY)
			return (-1);
		cfg->claim_system = 0;
		it = NULL;
		while ((elem = ucl_object_iterate(arr, &it, true)) != NULL) {
			if (!cfg_text(elem))
				return (-1);
			for (i = 0; i < nitems(gate_names); i++)
				if (strcmp(ucl_object_tostring(elem), gate_names[i].name) == 0)
					break;
			if (i == nitems(gate_names) ||
			    (cfg->claim_system & gate_names[i].gate) != 0)
				return (-1);
			cfg->claim_system |= gate_names[i].gate;
		}
	}
	cfg->claim_system_policy = cfg->claim_system;
	return (0);
}

/* Canonical, nonempty path components: no aliases, snapshots or shell syntax. */
static bool
storage_components(const char *text, bool slash)
{
	const char *start = text, *p;

	for (p = text;; p++) {
		if (*p == '\0' || (slash && *p == '/')) {
			if (p == start || (p - start == 1 && *start == '.') ||
			    (p - start == 2 && start[0] == '.' && start[1] == '.'))
				return (false);
			if (*p == '\0')
				return (true);
			start = p + 1;
		} else if (!((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
		    *p == '_' || *p == '-' || *p == '.' || *p == ':'))
			return (false);
	}
}


static int
cfg_crypto(const ucl_object_t *root, struct capsule_config *cfg)
{
	const char *separator;

	if (cfg_string(root, "crypto_recipient", cfg->crypto_recipient,
	    sizeof(cfg->crypto_recipient)) != 0)
		return (-1);
	if (cfg->crypto_recipient[0] == '\0')
		return (0);
	separator = strchr(cfg->crypto_recipient, '/');
	return (storage_components(cfg->crypto_recipient, true) &&
	    separator != NULL && strchr(separator + 1, '/') == NULL ? 0 : -1);
}

static int
storage_guid(const ucl_object_t *obj, const char *key, uint64_t *guid)
{
	const ucl_object_t *value = ucl_object_lookup(obj, key);
	const char *text, *p;
	char *end;
	uintmax_t parsed;

	if (!cfg_text(value))
		return (-1);
	text = ucl_object_tostring(value);
	if (*text < '1' || *text > '9')
		return (-1);
	for (p = text; *p != '\0'; p++)
		if (*p < '0' || *p > '9')
			return (-1);
	errno = 0;
	parsed = strtoumax(text, &end, 10);
	if (errno != 0 || *end != '\0' || parsed > UINT64_MAX)
		return (-1);
	*guid = parsed;
	return (0);
}

static bool
storage_beneath(const char *parent, const char *child)
{
	size_t length = strlen(parent);

	return (strncmp(parent, child, length) == 0 && child[length] == '/');
}

static int
storage_devices_compare(const void *a, const void *b)
{

	return (strcmp(a, b));
}

static int
cfg_storage(const ucl_object_t *root, struct capsule_config *cfg)
{
	static const char *const keys[] = {
    "recipient", "pool", "pool_guid", "dataset", "dataset_guid", "devices", "rights"
	};
	static const char *const required[] = {
	    "pool", "pool_guid", "dataset", "dataset_guid", "devices", "rights"
	};
	static const struct { const char *name; uint64_t bit; } rights[] = {
	    {"props_read", ZH_PROPS_READ}, {"props_write", ZH_PROPS_WRITE},
	    {"snapshot", ZH_SNAPSHOT}, {"snap_destroy", ZH_SNAP_DESTROY},
	    {"rollback", ZH_ROLLBACK}, {"clone_src", ZH_CLONE_SRC},
	    {"create", ZH_CREATE}, {"destroy", ZH_DESTROY},
	    {"send", ZH_SEND}, {"recv", ZH_RECV}, {"mount", ZH_MOUNT},
	    {"hold", ZH_HOLD}, {"event", ZH_EVENT}, {"scrub", ZH_SCRUB},
	    {"rename", ZH_RENAME}, {"promote", ZH_PROMOTE},
	    {"bookmark", ZH_BOOKMARK}, {"release", ZH_RELEASE}
	};
	const ucl_object_t *array, *obj, *value, *item;
	ucl_object_iter_t it = NULL, values;
	struct capsule_storage *s, *prior;
	unsigned i;
	const char *text, *separator;

	array = ucl_object_lookup(root, "storage");
	if (array == NULL)
		return (0);
	if (ucl_object_type(array) != UCL_ARRAY)
		return (-1);
	if (ucl_array_size(array) > CAPSULE_STORAGE_MAX)
		return (errno = E2BIG, -1);
	config_free(cfg);
	if (ucl_array_size(array) != 0) {
		cfg->storage = calloc(ucl_array_size(array), sizeof(*cfg->storage));
		if (cfg->storage == NULL)
			return (-1);
	}
	while ((obj = ucl_object_iterate(array, &it, true)) != NULL) {
		if (cfg->nstorage == CAPSULE_STORAGE_MAX ||
		    !cfg_keys(obj, keys, nitems(keys)))
			return (-1);
		for (i = 0; i < nitems(required); i++)
			if (ucl_object_lookup(obj, required[i]) == NULL)
				return (-1);
		s = &cfg->storage[cfg->nstorage];
		if (cfg_string(obj, "recipient", s->recipient, sizeof(s->recipient)) ||
		    cfg_string(obj, "pool", s->pool, sizeof(s->pool)) ||
		    cfg_string(obj, "dataset", s->dataset, sizeof(s->dataset)) ||
		    storage_guid(obj, "pool_guid", &s->pool_guid) ||
		    storage_guid(obj, "dataset_guid", &s->dataset_guid))
			return (-1);
		if (s->recipient[0] != '\0') {
			separator = strchr(s->recipient, '/');
			if (!storage_components(s->recipient, true) || separator == NULL ||
			    strchr(separator + 1, '/') != NULL)
				return (-1);
		} else {
			return (-1);
		}
		if (!storage_components(s->pool, false) ||
		    !storage_components(s->dataset, true) ||
		    !storage_beneath(s->pool, s->dataset))
			return (-1);
		value = ucl_object_lookup(obj, "devices");
		if (ucl_object_type(value) != UCL_ARRAY)
			return (-1);
		values = NULL;
		while ((item = ucl_object_iterate(value, &values, true)) != NULL) {
			if (s->ndevices == CAPSULE_STORAGE_DEVICES_MAX || !cfg_text(item) ||
			    item->len >= sizeof(s->devices[0]))
				return (-1);
			text = ucl_object_tostring(item);
			if (strncmp(text, "/dev/", 5) != 0 ||
			    !storage_components(text + 5, true))
				return (-1);
			for (i = 0; i < s->ndevices; i++)
				if (strcmp(text, s->devices[i]) == 0)
					return (-1);
			strlcpy(s->devices[s->ndevices++], text, sizeof(s->devices[0]));
		}
		if (s->ndevices == 0)
			return (-1);
		qsort(s->devices, s->ndevices, sizeof(s->devices[0]), storage_devices_compare);
		value = ucl_object_lookup(obj, "rights");
		if (ucl_object_type(value) != UCL_ARRAY)
			return (-1);
		values = NULL;
		while ((item = ucl_object_iterate(value, &values, true)) != NULL) {
			if (!cfg_text(item))
				return (-1);
			for (i = 0; i < nitems(rights); i++)
				if (strcmp(ucl_object_tostring(item), rights[i].name) == 0)
					break;
			if (i == nitems(rights) || (s->rights & rights[i].bit) != 0)
				return (-1);
			s->rights |= rights[i].bit;
		}
		if ((s->rights & ZH_IMPLICIT_RIGHTS) != ZH_IMPLICIT_RIGHTS)
			return (-1);
		for (i = 0; i < cfg->nstorage; i++) {
			prior = &cfg->storage[i];
			if (s->recipient[0] != '\0' &&
			    strcmp(prior->recipient, s->recipient) == 0)
				return (-1);
			if (prior->pool_guid == s->pool_guid || strcmp(prior->pool, s->pool) == 0) {
				if (prior->pool_guid != s->pool_guid || strcmp(prior->pool, s->pool) != 0 ||
				    prior->ndevices != s->ndevices ||
				    memcmp(prior->devices, s->devices, sizeof(s->devices)) != 0 ||
				    prior->dataset_guid == s->dataset_guid ||
				    strcmp(prior->dataset, s->dataset) == 0)
					return (-1);
				/* Keep independent delegated dataset scopes disjoint. */
				if (storage_beneath(prior->dataset, s->dataset) ||
				    storage_beneath(s->dataset, prior->dataset))
					return (-1);
			}
		}
		cfg->nstorage++;
	}
	return (0);
}

/* Match rc.d/hostid: the first four bytes of MD5(canonical UUID), in
 * network byte order. This is ZFS host coordination, not cryptographic identity.
 * Deployment supplies a stable UUID; neither hardware nor root-writable files
 * may silently choose a different value for authenticated boot policy. */
bool
config_hostid(const char *uuid, unsigned long *id)
{
	MD5_CTX context;
	unsigned char digest[MD5_DIGEST_LENGTH];
	unsigned i;

	if (uuid == NULL || id == NULL || strlen(uuid) != 36 ||
	    strcmp(uuid, "00000000-0000-0000-0000-000000000000") == 0)
		return (false);
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (uuid[i] != '-')
				return (false);
		} else if (!((uuid[i] >= '0' && uuid[i] <= '9') ||
		    (uuid[i] >= 'a' && uuid[i] <= 'f')))
			return (false);
	}
	MD5Init(&context);
	MD5Update(&context, uuid, 36);
	MD5Final(digest, &context);
	*id = ((unsigned long)digest[0] << 24) |
	    ((unsigned long)digest[1] << 16) |
	    ((unsigned long)digest[2] << 8) | digest[3];
	return (*id != 0);
}

bool
config_boot_policy_equal(const struct capsule_config *a, const struct capsule_config *b)
{
	unsigned i, j;

	if (strcmp(a->hostuuid, b->hostuuid) != 0 ||
	    strcmp(a->crypto_recipient, b->crypto_recipient) != 0 ||
	    a->nstorage != b->nstorage)
		return (false);
	for (i = 0; i < a->nstorage; i++) {
		for (j = 0; j < b->nstorage; j++)
			if (memcmp(&a->storage[i], &b->storage[j], sizeof(a->storage[i])) == 0)
				break;
		if (j == b->nstorage)
			return (false);
	}
	return (true);
}

/* Maximum config file size (1 MB). */
#define	CONFIG_MAX_UCL_SIZE	(1024 * 1024)

/* Consumes fd, including on failure. No partial policy is installed. */
int
config_load_fd(struct capsule_config *cfg, int fd)
{
	static const char *const keys[] = {
	    "pidfile", "control_socket", "control_socket_mode", "service_manager",
	    "integrity", "claims", "storage", "hostuuid", "crypto_recipient"
	};
	struct capsule_config candidate = {0};
	struct ucl_parser *parser = NULL;
	ucl_object_t *root = NULL;
	struct stat st, after;
	unsigned char *text = NULL, extra;
	unsigned long hostid;
	size_t offset = 0;
	ssize_t n;
	int error = EINVAL, result = -1;

	if (cfg == NULL || fd < 0)
		goto out;
	if (fstat(fd, &st) == -1) {
		error = errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
	    st.st_size > CONFIG_MAX_UCL_SIZE || (st.st_mode & 022) != 0 ||
	    (st.st_uid != 0 && st.st_uid != geteuid()))
		goto out;
	text = malloc((size_t)st.st_size + 1);
	if (text == NULL) {
		error = ENOMEM;
		goto out;
	}
	while (offset < (size_t)st.st_size) {
		n = pread(fd, text + offset, (size_t)st.st_size - offset, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto out;
		offset += n;
	}
	do {
		n = pread(fd, &extra, 1, st.st_size);
	} while (n < 0 && errno == EINTR);
	if (n != 0 || memchr(text, '\0', offset) != NULL ||
	    fstat(fd, &after) == -1 || after.st_size != st.st_size ||
	    after.st_mode != st.st_mode || after.st_uid != st.st_uid ||
	    after.st_gid != st.st_gid ||
	    timespeccmp(&after.st_mtim, &st.st_mtim, !=) ||
	    timespeccmp(&after.st_ctim, &st.st_ctim, !=))
		goto out;
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS | UCL_PARSER_DISABLE_MACRO |
	    UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL) {
		error = ENOMEM;
		goto out;
	}
	if (!ucl_parser_add_chunk_full(parser, text, offset, 0,
	    UCL_DUPLICATE_ERROR, UCL_PARSE_UCL))
		goto out;
	root = ucl_parser_get_object(parser);
	/* Empty/comment-only files are an explicit request for defaults. */
	if (config_copy(&candidate, cfg) != 0) {
		error = errno;
		goto out;
	}
	if (root != NULL &&
	    (!cfg_keys(root, keys, nitems(keys)) ||
	    cfg_string(root, "pidfile", candidate.pidfile, sizeof(candidate.pidfile)) ||
	    cfg_string(root, "control_socket", candidate.control_socket,
	    sizeof(candidate.control_socket)) ||
	    cfg_string(root, "service_manager", candidate.service_manager,
	    sizeof(candidate.service_manager)) ||
	    cfg_mode(root, &candidate) || cfg_integrity(root, &candidate) ||
	    cfg_claims(root, &candidate) || cfg_storage(root, &candidate) ||
	    cfg_crypto(root, &candidate) ||
	    cfg_string(root, "hostuuid", candidate.hostuuid, sizeof(candidate.hostuuid))))
		goto out;
	if ((candidate.nstorage != 0 || candidate.hostuuid[0] != '\0' ||
	    (root != NULL && ucl_object_lookup(root, "hostuuid") != NULL)) &&
	    !config_hostid(candidate.hostuuid, &hostid))
		goto out;
	candidate.integrity_flags |= CAPSULE_REQUIRED_INTEGRITY_FLAGS;
	candidate.loaded_from_file = true;
	config_free(cfg);
	*cfg = candidate;
	candidate.storage = NULL;
	result = 0;
out:
	config_free(&candidate);
	if (root != NULL)
		ucl_object_unref(root);
	if (parser != NULL)
		ucl_parser_free(parser);
	free(text);
	if (fd >= 0)
		close(fd);
	if (result != 0)
		errno = error;
	return (result);
}

int
config_load(struct capsule_config *cfg, const char *path)
{
	int fd, error;

	if (cfg == NULL || path == NULL)
		return (errno = EINVAL, -1);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd == -1) {
		if (errno == ENOENT &&
		    strcmp(path, CAPSULE_DEFAULT_CONFFILE) == 0)
			return (0);
		return (-1);
	}
	if (config_load_fd(cfg, fd) == 0)
		return (0);
	error = errno;
	fprintf(stderr, "capsule: invalid configuration: %s: %s\n", path,
	    strerror(error));
	return (errno = error, -1);
}

void
config_log(const struct capsule_config *cfg)
{

	if (cfg->loaded_from_file)
		syslog(LOG_INFO, "config: loaded from file");
	else
		syslog(LOG_INFO, "config: using defaults");
	syslog(LOG_INFO, "config: pidfile=%s", cfg->pidfile);
	syslog(LOG_INFO, "config: control_socket=%s mode=%04o",
	    cfg->control_socket, cfg->control_socket_mode);
	syslog(LOG_INFO, "config: integrity_flags=0x%x", cfg->integrity_flags);
	syslog(LOG_INFO, "config: claims network=%d system=0x%x",
	    cfg->nclaim_net, cfg->claim_system);
}
