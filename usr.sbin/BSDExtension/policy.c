/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ucl.h>
#include <libservice.h>
#include "bsdextension.h"

struct override {
	char name[SYSEXT_NAME_MAX];
	int permission; /* -1 inherit, 0 deny, 1 allow */
	bool enabled;
};
struct policy_state {
	struct sysext_config base, effective;
	size_t count;
	struct override entries[SYSEXT_MAX_ALLOW];
};
/* Publication switches complete slots, including the administrator overrides. */
struct sysext_policy {
	pthread_mutex_t lock;
	unsigned active;
	int dirfd, fault;
	bool committing;
	struct policy_state slots[2];
};

static int read_state(int, struct policy_state *);
static int resolve(struct policy_state *);
static void publish(struct sysext_policy *, const struct policy_state *);

static int
policy_lock(struct sysext_policy *p)
    __trylocks_exclusive(0, &p->lock) __no_lock_analysis
{
	int error = pthread_mutex_lock(&p->lock);

	if (error == EOWNERDEAD) {
		if (p->committing) {
			struct policy_state recovered = p->slots[p->active];

			recovered.count = 0;
			if (read_state(p->dirfd, &recovered) == -1 ||
			    resolve(&recovered) == -1 || fsync(p->dirfd) == -1)
				p->fault = errno;
			else
				publish(p, &recovered);
			p->committing = false;
		}
		error = pthread_mutex_consistent(&p->lock);
		if (error != 0)
			(void)pthread_mutex_unlock(&p->lock);
	}
	if (error != 0)
		return (errno = error, -1);
	return (0);
}

static bool
safe_name(const char *s)
{
	size_t n = strnlen(s, SYSEXT_NAME_MAX);

	if (n == 0 || n == SYSEXT_NAME_MAX || strcmp(s, ".") == 0 ||
	    strcmp(s, "..") == 0)
		return (false);
	return (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789_.-") == n);
}

static int
index_of(const struct policy_state *s, const char *name)
{
	size_t i;

	for (i = 0; i < s->count; i++)
		if (strcmp(s->entries[i].name, name) == 0)
			return ((int)i);
	return (-1);
}

static bool
allowed(const struct policy_state *s, const char *name)
{
	int i = index_of(s, name);
	size_t j;

	if (i >= 0 && s->entries[i].permission != -1)
		return (s->entries[i].permission == 1);
	for (j = 0; j < s->base.nallow; j++)
		if (strcmp(s->base.allow[j], name) == 0)
			return (true);
	return (false);
}

static int
add_name(struct sysext_config *cfg, const char *name)
{
	size_t i;

	for (i = 0; i < cfg->nallow; i++)
		if (strcmp(cfg->allow[i], name) == 0)
			return (0);
	if (cfg->nallow == SYSEXT_MAX_ALLOW)
		return (errno = ENOSPC, -1);
	strlcpy(cfg->allow[cfg->nallow++], name, SYSEXT_NAME_MAX);
	return (0);
}

static int
resolve(struct policy_state *s)
{
	size_t i;

	memset(&s->effective, 0, sizeof(s->effective));
	for (i = 0; i < s->base.nallow; i++)
		if (allowed(s, s->base.allow[i]) &&
		    add_name(&s->effective, s->base.allow[i]) == -1)
			return (-1);
	for (i = 0; i < s->count; i++)
		if (allowed(s, s->entries[i].name) &&
		    add_name(&s->effective, s->entries[i].name) == -1)
			return (-1);
	return (0);
}

struct sysext_policy *
sysext_policy_create(const struct sysext_config *initial)
{
	struct sysext_policy *p;
	pthread_mutexattr_t attr;
	int error;

	p = mmap(NULL, sizeof(*p), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	if (p == MAP_FAILED)
		return (NULL);
	memset(p, 0, sizeof(*p));
	p->dirfd = -1;
	error = pthread_mutexattr_init(&attr);
	if (error != 0)
		goto fail;
	error = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (error == 0)
		error = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
	if (error == 0)
		error = pthread_mutex_init(&p->lock, &attr);
	(void)pthread_mutexattr_destroy(&attr);
	if (error != 0)
		goto fail;
	p->slots[0].base = p->slots[0].effective = *initial;
	return (p);
fail:
	munmap(p, sizeof(*p));
	return (errno = error, NULL);
}

void
sysext_policy_destroy(struct sysext_policy *p)
{
	if (p->dirfd >= 0)
		close(p->dirfd);
	(void)pthread_mutex_destroy(&p->lock);
	(void)munmap(p, sizeof(*p));
}

int
sysext_policy_snapshot(struct sysext_policy *p, struct sysext_config *out)
{
	int error;

	if (policy_lock(p) != 0)
		return (-1);
	error = p->fault;
	if (error == 0)
		*out = p->slots[p->active].effective;
	(void)pthread_mutex_unlock(&p->lock);
	return (error == 0 ? 0 : (errno = error, -1));
}

static void
publish(struct sysext_policy *p, const struct policy_state *s)
{
	unsigned next = p->active ^ 1;

	p->slots[next] = *s;
	__atomic_store_n(&p->active, next, __ATOMIC_RELEASE);
}

static int
reload(struct sysext_policy *p, const char *path, int fd,
    service_rights_t rights)
{
	struct policy_state candidate;
	int error = 0;

	if (!service_rights_allow(rights, SERVICE_RIGHTS_ADMIN))
		return (errno = EPERM, -1);
	if (policy_lock(p) != 0)
		return (-1);
	candidate = p->slots[p->active];
	if (p->fault != 0)
		error = p->fault;
	else if ((fd >= 0 ? sysext_config_reload_fd(&candidate.base, fd) :
	    sysext_config_reload(&candidate.base, path)) == -1 ||
	    resolve(&candidate) == -1)
		error = errno;
	else
		publish(p, &candidate);
	(void)pthread_mutex_unlock(&p->lock);
	return (error == 0 ? 0 : (errno = error, -1));
}

int
sysext_policy_reload(struct sysext_policy *p, const char *path,
    service_rights_t rights)
{
	return (reload(p, path, -1, rights));
}

int
sysext_policy_reload_fd(struct sysext_policy *p, int fd, service_rights_t rights)
{
	return (reload(p, NULL, fd, rights));
}

/* Strict, versioned UCL.  Never silently discard corrupt administrator state. */
static int
read_state(int dirfd, struct policy_state *s)
{
	struct ucl_parser *parser;
	ucl_object_t *root = NULL;
	const ucl_object_t *array, *obj, *name, *permission, *enabled, *version;
	ucl_object_iter_t it = NULL;
	struct stat st;
	int fd, error = EINVAL;

	fd = openat(dirfd, "overrides.ucl", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1)
		return (errno == ENOENT ? 0 : -1);
	if (fstat(fd, &st) == -1) {
		error = errno;
		goto done;
	}
	if (!S_ISREG(st.st_mode) || st.st_size > 1024 * 1024 ||
	    (st.st_mode & 077) != 0)
		goto done;
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
	if (parser == NULL) {
		error = ENOMEM;
		goto done;
	}
	if (!ucl_parser_add_fd(parser, fd))
		goto parsed;
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT || root->len != 2)
		goto parsed;
	version = ucl_object_lookup(root, "version");
	array = ucl_object_lookup(root, "extensions");
	if (version == NULL || version->next != NULL ||
	    ucl_object_type(version) != UCL_INT || ucl_object_toint(version) != 1 ||
	    array == NULL || array->next != NULL || ucl_object_type(array) != UCL_ARRAY)
		goto parsed;
	while ((obj = ucl_object_iterate(array, &it, true)) != NULL) {
		struct override *entry;
		const char *text;
		int64_t value;

		if (s->count == SYSEXT_MAX_ALLOW ||
		    ucl_object_type(obj) != UCL_OBJECT || obj->len != 3)
			goto parsed;
		name = ucl_object_lookup(obj, "name");
		permission = ucl_object_lookup(obj, "permission");
		enabled = ucl_object_lookup(obj, "enabled");
		if (name == NULL || permission == NULL || enabled == NULL ||
		    name->next != NULL || permission->next != NULL || enabled->next != NULL ||
		    ucl_object_type(name) != UCL_STRING ||
		    ucl_object_type(permission) != UCL_INT ||
		    ucl_object_type(enabled) != UCL_BOOLEAN)
			goto parsed;
		text = ucl_object_tostring(name);
		value = ucl_object_toint(permission);
		if (strlen(text) != name->len || !safe_name(text) || index_of(s, text) >= 0 || value < -1 || value > 1)
			goto parsed;
		entry = &s->entries[s->count++];
		strlcpy(entry->name, text, sizeof(entry->name));
		entry->permission = value;
		entry->enabled = ucl_object_toboolean(enabled);
	}
	error = 0;
parsed:
	if (root != NULL)
		ucl_object_unref(root);
	ucl_parser_free(parser);
done:
	close(fd);
	return (error == 0 ? 0 : (errno = error, -1));
}

int
sysext_policy_attach(struct sysext_policy *p, int dirfd)
{
	struct policy_state candidate;
	int fd, error = 0;

	fd = fcntl(dirfd, F_DUPFD_CLOEXEC, 3);
	if (fd == -1)
		return (-1);
	if (policy_lock(p) != 0) {
		close(fd);
		return (-1);
	}
	if (p->dirfd >= 0) {
		error = EALREADY;
		goto done;
	}
	candidate = p->slots[p->active];
	candidate.count = 0;
	if (read_state(fd, &candidate) == -1 || resolve(&candidate) == -1) {
		error = errno;
		/* A corrupt registry must not silently revert to permissive defaults. */
		p->fault = error;
		goto done;
	}
	publish(p, &candidate);
	p->fault = 0;
	p->dirfd = fd;
	fd = -1;
done:
	(void)pthread_mutex_unlock(&p->lock);
	if (fd >= 0)
		close(fd);
	return (error == 0 ? 0 : (errno = error, -1));
}

/* Serialize, sync, then replace.  Never edit the package's read-only Config. */
static int
persist(struct sysext_policy *p, const struct policy_state *s)
{
	FILE *f;
	size_t i;
	int fd, error = 0;

	/* The policy mutex serializes writers; a stale temporary is safe to remove. */
	if (unlinkat(p->dirfd, "overrides.new", 0) == -1 && errno != ENOENT)
		return (-1);
	fd = openat(p->dirfd, "overrides.new", O_WRONLY | O_CREAT | O_EXCL |
	    O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd == -1)
		return (-1);
	f = fdopen(fd, "w");
	if (f == NULL) {
		error = errno;
		close(fd);
		goto done;
	}
	fprintf(f, "version = 1;\nextensions = [\n");
	for (i = 0; i < s->count; i++)
		fprintf(f, "{name=\"%s\"; permission=%d; enabled=%s;}%s\n",
		    s->entries[i].name, s->entries[i].permission,
		    s->entries[i].enabled ? "true" : "false",
		    i + 1 == s->count ? "" : ",");
	fprintf(f, "];\n");
	if (ferror(f) || fflush(f) == EOF || fsync(fd) == -1)
		error = errno != 0 ? errno : EIO;
	if (fclose(f) == EOF && error == 0)
		error = errno;
	if (error == 0 && renameat(p->dirfd, "overrides.new", p->dirfd,
	    "overrides.ucl") == -1)
		error = errno;
	if (error == 0 && fsync(p->dirfd) == -1) {
		error = errno;
		/* Rename happened, durability is uncertain.  Fail closed until restart. */
		p->fault = error;
	}
done:
	(void)unlinkat(p->dirfd, "overrides.new", 0);
	return (error == 0 ? 0 : (errno = error, -1));
}

int
sysext_policy_change(struct sysext_policy *p, uint32_t op, const char *name,
    service_rights_t rights)
{
	struct policy_state candidate;
	struct override *entry;
	int i, error = 0;

	if (!service_rights_allow(rights, SERVICE_RIGHTS_ADMIN))
		return (errno = EPERM, -1);
	if (name == NULL || !safe_name(name) || op < SYSEXT_OP_ALLOW ||
	    op > SYSEXT_OP_DISABLE)
		return (errno = EINVAL, -1);
	if (policy_lock(p) != 0)
		return (-1);
	if (p->fault != 0 || p->dirfd < 0) {
		error = p->fault != 0 ? p->fault : EAGAIN;
		goto done;
	}
	candidate = p->slots[p->active];
	i = index_of(&candidate, name);
	if (op == SYSEXT_OP_ENABLE && !allowed(&candidate, name)) {
		error = EPERM;
		goto done;
	}
	if (i < 0) {
		if (op == SYSEXT_OP_RESET || op == SYSEXT_OP_DISABLE)
			goto done;
		if (candidate.count == SYSEXT_MAX_ALLOW) {
			error = ENOSPC;
			goto done;
		}
		i = candidate.count++;
		memset(&candidate.entries[i], 0, sizeof(candidate.entries[i]));
		strlcpy(candidate.entries[i].name, name, SYSEXT_NAME_MAX);
		candidate.entries[i].permission = -1;
	}
	entry = &candidate.entries[i];
	switch (op) {
	case SYSEXT_OP_ALLOW: entry->permission = 1; break;
	case SYSEXT_OP_DENY: entry->permission = 0; break;
	case SYSEXT_OP_ENABLE: entry->enabled = true; break;
	case SYSEXT_OP_DISABLE: entry->enabled = false; break;
	case SYSEXT_OP_RESET:
		memmove(entry, entry + 1, (candidate.count - i - 1) * sizeof(*entry));
		candidate.count--;
		break;
	}
	if (resolve(&candidate) == -1) {
		error = errno;
		goto done;
	}
	p->committing = true;
	if (persist(p, &candidate) == -1)
		error = errno;
	else
		publish(p, &candidate);
	p->committing = false;
done:
	(void)pthread_mutex_unlock(&p->lock);
	return (error == 0 ? 0 : (errno = error, -1));
}

int
sysext_policy_info(struct sysext_policy *p, const char *name, bool next,
    struct sysext_info_reply *out)
{
	const struct policy_state *s;
	const char *found = NULL;
	int i, error = 0;
	size_t j;

	memset(out, 0, sizeof(*out));
	if (policy_lock(p) != 0)
		return (-1);
	s = &p->slots[p->active];
	if (p->fault != 0) {
		error = p->fault;
		goto done;
	}
	if (!next)
		found = name;
	else {
		for (j = 0; j < s->base.nallow + s->count; j++) {
			const char *n = j < s->base.nallow ? s->base.allow[j] :
			    s->entries[j - s->base.nallow].name;
			if (strcmp(n, name) > 0 && (found == NULL || strcmp(n, found) < 0))
				found = n;
		}
	}
	if (found == NULL) {
		error = ENOENT;
		goto done;
	}
	strlcpy(out->name, found, sizeof(out->name));
	if (allowed(s, found))
		out->flags |= SYSEXT_STATE_ALLOWED;
	i = index_of(s, found);
	if (i >= 0) {
		out->flags |= SYSEXT_STATE_OVERRIDE;
		if (s->entries[i].enabled)
			out->flags |= SYSEXT_STATE_ENABLED;
	}
	if (p->dirfd >= 0)
		out->flags |= SYSEXT_STATE_READY;
done:
	(void)pthread_mutex_unlock(&p->lock);
	return (error == 0 ? 0 : (errno = error, -1));
}

int
sysext_policy_enabled(struct sysext_policy *p, struct sysext_config *out)
{
	const struct policy_state *s;
	size_t i;
	int error = 0;

	if (policy_lock(p) != 0)
		return (-1);
	memset(out, 0, sizeof(*out));
	s = &p->slots[p->active];
	if (p->fault != 0 || p->dirfd < 0)
		error = p->fault != 0 ? p->fault : EAGAIN;
	else
		for (i = 0; i < s->count; i++)
			if (s->entries[i].enabled && allowed(s, s->entries[i].name))
				(void)add_name(out, s->entries[i].name);
	(void)pthread_mutex_unlock(&p->lock);
	return (error == 0 ? 0 : (errno = error, -1));
}

#ifdef BSDEXTENSION_TESTING
void
sysext_test_policy_abandon(struct sysext_policy *p) __no_lock_analysis
{
	(void)policy_lock(p);
	memset(&p->slots[p->active ^ 1], 0xff, sizeof(p->slots[0]));
}
/* Simulate death after durable replacement but before live publication. */
void
sysext_test_policy_commit_abandon(struct sysext_policy *p) __no_lock_analysis
{
	struct policy_state candidate;
	struct override *entry;

	(void)policy_lock(p);
	candidate = p->slots[p->active];
	entry = &candidate.entries[candidate.count++];
	memset(entry, 0, sizeof(*entry));
	strlcpy(entry->name, "recovered", sizeof(entry->name));
	entry->permission = 1;
	p->committing = true;
	if (persist(p, &candidate) == -1)
		_exit(1);
}
#endif
