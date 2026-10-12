/* SPDX-License-Identifier: BSD-2-Clause */
/* Default-off, issuer-owned common-layout membership for selected daemons. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <capimage.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>
#include "switchboard.h"
#include "library_cache_domain.h"

#define CACHE_POLICY "/Capabilities/Config/switchboard/elf-cache-domain.ucl"
#define CACHE_SEED "/usr/libexec/elfcache-seed"
#define CACHE_MEMBERS_MAX 64
#define CACHE_DOMAINS_MAX 8
struct cache_domain_policy {
	struct svc_cache_domain domain;
	char *members[CACHE_MEMBERS_MAX];
	unsigned nmembers;
};
struct cache_domain_spec {
	const char *layout, *signature;
	char *libraries[CACHE_MEMBERS_MAX];
	unsigned nlibraries;
};
static struct cache_domain_policy *selected;
static unsigned nselected;

static int
seed_generation(int issuer, struct svc_cache_domain *domain, char **libraries,
    unsigned count)
{
	struct cap_authority_spec spec = {.version = CAP_AUTH_VERSION,
	    .kind = CAP_AUTH_MANAGED, .uid = 0};
	struct cap_authority_constraint constraint = {.token_fd = -1, .nexec = 1};
	struct cap_authority_libdirs dirs = {.token_fd = -1};
	struct capimage_policy policy = {0};
	struct stat st;
	char error[256], *args[CACHE_MEMBERS_MAX + 2];
	char path_environment[] = "PATH=/bin:/usr/bin";
	char *environment[] = {path_environment, NULL};
	struct timespec start, now;
	int executable = -1, token = -1, pd = -1, status, result = -1, saved;
	pid_t pid;

	executable = open(CACHE_SEED, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_VERIFY);
	if (executable < 0 || fstat(executable, &st) != 0) goto out;
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
	    capimage_verify(executable, NULL, &policy, error, sizeof(error)) != 0) {
		errno = EAUTH; goto out;
	}
	token = syscall(SYS_cap_process, CAP_AUTH_ISSUE, issuer, 0, &spec);
	if (token < 0) goto out;
	constraint.token_fd = token;
	constraint.executable_fds[0] = executable;
	if (syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, issuer, 0, &constraint) != 0)
		goto out;
	dirs.token_fd = token;
	const char *paths[] = {"/lib", "/usr/lib"};
	for (unsigned i = 0; i < 2; i++) {
		int fd = open(paths[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0) goto out;
		dirs.directory_fds[dirs.count++] = fd;
	}
	if (syscall(SYS_cap_process, CAP_AUTH_SET_LIBDIRS, issuer, 0, &dirs) != 0 ||
	    svc_cache_domain_bind(issuer, domain, token, true) != 0)
		goto out;
	args[0] = __DECONST(char *, CACHE_SEED);
	for (unsigned i = 0; i < count; i++) args[i + 1] = libraries[i];
	args[count + 1] = NULL;
	pid = pdfork(&pd, PD_CLOEXEC | PD_NOWAITPID);
	if (pid < 0) goto out;
	if (pid == 0) {
		/* Install before closing token; retain only the constrained image. */
		if (syscall(SYS_cap_process, CAP_AUTH_INSTALL, token, 0, NULL) != 0 ||
		    dup2(executable, 3) < 0 || fcntl(3, F_SETFD, FD_CLOEXEC) < 0)
			_exit(120);
		closefrom(4);
		if (cap_enter() != 0) _exit(122);
		fexecve(3, args, environment);
		_exit(121);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) goto out;
	for (;;) {
		struct pollfd event = {.fd = pd, .events = POLLHUP};
		int n = poll(&event, 1, 100);
		if (n < 0 && errno != EINTR) goto out;
		if (n > 0 && (event.revents & POLLHUP) != 0) break;
		if (n > 0 && (event.revents & (POLLERR | POLLNVAL)) != 0) { errno = EIO; goto out; }
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) goto out;
		if (now.tv_sec - start.tv_sec >= 30) { errno = ETIMEDOUT; goto out; }
	}
	if (syscall(SYS_pdwait, pd, &status, WEXITED, NULL, NULL) != 0) goto out;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { errno = EIO; goto out; }
	result = svc_cache_domain_publish(issuer, domain);
out:
	saved = errno;
	if (pd >= 0) {
		if (result != 0) (void)pdkill(pd, SIGKILL);
		close(pd);
	}
	if (token >= 0) close(token);
	if (executable >= 0) close(executable);
	for (unsigned i = 0; i < dirs.count; i++) close(dirs.directory_fds[i]);
	capimage_policy_free(&policy);
	errno = saved;
	return (result);
}

static int
string_list(const ucl_object_t *root, const char *key, char **strings, unsigned *count,
    bool basenames)
{
	const ucl_object_t *array = ucl_object_lookup(root, key), *item;
	ucl_object_iter_t iterator = NULL;
	if (array == NULL || ucl_object_type(array) != UCL_ARRAY) return (errno = EINVAL, -1);
	while ((item = ucl_object_iterate(array, &iterator, true)) != NULL) {
		const char *s = ucl_object_tostring(item);
		if (*count == CACHE_MEMBERS_MAX || ucl_object_type(item) != UCL_STRING ||
		    s == NULL || *s == 0 || strlen(s) != item->len ||
		    strlen(s) >= SWITCHBOARD_LABEL_MAX ||
		    (basenames && (strchr(s, '/') != NULL || strcmp(s, ".") == 0 ||
		    strcmp(s, "..") == 0))) return (errno = EINVAL, -1);
		for (unsigned i = 0; i < *count; i++)
			if (strcmp(strings[i], s) == 0) return (errno = EINVAL, -1);
		strings[*count] = strdup(s);
		if (strings[*count] == NULL) return (-1);
		(*count)++;
	}
	return (*count == 0 ? (errno = EINVAL, -1) : 0);
}


static void
close_policies(struct cache_domain_policy *policies, unsigned count)
{
	if (policies == NULL) return;
	for (unsigned i = 0; i < count; i++) {
		svc_cache_domain_close(&policies[i].domain);
		for (unsigned j = 0; j < policies[i].nmembers; j++)
			free(policies[i].members[j]);
	}
	free(policies);
}

/* Reject duplicate/unknown keys before interpreting either syntax. */
static int
policy_keys(const ucl_object_t *object, bool top)
{
	static const char *const keys[] = {
	    "layout", "signature", "services", "libraries", "enabled", "domains"};
	ucl_object_iter_t iterator = NULL;
	const ucl_object_t *entry;
	unsigned seen = 0;

	if (ucl_object_type(object) != UCL_OBJECT) return (errno = EINVAL, -1);
	while ((entry = ucl_object_iterate(object, &iterator, true)) != NULL) {
		unsigned i;
		size_t keylen;
		const char *key = ucl_object_keyl(entry, &keylen);
		for (i = 0; i < (top ? 6U : 4U); i++)
			if (strlen(keys[i]) == keylen &&
			    memcmp(keys[i], key, strlen(keys[i])) == 0) break;
		if (i == (top ? 6U : 4U) || (seen & (1U << i)) != 0 || entry->next != NULL)
			return (errno = EINVAL, -1);
		seen |= 1U << i;
	}
	return (0);
}

static const char *
policy_path(const ucl_object_t *object, const char *key)
{
	const ucl_object_t *value = ucl_object_lookup(object, key);
	const char *path;
	if (value == NULL || ucl_object_type(value) != UCL_STRING) return (NULL);
	path = ucl_object_tostring(value);
	if (path == NULL || path[0] != '/' || strlen(path) != value->len ||
	    strlen(path) >= PATH_MAX) return (NULL);
	return (path);
}

/* No service sees a staged domain until every requested domain is ready.
 * The seed callback is explicit so tests can exercise this transaction without
 * issuing authority or launching a helper. Production always uses seed_generation. */
static int
configure_domains(const ucl_object_t *root, int cache,
    int (*seed)(int, struct svc_cache_domain *, char **, unsigned))
{
	struct cache_domain_policy *pending = NULL;
	struct cache_domain_spec *specs = NULL;
	const ucl_object_t *enabled, *array, *object;
	ucl_object_iter_t iterator = NULL;
	unsigned count = 0, total = 0;
	int result = -1, saved;

	if (policy_keys(root, true) != 0) return (-1);
	array = ucl_object_lookup(root, "domains");
	if (array != NULL && (ucl_object_lookup(root, "layout") != NULL ||
	    ucl_object_lookup(root, "signature") != NULL ||
	    ucl_object_lookup(root, "services") != NULL ||
	    ucl_object_lookup(root, "libraries") != NULL)) return (errno = EINVAL, -1);
	enabled = ucl_object_lookup(root, "enabled");
	if (enabled != NULL && ucl_object_type(enabled) != UCL_BOOLEAN)
		return (errno = EINVAL, -1);
	if (enabled == NULL || !ucl_object_toboolean(enabled)) {
		close_policies(selected, nselected); selected = NULL; nselected = 0;
		return (0);
	}
	if (array != NULL && (ucl_object_type(array) != UCL_ARRAY ||
	    array->len == 0 || array->len > CACHE_DOMAINS_MAX)) return (errno = EINVAL, -1);
	pending = calloc(CACHE_DOMAINS_MAX, sizeof(*pending));
	specs = calloc(CACHE_DOMAINS_MAX, sizeof(*specs));
	if (pending == NULL || specs == NULL) { free(pending); free(specs); return (-1); }
	for (unsigned i = 0; i < CACHE_DOMAINS_MAX; i++)
		pending[i].domain = (struct svc_cache_domain){-1, -1};
	/* Parse the COMPLETE set before creating even the first kernel domain. */
	for (;;) {
		object = array == NULL ? root : ucl_object_iterate(array, &iterator, true);
		if (object == NULL) break;
		if (count == CACHE_DOMAINS_MAX ||
		    (array != NULL && policy_keys(object, false) != 0)) { errno = EINVAL; goto out; }
		struct cache_domain_policy *p = &pending[count];
		struct cache_domain_spec *s = &specs[count];
		s->layout = policy_path(object, "layout");
		s->signature = policy_path(object, "signature");
		if (s->layout == NULL || s->signature == NULL ||
		    string_list(object, "services", p->members, &p->nmembers, false) != 0 ||
		    string_list(object, "libraries", s->libraries, &s->nlibraries, true) != 0) {
			errno = EINVAL; goto out;
		}
		if (p->nmembers > CACHE_MEMBERS_MAX - total) { errno = E2BIG; goto out; }
		total += p->nmembers;
		for (unsigned i = 0; i < count; i++)
			for (unsigned a = 0; a < p->nmembers; a++)
				for (unsigned b = 0; b < pending[i].nmembers; b++)
					if (strcmp(p->members[a], pending[i].members[b]) == 0) {
						errno = EINVAL; goto out;
					}
		count++;
		if (array == NULL) break;
	}
	if (count == 0) { errno = EINVAL; goto out; }
	for (unsigned i = 0; i < count; i++) {
		if (svc_cache_domain_create(sd.authority_issuer_fd, cache,
		    specs[i].layout, specs[i].signature, &pending[i].domain) != 0 ||
		    seed(sd.authority_issuer_fd, &pending[i].domain,
		    specs[i].libraries, specs[i].nlibraries) != 0) goto out;
	}
	close_policies(selected, nselected);
	selected = pending; nselected = count; pending = NULL;
	syslog(LOG_NOTICE, "ELF RELRO %u domains published for %u explicitly selected services", count, total);
	result = 0;
out:
	saved = errno;
	close_policies(pending, CACHE_DOMAINS_MAX);
	for (unsigned i = 0; i < CACHE_DOMAINS_MAX; i++)
		for (unsigned j = 0; j < specs[i].nlibraries; j++) free(specs[i].libraries[j]);
	free(specs); errno = saved;
	return (result);
}

int
svc_library_cache_policy_init(int cache)
{
	struct ucl_parser *parser = NULL;
	ucl_object_t *root = NULL;
	struct stat st;
	int fd, result = -1, saved;

	fd = open(CACHE_POLICY, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) return (errno == ENOENT ? 0 : -1);
	if (fstat(fd, &st) != 0) goto out;
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 || st.st_size > 16384) {
		errno = EPERM; goto out;
	}
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS | UCL_PARSER_DISABLE_MACRO);
	if (parser == NULL || !ucl_parser_add_fd(parser, fd)) { errno = EINVAL; goto out; }
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) { errno = EINVAL; goto out; }
	result = configure_domains(root, cache, seed_generation);
out:
	saved = errno;
	if (root != NULL) ucl_object_unref(root);
	if (parser != NULL) ucl_parser_free(parser);
	close(fd); errno = saved;
	return (result);
}

int
svc_library_cache_policy_bind(const struct svc_runtime *svc, int token)
{
	if (svc->owner_uid != (uid_t)-1) return (0);
	for (unsigned d = 0; d < nselected; d++) {
		for (unsigned i = 0; i < selected[d].nmembers; i++) {
			if (strcmp(svc->manifest.label, selected[d].members[i]) == 0)
				return (svc_cache_domain_bind(sd.authority_issuer_fd,
				    &selected[d].domain, token, false));
		}
	}
	return (0);
}
