/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Issued authority registry. Routes never contain grants: each request is
 * resolved from the kernel's sender stamp. The table is confined to the
 * SwitchBoard event thread; no parser, filesystem lookup or NSS call occurs
 * during admission. Policy is resolved once, before issuing a grant.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <channel.h>
#include <libcapbundle.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>

#include "switchboard.h"
#include "authority.h"
#include "fd_budget.h"

#define AUTH_BUCKETS 1024
#define AUTH_MAX_RECORDS 8192
#define AUTH_PENDING_SECONDS 60

struct authority_record {
	struct authority_record *next;
	uint64_t issuer, identity;
	unsigned kind;
	uid_t uid;
	int token;
	time_t created;
	struct svc_domain domain;
	char label[SWITCHBOARD_LABEL_MAX];
	uint64_t launch_id;
	bool application, retained;
	dev_t image_dev;
	ino_t image_ino;
	/* Only the static rc bootstrap runtime lives outside the service array. */
	struct svc_runtime *boot_owner;
	const struct svc_authority_scope *scope;
};
static struct authority_record *records[AUTH_BUCKETS];
static size_t nrecords;
static unsigned collect_bucket;

static int
authority_call(int op, int fd, void *data)
{
	return (syscall(SYS_cap_process, op, fd, 0, data));
}
/* Only the issuer selects loader directories; no LD_* input is consulted. */
static int
set_loader_directories(const struct svc_manifest *m, int token, bool private_libraries)
{
	struct cap_authority_libdirs request = { .token_fd = token };
	struct stat st;
	char private[PATH_MAX], *slash;
	const char *paths[CAP_AUTH_LIBDIR_MAX] = { "/lib", "/usr/lib", NULL };
	int result = -1, saved;

	if (strlcpy(private, m->program, sizeof(private)) >= sizeof(private))
		return (errno = ENAMETOOLONG, -1);
	slash = strrchr(private, '/');
	if (private_libraries && slash != NULL) {
		*slash = '\0';
		slash = strrchr(private, '/');
		if (slash != NULL && strcmp(slash, "/bin") == 0) {
			/* bin and lib have equal length, including their terminator. */
			memcpy(slash, "/lib", sizeof("/lib"));
			paths[2] = private;
		}
	}
	for (unsigned i = 0; i < CAP_AUTH_LIBDIR_MAX && paths[i] != NULL; i++) {
		int fd = open(paths[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC |
		    O_NOFOLLOW);
		if (fd == -1) {
			if (i == 2 && errno == ENOENT)
				break;
			goto out;
		}
		request.directory_fds[request.count++] = fd;
		if (fstat(fd, &st) == -1)
			goto out;
		if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
			errno = EPERM;
			goto out;
		}
	}
	result = authority_call(CAP_AUTH_SET_LIBDIRS, sd.authority_issuer_fd,
	    &request);
out:
	saved = errno;
	for (unsigned i = 0; i < request.count; i++)
		close(request.directory_fds[i]);
	errno = saved;
	return (result);
}

/* Image policy names executable objects; no authentication program is special. */
int
svc_authority_constrain_application(const struct svc_runtime *svc, int token)
{
	struct cap_authority_constraint constraint = {
	    .token_fd = token };
	const struct svc_manifest *m = &svc->manifest;
	struct stat st;
	unsigned i, opened = 0;
	int result = -1, saved;
	uid_t image_owner = svc->owner_uid == (uid_t)-1 ? 0 : svc->owner_uid;

	/* User-owned units receive an identity for their supervised process,
	 * never software grants from their writable manifest. Pin that image
	 * only after checking the effective confinement, and use system libraries. */
	if (svc->owner_uid != (uid_t)-1 &&
	    (svc->domain.kind != SVC_DOMAIN_USER || svc->domain.anoint.n != 0 ||
	    svc->domain.anoint.all || svc->domain.anoint.admin_rights ||
	    m->nanointments != 0 || m->cap_system != 0 || m->ambient))
		return (errno = EPERM, -1);

	constraint.nexec = 1;
	for (i = 0; i < constraint.nexec; i++) {
		const char *path = m->program;
		constraint.executable_fds[i] = open(path,
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_VERIFY);
		if (constraint.executable_fds[i] < 0)
			goto out;
		opened++;
		if (fstat(constraint.executable_fds[i], &st) == -1)
			goto out;
		if (!S_ISREG(st.st_mode) || st.st_uid != image_owner ||
		    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
		    (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
			errno = EPERM;
			goto out;
		}
	}
	result = authority_call(CAP_AUTH_CONSTRAIN, sd.authority_issuer_fd,
	    &constraint);
	if (result == 0)
		result = set_loader_directories(m, token, svc->owner_uid == (uid_t)-1);
out:
	saved = errno;
	for (i = 0; i < opened; i++)
		close(constraint.executable_fds[i]);
	errno = saved;
	return (result);
}

static unsigned
bucket(uint64_t issuer, uint64_t identity)
{
	uint64_t value = issuer ^ identity;

	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	return ((unsigned)value & (AUTH_BUCKETS - 1));
}
static struct authority_record *
find(uint64_t issuer, uint64_t identity)
{
	struct authority_record *r;

	for (r = records[bucket(issuer, identity)]; r != NULL; r = r->next)
		if (r->issuer == issuer && r->identity == identity)
			return (r);
	return (NULL);
}
static time_t
monotonic_seconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		abort();
	return (now.tv_sec);
}
static void
remove_record(struct authority_record **link)
{
	struct authority_record *r = *link;
	struct cap_authority_revoke revoke = { .token_fd = r->token };

	(void)authority_call(CAP_AUTH_REVOKE, sd.authority_issuer_fd, &revoke);
	*link = r->next;
	close(r->token);
	free(r);
	nrecords--;
}

/* Bounded maintenance work, never a full table scan on every request. */
void
svc_authority_collect(void)
{
	struct authority_record **link, *r;
	struct cap_authority_info info;
	time_t now = monotonic_seconds();
	unsigned i;

	for (i = 0; i < 16; i++) {
		link = &records[collect_bucket++ % AUTH_BUCKETS];
		while ((r = *link) != NULL) {
			if (authority_call(CAP_AUTH_TOKEN_INFO, r->token, &info) == -1 ||
			    info.revoked || (info.consumed && info.references == 1) ||
			    (!info.consumed && now - r->created >= AUTH_PENDING_SECONDS))
				remove_record(link);
			else
				link = &r->next;
		}
	}
}

static int
issue_record(uid_t uid, struct svc_domain *domain,
    const struct svc_runtime *svc, const char *application, int *out)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED, .uid = uid,
	};
	struct cap_authority_info info;
	struct authority_record *r;
	cap_rights_t rights;
	int grant, saved;
	unsigned h;

	*out = -1;
	if (sd.authority_issuer_fd < 0 || domain == NULL ||
	    (svc == NULL && application == NULL) ||
	    (svc != NULL && (application != NULL || svc->launch_id == 0)))
		return (errno = EINVAL, -1);
	svc_authority_collect();
	if (nrecords >= AUTH_MAX_RECORDS)
		return (errno = ENOSPC, -1);
	if (switchboard_fd_budget_check(2,
	    "issued authority") == -1)
		return (-1);
	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (-1);
	r->token = -1;
	grant = authority_call(CAP_AUTH_ISSUE, sd.authority_issuer_fd, &spec);
	if (grant < 0)
		goto fail;
	if (authority_call(CAP_AUTH_TOKEN_INFO, grant, &info) == -1)
		goto fail;
	r->token = fcntl(grant, F_DUPFD_CLOEXEC, 0);
	if (r->token < 0 ||
	    cap_rights_limit(r->token, cap_rights_init(&rights, CAP_FSTAT)) == -1 ||
	    cap_xfer_limit(r->token, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(r->token, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(r->token, CAP_CLOEXEC_LOCKED) == -1)
		goto fail;
	r->issuer = info.issuer;
	r->identity = info.identity;
	r->kind = CAP_AUTH_MANAGED;
	r->uid = uid;
	r->created = monotonic_seconds();
	r->domain = *domain;
	r->domain.authority_issuer = info.issuer;
	r->domain.authority_identity = info.identity;
	*domain = r->domain;
	if (svc != NULL) {
		strlcpy(r->label, svc->manifest.label, sizeof(r->label));
		r->launch_id = svc->launch_id;
	}
	if (application != NULL) {
		r->application = true;
		strlcpy(r->label, application, sizeof(r->label));
	}
	h = bucket(r->issuer, r->identity);
	r->next = records[h];
	records[h] = r;
	nrecords++;
	*out = grant;
	return (0);
fail:
	saved = errno;
	if (r->token >= 0)
		close(r->token);
	if (grant >= 0)
		close(grant);
	free(r);
	return (errno = saved, -1);
}

int
svc_authority_issue(uid_t uid, struct svc_domain *domain,
    const struct svc_runtime *svc, int *out)
{
	return (issue_record(uid, domain, svc, NULL, out));
}

/* Exec policies are not runtime service slots and never own provider names. */
struct application_policy {
	struct application_policy *next;
	struct svc_domain domain;
	char label[SWITCHBOARD_LABEL_MAX];
	int image;
	dev_t dev;
	ino_t ino;
	struct authority_record *retained;
};

static void
remove_application_record(struct authority_record *r)
{
	struct authority_record **link = &records[bucket(r->issuer, r->identity)];

	while (*link != NULL && *link != r)
		link = &(*link)->next;
	if (*link != NULL)
		remove_record(link);
}

int
svc_authority_applications_sync(void)
{
	struct application_policy *policies = NULL, *a, *other;
	struct authority_record *r, **link;
	struct capbundle *bundle;
	struct capbundle_service *unit;
	struct svc_manifest *m;
	struct stat st;
	struct cap_authority_constraint constraint;
	struct cap_authority_application registration;
	unsigned count = 0;
	int grant, error = 0, saved;

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return (-1);
	/* Validate all inputs before altering the last accepted catalogue. */
	for (unsigned bi = 0; bi < bundle_registry_count(); bi++) {
		bundle = bundle_registry_get(bi);
		if (bundle == NULL)
			continue;
		for (unsigned si = 0; si < capbundle_nservices(bundle); si++) {
			unit = capbundle_service(bundle, si);
			if (!capbundle_svc_activates_on_exec(unit))
				continue;
			/* A user's writable agent tree cannot confer software attributes. */
			if (bundle_registry_owner_uid(bi) != (uid_t)-1) {
				errno = EPERM;
				goto invalid;
			}
			if (++count > 4096) {
				errno = E2BIG;
				goto invalid;
			}
			memset(m, 0, sizeof(*m));
			if (capbundle_svc_fill_manifest(unit, m) == -1 ||
			    switchboard_fd_budget_check(3, "application catalogue") == -1)
				goto invalid;
			a = calloc(1, sizeof(*a));
			if (a == NULL)
				goto invalid;
			a->image = -1;
			a->next = policies;
			policies = a;
			strlcpy(a->label, m->label, sizeof(a->label));
			a->image = open(m->program, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_VERIFY);
			if (a->image < 0 || fstat(a->image, &st) == -1)
				goto invalid;
			if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
			    (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
			    (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
				errno = EPERM;
				goto invalid;
			}
			a->dev = st.st_dev;
			a->ino = st.st_ino;
			for (other = a->next; other != NULL; other = other->next) {
				if ((other->dev == a->dev && other->ino == a->ino) ||
				    strcmp(other->label, a->label) == 0) {
					errno = EEXIST;
					goto invalid;
				}
			}
			a->domain.uid = (uid_t)-1;
			a->domain.kind = m->domain == SVC_MANIFEST_DOMAIN_SYSTEM ||
			    (m->domain == SVC_MANIFEST_DOMAIN_DEFAULT &&
			    bundle_registry_is_system(bi)) ? SVC_DOMAIN_SYSTEM : SVC_DOMAIN_USER;
			svc_anoint_set_from_manifest(&a->domain.anoint, m);
		}
	}
	/* Preserve unchanged contexts and their already-bound endpoints. */
	for (unsigned h = 0; h < AUTH_BUCKETS; h++) {
		for (r = records[h]; r != NULL; r = r->next) {
			if (!r->application)
				continue;
			r->retained = false;
			for (a = policies; a != NULL; a = a->next) {
				if (strcmp(r->label, a->label) == 0 &&
				    r->image_dev == a->dev && r->image_ino == a->ino &&
				    r->domain.kind == a->domain.kind &&
				    memcmp(&r->domain.anoint, &a->domain.anoint,
				    sizeof(r->domain.anoint)) == 0) {
					r->retained = true;
					a->retained = r;
					break;
				}
			}
		}
	}
	/* Revocation precedes replacement: failure cannot preserve removed grants. */
	for (unsigned h = 0; h < AUTH_BUCKETS; h++) {
		link = &records[h];
		while ((r = *link) != NULL) {
			if (r->application && !r->retained)
				remove_record(link);
			else
				link = &r->next;
		}
	}
	for (a = policies; a != NULL; a = a->next) {
		if (a->retained != NULL)
			continue;
		if (issue_record((uid_t)-1, &a->domain, NULL, a->label, &grant) == -1) {
			error = errno;
			continue;
		}
		r = find(a->domain.authority_issuer, a->domain.authority_identity);
		memset(&constraint, 0, sizeof(constraint));
		constraint.token_fd = grant;
		constraint.nexec = 1;
		constraint.executable_fds[0] = a->image;
		registration = (struct cap_authority_application){ grant, 0 };
		if (authority_call(CAP_AUTH_CONSTRAIN, sd.authority_issuer_fd,
		    &constraint) == -1 ||
		    authority_call(CAP_AUTH_REGISTER_APP, sd.authority_issuer_fd,
		    &registration) == -1) {
			error = errno;
			remove_application_record(r);
		} else {
			r->image_dev = a->dev;
			r->image_ino = a->ino;
		}
		close(grant);
	}
	goto out;
invalid:
	error = errno;
out:
	saved = error;
	while ((a = policies) != NULL) {
		policies = a->next;
		if (a->image >= 0)
			close(a->image);
		free(a);
	}
	free(m);
	if (saved != 0) {
		syslog(LOG_ERR, "application catalogue update failed: %s", strerror(saved));
		return (errno = saved, -1);
	}
	return (0);
}

int
svc_authority_resolve(const struct channel_message *request,
    struct svc_domain *domain, struct svc_runtime **svc)
{
	const struct cap_authority_stamp *stamp;
	struct authority_record *r;
	struct svc_runtime *owner = NULL;

	/* Anonymous callers may discover public endpoints, but have no grants. */
	memset(domain, 0, sizeof(*domain));
	domain->kind = SVC_DOMAIN_USER;
	domain->uid = (uid_t)-1;
	*svc = NULL;
	stamp = channel_message_authority(request);
	if (stamp == NULL)
		return (0);
	r = find(stamp->issuer, stamp->identity);
	if (r == NULL || stamp->kind != r->kind || stamp->uid != r->uid ||
	    stamp->generation == 0)
		return (errno = EACCES, -1);
	if (r->kind == CAP_AUTH_MANAGED && !r->application) {
		owner = r->boot_owner != NULL ? r->boot_owner : svc_by_label(r->label);
		if (owner == NULL || owner->launch_id != r->launch_id)
			return (errno = EACCES, -1);
	}
	*domain = r->domain;
	*svc = owner;
	return (0);
}

const char *
svc_authority_label(const struct svc_domain *domain)
{
	struct authority_record *r;

	if (domain == NULL || domain->authority_identity == 0)
		return (SVC_SESSION_LABEL);
	r = find(domain->authority_issuer, domain->authority_identity);
	return (r != NULL ? r->label : SVC_SESSION_LABEL);
}

int
svc_authority_bind(const struct svc_domain *domain, int fd)
{
	struct authority_record *r;
	struct cap_authority_bind binding = { .capability_fd = fd };

	if (domain == NULL || domain->authority_identity == 0)
		return (errno = EACCES, -1);
	r = find(domain->authority_issuer, domain->authority_identity);
	if (r == NULL)
		return (errno = EACCES, -1);
	binding.token_fd = r->token;
	return (authority_call(CAP_AUTH_BIND, sd.authority_issuer_fd, &binding));
}

void
svc_authority_revoke_unit(const struct svc_runtime *svc)
{
	struct authority_record **link, *r;
	unsigned h;

	for (h = 0; h < AUTH_BUCKETS; h++) {
		link = &records[h];
		while ((r = *link) != NULL) {
			if (!r->application && r->kind == CAP_AUTH_MANAGED &&
			    r->launch_id == svc->launch_id &&
			    strcmp(r->label, svc->manifest.label) == 0)
				remove_record(link);
			else
				link = &r->next;
		}
	}
}
void
svc_authority_teardown(void)
{
	unsigned h;

	for (h = 0; h < AUTH_BUCKETS; h++)
		while (records[h] != NULL)
			remove_record(&records[h]);
}

int
svc_authority_issue_boot(struct svc_runtime *svc, int *out)
{
	const struct svc_authority_scope *scope;
	struct authority_record *r;

	*out = -1;
	if (svc_authority_boot_policy(&svc->domain, &scope) == -1 ||
	    svc_authority_issue(0, &svc->domain, svc, out) == -1)
		return (-1);
	r = find(svc->domain.authority_issuer, svc->domain.authority_identity);
	r->boot_owner = svc;
	r->scope = scope;
	return (0);
}
bool
svc_authority_permits(const struct svc_domain *domain, const char *name)
{
	struct authority_record *r;

	if (domain == NULL || domain->authority_identity == 0)
		return (true); /* Anonymous visibility is checked by normal admission. */
	r = find(domain->authority_issuer, domain->authority_identity);
	if (r == NULL)
		return (false);
	if (r->scope == NULL)
		return (true);
	for (unsigned i = 0; i < r->scope->count; i++)
		if (strcmp(r->scope->endpoints[i], name) == 0)
			return (true);
	return (false);
}
