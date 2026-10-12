/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.SystemExtension client over bsd.extension.v1 (extensioncmp.fidl):
 * the process-wide service_ensure_extension(3), service_extension_stat(3) and
 * service_extension_list(3), and explicit extensioncmp_session(3) sessions.
 *
 * A session is opened by name and negotiated with GetProtocolInfo on first
 * use.  Application errors keep it.  A transport failure, timeout or
 * malformed reply ends it: the process-wide session is then dropped and the
 * next call opens a new one (which also replaces a session to a provider that
 * died or was relaunched); an explicit session fails every later call.  A
 * session inherited across fork or pdfork belongs to the parent: the
 * process-wide one is abandoned and reopened, an explicit one refuses with
 * ECHILD.
 */
#include <sys/types.h>

#include <errno.h>
#include <fidl/bsd.extension.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>
#include <sysext_proto.h>

#include "extensioncmp.h"

#define	EXTENSIONCMP_CALL_TIMEOUT_MS	30000

_Static_assert(SERVICE_EXTENSION_NAME_MAX == SYSEXT_NAME_MAX,
    "extension name size mismatch");
_Static_assert(SERVICE_EXTENSION_LIST_MAX == SYSEXT_LIST_MAX,
    "extension list size mismatch");

struct extensioncmp_session {
	pthread_mutex_t		 lock;
	struct fidl_bsd_connection *connection;
	pid_t			 owner;
	pid_t			 creator; /* explicit session: immutable */
	bool			 negotiated;
	bool			 reopen;	/* process-wide: replace on failure */
	int			 failed;	/* explicit session: terminal */
};

struct completion {
	bool done, malformed;
	int error;
	const char *name;		/* Info/Next: the request's name */
	bool next;
	int loaded;
	char (*names)[SERVICE_EXTENSION_NAME_MAX];
	size_t max, count;
	struct service_extension_info *info;
};

static bool
valid_name(const char *name, size_t length)
{
	return (length != 0 && length < SYSEXT_NAME_MAX &&
	    memchr(name, '\0', length) == NULL &&
	    memchr(name, '/', length) == NULL &&
	    !(length == 1 && name[0] == '.') &&
	    !(length == 2 && name[0] == '.' && name[1] == '.'));
}

/* Client-side argument check (the legacy record's rules). */
static int
check_name(const char *name, bool empty_ok)
{
	size_t length;

	if (name == NULL)
		return (EINVAL);
	length = strnlen(name, SYSEXT_NAME_MAX);
	if (length >= SYSEXT_NAME_MAX)
		return (ENAMETOOLONG);
	if (length == 0 && empty_ok)
		return (0);
	return (valid_name(name, length) ? 0 : EINVAL);
}

static void
malformed(struct completion *result)
{
	result->malformed = true;
	result->error = EPROTO;
}

static void
domain_error(struct completion *result, uint32_t error)
{
	if (error == 0 || error > ELAST)
		malformed(result);
	else
		result->error = (int)error;
}

static void
info_reply(void *context, int error, struct bsd_extension_v1_ProtocolInfo *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (!error && (v == NULL || v->wire_version != SYSEXT_WIRE_VERSION)) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	}
}

/* The methods whose success reply is empty share one result layout. */
#define	EMPTY_REPLY(fn, method)						\
static void								\
fn(void *context, int error,						\
    struct bsd_extension_v1_SystemExtension_##method##_Result *v)	\
{									\
	struct completion *result = context;				\
									\
	result->done = true;						\
	result->error = error;						\
	if (error)							\
		return;							\
	if (v == NULL)							\
		malformed(result);					\
	else if (v->tag ==						\
	    bsd_extension_v1_SystemExtension_##method##_Result_err_tag)	\
		domain_error(result, v->value.err);			\
	else if (v->tag !=						\
	    bsd_extension_v1_SystemExtension_##method##_Result_response_tag) \
		malformed(result);					\
}
EMPTY_REPLY(ensure_reply, Ensure)
EMPTY_REPLY(reload_reply, Reload)
EMPTY_REPLY(allow_reply, Allow)
EMPTY_REPLY(deny_reply, Deny)
EMPTY_REPLY(reset_reply, Reset)
EMPTY_REPLY(enable_reply, Enable)
EMPTY_REPLY(disable_reply, Disable)
EMPTY_REPLY(restore_reply, Restore)

static void
stat_reply(void *context, int error,
    struct bsd_extension_v1_SystemExtension_Stat_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_extension_v1_SystemExtension_Stat_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag !=
	    bsd_extension_v1_SystemExtension_Stat_Result_response_tag)
		malformed(result);
	else
		result->loaded = v->value.response.loaded ? 1 : 0;
}

static void
list_reply(void *context, int error,
    struct bsd_extension_v1_SystemExtension_List_Result *v)
{
	struct completion *result = context;
	const struct bsd_extension_v1_ModuleList *list;
	size_t i;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL) {
		malformed(result);
		return;
	}
	if (v->tag == bsd_extension_v1_SystemExtension_List_Result_err_tag) {
		domain_error(result, v->value.err);
		return;
	}
	if (v->tag != bsd_extension_v1_SystemExtension_List_Result_response_tag) {
		malformed(result);
		return;
	}
	list = &v->value.response;
	if (list->modules_size > SYSEXT_LIST_MAX) {
		malformed(result);
		return;
	}
	for (i = 0; i < list->modules_size; i++)
		if (!valid_name(list->modules[i].name,
		    list->modules[i].name_size)) {
			malformed(result);
			return;
		}
	result->count = list->modules_size;
	if (result->count > result->max)
		return;		/* the caller reports EMSGSIZE */
	for (i = 0; i < result->count; i++) {
		memset(result->names[i], 0, SERVICE_EXTENSION_NAME_MAX);
		memcpy(result->names[i], list->modules[i].name,
		    list->modules[i].name_size);
	}
}

static void
module_info(struct completion *result,
    const struct bsd_extension_v1_ModuleInfo *reply)
{
	struct service_extension_info *info = result->info;
	char name[SYSEXT_NAME_MAX];
	int order;

	if (!valid_name(reply->name, reply->name_size) ||
	    (reply->flags & ~0x1fU) != 0) {
		malformed(result);
		return;
	}
	memcpy(name, reply->name, reply->name_size);
	name[reply->name_size] = '\0';
	order = strcmp(name, result->name);
	if (result->next ? order <= 0 : order != 0) {
		malformed(result);
		return;
	}
	strlcpy(info->name, name, sizeof(info->name));
	info->allowed = (reply->flags & SYSEXT_STATE_ALLOWED) != 0;
	info->enabled = (reply->flags & SYSEXT_STATE_ENABLED) != 0;
	info->loaded = (reply->flags & SYSEXT_STATE_LOADED) != 0;
	info->overridden = (reply->flags & SYSEXT_STATE_OVERRIDE) != 0;
	info->ready = (reply->flags & SYSEXT_STATE_READY) != 0;
}

static void
info_entry_reply(void *context, int error,
    struct bsd_extension_v1_SystemExtension_Info_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_extension_v1_SystemExtension_Info_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag !=
	    bsd_extension_v1_SystemExtension_Info_Result_response_tag)
		malformed(result);
	else
		module_info(result, &v->value.response);
}

static void
next_entry_reply(void *context, int error,
    struct bsd_extension_v1_SystemExtension_Next_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed(result);
	else if (v->tag == bsd_extension_v1_SystemExtension_Next_Result_err_tag)
		domain_error(result, v->value.err);
	else if (v->tag !=
	    bsd_extension_v1_SystemExtension_Next_Result_response_tag)
		malformed(result);
	else
		module_info(result, &v->value.response);
}

/* ---------------------------------------------------------------- sessions */

static int
session_init(struct extensioncmp_session *session, int fd)
{
	int error;

	error = fidl_bsd_connection_create(fd, FIDL_BSD_CLIENT,
	    &session->connection);
	if (error != 0) {
		session->connection = NULL;
		return (errno = error, -1);
	}
	session->owner = getpid();
	session->negotiated = false;
	session->failed = 0;
	return (0);
}

/* Drop the connection.  Caller holds session->lock. */
static void
session_drop(struct extensioncmp_session *session)
{

	if (session->connection != NULL && session->owner == getpid())
		fidl_bsd_connection_destroy(session->connection);
	session->connection = NULL;
	session->owner = 0;
	session->negotiated = false;
}

/*
 * Wait for one completion with the lock held.  Transport failures, timeouts
 * and malformed replies end the session; application errors keep it.
 */
static int
finish_locked(struct extensioncmp_session *session, int error,
    struct completion *result, const struct timespec *deadline)
{

	if (error == 0)
		error = fidl_bsd_sync_wait(session->connection, &result->done,
		    deadline);
	if (error == 0 && result->malformed)
		error = result->error;
	/* A reply failed by the transport (the peer closed) is not an
	 * application error: the session is gone. */
	if (error == 0 && result->error != 0 &&
	    fidl_bsd_connection_error(session->connection) != 0)
		error = result->error;
	if (error != 0) {
		session_drop(session);
		session->failed = error;
		return (errno = error, -1);
	}
	if (result->error != 0)
		return (errno = result->error, -1);
	return (0);
}

/* Negotiate once and arm the call deadline.  Caller holds session->lock. */
static int
begin_locked(struct extensioncmp_session *session, struct timespec *deadline)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = EXTENSIONCMP_CALL_TIMEOUT_MS, txid;
	int error, fd;

	if (session->connection != NULL && session->owner != getpid()) {
		if (!session->reopen)
			return (errno = ECHILD, -1);
		/* Never close an inherited session: it is the parent's. */
		session->connection = NULL;
		session->negotiated = false;
	}
	if (session->connection == NULL) {
		if (!session->reopen)
			return (errno = session->failed != 0 ?
			    session->failed : EPIPE, -1);
		if (service_open(SYSEXT_SERVICE_NAME, &fd) == -1)
			return (-1);
		if (session_init(session, fd) == -1) {
			error = errno;
			(void)close(fd);
			return (errno = error, -1);
		}
	}
	/* A caller's service_budget_begin(3) bounds the whole operation. */
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	if (session->negotiated)
		return (0);
	error = bsd_extension_v1_SystemExtension_GetProtocolInfo(
	    session->connection, &empty, info_reply, &result, &txid);
	if (finish_locked(session, error, &result, deadline) == -1)
		return (-1);
	session->negotiated = true;
	return (0);
}

int
extensioncmp_session_create(int fd, struct extensioncmp_session **sessionp)
{
	struct extensioncmp_session *session;
	int error;

	if (sessionp == NULL || fd < 0)
		return (errno = EINVAL, -1);
	session = calloc(1, sizeof(*session));
	if (session == NULL)
		return (-1);
	if ((error = pthread_mutex_init(&session->lock, NULL)) != 0) {
		free(session);
		return (errno = error, -1);
	}
	if (session_init(session, fd) == -1) {
		error = errno;
		(void)pthread_mutex_destroy(&session->lock);
		free(session);
		return (errno = error, -1);
	}
	session->creator = getpid();
	*sessionp = session;
	return (0);
}

int
extensioncmp_session_open(struct extensioncmp_session **sessionp)
{
	int error, fd;

	if (sessionp == NULL)
		return (errno = EINVAL, -1);
	if (service_open(SYSEXT_SERVICE_NAME, &fd) == -1)
		return (-1);
	if (extensioncmp_session_create(fd, sessionp) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	return (0);
}

void
extensioncmp_session_close(struct extensioncmp_session *session)
{

	if (session == NULL)
		return;
	/* The inherited mutex may be owned by a vanished parent thread. */
	if (session->creator != getpid()) {
		free(session);
		return;
	}
	session_drop(session);
	(void)pthread_mutex_destroy(&session->lock);
	free(session);
}

/* --------------------------------------------------------------- operations */

/* Issue one method on a locked, negotiated session and wait for it. */
#define	CALL(session, result, issue)					\
	({								\
		struct timespec deadline_;				\
		uint32_t txid_;						\
		int rc_;						\
									\
		if (!(session)->reopen && (session)->creator != getpid()) { \
			errno = ECHILD;					\
			rc_ = -1;					\
		} else {						\
		pthread_mutex_lock(&(session)->lock);			\
		rc_ = begin_locked((session), &deadline_);		\
		if (rc_ == 0)						\
			rc_ = finish_locked((session), (issue),		\
			    (result), &deadline_);			\
		pthread_mutex_unlock(&(session)->lock);			\
		}							\
		(void)txid_;						\
		rc_;							\
	})
#define	CONN(session)	((session)->connection)

int
extensioncmp_load(struct extensioncmp_session *session, const char *name)
{
	struct completion result = { 0 };
	struct bsd_extension_v1_Module module;
	int error;

	if (session == NULL)
		return (errno = EINVAL, -1);
	if ((error = check_name(name, false)) != 0)
		return (errno = error, -1);
	module.name = name;
	module.name_size = strlen(name);
	return (CALL(session, &result,
	    bsd_extension_v1_SystemExtension_Ensure(CONN(session), &module,
	    ensure_reply, &result, &txid_)));
}

int
extensioncmp_reload(struct extensioncmp_session *session)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };

	if (session == NULL)
		return (errno = EINVAL, -1);
	return (CALL(session, &result,
	    bsd_extension_v1_SystemExtension_Reload(CONN(session), &empty,
	    reload_reply, &result, &txid_)));
}

int
extensioncmp_stat(struct extensioncmp_session *session, const char *name,
    int *loaded)
{
	struct completion result = { 0 };
	struct bsd_extension_v1_Module module;
	int error;

	if (session == NULL || loaded == NULL)
		return (errno = EINVAL, -1);
	*loaded = 0;
	if ((error = check_name(name, false)) != 0)
		return (errno = error, -1);
	module.name = name;
	module.name_size = strlen(name);
	if (CALL(session, &result,
	    bsd_extension_v1_SystemExtension_Stat(CONN(session), &module,
	    stat_reply, &result, &txid_)) == -1)
		return (-1);
	*loaded = result.loaded;
	return (0);
}

int
extensioncmp_list(struct extensioncmp_session *session,
    char (*names)[SERVICE_EXTENSION_NAME_MAX], size_t max, size_t *count)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };

	if (session == NULL || names == NULL || count == NULL || max == 0)
		return (errno = EINVAL, -1);
	*count = 0;
	result.names = names;
	result.max = max;
	if (CALL(session, &result,
	    bsd_extension_v1_SystemExtension_List(CONN(session), &empty,
	    list_reply, &result, &txid_)) == -1)
		return (-1);
	*count = result.count;
	if (result.count > max)
		return (errno = EMSGSIZE, -1);
	return (0);
}

int
extensioncmp_manage(struct extensioncmp_session *session,
    enum service_extension_action action, const char *name)
{
	struct completion result = { 0 };
	struct fidl_bsd_empty empty = { 0 };
	struct bsd_extension_v1_Module module;
	int error;

	if (session == NULL)
		return (errno = EINVAL, -1);
	if (action == SERVICE_EXTENSION_RESTORE)
		return (CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Restore(CONN(session),
		    &empty, restore_reply, &result, &txid_)));
	if ((error = check_name(name, false)) != 0)
		return (errno = error, -1);
	module.name = name;
	module.name_size = strlen(name);
	switch (action) {
	case SERVICE_EXTENSION_ALLOW:
		return (CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Allow(CONN(session),
		    &module, allow_reply, &result, &txid_)));
	case SERVICE_EXTENSION_DENY:
		return (CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Deny(CONN(session),
		    &module, deny_reply, &result, &txid_)));
	case SERVICE_EXTENSION_RESET:
		return (CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Reset(CONN(session),
		    &module, reset_reply, &result, &txid_)));
	case SERVICE_EXTENSION_ENABLE:
		return (CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Enable(CONN(session),
		    &module, enable_reply, &result, &txid_)));
	case SERVICE_EXTENSION_DISABLE:
		return (CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Disable(CONN(session),
		    &module, disable_reply, &result, &txid_)));
	default:
		return (errno = EINVAL, -1);
	}
}

int
extensioncmp_info(struct extensioncmp_session *session, const char *name,
    int next, struct service_extension_info *info)
{
	struct completion result = { 0 };
	struct bsd_extension_v1_Module module;
	struct bsd_extension_v1_Cursor cursor;
	int error;

	if (session == NULL || info == NULL || (next != 0 && next != 1))
		return (errno = EINVAL, -1);
	memset(info, 0, sizeof(*info));
	if ((error = check_name(name, next != 0)) != 0)
		return (errno = error, -1);
	result.name = name;
	result.next = next != 0;
	result.info = info;
	if (next) {
		cursor.name = name;
		cursor.name_size = strlen(name);
		error = CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Next(CONN(session), &cursor,
		    next_entry_reply, &result, &txid_));
	} else {
		module.name = name;
		module.name_size = strlen(name);
		error = CALL(session, &result,
		    bsd_extension_v1_SystemExtension_Info(CONN(session), &module,
		    info_entry_reply, &result, &txid_));
	}
	if (error == -1) {
		error = errno;
		memset(info, 0, sizeof(*info));
		errno = error;
		return (-1);
	}
	return (0);
}

/* ------------------------------------------------------ process-wide session */

/*
 * One process-wide session, opened by name on first use.  A session that
 * failed terminally (the provider died or was relaunched) is replaced on the
 * next call; a session inherited across fork or pdfork belongs to the parent
 * and is abandoned without being closed (begin_locked()).
 */
static struct extensioncmp_session extensioncmp_global = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.reopen = true
};

static struct extensioncmp_session *
global_session(struct service_context *context)
{

	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (NULL);
	}
	return (&extensioncmp_global);
}

/*
 * Ensure a named kernel extension is loaded via bsdextension.  bsdextension is a
 * socket-free provider: this library opens a system.SystemExtension channel by
 * name and asks it to load the module.  The channel is cached (all of a
 * service's ensures share it).  The discovery domain layer resolves the name
 * only for SYSTEM-domain callers, so a user service's lookup fails closed here.
 */
int
service_ensure_extension(struct service_context *context, const char *module)
{
	struct extensioncmp_session *session = global_session(context);

	return (session == NULL ? -1 : extensioncmp_load(session, module));
}

int
service_extension_stat(struct service_context *context, const char *module,
    int *loadedp)
{
	struct extensioncmp_session *session = global_session(context);

	return (session == NULL ? -1 :
	    extensioncmp_stat(session, module, loadedp));
}

int
service_extension_list(struct service_context *context,
    char (*names)[SERVICE_EXTENSION_NAME_MAX], size_t max, size_t *countp)
{
	struct extensioncmp_session *session = global_session(context);

	return (session == NULL ? -1 :
	    extensioncmp_list(session, names, max, countp));
}
