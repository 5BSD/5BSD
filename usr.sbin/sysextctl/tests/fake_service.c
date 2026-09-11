/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>
#include <sysext_proto.h>
struct service_session { int fd; };
static struct service_session session;
int
service_open(const char *name, int *fd)
{
	if (strcmp(name, SYSEXT_SERVICE_NAME) != 0) abort();
	*fd = open("/dev/null", O_RDONLY);
	return (*fd < 0 ? -1 : 0);
}
int
service_session_create(int fd, struct service_session **out)
{
	session.fd = fd;
	*out = &session;
	return (0);
}
void
service_session_close(struct service_session *s)
{
	close(s->fd);
}
int
service_session_call(struct service_session *s,
    const struct service_message *m, struct service_reply *r,
    const struct service_call_options *o)
{
	const struct sysext_request *q = m->data;
	struct sysext_list_reply *list = r->data;
	struct sysext_stat_reply *basic = r->data;
	const char *mode = getenv("SYSEXT_TEST");

	if (s != &session || m->length != sizeof(*q) || m->nfds != 0 ||
	    q->_reserved != 0 || o->timeout_ms != 30000) abort();
	if (q->op != SYSEXT_OP_LIST && strcmp(q->name, "linux64") != 0) abort();
	memset(r->data, 0, r->capacity);
	r->length = sizeof(*basic);
	if (q->op == SYSEXT_OP_LIST) {
		r->length = sizeof(*list);
		list->count = 1;
		strlcpy(list->names[0], "linux64", sizeof(list->names[0]));
	} else if (q->op == SYSEXT_OP_STAT)
		basic->loaded = 1;
	if (mode == NULL) return (0);
	if (strcmp(mode, "denied") == 0) {
		basic->status = EPERM;
		r->length = sizeof(*basic);
	} else if (strcmp(mode, "short") == 0)
		r->length = 3;
	else if (strcmp(mode, "count") == 0)
		list->count = SYSEXT_LIST_MAX + 1;
	else if (strcmp(mode, "name") == 0)
		memset(list->names[0], 'x', sizeof(list->names[0]));
	else if (strcmp(mode, "state") == 0)
		basic->loaded = 2;
	else if (strcmp(mode, "absent") == 0)
		basic->loaded = 0;
	else if (strcmp(mode, "errno") == 0)
		basic->status = -1;
	else if (strcmp(mode, "io") == 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}
