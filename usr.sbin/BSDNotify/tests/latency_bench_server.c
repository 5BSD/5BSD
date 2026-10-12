/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The router half of latency_bench: one BSDNotify session served by the
 * router's own code on an in-process router.  NOTIFY_BENCH_LEGACY selects
 * the event loop of the pre-FIDL router, whose session handling was inline
 * in router_main().
 */
#include <err.h>

#ifndef NOTIFY_SERVER_SOURCE
#define NOTIFY_SERVER_SOURCE "../bsdnotify.c"
#endif
int bsdnotify_main(void);
#define main bsdnotify_main
#include NOTIFY_SERVER_SOURCE
#undef main

int notify_bench_serve(int);

int
notify_bench_serve(int fd)
{
	struct router_control control = {
		.magic = ROUTER_CONTROL_MAGIC,
		.queue_depth = NOTIFY_DEFAULT_QUEUE,
		.tier = NOTIFY_TIER_OPEN
	};
	struct notify_policy_db db;
	struct router router;
	struct kevent events[16];

	memset(&router, 0, sizeof(router));
	strlcpy(control.label, "org.5bsd.bench", sizeof(control.label));
	if (notify_policy_db_parse("{}", &db) == -1)
		return (1);
	router.policy_db = &db;
	router.broker = notify_broker_create();
	router.kq = kqueue();
	if (router.broker == NULL || router.kq == -1 ||
	    router_add_session(&router, &control, fd) == -1)
		return (1);
	while (router.nsessions != 0) {
		int count = kevent(router.kq, NULL, 0, events, nitems(events),
		    NULL);

		for (int i = 0; i < count; i++) {
			struct event_source *source = events[i].udata;

			if (source == NULL || source->type == 0)
				continue;
#ifdef NOTIFY_BENCH_LEGACY
			if (source->type == ROUTER_EVENT_SESSION) {
				struct router_session *session = (void *)source;
				int wants_write;

				if ((events[i].flags & EV_EOF) != 0 ||
				    (events[i].filter == EVFILT_READ &&
				    channel_dispatch(session->channel) == -1) ||
				    (events[i].filter == EVFILT_WRITE &&
				    channel_flush(session->channel) == -1) ||
				    session->terminal_error != 0 ||
				    (wants_write = channel_wants_write(
				    session->channel)) == -1 ||
				    router_change(&router, session->fd,
				    EVFILT_WRITE, wants_write ? EV_ENABLE :
				    EV_DISABLE, 0, 0, session) == -1)
					router_remove_session(&router, session);
			}
#else
			router_event(&router, source, &events[i]);
#endif
		}
		router_collect_garbage(&router);
	}
	return (0);
}
