/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>

#include <errno.h>
#include <libservice.h>
#include <notify.h>
#include <notify_pressure.h>
#include <stdint.h>
#include <sysctlcmp.h>
#include <syslog.h>
#include <unistd.h>

#include "pressure.h"

static int
sample(struct sysctlcmp_client **client, uint32_t values[3])
{
	static const char *const names[] = { "vm.stats.vm.v_free_count",
		"vm.stats.vm.v_free_min", "vm.stats.vm.v_free_target" };
	if (*client == NULL && sysctlcmp_client_open(client) == -1)
		return (-1);
	for (unsigned i = 0; i < 3; i++) {
		size_t length = sizeof(values[i]);
		if (sysctlcmp_get(*client, names[i], &values[i], &length) ==
			-1 ||
		    length != sizeof(values[i])) {
			sysctlcmp_client_close(*client);
			*client = NULL;
			return (-1);
		}
	}
	return (0);
}
int
main(void)
{
	struct service_provider *provider;
	struct sysctlcmp_client *source = NULL;
	struct notify_client *notify = NULL;
	struct notify_state_reply observed;
	struct pressure_filter filter = { .level = NOTIFY_PRESSURE_UNKNOWN };
	struct kevent timer, event;
	uint32_t values[3];
	unsigned level, published = NOTIFY_PRESSURE_UNKNOWN + 1;
	int kq, count;

	service_set_proctitle();
	openlog("BSDPressure", LOG_PID, LOG_DAEMON);
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider,
		SERVICE_PROTECT_EXTERNAL | SERVICE_PROTECT_NOPRIVS |
		    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (1);
	kq = kqueue();
	if (kq == -1)
		return (1);
	EV_SET(&timer, 1, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, 1, NULL);
	if (kevent(kq, &timer, 1, NULL, 0, NULL) == -1)
		return (1);
	for (;;) {
		if (service_provider_quiescing(provider) == 1)
			break;
		values[0] = values[1] = values[2] = 0;
		int error = sample(&source, values);
		level = pressure_update(&filter, error, values[0], values[1],
		    values[2]);
		if (notify == NULL) {
			if (notify_client_open_system(&notify) == 0)
				published = NOTIFY_PRESSURE_UNKNOWN + 1;
		}
		/* Check unchanged state too, so a router restart is detected.
		 */
		if (notify != NULL &&
		    !(published == level &&
			notify_state_get(notify, NOTIFY_PRESSURE_TOPIC,
			    &observed) == 0 &&
			observed.state == level) &&
		    notify_state_set(notify, NOTIFY_PRESSURE_TOPIC, level) ==
			-1) {
			notify_client_close(notify);
			notify = NULL;
		} else if (notify != NULL && published != level) {
			syslog(LOG_INFO, "memory pressure level=%u", level);
			published = level;
		}
		if (service_provider_heartbeat(provider) == -1)
			break;
		do {
			count = kevent(kq, NULL, 0, &event, 1, NULL);
		} while (count == -1 && errno == EINTR);
		if (count == -1)
			break;
	}
	if (notify != NULL)
		notify_client_close(notify);
	if (source != NULL)
		sysctlcmp_client_close(source);
	close(kq);
	return (service_provider_quiescing(provider) == 1 ?
		service_provider_quiesce_complete(provider, 0) :
		1);
}
