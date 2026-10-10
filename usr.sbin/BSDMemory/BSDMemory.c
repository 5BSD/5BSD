/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>

#include <errno.h>
#include <libservice.h>
#include <notify.h>
#include <notify_pressure.h>
#include <service_runtime.h>
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
			if (length != sizeof(values[i]))
				errno = EPROTO;
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
	struct service_retry source_retry, notify_retry;
	struct service_health source_health = { 0 }, notify_health = { 0 };
	uint32_t values[3];
	unsigned level, published = NOTIFY_PRESSURE_UNKNOWN + 1;
	int kq, count;

	(void)service_retry_init(&source_retry, 1000, 30000);
	(void)service_retry_init(&notify_retry, 1000, 30000);
	service_set_proctitle();
	openlog("BSDMemory", LOG_PID, LOG_DAEMON);
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
		int error = -1;
		if (service_retry_ready(&source_retry, service_monotime_ms())) {
			if (service_budget_begin(400) == 0) {
				error = sample(&source, values);
				service_budget_end();
			}
			int saved = error == 0 ? 0 : (errno != 0 ? errno : EIO);
			service_retry_result(&source_retry,
			    service_monotime_ms(), error == 0);
			if (service_health_record(&source_health, saved))
				syslog(saved ? LOG_WARNING : LOG_NOTICE,
				    "sysctl dependency error=%d failures=%ju",
				    saved, (uintmax_t)source_health.failures);
		}
		level = pressure_update(&filter, error, values[0], values[1],
		    values[2]);
		if (service_retry_ready(&notify_retry, service_monotime_ms()) &&
		    service_budget_begin(400) == 0) {
			if (notify == NULL) {
				if (notify_client_open_system(&notify) == 0)
					published = NOTIFY_PRESSURE_UNKNOWN + 1;
			}
			/* Check unchanged state too, so a router restart is
			 * detected.
			 */
			if (notify != NULL &&
			    !(published == level &&
				notify_state_get(notify, NOTIFY_PRESSURE_TOPIC,
				    &observed) == 0 &&
				observed.state == level) &&
			    notify_state_set(notify, NOTIFY_PRESSURE_TOPIC,
				level) == -1) {
				notify_client_close(notify);
				notify = NULL;
			} else if (notify != NULL && published != level) {
				syslog(LOG_INFO, "memory pressure level=%u",
				    level);
				published = level;
			}
			int saved = notify == NULL ?
			    (errno != 0 ? errno : EIO) :
			    0;
			service_budget_end();
			service_retry_result(&notify_retry,
			    service_monotime_ms(), saved == 0);
			if (service_health_record(&notify_health, saved))
				syslog(saved ? LOG_WARNING : LOG_NOTICE,
				    "notify dependency error=%d failures=%ju",
				    saved, (uintmax_t)notify_health.failures);
		}
		if (service_budget_begin(400) == -1)
			break;
		int heartbeat = service_provider_heartbeat(provider);
		service_budget_end();
		if (heartbeat == -1)
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
