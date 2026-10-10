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
#include "bsdmemory_probes.h"

static int
sample(struct sysctlcmp_client **client, uint32_t values[3])
{
	static const char *const names[] = { "vm.stats.vm.v_free_count",
		"vm.stats.vm.v_free_min", "vm.stats.vm.v_free_target" };
	if (*client == NULL && sysctlcmp_client_open(client) == -1)
		return (-1);
	for (unsigned i = 0; i < 3; i++) {
		size_t length = sizeof(values[i]);
		int result = sysctlcmp_get(*client, names[i], &values[i], &length);
		if (result == -1 || length != sizeof(values[i])) {
			int error = result == -1 ? (errno != 0 ? errno : EIO) : EPROTO;
			sysctlcmp_client_close(*client);
			*client = NULL;
			return (errno = error, -1);
		}
	}
	return (0);
}
static int
publish_pressure(struct notify_client **client, unsigned level,
    unsigned *published)
{
	struct notify_state_reply observed;
	int error;

	if (*client == NULL) {
		if (notify_client_open_system(client) == -1)
			return (-1);
		*published = NOTIFY_PRESSURE_UNKNOWN + 1;
	}
	/* Check unchanged state too: missing state and router restarts must heal. */
	if (*published == level &&
	    notify_state_get(*client, NOTIFY_PRESSURE_TOPIC, &observed) == 0 &&
	    observed.state == level)
		return (0);
	if (notify_state_set(*client, NOTIFY_PRESSURE_TOPIC, level) == -1) {
		error = errno != 0 ? errno : EIO;
		notify_client_close(*client);
		*client = NULL;
		return (errno = error, -1);
	}
	*published = level;
	return (0);
}

int
main(void)
{
	struct service_provider *provider = NULL;
	struct sysctlcmp_client *source = NULL;
	struct notify_client *notify = NULL;
	struct pressure_filter filter = { .level = NOTIFY_PRESSURE_UNKNOWN };
	struct kevent timer, event;
	struct service_retry source_retry, notify_retry;
	struct service_health source_health = { 0 }, notify_health = { 0 };
	uint32_t values[3];
	unsigned level, published = NOTIFY_PRESSURE_UNKNOWN + 1;
	int kq = -1, count, result = 1;
	bool ready = false;

	(void)service_retry_init(&source_retry, 1000, 30000);
	(void)service_retry_init(&notify_retry, 1000, 30000);
	service_set_proctitle();
	openlog("BSDMemory", LOG_PID, LOG_DAEMON);
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider,
		SERVICE_PROTECT_EXTERNAL | SERVICE_PROTECT_NOPRIVS |
		    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1)
		goto out;
	kq = kqueue();
	if (kq == -1)
		goto out;
	EV_SET(&timer, 1, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, 1, NULL);
	if (kevent(kq, &timer, 1, NULL, 0, NULL) == -1 ||
	    service_provider_ready(provider) == -1)
		goto out;
	ready = true;
	BSDMEMORY_READY();
	for (;;) {
		if (service_provider_quiescing(provider) == 1)
			break;
		values[0] = values[1] = values[2] = 0;
		int error = -1;
		if (service_retry_ready(&source_retry, service_monotime_ms())) {
			BSDMEMORY_SAMPLE_START();
			if (service_budget_begin(400) == 0) {
				error = sample(&source, values);
				service_budget_end();
			}
			int saved = error == 0 ? 0 : (errno != 0 ? errno : EIO);
			BSDMEMORY_SAMPLE_DONE(saved, values[0], values[1], values[2]);
			service_retry_result(&source_retry,
			    service_monotime_ms(), error == 0);
			if (service_health_record(&source_health, saved))
				syslog(saved ? LOG_WARNING : LOG_NOTICE,
				    "sysctl dependency error=%d failures=%ju",
				    saved, (uintmax_t)source_health.failures);
		}
		level = pressure_update(&filter, error, values[0], values[1],
		    values[2]);
		BSDMEMORY_PRESSURE(level, filter.effective, filter.recovery);
		if (service_retry_ready(&notify_retry, service_monotime_ms()) &&
		    service_budget_begin(400) == 0) {
			unsigned previous = published;
			BSDMEMORY_PUBLISH_START(level);
			int saved = publish_pressure(&notify, level, &published) == -1 ?
			    (errno != 0 ? errno : EIO) : 0;
			BSDMEMORY_PUBLISH_DONE(level, published, saved);
			if (saved == 0 && previous != published)
				syslog(LOG_INFO, "memory pressure level=%u", level);
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
out:
	if (notify != NULL)
		notify_client_close(notify);
	if (source != NULL)
		sysctlcmp_client_close(source);
	if (kq >= 0)
		close(kq);
	if (ready && service_provider_quiescing(provider) == 1 &&
	    service_provider_quiesce_complete(provider, 0) == 0)
		result = 0;
	if (provider != NULL)
		service_provider_destroy(provider);
	BSDMEMORY_EXIT(result);
	return (result);
}
