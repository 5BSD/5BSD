/*
 * OES event ABI consistency tests.
 *
 * This catches enum/mask drift in the public header.  The kernel and liboes
 * consume these same masks for bitmap subscription.
 */
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <security/oes/oes.h>

static void
add_event_mask(oes_event_type_t event, uint64_t auth[2], uint64_t notify[2])
{
	uint64_t *mask;
	uint32_t bit, word;

	bit = (uint32_t)event & 0x0FFF;
	word = bit / 64;
	if (bit >= 128) {
		printf("    FAIL: event 0x%x bit out of range\n", event);
		return;
	}

	mask = OES_EVENT_IS_NOTIFY(event) ? notify : auth;
	mask[word] |= 1ULL << (bit % 64);
}

static int
test_event_masks(void)
{
	uint64_t auth[2] = { 0, 0 };
	uint64_t notify[2] = { 0, 0 };
	size_t i;
	static const oes_event_type_t auth_events[] = {
#define OES_EVENT_ITEM(name, value) name,
		OES_AUTH_EVENT_LIST(OES_EVENT_ITEM)
#undef OES_EVENT_ITEM
	};
	static const oes_event_type_t notify_events[] = {
#define OES_EVENT_ITEM(name, value) name,
		OES_NOTIFY_EVENT_LIST(OES_EVENT_ITEM)
#undef OES_EVENT_ITEM
	};

	for (i = 0; i < sizeof(auth_events) / sizeof(auth_events[0]); i++) {
		if (!OES_EVENT_IS_AUTH(auth_events[i])) {
			printf("    FAIL: AUTH event 0x%x classified as NOTIFY\n",
			    auth_events[i]);
			return (1);
		}
		add_event_mask(auth_events[i], auth, notify);
	}
	for (i = 0; i < sizeof(notify_events) / sizeof(notify_events[0]); i++) {
		if (!OES_EVENT_IS_NOTIFY(notify_events[i])) {
			printf("    FAIL: NOTIFY event 0x%x classified as AUTH\n",
			    notify_events[i]);
			return (1);
		}
		add_event_mask(notify_events[i], auth, notify);
	}

	if (auth[0] != OES_AUTH_EVENT_MASK_LO ||
	    auth[1] != OES_AUTH_EVENT_MASK_HI ||
	    notify[0] != OES_NOTIFY_EVENT_MASK_LO ||
	    notify[1] != OES_NOTIFY_EVENT_MASK_HI) {
		printf("    FAIL: event masks drifted\n");
		printf("      auth   got 0x%jx 0x%jx expected 0x%jx 0x%jx\n",
		    (uintmax_t)auth[0], (uintmax_t)auth[1],
		    (uintmax_t)OES_AUTH_EVENT_MASK_LO,
		    (uintmax_t)OES_AUTH_EVENT_MASK_HI);
		printf("      notify got 0x%jx 0x%jx expected 0x%jx 0x%jx\n",
		    (uintmax_t)notify[0], (uintmax_t)notify[1],
		    (uintmax_t)OES_NOTIFY_EVENT_MASK_LO,
		    (uintmax_t)OES_NOTIFY_EVENT_MASK_HI);
		return (1);
	}

	printf("    PASS: public event masks match enum list\n");
	return (0);
}

static int
test_message_version(void)
{
	oes_message_t msg;

	memset(&msg, 0, sizeof(msg));
	msg.em_version = OES_MESSAGE_VERSION;
	msg.em_reserved = 0;
	if (!oes_message_is_compatible(&msg)) {
		printf("    FAIL: current message version rejected\n");
		return (1);
	}

	msg.em_version = OES_MESSAGE_VERSION + 1;
	if (oes_message_is_compatible(&msg)) {
		printf("    FAIL: future message version accepted\n");
		return (1);
	}

	msg.em_version = OES_MESSAGE_VERSION;
	msg.em_reserved = 1;
	if (oes_message_is_compatible(&msg)) {
		printf("    FAIL: nonzero reserved field accepted\n");
		return (1);
	}

	printf("    PASS: message version compatibility checks work\n");
	return (0);
}

int
main(void)
{
	int errors = 0;

	printf("Testing event ABI tables...\n");
	errors += test_event_masks();
	errors += test_message_version();
	return (errors != 0);
}
