/*
 * OES event ABI consistency tests.
 *
 * This catches enum/mask drift in the public header.  The kernel and liboes
 * consume these same masks for bitmap subscription.
 */
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <security/oes/oes.h>

_Static_assert(OES_API_VERSION == 1, "update API version coverage");
_Static_assert(OES_MESSAGE_VERSION == 1,
    "scope API must not silently change the message ABI");
_Static_assert(sizeof(void *) == 8, "OES is available only on LP64 targets");
_Static_assert(sizeof(oes_message_t) == 1200,
    "message v1 wire size changed");
_Static_assert(sizeof(oes_process_t) == 408,
    "process v1 wire size changed");
_Static_assert(sizeof(oes_file_t) == 208,
    "file v1 wire size changed");
_Static_assert(sizeof(oes_thread_t) == 40,
    "thread v1 wire size changed");
_Static_assert(offsetof(oes_process_t, ep_audit_flags) == 256,
    "process audit metadata offset changed");
_Static_assert(offsetof(oes_process_t, ep_path_off) == 384,
    "process string-table offset fields changed");
_Static_assert(offsetof(oes_file_t, ef_allocated_bytes) == 48,
    "file allocation metadata offset changed");
_Static_assert(offsetof(oes_file_t, ef_atime) == 112,
    "file timestamp metadata offset changed");
_Static_assert(offsetof(oes_file_t, ef_path_off) == 192,
    "file string-table offset changed");
_Static_assert(offsetof(oes_message_t, em_wall_time) == 88,
    "wall timestamp offset changed");
_Static_assert(offsetof(oes_message_t, em_thread) == 104,
    "thread metadata offset changed");
_Static_assert(offsetof(oes_message_t, em_process) == 144,
    "process metadata offset changed");
_Static_assert(offsetof(oes_message_t, em_event_data) == 552,
    "event payload offset changed");
_Static_assert(sizeof(oes_event_type_t) == 4,
    "event enum elements must remain 32-bit-wide on the ioctl ABI");
_Static_assert(sizeof(oes_auth_result_t) == 4,
    "authorization enum must remain 32-bit-wide");
_Static_assert(sizeof(oes_timespec_t) == 16,
    "wire timestamps must remain fixed-width");
_Static_assert(sizeof(struct oes_subscribe_args) == 24,
    "subscribe ioctl LP64 layout changed");
_Static_assert(sizeof(struct oes_get_muted_processes_args) == 24,
    "process query ioctl LP64 layout changed");
_Static_assert(sizeof(struct oes_get_muted_paths_args) == 32,
    "path query ioctl LP64 layout changed");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct oes_subscribe_args *)0)->esa_events),
    const oes_event_type_t *),
    "subscribe events must be a native pointer, not a compatibility union");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct oes_subscribe_args *)0)->esa_count), size_t),
    "subscribe count must use the native LP64 size_t");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct oes_get_muted_processes_args *)0)->egmp_entries),
    struct oes_muted_process_entry *),
    "muted-process output must be a native pointer");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(((struct oes_get_muted_paths_args *)0)->egmpa_entries),
    struct oes_muted_path_entry *),
    "muted-path output must be a native pointer");
_Static_assert(sizeof(struct oes_scope_args) == 8,
    "scope ioctl layout changed");
_Static_assert(sizeof(struct oes_event_deadline_args) == 16,
    "deadline ioctl layout changed");

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
	struct {
		oes_message_t msg;
		uint64_t future_data;
	} storage;
	oes_message_t *msg;

	memset(&storage, 0, sizeof(storage));
	msg = &storage.msg;
	msg->em_version = OES_MESSAGE_VERSION;
	msg->em_size = sizeof(*msg);
	msg->em_struct_size = sizeof(*msg);
	msg->em_reserved = 0;
	if (!oes_message_is_compatible(msg)) {
		printf("    FAIL: current message version rejected\n");
		return (1);
	}

	msg->em_version = OES_MESSAGE_VERSION + 1;
	msg->em_size = sizeof(storage);
	msg->em_struct_size = sizeof(storage);
	if (!oes_message_is_compatible(msg)) {
		printf("    FAIL: additive future message version rejected\n");
		return (1);
	}

	msg->em_version = OES_MESSAGE_VERSION;
	msg->em_size = sizeof(*msg);
	msg->em_struct_size = sizeof(*msg) - 1;
	if (oes_message_is_compatible(msg)) {
		printf("    FAIL: undersized fixed structure accepted\n");
		return (1);
	}

	msg->em_struct_size = sizeof(*msg);
	msg->em_flags |= OES_MSG_FLAG_AUTH_RESULT;
	msg->em_result = OES_AUTH_DENY;
	if (!oes_message_has_auth_result(msg)) {
		printf("    FAIL: valid applied AUTH result rejected\n");
		return (1);
	}
	msg->em_flags &= ~OES_MSG_FLAG_AUTH_RESULT;
	msg->em_reserved = 1;
	if (oes_message_is_compatible(msg)) {
		printf("    FAIL: nonzero reserved field accepted\n");
		return (1);
	}

	printf("    PASS: message version compatibility checks work\n");
	return (0);
}

static int
test_string_bounds(void)
{
	struct {
		oes_message_t msg;
		char string[8];
	} storage;
	uint32_t off;

	memset(&storage, 'x', sizeof(storage));
	storage.msg.em_version = OES_MESSAGE_VERSION;
	storage.msg.em_size = sizeof(storage);
	storage.msg.em_struct_size = sizeof(storage.msg);
	storage.msg.em_flags = 0;
	storage.msg.em_reserved = 0;
	off = sizeof(storage.msg);
	if (oes_msg_string(&storage.msg, off)[0] != '\0') {
		printf("    FAIL: unterminated message string accepted\n");
		return (1);
	}
	storage.string[sizeof(storage.string) - 1] = '\0';
	if (strcmp(oes_msg_string(&storage.msg, off), "xxxxxxx") != 0) {
		printf("    FAIL: bounded message string rejected\n");
		return (1);
	}

	printf("    PASS: message strings are bounds checked\n");
	return (0);
}

int
main(void)
{
	int errors = 0;

	printf("Testing event ABI tables...\n");
	errors += test_event_masks();
	errors += test_message_version();
	errors += test_string_bounds();
	return (errors != 0);
}
