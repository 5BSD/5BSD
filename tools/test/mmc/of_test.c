/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef ENODATA
#define ENODATA 61
#endif
#define GFP_KERNEL 0
#define ETH_ALEN 6
#define max(a, b) ((a) > (b) ? (a) : (b))
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
typedef uint8_t u8;
typedef uint32_t u32;
struct property { struct property *next; char *name; void *value; int length; };
struct device_node { unsigned refs; int bsd_node; struct property *properties; };
static unsigned allocations;
static int fail_after = -1;
static void *allocate(size_t n) {
	if (fail_after == 0) return NULL;
	if (fail_after > 0) fail_after--;
	void *p = calloc(1, n); assert(p); allocations++; return p;
}
static void kfree(void *p) { if (p) { assert(allocations); allocations--; free(p); } }
#define kzalloc(n, g) allocate(n)
#define kmalloc(n, g) allocate(n)
static char *kstrdup(const char *s, int g) {
	(void)g; char *p = allocate(strlen(s) + 1); if (p) strcpy(p, s); return p;
}
static void refcount_set(unsigned *p, unsigned v) { *p = v; }
static void refcount_inc(unsigned *p) { assert(*p); ++*p; }
static bool refcount_dec_and_test(unsigned *p) { assert(*p); return --*p == 0; }
static uint32_t be32dec(const void *data) {
	const u8 *p = data; return ((u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]);
}
static bool is_valid_ether_addr(const u8 *p) {
	u8 sum = 0; for (int i = 0; i < 6; i++) sum |= p[i]; return sum != 0 && !(p[0] & 1);
}
static size_t test_strlcpy(char *dst, const char *src, size_t n) {
	size_t len = strlen(src); assert(n > len); memcpy(dst, src, len + 1); return len;
}
#define strlcpy test_strlcpy
static const u8 cell[] = { 0, 0, 0x12, 0x34 };
static const u8 zero_mac[6];
static const u8 mac[] = { 2, 3, 4, 5, 6, 7 };
static struct { const char *name; const void *data; int length; } native[] = {
	{ "compatible", "raspberrypi,model-zero-2-w\0brcm,bcm2837", 38 },
	{ "present", "", 0 },
	{ "broken", "bad", 3 },
	{ "number", cell, 4 },
	{ "short", cell, 3 },
	{ "mac-address", zero_mac, 6 },
	{ "local-mac-address", mac, 6 },
};
static int OF_nextprop(int node, const char *prev, char *next, size_t size) {
	assert(node == 1);
	for (unsigned i = 0; i < nitems(native); i++) {
		if ((i == 0 && *prev == '\0') || (i > 0 && strcmp(prev, native[i-1].name) == 0)) {
			strlcpy(next, native[i].name, size); return 1;
		}
	}
	return 0;
}
static int OF_getproplen(int node, const char *name) {
	assert(node == 1);
	for (unsigned i = 0; i < nitems(native); i++) if (!strcmp(name, native[i].name)) return native[i].length;
	return -1;
}
static int OF_getprop(int node, const char *name, void *value, int length) {
	assert(node == 1);
	for (unsigned i = 0; i < nitems(native); i++) if (!strcmp(name, native[i].name)) {
		assert(length == native[i].length); memcpy(value, native[i].data, length); return length;
	}
	return -1;
}
#include "power_functions.h"
int main(void) {
	struct device_node *np;
	const char *value;
	u32 number = 77;
	u8 address[6];
	/* Compute the explicit string-list size, excluding C's extra terminator. */
	native[0].length = sizeof("raspberrypi,model-zero-2-w\0brcm,bcm2837");
	np = linux_of_node_from_handle(1); assert(np);
	assert(linux_of_property_count_strings(np, "compatible") == 2);
	assert(linux_of_property_read_string_index(np, "compatible", 0, &value) == 0);
	assert(!strcmp(value, "raspberrypi,model-zero-2-w"));
	assert(linux_of_device_is_compatible(np, "brcm,bcm2837"));
	assert(!linux_of_device_is_compatible(np, "brcm,bcm283"));
	assert(linux_of_property_read_string_index(np, "compatible", 2, &value) == -ENODATA);
	assert(linux_of_property_read_string_index(np, "compatible", -1, &value) == -EINVAL);
	assert(linux_of_property_read_string_index(np, "broken", 0, &value) == -EILSEQ);
	assert(linux_of_property_count_strings(np, "broken") == -EILSEQ);
	assert(linux_of_property_count_strings(np, "missing") == -EINVAL);
	assert(linux_of_get_property(np, "present", NULL) != NULL);
	assert(linux_of_property_count_strings(np, "present") == -ENODATA);
	assert(linux_of_property_read_u32(np, "short", &number) == -EOVERFLOW && number == 77);
	assert(linux_of_property_read_u32(np, "number", &number) == 0 && number == 0x1234);
	assert(linux_of_get_mac_address(np, address) == 0 && !memcmp(address, mac, 6));
	assert(linux_of_node_get(np) == np); linux_of_node_put(np);
	assert(np->refs == 1); linux_of_node_put(np); assert(allocations == 0);
	/* Every partially constructed snapshot must unwind without a leak. */
	for (int i = 0; i < 1 + (int)nitems(native) * 3; i++) {
		fail_after = i; assert(linux_of_node_from_handle(1) == NULL); assert(allocations == 0);
	}
	assert(linux_of_node_from_handle(0) == NULL);
	puts("PASS: OF board identity, bounded string/cell reads, MAC fallback, snapshot failure cleanup");
	return 0;
}
