/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "interfaces.h"

static int
compare_index(const void *a, const void *b)
{
	const struct sysctlcmp_interface *left = a, *right = b;
	return ((left->index > right->index) - (left->index < right->index));
}

/* Parse the native extensible IFLISTL format; never export kernel structs. */
int
sysctlcmp_interfaces_parse(const void *data, size_t length,
    struct sysctlcmp_interface *out, size_t *count)
{
	struct sysctlcmp_interface records[SYSCTLCMP_MAX_INTERFACES] = { 0 };
	struct if_msghdrl header;
	struct if_data stats;
	struct sockaddr_dl link;
	const unsigned char *p = data, *address;
	size_t offset, n, available, name_length;
	struct {
		uint16_t length;
		uint8_t version, type;
	} common;

	if ((data == NULL && length != 0) || out == NULL || count == NULL)
		return (errno = EINVAL, -1);
	if (length > SYSCTLCMP_IFLIST_MAX_BYTES)
		return (errno = EOVERFLOW, -1);
	n = 0;
	for (offset = 0; offset < length; offset += common.length) {
		if (length - offset < sizeof(common))
			return (errno = EPROTO, -1);
		memcpy(&common, p + offset, sizeof(common));
		if (common.length < sizeof(common) ||
		    common.length > length - offset ||
		    common.version != RTM_VERSION)
			return (errno = EPROTO, -1);
		/* Address records are deliberately not exposed by this
		 * operation. */
		if (common.type == RTM_NEWADDR) {
			if (common.length < sizeof(struct ifa_msghdrl))
				return (errno = EPROTO, -1);
			continue;
		}
		if (common.type != RTM_IFINFO ||
		    common.length < offsetof(struct if_msghdrl, ifm_data))
			return (errno = EPROTO, -1);
		memset(&header, 0, sizeof(header));
		memcpy(&header, p + offset,
		    offsetof(struct if_msghdrl, ifm_data));
		if (header.ifm_index == 0 || header.ifm_addrs != RTA_IFP ||
		    header.ifm_len > common.length ||
		    header.ifm_data_off <
			offsetof(struct if_msghdrl, ifm_data) ||
		    header.ifm_data_off > header.ifm_len ||
		    header.ifm_len - header.ifm_data_off <
			offsetof(struct if_data, ifi_metric))
			return (errno = EPROTO, -1);
		memset(&stats, 0, sizeof(stats));
		memcpy(&stats, p + offset + header.ifm_data_off,
		    offsetof(struct if_data, ifi_metric));
		if (stats.ifi_datalen < offsetof(struct if_data, ifi_metric) ||
		    stats.ifi_datalen > header.ifm_len - header.ifm_data_off ||
		    stats.ifi_link_state > LINK_STATE_UP)
			return (errno = EPROTO, -1);
		available = common.length - header.ifm_len;
		address = p + offset + header.ifm_len;
		if (available < offsetof(struct sockaddr_dl, sdl_data))
			return (errno = EPROTO, -1);
		memset(&link, 0, sizeof(link));
		memcpy(&link, address, offsetof(struct sockaddr_dl, sdl_data));
		name_length = link.sdl_nlen;
		if (link.sdl_family != AF_LINK ||
		    link.sdl_index != header.ifm_index ||
		    link.sdl_len > available ||
		    link.sdl_len < offsetof(struct sockaddr_dl, sdl_data) +
			    name_length + link.sdl_alen + link.sdl_slen ||
		    name_length == 0 || name_length >= SYSCTLCMP_IFNAME_SIZE ||
		    memchr(address + offsetof(struct sockaddr_dl, sdl_data), 0,
			name_length) != NULL)
			return (errno = EPROTO, -1);
		if (n == SYSCTLCMP_MAX_INTERFACES)
			return (errno = EOVERFLOW, -1);
		records[n].index = header.ifm_index;
		records[n].flags = (uint32_t)header.ifm_flags;
		records[n].mtu = stats.ifi_mtu;
		records[n].link_state = stats.ifi_link_state;
		memcpy(records[n].name,
		    address + offsetof(struct sockaddr_dl, sdl_data),
		    name_length);
		n++;
	}
	qsort(records, n, sizeof(*records), compare_index);
	for (size_t i = 0; i < n; i++) {
		if (i != 0 && records[i - 1].index == records[i].index)
			return (errno = EPROTO, -1);
		for (size_t j = 0; j < i; j++)
			if (strcmp(records[i].name, records[j].name) == 0)
				return (errno = EPROTO, -1);
	}
	memcpy(out, records, n * sizeof(*records));
	*count = n;
	return (0);
}

int
sysctlcmp_interfaces_collect(sysctlcmp_iflist_reader reader, void *context,
    struct sysctlcmp_interface *out, size_t *count)
{
	void *buffer;
	size_t capacity, length;
	int result, error;

	if (reader == NULL || out == NULL || count == NULL)
		return (errno = EINVAL, -1);
	/* Interface churn can enlarge the dump between probing and copying. */
	for (unsigned attempt = 0; attempt < 3; attempt++) {
		capacity = 0;
		if (reader(context, NULL, &capacity) == -1)
			return (-1);
		if (capacity > SYSCTLCMP_IFLIST_MAX_BYTES)
			return (errno = EOVERFLOW, -1);
		buffer = malloc(capacity == 0 ? 1 : capacity);
		if (buffer == NULL)
			return (-1);
		length = capacity;
		result = reader(context, buffer, &length);
		error = errno;
		if (result == 0) {
			if (length > capacity) {
				result = -1;
				error = EPROTO;
			} else {
				result = sysctlcmp_interfaces_parse(buffer,
				    length, out, count);
				error = errno;
			}
		}
		free(buffer);
		if (result == 0)
			return (0);
		if (error != ENOMEM)
			return (errno = error, -1);
	}
	return (errno = EAGAIN, -1);
}
