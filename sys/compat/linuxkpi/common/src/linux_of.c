/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux OF property access over snapshots of the native boot device tree. */
#include "opt_platform.h"
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/endian.h>
#ifdef FDT
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>

struct device_node *
linux_of_node_get(struct device_node *np)
{

	if (np != NULL)
		refcount_inc(&np->refs);
	return (np);
}

void
linux_of_node_put(struct device_node *np)
{
	struct property *prop;

	if (np == NULL || !refcount_dec_and_test(&np->refs))
		return;
	while ((prop = np->properties) != NULL) {
		np->properties = prop->next;
		kfree(prop->name);
		kfree(prop->value);
		kfree(prop);
	}
	kfree(np);
}

struct device_node *
linux_of_node_from_handle(int node)
{
#ifdef FDT
	struct device_node *np;
	struct property *prop;
	char name[256], next[256];
	const char *previous;
	int length, result;

	if (node <= 0)
		return (NULL);
	np = kzalloc(sizeof(*np), GFP_KERNEL);
	if (np == NULL)
		return (NULL);
	refcount_set(&np->refs, 1);
	np->bsd_node = node;
	/* The native FDT backend uses NULL to request the first property. */
	previous = NULL;
	while ((result = OF_nextprop(node, previous, next, sizeof(next))) == 1) {
		/* OF_nextprop may return a full, unterminated name buffer. */
		if (memchr(next, '\0', sizeof(next)) == NULL)
			goto fail;
		strlcpy(name, next, sizeof(name));
		previous = name;
		length = OF_getproplen(node, name);
		if (length < 0)
			goto fail;
		prop = kzalloc(sizeof(*prop), GFP_KERNEL);
		if (prop == NULL)
			goto fail;
		prop->next = np->properties;
		np->properties = prop;
		prop->name = kstrdup(name, GFP_KERNEL);
		/* A zero-length boolean property must have a non-NULL value. */
		prop->value = kmalloc(max(1, length), GFP_KERNEL);
		prop->length = length;
		if (prop->name == NULL || prop->value == NULL ||
		    (length != 0 && OF_getprop(node, name, prop->value, length) != length))
			goto fail;
	}
	if (result != 0)
		goto fail;
	return (np);
fail:
	linux_of_node_put(np);
#else
	(void)node;
#endif
	return (NULL);
}

struct device_node *
linux_of_find_node_by_path(const char *path)
{

#ifdef FDT
	if (path != NULL)
		return (linux_of_node_from_handle(OF_finddevice(path)));
#else
	(void)path;
#endif
	return (NULL);
}

const void *
linux_of_get_property(const struct device_node *np, const char *name, int *length)
{
	struct property *prop;

	if (np != NULL && name != NULL) {
		for (prop = np->properties; prop != NULL; prop = prop->next) {
			if (strcmp(prop->name, name) != 0)
				continue;
			if (length != NULL)
				*length = prop->length;
			return (prop->value);
		}
	}
	return (NULL);
}

int
linux_of_property_read_string_index(const struct device_node *np,
    const char *name, int index, const char **value)
{
	const char *strings;
	size_t size;
	int length;

	if (index < 0 || value == NULL)
		return (-EINVAL);
	strings = linux_of_get_property(np, name, &length);
	if (strings == NULL)
		return (-EINVAL);
	while (length > 0) {
		size = strnlen(strings, length);
		if (size == (size_t)length)
			return (-EILSEQ);
		if (index-- == 0) {
			*value = strings;
			return (0);
		}
		strings += size + 1;
		length -= size + 1;
	}
	return (-ENODATA);
}

int
linux_of_property_count_strings(const struct device_node *np, const char *name)
{
	const char *strings;
	size_t size;
	int count = 0, length;

	strings = linux_of_get_property(np, name, &length);
	if (strings == NULL)
		return (-EINVAL);
	if (length == 0)
		return (-ENODATA);
	while (length > 0) {
		size = strnlen(strings, length);
		if (size == (size_t)length)
			return (-EILSEQ);
		strings += size + 1;
		length -= size + 1;
		count++;
	}
	return (count);
}

int
linux_of_property_read_u32(const struct device_node *np, const char *name, u32 *value)
{
	const void *data;
	int length;

	if (value == NULL)
		return (-EINVAL);
	data = linux_of_get_property(np, name, &length);
	if (data == NULL)
		return (-EINVAL);
	if (length == 0)
		return (-ENODATA);
	if (length < (int)sizeof(*value))
		return (-EOVERFLOW);
	*value = be32dec(data);
	return (0);
}

bool
linux_of_device_is_compatible(const struct device_node *np, const char *compatible)
{
	const char *value;

	for (int i = 0; linux_of_property_read_string_index(np, "compatible", i,
	    &value) == 0; i++) {
		if (strcmp(value, compatible) == 0)
			return (true);
	}
	return (false);
}

int
linux_of_get_mac_address(const struct device_node *np, u8 *address)
{
	static const char *names[] = { "mac-address", "local-mac-address", "address" };
	const u8 *value;
	int length;

	for (unsigned int i = 0; i < nitems(names); i++) {
		value = linux_of_get_property(np, names[i], &length);
		if (value != NULL && length == ETH_ALEN && is_valid_ether_addr(value)) {
			memcpy(address, value, ETH_ALEN);
			return (0);
		}
	}
	return (-ENODEV);
}

struct device_node *
linux_of_get_sdio_node(device_t host, unsigned int fn)
{
#ifdef FDT
	phandle_t node, child;
	pcell_t reg;

	node = ofw_bus_get_node(host);
	if (node > 0) {
		for (child = OF_child(node); child > 0; child = OF_peer(child)) {
			if (!ofw_bus_node_status_okay(child) ||
			    OF_getencprop(child, "reg", &reg, sizeof(reg)) != sizeof(reg))
				continue;
			if (reg == fn)
				return (linux_of_node_from_handle(child));
		}
	}
#else
	(void)host;
	(void)fn;
#endif
	return (NULL);
}
