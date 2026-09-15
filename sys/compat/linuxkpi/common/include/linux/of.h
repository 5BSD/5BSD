/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Serenity Cyber Security, LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _LINUXKPI_LINUX_OF_H
#define	_LINUXKPI_LINUX_OF_H

#include <linux/kobject.h>
#include <linux/refcount.h>
#include <linux/types.h>

struct device;
struct property {
	struct property *next;
	char *name;
	void *value;
	int length;
};

/* A reference-counted snapshot of the native, boot-time device tree node. */
struct device_node {
	refcount_t refs;
	int bsd_node;
	struct property *properties;
};

struct device_node *linux_of_node_from_handle(int);
struct device_node *linux_of_find_node_by_path(const char *);
struct device_node *linux_of_node_get(struct device_node *);
void linux_of_node_put(struct device_node *);
const void *linux_of_get_property(const struct device_node *, const char *, int *);
int linux_of_property_read_string_index(const struct device_node *, const char *,
    int, const char **);
int linux_of_property_count_strings(const struct device_node *, const char *);
int linux_of_property_read_u32(const struct device_node *, const char *, u32 *);
int linux_of_get_mac_address(const struct device_node *, u8 *);
bool linux_of_device_is_compatible(const struct device_node *, const char *);
struct device_node *linux_of_get_sdio_node(device_t, unsigned int);
#define of_find_node_by_path linux_of_find_node_by_path
#define of_node_get linux_of_node_get
#define of_node_put linux_of_node_put
#define of_get_property linux_of_get_property
#define of_property_read_string_index linux_of_property_read_string_index
#define of_property_count_strings linux_of_property_count_strings
#define of_property_read_u32 linux_of_property_read_u32
#define of_device_is_compatible linux_of_device_is_compatible
static inline int
of_property_read_string(const struct device_node *np, const char *name,
    const char **value)
{
	return (of_property_read_string_index(np, name, 0, value));
}
static inline bool
of_property_read_bool(const struct device_node *np, const char *name)
{
	return (of_get_property(np, name, NULL) != NULL);
}

#endif
