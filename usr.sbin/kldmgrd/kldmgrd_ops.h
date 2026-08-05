/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _KLDMGRD_OPS_H_
#define	_KLDMGRD_OPS_H_

#include <sys/types.h>
#include <sys/linker.h>

#include <stdbool.h>
#include <stdint.h>

struct kldmgr_module_request;
struct kldmgr_list_entry;

struct kldmgrd_backend {
	int	(*load)(const char *, void *);
	int	(*find)(const char *, void *);
	int	(*unload)(int, void *);
	int	(*next)(int, void *);
	int	(*stat)(int, struct kld_file_stat *, void *);
	void	*context;
};

int	kldmgrd_module_name_valid(const char *, size_t);
int	kldmgrd_execute_module(uint16_t,
	    const struct kldmgr_module_request *, bool,
	    const struct kldmgrd_backend *, int *);
int	kldmgrd_list(bool, const struct kldmgrd_backend *,
	    struct kldmgr_list_entry *, size_t, size_t *);

#endif /* !_KLDMGRD_OPS_H_ */
