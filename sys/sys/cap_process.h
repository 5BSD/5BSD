/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SYS_CAP_PROCESS_H_
#define _SYS_CAP_PROCESS_H_
#include <sys/types.h>
#define MAC_CAP_PROCESS_SET	      1
#define MAC_CAP_PROCESS_GET	      2
#define MAC_CAP_PROCESS_CLEAR	      3
#define MAC_CAP_PROCESS_INFO	      4
#define MAC_CAP_PROCESS_ORIGIN_EXPORT 5
#define MAC_CAP_PROCESS_ORIGIN_SET    6
struct mac_cap_process_info {
	uint64_t identity;
	uint64_t responsible_identity;
	uint64_t generation;
	int32_t pid;
	int32_t responsible_pid;
	uint32_t uid;
	uint32_t present;
};
#ifndef _KERNEL
__BEGIN_DECLS
int cap_process(int op, int fd, uid_t uid, void *data);
__END_DECLS
#endif
#ifdef _KERNEL
struct proc;
void mac_capability_process_info(struct proc *, struct mac_cap_process_info *);
#endif
#endif
