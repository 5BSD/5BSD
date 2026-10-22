/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BHYVE_COV_VMMFAKE_H
#define BHYVE_COV_VMMFAKE_H
#include <stddef.h>
#include <stdint.h>

#define VMMFAKE_RING 64
struct vmmfake_record {
	unsigned long cmd;
	int fd;
	size_t len;
	unsigned char in[512];
};

const char *vmmfake_cmd_name(unsigned long);
void vmmfake_fail(const char *, int, int);
void vmmfake_clear_faults(void);
void vmmfake_fail_spec(const char *);
void vmmfake_preempt_next_alloc(const char *);
int vmmfake_last_mmap_nocore(void);
void vmmfake_reset(void);
const struct vmmfake_record *vmmfake_last(unsigned long);
unsigned long vmmfake_count(void);
unsigned long vmmfake_cmd_count(unsigned long);
uint64_t vmmfake_default_register(int, int);
int vmmfake_cap_available(int);
int vmmfake_vm_exists(const char *);
int vmmfake_set_exitcode(int);
int vmmfake_mark_suspended(const char *, uint64_t, uint64_t);
int vmmfake_vm_suspend_how(const char *);
int vmmfake_vm_identity(const char *, uint16_t *, uint64_t *);
int vmmfake_counts(const char *, int *, int *, int *);
int vmmfake_set_identity(const char *, uint16_t, uint64_t);
#endif
