/* SPDX-License-Identifier: BSD-2-Clause */
/* Harness API for the DTrace/HyperTrace kernel suites.  Not production. */
#ifndef KHX_DTRACE_H
#define KHX_DTRACE_H

struct khx_file;
struct khx_file *khx_file_new(void);
void khx_file_set_current(struct khx_file *fp);
void khx_file_close(struct khx_file *fp);

int khx_callout_fire(void (*func)(void *));
int khx_callout_pending(void (*func)(void *));
void khx_fail_alloc_unr(int on);
void *khx_eventhandler_find(const char *name, void **arg);
void khx_priv_deny_all(int on);
long khx_psignal_count(void);
long khx_kmem_mismatches(void);
void khx_taskqs_run(void);
void khx_preload_dof(const char *buf, unsigned long len);
int khx_eh_invoke(const char *name, void (*call)(void *func, void *arg,
    void *ctx), void *ctx);
struct kobjop_desc;
void khx_kobj_bind(struct kobjop_desc *desc, void (*func)(void));
int khx_psignal_last(pid_t *pid);
long khx_kdb_count(void);
uint64_t khx_mbufid_epoch(uint16_t vmid);
int khx_interrupts_disabled(void);
void khx_set_hrtime(long long t);
void khx_hypercall_result(int ret);
long khx_hypercall_count(void);
struct hypertrace_args;
const struct hypertrace_args *khx_hypercall_last(int *id, uintptr_t **pcstack);
const struct hypertrace_args *khx_hypercall_nth(long n, int *id,
    uintptr_t **pcstack);
void khx_guest_map(int slot, uint64_t gla, void *hva, uint64_t len);
void khx_cpuid_bhyve_guest(int on);

extern uint64_t khx_probe_args[16];
extern unsigned long khx_regs[64];
extern int khx_kstack_depth, khx_ustack_depth;
extern uint64_t khx_ustack[64];
#endif
