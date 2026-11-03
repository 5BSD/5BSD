#ifndef __HYPERTRACE_H_
#define __HYPERTRACE_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/*
 * HyperTrace defines
 */
#define	HYPERTRACE_MAX_VMS      1024
#define	HYPERTRACE_HOSTID       0
#define	HYPERTRACE_ARGS_MAX     10
#define HYPERTRACE_ARGS_WALLTIME_VALID 0x1ULL
/* The DIF hypercall instruction's R1 byte requests this many raw PCs. */
#define HYPERTRACE_STACK_MAX_FRAMES 64U
/* A stack record keeps its guest identity so libdtrace does not look up a
 * guest PC in the host kernel's symbol table. The low word is frame count. */
#define HYPERTRACE_STACK_GUEST_TAG 0x8000000000000000ULL
#define HYPERTRACE_STACK_VMID_SHIFT 32
#define HYPERTRACE_STACK_GUEST(v) (((v) & HYPERTRACE_STACK_GUEST_TAG) != 0)
#define HYPERTRACE_STACK_VMID(v) \
	((uint16_t)(((v) >> HYPERTRACE_STACK_VMID_SHIFT) & 0xffffU))
#define HYPERTRACE_STACK_NFRAMES(v) ((uint32_t)(v))
#define HYPERTRACE_STACK_ENCODE(vmid, frames) \
	(HYPERTRACE_STACK_GUEST_TAG | \
	((uint64_t)(vmid) << HYPERTRACE_STACK_VMID_SHIFT) | \
	(uint32_t)(frames))

/* USTACK's first 64-bit slot is a native PID for host probes. Virtual
 * probes tag that slot so libdtrace never resolves guest PCs in a host
 * process with the same PID. Guest symbols need a separate VM-aware map. */
#define HYPERTRACE_USTACK_GUEST_TAG 0x8000000000000000ULL
#define HYPERTRACE_USTACK_VMID_SHIFT 32
#define HYPERTRACE_USTACK_PID_MASK 0xffffffffULL
#define HYPERTRACE_USTACK_GUEST(v) (((v) & HYPERTRACE_USTACK_GUEST_TAG) != 0)
#define HYPERTRACE_USTACK_VMID(v) \
	((uint16_t)(((v) >> HYPERTRACE_USTACK_VMID_SHIFT) & 0xffffU))
#define HYPERTRACE_USTACK_PID(v) ((uint32_t)((v) & HYPERTRACE_USTACK_PID_MASK))
#define HYPERTRACE_USTACK_ENCODE(vmid, pid) \
	(HYPERTRACE_USTACK_GUEST_TAG | \
	((uint64_t)(vmid) << HYPERTRACE_USTACK_VMID_SHIFT) | (uint32_t)(pid))

/* UADDR uses the same tagged VM/PID first word as USTACK. */
#define HYPERTRACE_UADDR_GUEST(v) HYPERTRACE_USTACK_GUEST(v)
#define HYPERTRACE_UADDR_VMID(v) HYPERTRACE_USTACK_VMID(v)
#define HYPERTRACE_UADDR_PID(v) HYPERTRACE_USTACK_PID(v)
#define HYPERTRACE_UADDR_ENCODE(vmid, pid) \
	HYPERTRACE_USTACK_ENCODE(vmid, pid)

/* Version 2 host forwarding envelope has a fixed little-endian wire form. */
#define HYPERTRACE_ENVELOPE_MAGIC 0x32565448U
#define HYPERTRACE_ENVELOPE_VERSION 2
#define HYPERTRACE_TARGET_MAGIC 0x32544748U
struct hypertrace_vm_identity {
	uint64_t epoch;
	uint16_t vmid;
	uint16_t reserved[3];
};
#define HYPERTRACE_VM_ATTEST_NAME_LEN 128
struct hypertrace_vm_attestation {
	uint64_t epoch;
	uint16_t vmid;
	uint16_t reserved[3];
	char name[HYPERTRACE_VM_ATTEST_NAME_LEN];
};
/* A zero live result is usable as a release witness only when a trusted
 * journal previously bound this exact VM lifetime. Kernel publication of
 * zero follows the DTrace cross-CPU drain. */
struct hypertrace_epoch_query {
	uint64_t epoch;
	uint16_t vmid;
	uint16_t reserved[3];
	uint32_t live;
	uint32_t reserved2;
};
#define HYPERTRACE_IOC_EPOCH_QUERY \
	_IOWR('H', 1, struct hypertrace_epoch_query)
/* A source handoff may stop guest-origin ECB actions without retiring the
 * VM identity. The exact epoch prevents a stale caller from gating a reused
 * VMID. The query reports this DTrace gate, not the VMM lifetime. */
struct hypertrace_epoch_gate {
	uint64_t epoch;
	uint16_t vmid;
	uint16_t reserved[3];
	uint32_t suspended;
	uint32_t reserved2;
	uint8_t token[16];	/* handoff owner; zero on query input */
	uint8_t previous_token[16]; /* observed owner on SUSPEND; zero otherwise */
};
#define HYPERTRACE_IOC_EPOCH_SUSPEND \
	_IOW('H', 2, struct hypertrace_epoch_gate)
#define HYPERTRACE_IOC_EPOCH_RESUME \
	_IOW('H', 3, struct hypertrace_epoch_gate)
#define HYPERTRACE_IOC_EPOCH_GATE_QUERY \
	_IOWR('H', 4, struct hypertrace_epoch_gate)
typedef struct dtrace_handle_lifetime {
	uint64_t generation[2];
	uint64_t serial;
	uint32_t retired;
	uint32_t reserved;
} dtrace_handle_lifetime_t;
/* Privileged read-only state query; opening this device creates no consumer. */
#define HYPERTRACE_IOC_HANDLE_QUERY \
	_IOWR('H', 5, dtrace_handle_lifetime_t)
struct hypertrace_vm_envelope {
	uint32_t magic;
	uint16_t version;
	uint16_t vmid;
	uint64_t epoch;
	uint64_t name_length;
};

/*
 * XXX: This should be defined to dtrace_id_t, but because of annoying linking
 * issues, we have to do it this way. It should be fixed, but for now we just
 * have to manually keep dtrace_id_t and hypertrace_id_t in sync.
 */
typedef int hypertrace_id_t;

/*
 * The arguments that we pass in from the guest to host to implement builtin
 * variables. (v) denotes that we have to validate the argument before we send
 * it off to DTrace. The guest fills this envelope; the VMM replaces fields
 * marked (h) with host-attested values before dispatching a virtual probe.
 */
typedef struct hypertrace_args {
	uintptr_t htr_args[HYPERTRACE_ARGS_MAX]; /* guest probe args */
	void *htr_curthread;                     /* guest thread */
	char *htr_execname;                      /* (v) guest execname */
	char *htr_execargs;                      /* (v) guest execargs */
	lwpid_t htr_tid;                         /* guest tid */
	pid_t htr_pid;                           /* guest pid */
	pid_t htr_ppid;                          /* guest ppid */
	uid_t htr_uid;                           /* guest uid */
	gid_t htr_gid;                           /* guest gid */
	int htr_errno;                           /* guest errno */
	u_int htr_curcpu;                        /* (h) guest vCPU ID */
	u_int htr_execargs_len;                  /* (v) guest execargs */
	char *htr_jailname;                      /* (v) guest jailname */
	int htr_jid;                             /* guest jid */
	char *htr_immstack;                      /* guest immstack */
	int htr_immstacksize;                    /* guest immstack size */
	uintptr_t *htr_pcstack;                  /* guest raw kernel PCs */
	uint32_t htr_pcstack_count;              /* populated PC slots */
	uint32_t htr_pcstack_reserved;
	u_int htr_entry;                         /* (v) guest entry-probe context */
	uint64_t htr_stackdepth;                 /* guest kernel stack depth */
	uintptr_t htr_caller;                   /* guest kernel caller PC */
	uint64_t htr_vtimestamp;                /* guest thread virtual time */
	uint64_t htr_timestamp;                 /* guest monotonic probe time */
	uint64_t htr_walltimestamp;             /* guest wall clock, when valid */
	uint64_t htr_present;                   /* HYPERTRACE_ARGS_*_VALID */
} hypertrace_args_t;

static __inline int
hypertrace_pcstack_valid(const hypertrace_args_t *args)
{
	return (args->htr_pcstack_reserved == 0 &&
	    args->htr_pcstack_count <= HYPERTRACE_STACK_MAX_FRAMES &&
	    (args->htr_pcstack_count == 0) == (args->htr_pcstack == 0) &&
	    ((uintptr_t)args->htr_pcstack & (sizeof(uintptr_t) - 1)) == 0 &&
	    (uintptr_t)args->htr_pcstack <= ~(uintptr_t)0 -
	    (size_t)args->htr_pcstack_count * sizeof(uintptr_t));
}

/*
 * Handles that depend on hypertrace.ko being loaded. This would normally not be
 * needed, but the weird interfaces between CDDL and BSD code in the kernel make
 * it necessary for anything to work. Maybe there is a better way, but this will
 * do for now. This acts as a public interface to HyperTrace for both FreeBSD
 * and DTrace.
 */
extern int        hypertrace_probe(const void *, hypertrace_id_t, hypertrace_args_t *);
extern lwpid_t    (*hypertrace_gettid)(const void *);
extern uint16_t   (*hypertrace_getns)(const void *);
extern const char *(*hypertrace_getname)(const void *);
extern int        (*hypertrace_getreg)(const void *, int, uint64_t *);
extern int        (*hypertrace_guest_copyin)(const void *, uint64_t, void *, size_t);
extern int        (*hypertrace_guest_user_copyin)(const void *, uint64_t, void *, size_t);
extern int        (*hypertrace_guest_user_copyout)(const void *, uint64_t, const void *, size_t);
extern int        (*hypertrace_check_epoch)(uint16_t, uint64_t);
extern int        (*hypertrace_create_probes)(uint16_t, uint64_t, void *, size_t);
extern int        (*hypertrace_rmprobe)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_is_enabled)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_enable)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_disable)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_suspend)(uint16_t, hypertrace_id_t);
extern int        (*hypertrace_resume)(uint16_t, hypertrace_id_t);

#ifdef _KERNEL
#ifdef __amd64__
struct vm_guest_paging;
/* Caller holds the guest pmap lock, acquired outside probe context. */
int dtrace_guest_copy(struct vm_guest_paging *, uint64_t, void *, size_t, int);
#endif
/* IDs remain unavailable while an old tracing consumer owns probes. */
int hypertrace_vm_alloc(uint16_t *, uint64_t *);
int hypertrace_vm_release(uint16_t, uint64_t);
/* Serialize provider hook publication/retirement with DTrace control paths. */
void dtrace_hypertrace_config_lock(void);
/* Caller holds the DTrace configuration lock. */
int dtrace_handle_query(dtrace_handle_lifetime_t *);
void dtrace_hypertrace_config_unlock(void);
/* Called under the configuration lock; revoke drains in-flight ECBs. */
int dtrace_hypertrace_epoch_publish(uint16_t, uint64_t);
int dtrace_hypertrace_epoch_revoke(uint16_t, uint64_t);
int dtrace_hypertrace_epoch_suspend(uint16_t, uint64_t);
int dtrace_hypertrace_epoch_resume(uint16_t, uint64_t);
int dtrace_hypertrace_epoch_suspended(uint16_t, uint64_t);
/* Roll back an unpublished virtual probe while holding the config locks. */
void dtrace_vprobe_discard(uint16_t, hypertrace_id_t);
#endif

#endif // __HYPERTRACE_H_
