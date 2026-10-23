/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2026 Hans Rosenfeld
 * Copyright (c) 2022 Domagoj Stolfa <ds815@cam.ac.uk>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/cpuset.h>
#include <sys/domainset.h>
#include <sys/mman.h>
#ifdef BHYVE_SNAPSHOT
#include <sys/socket.h>
#include <sys/stat.h>
#endif
#include <sys/time.h>
#ifdef BHYVE_SNAPSHOT
#include <sys/un.h>
#endif
#include <sys/wait.h>

#include <machine/atomic.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <libgen.h>
#include <libutil.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sysexits.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#ifdef BHYVE_SNAPSHOT
#include <ucl.h>
#include <unistd.h>

#include <libxo/xo.h>
#endif

#include <dev/vmm/vmm_mem.h>
#include <vmmapi.h>

#include "acpi.h"
#include "console.h"
#include "bhyverun.h"
#include "bootrom.h"
#include "config.h"
#include "debug.h"
#ifdef BHYVE_GDB
#include "gdb.h"
#endif
#include "ipc.h"
#include "globals.h"
#include "hypertrace.h"
#include "mem.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef __amd64__
#include "amd64/pci_lpc.h"
#endif
#include "qemu_fwcfg.h"
#include "snapshot_md.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#include "migration_session.h"
#include "migration_recovery.h"
#include "migration_credentials.h"
#include "migration_restart_command.h"
#include "migration_dest_image.h"
#include "migration_vsock_owner.h"
#endif
#include "tpm_device.h"
#include "vmgenc.h"
#include "vmexit.h"

#define MB		(1024UL * 1024)
#define GB		(1024UL * MB)

char *g_vmname = NULL;
int guest_ncpus;
uint16_t cpu_cores, cpu_sockets, cpu_threads;

int raw_stdio = 0;

#ifdef BHYVE_SNAPSHOT
char *restore_file;
#endif

static const int BSP = 0;

#ifdef __amd64__
static bool kernel_startup;
static uint64_t kernel_startup_generation;
#endif

static cpuset_t cpumask;

static struct vm_mem_domain guest_domains[VM_MAXMEMDOM];
static int guest_ndomains = 0;
#ifdef BHYVE_SNAPSHOT
static uint16_t *guest_vcpu_domains;
static bool guest_numa_restored;
#endif

static void vm_loop(struct vmctx *ctx, struct vcpu *vcpu);

static struct vcpu_info {
	struct vmctx	*ctx;
	struct vcpu	*vcpu;
	int		vcpuid;
	pthread_t	thread;
	bool		thread_created, thread_joined;
} *vcpu_info;

static cpuset_t **vcpumap;
static atomic_bool migration_retiring_cpus;
static void fbsdrun_migration_retire_wake(void);

void
fbsdrun_retire_cpus_begin(void)
{
	console_input_retire();
#ifdef __amd64__
	sci_retire();
#endif
	atomic_store_explicit(&migration_retiring_cpus, true, memory_order_release);
	fbsdrun_migration_retire_wake();
}

bool
fbsdrun_cpus_retiring(void)
{
	return (atomic_load_explicit(&migration_retiring_cpus, memory_order_acquire));
}

int
fbsdrun_retire_cpus_wait(void)
{
	int error;

	if (!fbsdrun_cpus_retiring())
		return (EINVAL);
	for (int i = 0; i < guest_ncpus; i++) {
		if (!vcpu_info[i].thread_created || vcpu_info[i].thread_joined)
			continue;
		error = pthread_join(vcpu_info[i].thread, NULL);
		if (error != 0)
			return (error);
		vcpu_info[i].thread_joined = true;
	}
	return (0);
}

static void
fbsdrun_retirecpu_if_requested(int vcpuid)
{
	if (fbsdrun_cpus_retiring()) {
		fbsdrun_deletecpu(vcpuid);
		pthread_exit(NULL);
	}
}

/* Migration acknowledgments are taken between complete VM-exit handlers.
 * The suspend ioctl alone only requests debug exits; it does not drain them. */
static pthread_mutex_t migration_cpu_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t migration_cpu_cond;
static pthread_once_t migration_cpu_once = PTHREAD_ONCE_INIT;
static atomic_bool migration_cpu_hold;
static int migration_cpu_parked, migration_cpu_init_error;

static void
fbsdrun_migration_cpu_init(void)
{
	pthread_condattr_t attr;
	int error;

	error = pthread_condattr_init(&attr);
	if (error == 0) {
		error = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
		if (error == 0)
			error = pthread_cond_init(&migration_cpu_cond, &attr);
		pthread_condattr_destroy(&attr);
	}
	migration_cpu_init_error = error;
}

static void
fbsdrun_migration_retire_wake(void)
{
	pthread_once(&migration_cpu_once, fbsdrun_migration_cpu_init);
	if (migration_cpu_init_error != 0)
		return;
	pthread_mutex_lock(&migration_cpu_mutex);
	pthread_cond_broadcast(&migration_cpu_cond);
	pthread_mutex_unlock(&migration_cpu_mutex);
}

static void
fbsdrun_migration_cpu_point(void)
{
	/* Avoid a lock on the normal VM-exit path when no cutover is pending. */
	if (!atomic_load_explicit(&migration_cpu_hold, memory_order_acquire))
		return;
	pthread_mutex_lock(&migration_cpu_mutex);
	if (atomic_load_explicit(&migration_cpu_hold, memory_order_relaxed)) {
		migration_cpu_parked++;
		pthread_cond_broadcast(&migration_cpu_cond);
		while (atomic_load_explicit(&migration_cpu_hold, memory_order_relaxed) &&
		    !fbsdrun_cpus_retiring())
			pthread_cond_wait(&migration_cpu_cond, &migration_cpu_mutex);
		migration_cpu_parked--;
	}
	pthread_mutex_unlock(&migration_cpu_mutex);
}

int
fbsdrun_migration_resume_cpus(struct vmctx *ctx)
{
	int error;

	pthread_once(&migration_cpu_once, fbsdrun_migration_cpu_init);
	if (migration_cpu_init_error != 0)
		return (migration_cpu_init_error);

	pthread_mutex_lock(&migration_cpu_mutex);
	if (fbsdrun_cpus_retiring())
		error = ECANCELED;
#ifdef __amd64__
	else if (vm_resume_all_cpus(ctx) != 0)
#else
	else if (bhyve_resume_powered_cpus(ctx) != 0)
#endif
		error = errno != 0 ? errno : EIO;
	else {
		atomic_store_explicit(&migration_cpu_hold, false, memory_order_release);
		pthread_cond_broadcast(&migration_cpu_cond);
		error = 0;
	}
	pthread_mutex_unlock(&migration_cpu_mutex);
	return (error);
}

int
fbsdrun_migration_pause_cpus(struct vmctx *ctx, bool *runnable)
{
	struct timespec deadline;
	int error, resume_error;

	*runnable = false;
	pthread_mutex_lock(&migration_cpu_mutex);
	if (atomic_load_explicit(&migration_cpu_hold, memory_order_relaxed) ||
	    fbsdrun_cpus_retiring()) {
		pthread_mutex_unlock(&migration_cpu_mutex);
		*runnable = false;
		return (EBUSY);
	}
	/* Only an unfenced source can remain runnable on setup failure. */
	*runnable = true;
	pthread_once(&migration_cpu_once, fbsdrun_migration_cpu_init);
	error = migration_cpu_init_error;
	if (error == 0 && clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		error = errno != 0 ? errno : EIO;
	if (error != 0) {
		pthread_mutex_unlock(&migration_cpu_mutex);
		return (error);
	}
	deadline.tv_sec += 30;
	atomic_store_explicit(&migration_cpu_hold, true, memory_order_release);
	*runnable = false;
	error = vm_suspend_all_cpus(ctx) == 0 ? 0 : (errno != 0 ? errno : EIO);
	while (error == 0 && migration_cpu_parked != guest_ncpus)
		error = pthread_cond_timedwait(&migration_cpu_cond,
		    &migration_cpu_mutex, &deadline);
	pthread_mutex_unlock(&migration_cpu_mutex);
	if (error != 0) {
		/* Even a failed suspend request may have changed CPU state. */
		resume_error = fbsdrun_migration_resume_cpus(ctx);
		*runnable = resume_error == 0;
		if (resume_error != 0)
			return (resume_error);
	}
	return (error);
}

#ifdef __amd64__
static int
kernel_startup_request(struct vmctx *ctx,
    struct vmm_startup_request *request)
{
	int error;

	do {
		error = vm_startup_request(ctx, request);
	} while (error != 0 && errno == EINTR);
	return (error);
}

static void
kernel_startup_configure(struct vmctx *ctx)
{
	struct vmm_startup_request request;

	memset(&request, 0, sizeof(request));
	request.version = VMM_STARTUP_REQUEST_VERSION;
	request.size = VMM_STARTUP_REQUEST_SIZE;
	request.operation = VMM_STARTUP_REQUEST_CONFIGURE;
	request.expected_vcpus = guest_ncpus;
	if (kernel_startup_request(ctx, &request) != 0)
		err(EX_OSERR, "kernel-owned INIT/SIPI configuration");
	if (request.generation == 0 ||
	    request.expected_vcpus != (uint32_t)guest_ncpus ||
	    request.entered_vcpus != 0 || request.bootstrap_entered != 0 ||
	    request.phase != VMM_STARTUP_REQUEST_PHASE_COLLECTING ||
	    request.owner != VMM_STARTUP_REQUEST_OWNER_KERNEL ||
	    request.execution != VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED)
		errx(EX_OSERR, "invalid kernel-owned INIT/SIPI configuration status");
	kernel_startup_generation = request.generation;
}

static void
kernel_startup_commit(struct vmctx *ctx)
{
	struct vmm_startup_request request;

	memset(&request, 0, sizeof(request));
	request.version = VMM_STARTUP_REQUEST_VERSION;
	request.size = VMM_STARTUP_REQUEST_SIZE;
	request.operation = VMM_STARTUP_REQUEST_WAIT_READY;
	request.generation = kernel_startup_generation;
	if (kernel_startup_request(ctx, &request) != 0)
		err(EX_OSERR, "waiting for kernel-owned INIT/SIPI vCPUs");
	if (request.generation != kernel_startup_generation ||
	    request.expected_vcpus != (uint32_t)guest_ncpus ||
	    request.entered_vcpus != (uint32_t)guest_ncpus ||
	    request.bootstrap_entered != 1 ||
	    request.phase != VMM_STARTUP_REQUEST_PHASE_COLLECTING ||
	    request.owner != VMM_STARTUP_REQUEST_OWNER_KERNEL ||
	    request.execution != VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED)
		errx(EX_OSERR, "invalid kernel-owned INIT/SIPI ready status");

	/*
	 * WAIT_READY returns status in fields that are reserved as zero on input.
	 * Build a new request rather than feeding those output values back into
	 * the management ABI.
	 */
	memset(&request, 0, sizeof(request));
	request.version = VMM_STARTUP_REQUEST_VERSION;
	request.size = VMM_STARTUP_REQUEST_SIZE;
	request.operation = VMM_STARTUP_REQUEST_COMMIT;
	request.generation = kernel_startup_generation;
	if (kernel_startup_request(ctx, &request) != 0)
		err(EX_OSERR, "committing kernel-owned INIT/SIPI vCPUs");
	if (request.generation != kernel_startup_generation ||
	    request.expected_vcpus != (uint32_t)guest_ncpus ||
	    request.entered_vcpus != (uint32_t)guest_ncpus ||
	    request.bootstrap_entered != 1 ||
	    request.phase != VMM_STARTUP_REQUEST_PHASE_COMMITTED ||
	    request.owner != VMM_STARTUP_REQUEST_OWNER_KERNEL ||
	    request.execution != VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED)
		errx(EX_OSERR, "invalid kernel-owned INIT/SIPI commit status");
}

static void
kernel_startup_refresh(struct vmctx *ctx)
{
	struct vmm_startup_request request;
	uint64_t previous_generation;

	previous_generation = kernel_startup_generation;
	memset(&request, 0, sizeof(request));
	request.version = VMM_STARTUP_REQUEST_VERSION;
	request.size = VMM_STARTUP_REQUEST_SIZE;
	request.operation = VMM_STARTUP_REQUEST_STATUS;
	if (kernel_startup_request(ctx, &request) != 0)
		err(EX_OSERR, "refreshing kernel-owned INIT/SIPI generation");
	if (request.generation == 0 ||
	    request.generation == previous_generation ||
	    request.expected_vcpus != (uint32_t)guest_ncpus ||
	    request.entered_vcpus != 0 || request.bootstrap_entered != 0 ||
	    request.phase != VMM_STARTUP_REQUEST_PHASE_COLLECTING ||
	    request.owner != VMM_STARTUP_REQUEST_OWNER_KERNEL ||
	    request.execution != VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED)
		errx(EX_OSERR, "invalid replacement INIT/SIPI generation status");
	kernel_startup_generation = request.generation;
}
#endif

static void
monitor_pipe_handler(int fd __unused, enum ev_type type __unused,
    void *param __unused)
{

	exit(BHYVE_EXIT_ERROR);
}

static void
monitor_pipe_init(int fd)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_EVENT);
	if (caph_rights_limit(fd, &rights) == -1)
		err(BHYVE_EXIT_ERROR, "Unable to apply rights to monitor pipe");
#endif

	if (mevent_add(fd, EVF_READ, monitor_pipe_handler, NULL) == NULL)
		errx(BHYVE_EXIT_ERROR, "Unable to register parent exit event");
}

/*
 * XXX This parser is known to have the following issues:
 * 1.  It accepts null key=value tokens ",," as setting "cpus" to an
 *     empty string.
 *
 * The acceptance of a null specification ('-c ""') is by design to match the
 * manual page syntax specification, this results in a topology of 1 vCPU.
 */
int
bhyve_topology_parse(const char *opt)
{
	char *cp, *str, *tofree;

	if (*opt == '\0') {
		set_config_value("sockets", "1");
		set_config_value("cores", "1");
		set_config_value("threads", "1");
		set_config_value("cpus", "1");
		return (0);
	}

	tofree = str = strdup(opt);
	if (str == NULL)
		errx(4, "Failed to allocate memory");

	while ((cp = strsep(&str, ",")) != NULL) {
		if (strncmp(cp, "cpus=", strlen("cpus=")) == 0)
			set_config_value("cpus", cp + strlen("cpus="));
		else if (strncmp(cp, "sockets=", strlen("sockets=")) == 0)
			set_config_value("sockets", cp + strlen("sockets="));
		else if (strncmp(cp, "cores=", strlen("cores=")) == 0)
			set_config_value("cores", cp + strlen("cores="));
		else if (strncmp(cp, "threads=", strlen("threads=")) == 0)
			set_config_value("threads", cp + strlen("threads="));
		else if (strchr(cp, '=') != NULL)
			goto out;
		else
			set_config_value("cpus", cp);
	}
	free(tofree);
	return (0);

out:
	free(tofree);
	return (-1);
}

static int
parse_int_value(const char *key, const char *value, int minval, int maxval)
{
	char *cp;
	long lval;

	errno = 0;
	lval = strtol(value, &cp, 0);
	if (errno != 0 || *cp != '\0' || cp == value || lval < minval ||
	    lval > maxval)
		errx(4, "Invalid value for %s: '%s'", key, value);
	return (lval);
}

int
bhyve_numa_parse(const char *opt)
{
	int id = -1;
	nvlist_t *nvl;
	char *cp, *str, *tofree;
	char pathbuf[64] = { 0 };
	char *size = NULL, *cpus = NULL, *domain_policy = NULL;

	if (*opt == '\0') {
		return (-1);
	}

	tofree = str = strdup(opt);
	if (str == NULL)
		errx(4, "Failed to allocate memory");

	while ((cp = strsep(&str, ",")) != NULL) {
		if (strncmp(cp, "id=", strlen("id=")) == 0)
			id = parse_int_value("id", cp + strlen("id="), 0,
			    UINT8_MAX);
		else if (strncmp(cp, "size=", strlen("size=")) == 0)
			size = cp + strlen("size=");
		else if (strncmp(cp,
		    "domain_policy=", strlen("domain_policy=")) == 0)
			domain_policy = cp + strlen("domain_policy=");
		else if (strncmp(cp, "cpus=", strlen("cpus=")) == 0)
			cpus = cp + strlen("cpus=");
	}

	if (id == -1) {
		EPRINTLN("Missing NUMA domain ID in '%s'", opt);
		goto out;
	}

	snprintf(pathbuf, sizeof(pathbuf), "domains.%d", id);
	nvl = find_config_node(pathbuf);
	if (nvl == NULL)
		nvl = create_config_node(pathbuf);
	if (size != NULL)
		set_config_value_node(nvl, "size", size);
	if (domain_policy != NULL)
		set_config_value_node(nvl, "domain_policy", domain_policy);
	if (cpus != NULL)
		set_config_value_node(nvl, "cpus", cpus);

	free(tofree);
	return (0);

out:
	free(tofree);
	return (-1);
}

void
bhyve_cfg_warn(const char *old, const char *new)
{
	if (get_config_value(old) != NULL &&
	    get_config_value(new) == NULL) {
		warnx("'%s' is deprecated, use '%s' instead", old, new);
		set_config_value(new, get_config_value(old));
	}
}

static void
calc_mem_affinity(size_t vm_memsize)
{
	int i;
	int error;
	nvlist_t *nvl;
	bool need_recalc;
	const char *value;
	size_t domain_sizes[VM_MAXMEMDOM];
	struct vm_mem_domain *dom;
	char pathbuf[64] = { 0 };

	need_recalc = false;
	for (i = 0; i < VM_MAXMEMDOM; i++) {
		dom = &guest_domains[i];
		snprintf(pathbuf, sizeof(pathbuf), "domains.%d", i);
		nvl = find_config_node(pathbuf);
		if (nvl == NULL) {
			break;
		}

		value = get_config_value_node(nvl, "size");
		need_recalc |= value == NULL;
		if (value != NULL && vm_parse_memsize(value, &dom->size)) {
			errx(EX_USAGE, "invalid memsize for domain %d: '%s'", i,
			    value);
		}

		dom->ds_mask = calloc(1, sizeof(domainset_t));
		if (dom->ds_mask == NULL) {
			errx(EX_OSERR, "Failed to allocate domainset mask");
		}
		dom->ds_size = sizeof(domainset_t);
		value = get_config_value_node(nvl, "domain_policy");
		if (value == NULL) {
			dom->ds_policy = DOMAINSET_POLICY_INVALID;
			DOMAINSET_ZERO(dom->ds_mask);
		} else if (domainset_parselist(value, dom->ds_mask, &dom->ds_policy) !=
		    CPUSET_PARSE_OK) {
				errx(EX_USAGE, "failed to parse domain policy '%s'", value);
		}
	}

	guest_ndomains = i;
	if (guest_ndomains == 0) {
		/*
		 * No domains were specified - create domain
		 * 0 holding all CPUs and memory.
		 */
		guest_ndomains = 1;
		guest_domains[0].size = vm_memsize;
	} else if (need_recalc) {
		warnx("At least one domain memory size was not specified, distributing"
		    " total VM memory size across all domains");
		error = vm_distribute_memory_domains(vm_memsize,
		    guest_ndomains, PAGE_SIZE, domain_sizes,
		    nitems(domain_sizes));
		if (error != 0)
			errx(EX_USAGE,
			    "cannot distribute %zu bytes across %d memory "
			    "domains in %u-byte allocation units: %s",
			    vm_memsize, guest_ndomains, PAGE_SIZE,
			    strerror(error));
		for (i = 0; i < guest_ndomains; i++)
			guest_domains[i].size = domain_sizes[i];
	}
}

/*
 * Set the sockets, cores, threads, and guest_cpus variables based on
 * the configured topology.
 *
 * The limits of UINT16_MAX are due to the types passed to
 * vm_set_topology().  vmm.ko may enforce tighter limits.
 */
static void
calc_topology(void)
{
	const char *value;
	bool explicit_cpus;
	uint64_t ncpus;

	value = get_config_value("cpus");
	if (value != NULL) {
		guest_ncpus = parse_int_value("cpus", value, 1, UINT16_MAX);
		explicit_cpus = true;
	} else {
		guest_ncpus = 1;
		explicit_cpus = false;
	}
	value = get_config_value("cores");
	if (value != NULL)
		cpu_cores = parse_int_value("cores", value, 1, UINT16_MAX);
	else
		cpu_cores = 1;
	value = get_config_value("threads");
	if (value != NULL)
		cpu_threads = parse_int_value("threads", value, 1, UINT16_MAX);
	else
		cpu_threads = 1;
	value = get_config_value("sockets");
	if (value != NULL)
		cpu_sockets = parse_int_value("sockets", value, 1, UINT16_MAX);
	else
		cpu_sockets = guest_ncpus;

	/*
	 * Compute sockets * cores * threads avoiding overflow.  The
	 * range check above insures these are 16 bit values.
	 */
	ncpus = (uint64_t)cpu_sockets * cpu_cores * cpu_threads;
	if (ncpus > UINT16_MAX)
		errx(4, "Computed number of vCPUs too high: %ju",
		    (uintmax_t)ncpus);

	if (explicit_cpus) {
		if (guest_ncpus != (int)ncpus)
			errx(4, "Topology (%d sockets, %d cores, %d threads) "
			    "does not match %d vCPUs",
			    cpu_sockets, cpu_cores, cpu_threads,
			    guest_ncpus);
	} else
		guest_ncpus = ncpus;
}

static int
bhyve_pincpu(int vcpu, int pcpu)
{
	const char *value;
	char *newval;
	char key[16];

	if (vcpu < 0) {
		fprintf(stderr, "invalid vcpu '%d'\n", vcpu);
		return (-1);
	}

	if (pcpu < 0 || pcpu >= CPU_SETSIZE) {
		fprintf(stderr, "hostcpu '%d' outside valid range from "
		    "0 to %d\n", pcpu, CPU_SETSIZE - 1);
		return (-1);
	}

	snprintf(key, sizeof(key), "vcpu.%d.cpuset", vcpu);
	value = get_config_value(key);

	if (asprintf(&newval, "%s%s%d", value != NULL ? value : "",
	    value != NULL ? "," : "", pcpu) == -1) {
		perror("failed to build new cpuset string");
		return (-1);
	}

	set_config_value(key, newval);
	free(newval);
	return (0);
}

int
bhyve_pincpu_parse(const char *opt)
{
	int vcpu_first, vcpu_last, pcpu_first, pcpu_last;
	int vcpu, pcpu;

	if (sscanf(opt, "%d-%d:%d-%d", &vcpu_first, &vcpu_last, &pcpu_first, &pcpu_last) == 4) {
		if (vcpu_first > vcpu_last || pcpu_first > pcpu_last) {
			fprintf(stderr, "invalid range (must be ascending): %s\n", opt);
			return (-1);
		}
		if ((vcpu_last - vcpu_first) != (pcpu_last - pcpu_first)) {
			fprintf(stderr, "range sizes do not match: %s\n", opt);
			return (-1);
		}
		for (vcpu = vcpu_first, pcpu = pcpu_first; vcpu <= vcpu_last; vcpu++, pcpu++)
			if (bhyve_pincpu(vcpu, pcpu) != 0)
				return (-1);
		return (0);
	}

	if (sscanf(opt, "%d:%d", &vcpu, &pcpu) == 2)
		return (bhyve_pincpu(vcpu, pcpu));

	fprintf(stderr, "invalid format: %s\n", opt);
	return (-1);
}

static void
parse_cpuset(int vcpu, const char *list, cpuset_t *set)
{
	char *cp, *token;
	int pcpu, start;

	CPU_ZERO(set);
	start = -1;
	token = __DECONST(char *, list);
	for (;;) {
		pcpu = strtoul(token, &cp, 0);
		if (cp == token)
			errx(4, "invalid cpuset for vcpu %d: '%s'", vcpu, list);
		if (pcpu < 0 || pcpu >= CPU_SETSIZE)
			errx(4, "hostcpu '%d' outside valid range from 0 to %d",
			    pcpu, CPU_SETSIZE - 1);
		switch (*cp) {
		case ',':
		case '\0':
			if (start >= 0) {
				if (start > pcpu)
					errx(4, "Invalid hostcpu range %d-%d",
					    start, pcpu);
				while (start < pcpu) {
					CPU_SET(start, set);
					start++;
				}
				start = -1;
			}
			CPU_SET(pcpu, set);
			break;
		case '-':
			if (start >= 0)
				errx(4, "invalid cpuset for vcpu %d: '%s'",
				    vcpu, list);
			start = pcpu;
			break;
		default:
			errx(4, "invalid cpuset for vcpu %d: '%s'", vcpu, list);
		}
		if (*cp == '\0')
			break;
		token = cp + 1;
	}
}

static void
build_vcpumaps(void)
{
	char key[16];
	const char *value;
	int vcpu;

	vcpumap = calloc(guest_ncpus, sizeof(*vcpumap));
	for (vcpu = 0; vcpu < guest_ncpus; vcpu++) {
		snprintf(key, sizeof(key), "vcpu.%d.cpuset", vcpu);
		value = get_config_value(key);
		if (value == NULL)
			continue;
		vcpumap[vcpu] = malloc(sizeof(cpuset_t));
		if (vcpumap[vcpu] == NULL)
			err(4, "Failed to allocate cpuset for vcpu %d", vcpu);
		parse_cpuset(vcpu, value, vcpumap[vcpu]);
	}
}

static void
set_vcpu_affinities(void)
{
	int cpu, error;
	nvlist_t *nvl = NULL;
	cpuset_t cpus;
	const char *value;
	char pathbuf[64] = { 0 };

#ifdef BHYVE_SNAPSHOT
	if (guest_vcpu_domains == NULL) {
		guest_vcpu_domains = malloc((size_t)guest_ncpus *
		    sizeof(*guest_vcpu_domains));
		if (guest_vcpu_domains == NULL)
			err(EX_OSERR, "Failed to allocate guest NUMA map");
		for (cpu = 0; cpu < guest_ncpus; cpu++)
			guest_vcpu_domains[cpu] = UINT16_MAX;
	}
	if (guest_numa_restored) {
		for (cpu = 0; cpu < guest_ncpus; cpu++) {
			error = acpi_add_vcpu_affinity(cpu,
			    guest_vcpu_domains[cpu]);
			if (error != 0)
				errx(BHYVE_EXIT_ERROR,
				    "Unable to restore vCPU %d NUMA affinity: %s",
				    cpu, strerror(error));
		}
		return;
	}
#endif
	for (int dom = 0; dom < guest_ndomains; dom++) {
		snprintf(pathbuf, sizeof(pathbuf), "domains.%d", dom);
		nvl = find_config_node(pathbuf);
		if (nvl == NULL)
			break;

		value = get_config_value_node(nvl, "cpus");
		if (value == NULL) {
			EPRINTLN("Missing CPU set for domain %d", dom);
			exit(BHYVE_EXIT_ERROR);
		}

		parse_cpuset(dom, value, &cpus);
		CPU_FOREACH_ISSET(cpu, &cpus) {
			if (cpu >= guest_ncpus)
				errx(EX_USAGE,
				    "vCPU %d in NUMA domain %d exceeds guest "
				    "vCPU count %d", cpu, dom, guest_ncpus);
#ifdef BHYVE_SNAPSHOT
			if (guest_vcpu_domains[cpu] != UINT16_MAX)
				errx(EX_USAGE,
				    "vCPU %d belongs to more than one NUMA "
				    "domain", cpu);
			guest_vcpu_domains[cpu] = (uint16_t)dom;
#endif
			error = acpi_add_vcpu_affinity(cpu, dom);
			if (error) {
				EPRINTLN(
				    "Unable to set vCPU %d affinity for domain %d: %s",
				    cpu, dom, strerror(error));
				exit(BHYVE_EXIT_ERROR);
			}
		}
	}
	if (guest_ndomains > 1 || nvl != NULL) {
#ifdef BHYVE_SNAPSHOT
		for (cpu = 0; cpu < guest_ncpus; cpu++) {
			if (guest_vcpu_domains[cpu] == UINT16_MAX)
				errx(EX_USAGE,
				    "vCPU %d does not belong to a NUMA domain",
				    cpu);
		}
#endif
		return;
	}

	/*
	 * If we're dealing with one domain and no cpuset was provided, create a
	 * default one holding all cpus.
	 */
	for (cpu = 0; cpu < guest_ncpus; cpu++) {
#ifdef BHYVE_SNAPSHOT
		guest_vcpu_domains[cpu] = 0;
#endif
		error = acpi_add_vcpu_affinity(cpu, 0);
		if (error) {
			EPRINTLN(
			    "Unable to set vCPU %d affinity for domain %d: %s",
			    cpu, 0, strerror(error));
			exit(BHYVE_EXIT_ERROR);
		}
	}
}

#ifdef BHYVE_SNAPSHOT
int
bhyve_numa_checkpoint_export(uint64_t *domain_sizes, size_t domain_capacity,
    uint16_t *vcpu_domains, size_t vcpu_capacity, size_t *domain_count)
{

	if (domain_sizes == NULL || vcpu_domains == NULL ||
	    domain_count == NULL || guest_ndomains <= 0 ||
	    (size_t)guest_ndomains > domain_capacity ||
	    guest_ncpus <= 0 || (size_t)guest_ncpus > vcpu_capacity ||
	    guest_vcpu_domains == NULL)
		return (EINVAL);
	for (int domain = 0; domain < guest_ndomains; domain++)
		domain_sizes[domain] = guest_domains[domain].size;
	memcpy(vcpu_domains, guest_vcpu_domains,
	    (size_t)guest_ncpus * sizeof(*vcpu_domains));
	*domain_count = (size_t)guest_ndomains;
	return (0);
}

int
bhyve_numa_restore_apply(const uint64_t *domain_sizes, size_t domain_count,
    const uint16_t *vcpu_domains, size_t vcpu_count, uint64_t memory_size)
{
	uint16_t *replacement;
	int error;

	if (vcpu_count != (size_t)guest_ncpus ||
	    domain_count > nitems(guest_domains))
		return (EINVAL);
	error = checkpoint_numa_mapping_validate(domain_sizes, domain_count,
	    vcpu_domains, vcpu_count, memory_size);
	if (error != 0)
		return (error);
	replacement = malloc(vcpu_count * sizeof(*replacement));
	if (replacement == NULL)
		return (ENOMEM);
	memcpy(replacement, vcpu_domains,
	    vcpu_count * sizeof(*replacement));
	for (size_t domain = 0; domain < domain_count; domain++)
		guest_domains[domain].size = (size_t)domain_sizes[domain];
	for (size_t domain = domain_count; domain < nitems(guest_domains);
	    domain++)
		guest_domains[domain].size = 0;
	free(guest_vcpu_domains);
	guest_vcpu_domains = replacement;
	guest_ndomains = (int)domain_count;
	guest_numa_restored = true;
	return (0);
}
#endif

void *
paddr_guest2host(struct vmctx *ctx, uintptr_t gaddr, size_t len)
{

	return (vm_map_gpa(ctx, gaddr, len));
}

#ifdef BHYVE_SNAPSHOT
uintptr_t
paddr_host2guest(struct vmctx *ctx, void *addr)
{
	return (vm_rev_map_gpa(ctx, addr));
}
#endif

int
fbsdrun_virtio_msix(void)
{

	return (get_config_bool_default("virtio.msix", true));
}

struct vcpu *
fbsdrun_vcpu(int vcpuid)
{
	return (vcpu_info[vcpuid].vcpu);
}

static void *
fbsdrun_start_thread(void *param)
{
	char tname[MAXCOMLEN + 1];
	struct vcpu_info *vi = param;
	int error;

	snprintf(tname, sizeof(tname), "vcpu %d", vi->vcpuid);
	pthread_set_name_np(pthread_self(), tname);

	if (vcpumap[vi->vcpuid] != NULL) {
		error = pthread_setaffinity_np(pthread_self(),
		    sizeof(cpuset_t), vcpumap[vi->vcpuid]);
		if (error != 0) {
			int i;

			/* pthread_setaffinity_np() returns the error code. */
			warnc(error, "Error pinning vcpu %d to host cpuset@%p",
			    vi->vcpuid, vcpumap[vi->vcpuid]);
			CPU_FOREACH_ISSET(i, vcpumap[vi->vcpuid]) {
				warnx("cpu %d enabled", i);
			}
			errc(EX_OSERR, error,
			    "could not set affinity for CPU %d", vi->vcpuid);
		}
	}

#ifdef BHYVE_SNAPSHOT
	checkpoint_cpu_add(vi->vcpuid);
#endif
#ifdef BHYVE_GDB
	gdb_cpu_add(vi->vcpu);
#endif

	vm_loop(vi->ctx, vi->vcpu);
	fbsdrun_retirecpu_if_requested(vi->vcpuid);
	/* We get here if the VM was destroyed asynchronously. */
	exit(BHYVE_EXIT_ERROR);
}

void
fbsdrun_addcpu(int vcpuid)
{
	struct vcpu_info *vi;
	int error;

	vi = &vcpu_info[vcpuid];

	error = vm_activate_cpu(vi->vcpu);
	if (error != 0)
		err(EX_OSERR, "could not activate CPU %d", vi->vcpuid);

	CPU_SET_ATOMIC(vcpuid, &cpumask);

	error = vm_suspend_cpu(vi->vcpu);
	if (error != 0)
		err(EX_OSERR, "could not suspend CPU %d", vi->vcpuid);

	vi->thread_joined = false;
	error = pthread_create(&vi->thread, NULL, fbsdrun_start_thread, vi);
	if (error != 0)
		errc(EX_OSERR, error, "could not create CPU %d thread",
		    vi->vcpuid);
	vi->thread_created = true;
}

void
fbsdrun_deletecpu(int vcpu)
{
	static pthread_mutex_t resetcpu_mtx = PTHREAD_MUTEX_INITIALIZER;
	static pthread_cond_t resetcpu_cond = PTHREAD_COND_INITIALIZER;

	pthread_mutex_lock(&resetcpu_mtx);
	if (!CPU_ISSET(vcpu, &cpumask)) {
		EPRINTLN("Attempting to delete unknown cpu %d", vcpu);
		exit(BHYVE_EXIT_ERROR);
	}

	CPU_CLR(vcpu, &cpumask);

	if (vcpu != BSP) {
		pthread_cond_signal(&resetcpu_cond);
		pthread_mutex_unlock(&resetcpu_mtx);
		pthread_exit(NULL);
		/* NOTREACHED */
	}

	while (!CPU_EMPTY(&cpumask)) {
		pthread_cond_wait(&resetcpu_cond, &resetcpu_mtx);
	}
	pthread_mutex_unlock(&resetcpu_mtx);
}

int
fbsdrun_suspendcpu(int vcpuid)
{
	return (vm_suspend_cpu(vcpu_info[vcpuid].vcpu));
}

static void
vm_loop(struct vmctx *ctx, struct vcpu *vcpu)
{
	struct vm_exit vme;
	struct vm_run vmrun;
#ifdef __amd64__
	struct vmm_startup_run_request startup_run;
	bool startup_admitted;
#endif
	int error, rc;
	enum vm_exitcode exitcode;
	cpuset_t active_cpus, dmask;

	fbsdrun_retirecpu_if_requested(vcpu_id(vcpu));
	error = vm_active_cpus(ctx, &active_cpus);
	fbsdrun_retirecpu_if_requested(vcpu_id(vcpu));
	assert(CPU_ISSET(vcpu_id(vcpu), &active_cpus));

	vmrun.vm_exit = &vme;
	vmrun.cpuset = &dmask;
	vmrun.cpusetsize = sizeof(dmask);

#ifdef __amd64__
	startup_admitted = !kernel_startup;
#endif

	while (1) {
		fbsdrun_migration_cpu_point();
		fbsdrun_retirecpu_if_requested(vcpu_id(vcpu));
#ifdef __amd64__
		if (!startup_admitted) {
			memset(&startup_run, 0, sizeof(startup_run));
			startup_run.version = VMM_STARTUP_RUN_REQUEST_VERSION;
			startup_run.size = VMM_STARTUP_RUN_REQUEST_SIZE;
			startup_run.generation = kernel_startup_generation;
			startup_run.cpuset_address = (uintptr_t)&dmask;
			startup_run.cpuset_size = sizeof(dmask);
			startup_run.exit_address = (uintptr_t)&vme;
			startup_run.exit_size = sizeof(vme);
			error = vm_run_generation(vcpu, &startup_run);
			if (error != 0 && errno == EINTR)
				continue;
			if (error == 0)
				startup_admitted = true;
		} else
#endif
			error = vm_run(vcpu, &vmrun);
		fbsdrun_retirecpu_if_requested(vcpu_id(vcpu));
		if (error != 0)
			break;

		exitcode = vme.exitcode;
		if (exitcode >= VM_EXITCODE_MAX ||
		    vmexit_handlers[exitcode] == NULL) {
			warnx("vm_loop: unexpected exitcode 0x%x", exitcode);
			exit(BHYVE_EXIT_ERROR);
		}

		rc = (*vmexit_handlers[exitcode])(ctx, vcpu, &vmrun);

		switch (rc) {
		case VMEXIT_CONTINUE:
			break;
		case VMEXIT_ABORT:
			abort();
		default:
			exit(BHYVE_EXIT_ERROR);
		}
	}
	EPRINTLN("vm_run error %d, errno %d", error, errno);
}

static int
num_vcpus_allowed(struct vmctx *ctx, struct vcpu *vcpu)
{
	uint16_t sockets, cores, threads, maxcpus;
	int tmp, error;

	/*
	 * The guest is allowed to spinup more than one processor only if the
	 * UNRESTRICTED_GUEST capability is available.
	 */
	error = vm_get_capability(vcpu, VM_CAP_UNRESTRICTED_GUEST, &tmp);
	if (error != 0)
		return (1);

	error = vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus);
	if (error == 0)
		return (maxcpus);
	else
		return (1);
}

static struct vmctx *
do_open(const char *vmname)
{
	struct vmctx *ctx;
	int error, flags;
	bool romboot, monitor;

	monitor = get_config_bool_default("monitor.enabled", false);
	/*
	 * Populate our vmname for use in DTrace probes.
	 */
	g_vmname = (char *)(uintptr_t)vmname;
	romboot = bootrom_boot();

	/*
	 * If we don't have a boot ROM, the guest context must have been
	 * initialized by bhyveload(8) or equivalent.
	 */
	ctx = vm_openf(vmname, romboot ? VMMAPI_OPEN_REINIT : 0);
	if (ctx == NULL) {
		if (errno != ENOENT)
			err(4, "vm_openf");
		if (!romboot)
			errx(4, "no bootrom was configured");
		flags = VMMAPI_OPEN_CREATE;
		if (monitor)
			flags |= VMMAPI_OPEN_CREATE_DESTROY_ON_CLOSE;
		ctx = vm_openf(vmname, flags);
		if (ctx == NULL)
			err(4, "vm_openf");
	}

#ifndef WITHOUT_CAPSICUM
	if (vm_limit_rights(ctx) != 0)
		err(EX_OSERR, "vm_limit_rights");
#endif

	error = vm_set_topology(ctx, cpu_sockets, cpu_cores, cpu_threads, 0);
	if (error)
		errx(EX_OSERR, "vm_set_topology");
	return (ctx);
}

bool
bhyve_parse_config_option(const char *option)
{
	const char *value;
	char *path;

	value = strchr(option, '=');
	if (value == NULL || value[1] == '\0')
		return (false);
	path = strndup(option, value - option);
	if (path == NULL)
		err(4, "Failed to allocate memory");
	set_config_value(path, value + 1);
	free(path);
	return (true);
}

void
bhyve_parse_simple_config_file(const char *path)
{
	FILE *fp;
	char *line, *cp;
	size_t linecap;
	unsigned int lineno;

	fp = fopen(path, "r");
	if (fp == NULL)
		err(4, "Failed to open configuration file %s", path);
	line = NULL;
	linecap = 0;
	lineno = 1;
	for (lineno = 1; getline(&line, &linecap, fp) > 0; lineno++) {
		if (*line == '#' || *line == '\n')
			continue;
		cp = strchr(line, '\n');
		if (cp != NULL)
			*cp = '\0';
		if (!bhyve_parse_config_option(line))
			errx(4, "%s line %u: invalid config option '%s'", path,
			    lineno, line);
	}
	free(line);
	fclose(fp);
}

#ifdef BHYVE_GDB
void
bhyve_parse_gdb_options(const char *opt)
{
	const char *sport;
	char *colon;

	if (opt[0] == 'w') {
		set_config_bool("gdb.wait", true);
		opt++;
	}

	colon = strrchr(opt, ':');
	if (colon == NULL) {
		sport = opt;
	} else {
		*colon = '\0';
		colon++;
		sport = colon;
		set_config_value("gdb.address", opt);
	}

	set_config_value("gdb.port", sport);
}
#endif

/* Prepare the control endpoint and sandbox before any inbound guest runs.
 * IPC's startup gate remains closed until main finishes its remaining work. */
static void
bhyve_prepare_control(struct vmctx *ctx)
{
	/* Absolute journal lookup must precede Capsicum and IPC publication.
	 * Remember missing/invalid storage for a later migration error; ordinary
	 * VM operation does not require a migration journal directory. */
#ifdef BHYVE_SNAPSHOT
	(void)migration_prod_source_prepare();
#endif

	/*
	 * Thread for handling bhyvectl commands.
	 */
	if (init_ipc_thread(ctx, get_config_value("rundir")) != 0)
		errx(EX_OSERR, "Failed to start IPC thread");

#ifndef WITHOUT_CAPSICUM
	caph_cache_catpages();

	if (caph_limit_stdout() == -1 || caph_limit_stderr() == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");

	if (caph_enter() == -1)
		errx(EX_OSERR, "cap_enter() failed");
#endif

}

int
main(int argc, char *argv[])
{
	int error, status;
	int max_vcpus, memflags;
	struct vcpu *bsp;
	struct vmctx *ctx;
	size_t memsize;
	const char *value, *vmname;
	int enable_hypertrace = 0;
	bool defer_hypertrace = false;
#ifdef BHYVE_SNAPSHOT
	struct restore_state rstate;
	int migrate_recv_fd = -1;
	int migrate_recovery_fd = -1;
	int migrate_recovery_listener = -1;
	struct migration_tls_credentials migrate_credentials;
	bool migrate_tls_enabled = false, migrate_plaintext_unix = false;
	bool migrate_reconstruct = false, migrate_recovery_image = false;
	uint8_t migrate_reconstruct_challenge[32];
	struct migration_prod_reconstruct *migrate_reconstruction = NULL;
#endif

	bhyve_init_config();
	bhyve_optparse(argc, argv);
	argc -= optind;
	argv += optind;

	if (argc > 1)
		bhyve_usage(1);

#ifndef BHYVE_SNAPSHOT
	if (get_config_value("migrate.recover_source_fd") != NULL ||
	    get_config_value("migrate.recover_source_vmid") != NULL ||
	    get_config_value("migrate.recover_source_epoch") != NULL ||
	    get_config_value("migrate.recover_source_name") != NULL)
		errx(EX_USAGE, "source migration recovery requires snapshot support");
	if (get_config_value("migrate.reconstruct") != NULL ||
	    get_config_value("migrate.reconstruct_previous_name") != NULL ||
	    get_config_value("migrate.recovery_image") != NULL)
		errx(EX_USAGE, "destination migration reconstruction requires snapshot support");
#endif
#ifdef BHYVE_SNAPSHOT
	{
		const char *values[] = {
		    get_config_value("migrate.recover_source_fd"),
		    get_config_value("migrate.recover_source_vmid"),
		    get_config_value("migrate.recover_source_epoch"),
		    get_config_value("migrate.tls.certificate_fd"),
		    get_config_value("migrate.tls.private_key_fd"),
		    get_config_value("migrate.tls.trust_fd"),
		    get_config_value("migrate.tls.peer_sha256") };
		if (values[0] != NULL || values[1] != NULL || values[2] != NULL ||
		    get_config_value("migrate.recover_source_name") != NULL) {
			bool conflict = argc != 0 || restore_file != NULL ||
			    get_config_value("migrate.receive_fd") != NULL ||
			    get_config_value("migrate.recovery_fd") != NULL ||
			    get_config_value("migrate.recovery_listen_fd") != NULL;
			error = migration_restart_command_named(values, conflict,
			    get_config_value("migrate.recover_source_name"));
			if (error != 0)
				errx(EX_OSERR, "source migration recovery: %s", strerror(error));
			printf("source migration recovery confirmed; source remains retired\n");
			return (0);
		}
	}
	{
		const char *rv = get_config_value("migrate.receive_fd");
		const char *errstr;
		long descriptor;
		int fdflags, socket_type;
		socklen_t socket_type_len;

		if (rv != NULL) {
			descriptor = strtonum(rv, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(EX_USAGE, "invalid migrate receive fd '%s'",
				    rv);
			migrate_recv_fd = (int)descriptor;
			fdflags = fcntl(migrate_recv_fd, F_GETFD);
			socket_type_len = sizeof(socket_type);
			if (fdflags < 0 || getsockopt(migrate_recv_fd, SOL_SOCKET,
			    SO_TYPE, &socket_type, &socket_type_len) != 0 ||
			    socket_type_len != sizeof(socket_type) ||
			    socket_type != SOCK_STREAM)
				errx(EX_USAGE, "migrate receive fd '%s' is not a stream socket",
				    rv);
			if (fcntl(migrate_recv_fd, F_SETFD, fdflags | FD_CLOEXEC) < 0)
				errx(EX_OSERR, "cannot set close-on-exec on migrate receive fd");
		}
		/* A successor of a lost destination controller. The challenge names
		 * one preserved attempt from trusted local records, never the peer. */
		rv = get_config_value("migrate.reconstruct");
		if (rv != NULL) {
			if (migrate_recv_fd >= 0 || restore_file != NULL)
				errx(EX_USAGE, "migrate.reconstruct excludes restore and migration receive");
			if (migration_dest_challenge_parse(rv,
			    migrate_reconstruct_challenge) != 0)
				errx(EX_USAGE, "migrate.reconstruct requires a 64-digit lowercase attempt challenge");
			migrate_reconstruct = true;
		}
		if (get_config_value("migrate.reconstruct_previous_name") != NULL &&
		    !migrate_reconstruct)
			errx(EX_USAGE, "migrate.reconstruct_previous_name requires migrate.reconstruct");
		migrate_recovery_image = get_config_bool_default(
		    "migrate.recovery_image", false);
		if (migrate_recovery_image && migrate_recv_fd < 0)
			errx(EX_USAGE, "migrate.recovery_image requires a migration receiver");
		rv = get_config_value("migrate.recovery_fd");
		if (rv != NULL) {
			descriptor = strtonum(rv, 0, INT_MAX, &errstr);
			if (errstr != NULL || (migrate_recv_fd < 0 && !migrate_reconstruct))
				errx(EX_USAGE, "migrate.recovery_fd requires a valid fd and migration receiver");
			migrate_recovery_fd = (int)descriptor;
			if (migration_recovery_file_check(migrate_recovery_fd, true) != 0)
				errx(EX_USAGE, "migration recovery fd must be a private directory owned by this user");
			fdflags = fcntl(migrate_recovery_fd, F_GETFD);
			if (fdflags < 0 || fcntl(migrate_recovery_fd, F_SETFD,
			    fdflags | FD_CLOEXEC) < 0)
				errx(EX_OSERR, "cannot set close-on-exec on migration recovery fd");
		}
		rv = get_config_value("migrate.recovery_listen_fd");
		if (rv != NULL) {
			descriptor = strtonum(rv, 0, INT_MAX, &errstr);
			if (errstr != NULL || (migrate_recv_fd < 0 && !migrate_reconstruct) ||
			    migrate_recovery_fd < 0)
				errx(EX_USAGE, "migration recovery listener requires receive and recovery directory fds");
			migrate_recovery_listener = (int)descriptor;
			if (migration_recovery_listener_check(migrate_recovery_listener) != 0)
				errx(EX_USAGE, "migration recovery listener must be a listening stream socket");
			fdflags = fcntl(migrate_recovery_listener, F_GETFD);
			if (fdflags < 0 || fcntl(migrate_recovery_listener, F_SETFD,
			    fdflags | FD_CLOEXEC) < 0)
				errx(EX_OSERR, "cannot set close-on-exec on migration recovery listener");
		}
	}
	if (restore_file != NULL && migrate_recv_fd >= 0)
		errx(EX_USAGE, "-r (restore) and -R (migrate-receive) are "
		    "mutually exclusive");
	if (migration_credentials_config(
	    get_config_value("migrate.tls.certificate_fd"),
	    get_config_value("migrate.tls.private_key_fd"),
	    get_config_value("migrate.tls.trust_fd"),
	    get_config_value("migrate.tls.peer_sha256"),
	    &migrate_credentials, &migrate_tls_enabled) != 0)
		errx(EX_USAGE, "migration TLS requires all three credential fds and a 64-digit peer certificate SHA-256");
	if (migrate_tls_enabled) {
#ifdef NO_OPENSSL
		errx(EX_USAGE, "migration TLS requires an OpenSSL-enabled build");
#endif
		if (migrate_recv_fd < 0 && !migrate_reconstruct)
			errx(EX_USAGE, "migration TLS configuration requires a migration receiver");
		const int fds[] = {migrate_credentials.certificate_fd,
		    migrate_credentials.private_key_fd, migrate_credentials.trust_fd};
		for (size_t i = 0; i < nitems(fds); i++) {
			int flags = fcntl(fds[i], F_GETFD);
			if (flags < 0 || fcntl(fds[i], F_SETFD, flags | FD_CLOEXEC) < 0)
				errx(EX_OSERR, "invalid migration TLS credential descriptor");
		}
	}
	migrate_plaintext_unix = get_config_bool_default("migrate.plaintext_unix",
	    false);
	if (migrate_plaintext_unix && migrate_tls_enabled)
		errx(EX_USAGE, "migrate.plaintext_unix and migration TLS credentials "
		    "are mutually exclusive");
	if (migrate_plaintext_unix && migrate_recv_fd < 0)
		errx(EX_USAGE, "migrate.plaintext_unix requires a migration receiver");
	/* Migration streams carry guest memory and CPU state; they are
	 * authenticated unless a same-host plaintext socket is requested. */
	if (migrate_recv_fd >= 0 && !migrate_tls_enabled && !migrate_plaintext_unix)
		errx(EX_USAGE, "migration receive requires mutual TLS credentials "
		    "(migrate.tls.*) or migrate.plaintext_unix for a local "
		    "AF_UNIX socket");
	/* The active-vsock relay continues traffic over the raw stream after
	 * RELEASE from a process that does not hold the TLS session. */
	if (migrate_recv_fd >= 0 && migrate_tls_enabled &&
	    get_config_bool_default("checkpoint.migrate_active_vsock", false))
		errx(EX_USAGE, "checkpoint.migrate_active_vsock requires "
		    "migrate.plaintext_unix; it cannot be combined with TLS");
	if (migrate_recovery_listener >= 0 && !migrate_tls_enabled)
		errx(EX_USAGE, "migration recovery listener requires mutual TLS credentials");
	if ((migrate_reconstruct || migrate_recovery_image) &&
	    (migrate_recovery_fd < 0 || migrate_recovery_listener < 0 ||
	    !migrate_tls_enabled))
		errx(EX_USAGE, "destination reconstruction and recovery images require a recovery directory, listener and mutual TLS");
#endif

#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		error = load_restore_file(restore_file, &rstate);
		if (error) {
			fprintf(stderr, "Failed to read checkpoint info from "
					"file: '%s'.\n", restore_file);
			exit(BHYVE_EXIT_ERROR);
		}
		vmname = lookup_vmname(&rstate);
		if (vmname != NULL)
			set_config_value("name", vmname);
	}
#endif

	if (argc == 1)
		set_config_value("name", argv[0]);

	vmname = get_config_value("name");
	if (vmname == NULL)
		bhyve_usage(1);

	if (get_config_bool_default("config.dump", false)) {
		dump_config();
		exit(BHYVE_EXIT_POWEROFF);
	}

	calc_topology();
#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		int saved_ncpus;

		error = lookup_cpu_topology(&rstate, &saved_ncpus,
		    &cpu_sockets, &cpu_cores, &cpu_threads);
		if (error != 0) {
			fprintf(stderr,
			    "Invalid CPU topology in checkpoint metadata.\n");
			exit(BHYVE_EXIT_ERROR);
		}
		guest_ncpus = saved_ncpus;
	}
#endif
	build_vcpumaps();

	value = get_config_value("memory.size");
	error = vm_parse_memsize(value, &memsize);
	if (error)
		errx(EX_USAGE, "invalid memsize '%s'", value);

	ctx = do_open(vmname);

	enable_hypertrace = get_config_bool_default(
	    "enable_hypertrace", false);

#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		if (lookup_memflags(&rstate, &memflags) != 0) {
			fprintf(stderr,
			    "Invalid guest memory flags in checkpoint.\n");
			exit(BHYVE_EXIT_ERROR);
		}
		memsize = lookup_memsize(&rstate);
	}

	if (guest_ncpus < 1) {
		fprintf(stderr, "Invalid guest vCPUs (%d)\n", guest_ncpus);
		exit(BHYVE_EXIT_ERROR);
	}
#endif

	calc_mem_affinity(memsize);
#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		struct checkpoint_memory_geometry destination_geometry;
		struct checkpoint_memory_geometry source_geometry;
		uint64_t domain_sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
		uint16_t *vcpu_domains;
		size_t domain_count;

		vcpu_domains = calloc((size_t)guest_ncpus,
		    sizeof(*vcpu_domains));
		if (vcpu_domains == NULL)
			err(EX_OSERR, "Failed to allocate restored NUMA map");
		error = lookup_numa_topology(&rstate, guest_ncpus, memsize,
		    domain_sizes, &domain_count, vcpu_domains);
			if (error == 0)
				error = bhyve_numa_restore_apply(domain_sizes,
				    domain_count, vcpu_domains, (size_t)guest_ncpus,
				    memsize);
			free(vcpu_domains);
			if (error != 0) {
			fprintf(stderr,
			    "Invalid NUMA topology in checkpoint metadata.\n");
			exit(BHYVE_EXIT_ERROR);
		}

		destination_geometry = (struct checkpoint_memory_geometry) {
			.page_size = PAGE_SIZE,
			.lowmem_size = MIN(memsize,
			    (size_t)vm_get_lowmem_limit(ctx)),
			.highmem_base = vm_get_highmem_base(ctx),
			.highmem_size = memsize -
			    MIN(memsize, (size_t)vm_get_lowmem_limit(ctx)),
		};
		error = lookup_memory_geometry(&rstate, &source_geometry);
			if (error == 0)
				error = checkpoint_memory_geometry_match(
				    &source_geometry, &destination_geometry, memsize);
			if (error != 0) {
			fprintf(stderr,
			    "Checkpoint guest memory geometry is incompatible "
			    "with this destination.\n");
			exit(BHYVE_EXIT_ERROR);
		}
	}
#endif
#ifdef BHYVE_SNAPSHOT
	if (restore_file == NULL)
#endif
	{
		memflags = 0;
		if (get_config_bool_default("memory.wired", false))
			memflags |= VM_MEM_F_WIRED;
		if (get_config_bool_default("memory.guest_in_core", false))
			memflags |= VM_MEM_F_INCORE;
	}
	vm_set_memflags(ctx, memflags);
	error = vm_setup_memory_domains(ctx, VM_MMAP_ALL, guest_domains,
	    guest_ndomains);
	if (error) {
		fprintf(stderr, "Unable to setup memory (%d)\n", errno);
		exit(BHYVE_EXIT_ERROR);
	}

	set_vcpu_affinities();
	init_mem(guest_ncpus);
	init_bootrom(ctx);

#ifdef __amd64__
	kernel_startup = get_config_bool_default("x86.kernel_startup", false);
#ifdef BHYVE_SNAPSHOT
	if (kernel_startup && restore_file != NULL)
		errx(EX_USAGE, "x86.kernel_startup is not yet compatible with restore");
#endif
	/*
	 * The monitor parent owns the open VM description across replacement
	 * children.  Select the startup owner before fork so each child inherits
	 * the exact controller, then refresh the generation after vm_reinit().
	 */
	if (kernel_startup)
		kernel_startup_configure(ctx);
#endif

	if (get_config_bool_default("monitor.enabled", false)) {
		int monitor_pipe[2];
		pid_t child;

		while (1) {
			if (pipe2(monitor_pipe, O_CLOEXEC) == -1)
				err(BHYVE_EXIT_ERROR, "pipe2");

			child = fork();
			if (child == -1) {
				EPRINTLN("Monitor mode fork failed: %s",
				    strerror(errno));
				exit(BHYVE_EXIT_ERROR);
			}
			if (child == 0) {
				close(monitor_pipe[1]);
				monitor_pipe_init(monitor_pipe[0]);
				break;
			}

			close(monitor_pipe[0]);
			while ((error = waitpid(child, &status, 0)) == -1 && errno == EINTR)
			    ;
			close(monitor_pipe[1]);
			if (error == -1) {
				EPRINTLN("Monitor mode wait failed: %s",
				    strerror(errno));
				exit(BHYVE_EXIT_ERROR);
			}
			if (WIFSIGNALED(status)) {
				EPRINTLN("Child process was killed by signal %d",
				    WTERMSIG(status));
				exit(BHYVE_EXIT_ERROR);
			} else {
				status = WEXITSTATUS(status);
				if (get_config_bool_default("monitor.no_reboot", false) ||
				    status != BHYVE_EXIT_RESET)
					exit(status);
			}
			if (vm_reinit(ctx) != 0) {
				EPRINTLN("Monitor mode reinit failed: %s",
				    strerror(errno));
				exit(BHYVE_EXIT_ERROR);
			};
#ifdef __amd64__
			if (kernel_startup)
				kernel_startup_refresh(ctx);
#endif
		}
	}
	/*
	 * The monitor forks; a connector started before fork would not survive
	 * in the VM child even though its mutexes and started flag would.
	 */
	if (enable_hypertrace != 0 && hypertrace_init(ctx) != 0)
		err(EX_OSERR, "hypertrace_init");
#ifdef BHYVE_SNAPSHOT
	defer_hypertrace = restore_file != NULL || migrate_recv_fd >= 0 ||
	    migrate_reconstruct;
#endif

#ifdef BHYVE_SNAPSHOT
	if (get_config_bool_default("checkpoint.migrate_active_vsock", false)) {
		error = migration_vsock_owner_start(NULL);
		if (error != 0)
			errx(EX_OSERR, "cannot start vsock migration relay owner: %s",
			    strerror(error));
	}
#endif
	bsp = vm_vcpu_open(ctx, BSP);
	if (bsp == NULL) {
		fprintf(stderr, "Unable to open boot VCPU: %s",
		    strerror(errno));
		exit(BHYVE_EXIT_ERROR);
	}

	max_vcpus = num_vcpus_allowed(ctx, bsp);
	if (guest_ncpus > max_vcpus) {
		fprintf(stderr, "%d vCPUs requested but only %d available\n",
			guest_ncpus, max_vcpus);
		exit(BHYVE_EXIT_ERROR);
	}

	bhyve_init_vcpu(bsp);

	/* Allocate per-VCPU resources. */
	vcpu_info = calloc(guest_ncpus, sizeof(*vcpu_info));
	for (int vcpuid = 0; vcpuid < guest_ncpus; vcpuid++) {
		vcpu_info[vcpuid].ctx = ctx;
		vcpu_info[vcpuid].vcpuid = vcpuid;
		if (vcpuid == BSP)
			vcpu_info[vcpuid].vcpu = bsp;
		else
			vcpu_info[vcpuid].vcpu = vm_vcpu_open(ctx, vcpuid);

		if (vcpu_info[vcpuid].vcpu == NULL) {
			fprintf(stderr, "Unable to open VCPU %d: %s", vcpuid,
			    strerror(errno));
			exit(BHYVE_EXIT_ERROR);
		}
	}

	if (bhyve_init_platform(ctx, bsp) != 0)
		exit(BHYVE_EXIT_ERROR);

#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		error = checkpoint_restore_cpu_contract(&rstate, bsp);
		if (error != 0) {
			EPRINTLN("Checkpoint CPU contract is incompatible with "
			    "this destination.");
			exit(BHYVE_EXIT_ERROR);
		}
	}
#endif

	if (qemu_fwcfg_init(ctx) != 0) {
		fprintf(stderr, "qemu fwcfg initialization error\n");
		exit(BHYVE_EXIT_ERROR);
	}

	if (qemu_fwcfg_add_file("opt/bhyve/hw.ncpu", sizeof(guest_ncpus),
	    &guest_ncpus) != 0) {
		fprintf(stderr, "Could not add qemu fwcfg opt/bhyve/hw.ncpu\n");
		exit(BHYVE_EXIT_ERROR);
	}

	/*
	 * Exit if a device emulation finds an error in its initialization
	 */
	if (init_pci(ctx) != 0) {
		EPRINTLN("Device emulation initialization error: %s",
		    strerror(errno));
		exit(BHYVE_EXIT_ERROR);
	}
	if (init_tpm(ctx) != 0) {
		EPRINTLN("Failed to init TPM device");
		exit(BHYVE_EXIT_ERROR);
	}
	if (enable_hypertrace != 0 && !defer_hypertrace &&
	    hypertrace_start(ctx) != 0)
		err(EX_OSERR, "hypertrace_start");

	/*
	 * Initialize after PCI, to allow a bootrom file to reserve the high
	 * region.
	 */
	if (get_config_bool("acpi_tables"))
		vmgenc_init(ctx);

#ifdef BHYVE_GDB
	init_gdb(ctx);
#endif

	/*
	 * Add all vCPUs.
	 */
#ifdef BHYVE_SNAPSHOT
	/*
	 * A restored CPU starts with destination-local state until the restore
	 * transaction publishes the checkpoint.  Arm the common startup fence
	 * before creating a vCPU thread so it cannot reach vm_loop() in that
	 * interval.  vm_restore_transaction() releases this only after COMMIT and
	 * device resume; an error exits with all vCPUs still held.
	 */
	if (restore_file != NULL || migrate_recv_fd >= 0 || migrate_reconstruct)
		checkpoint_restore_startup_hold();
#endif
	for (int vcpuid = 0; vcpuid < guest_ncpus; vcpuid++)
		bhyve_start_vcpu(vcpu_info[vcpuid].vcpu, vcpuid == BSP);
#ifdef __amd64__
	if (kernel_startup)
		kernel_startup_commit(ctx);
#endif
	/* Finish firmware/platform writes before restoring RAM or releasing CPUs. */
	if (bhyve_init_platform_late(ctx, bsp) != 0)
		exit(BHYVE_EXIT_ERROR);

#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		FPRINTLN(stdout, "Validating checkpoint topology...");
		if (vm_restore_transaction(ctx, &rstate) != 0)
			exit(BHYVE_EXIT_ERROR);
		/* The restore transaction admitted both HyperTrace channels before
		 * releasing its startup fence. */
		defer_hypertrace = false;
	} else if (migrate_recv_fd >= 0) {
		struct migration_session_config mcfg;
		struct migration_dest_result mres;

		memset(&mcfg, 0, sizeof(mcfg));
		mcfg.version_max = MIGRATION_PROTO_VERSION;
		mcfg.version_min = MIGRATION_PROTO_VERSION_MIN;
		mcfg.recovery_enabled = migrate_recovery_fd >= 0;
		mcfg.recovery_dirfd = migrate_recovery_fd;
		mcfg.recovery_image = migrate_recovery_image;
		mcfg.tls_credentials = migrate_tls_enabled ? &migrate_credentials : NULL;
		mcfg.plaintext_unix = migrate_plaintext_unix;
		memset(&mres, 0, sizeof(mres));
		bhyve_prepare_control(ctx);
		FPRINTLN(stdout, "Awaiting inbound live migration...");
		if (migrate_recovery_listener >= 0)
			error = migration_prod_dest_serve_managed(ctx, migrate_recv_fd,
			    migrate_recovery_listener, &mcfg, &mres);
		else
			error = migration_prod_dest_serve(ctx, migrate_recv_fd, &mcfg, &mres);
		if (error != 0 && migrate_recovery_listener < 0 &&
		    migration_prod_dest_retained()) {
			/* COMMIT may have retired the source: this paused copy may
			 * be the only one.  Keep it until the operator decides. */
			fprintf(stderr, "Inbound migration failed after COMMIT at "
			    "phase %u (reason %u); the paused guest is retained. "
			    "Resolve it with migrate_resolve (resume or discard).\n",
			    mres.phase, mres.reason);
			if (migration_prod_dest_wait_resolution() != 0)
				exit(BHYVE_EXIT_ERROR);
			error = 0;
		}
		if (error != 0) {
			fprintf(stderr, "Inbound migration failed at phase %u "
			    "(reason %u).\n", mres.phase, mres.reason);
			exit(BHYVE_EXIT_ERROR);
		}
		if (enable_hypertrace != 0 && mres.resumed)
			defer_hypertrace = false;
	} else if (migrate_reconstruct) {
		struct migration_session_config mcfg;
		struct migration_dest_result mres;

		if (enable_hypertrace == 0)
			errx(EX_USAGE, "migrate.reconstruct requires enable_hypertrace");
		/* Admission may destroy an exact orphan through /dev/vmmctl, so it
		 * precedes Capsicum. No guest state is loaded until it succeeds. */
		error = migration_prod_dest_reconstruct_begin(ctx, migrate_recovery_fd,
		    migrate_reconstruct_challenge,
		    get_config_value("migrate.reconstruct_previous_name"),
		    &migrate_reconstruction);
		if (error != 0) {
			fprintf(stderr, "Destination reconstruction refused: %s\n",
			    strerror(error));
			exit(BHYVE_EXIT_ERROR);
		}
		memset(&mcfg, 0, sizeof(mcfg));
		mcfg.version_max = MIGRATION_PROTO_VERSION;
		mcfg.version_min = MIGRATION_PROTO_VERSION_MIN;
		mcfg.recovery_enabled = true;
		mcfg.recovery_dirfd = migrate_recovery_fd;
		mcfg.tls_credentials = &migrate_credentials;
		memset(&mres, 0, sizeof(mres));
		bhyve_prepare_control(ctx);
		FPRINTLN(stdout, "Reconstructed destination fenced; awaiting authenticated recovery...");
		error = migration_prod_dest_reconstruct_managed(ctx,
		    migrate_reconstruction, migrate_recovery_listener, &mcfg, &mres);
		migrate_reconstruction = NULL;	/* consumed */
		if (error != 0) {
			fprintf(stderr, "Destination reconstruction failed: %s\n",
			    strerror(error));
			exit(BHYVE_EXIT_ERROR);
		}
		if (mres.resumed)
			defer_hypertrace = false;
	}
#endif
	if (enable_hypertrace != 0 && defer_hypertrace &&
	    hypertrace_start(ctx) != 0)
		err(EX_OSERR, "hypertrace_start after restore");


	/*
	 * Change the proc title to include the VM name.
	 */
	setproctitle("%s", vmname);

#ifdef BHYVE_SNAPSHOT
	if (migrate_recv_fd < 0 && !migrate_reconstruct)
#endif
		bhyve_prepare_control(ctx);

#ifdef BHYVE_SNAPSHOT
	if (restore_file != NULL) {
		destroy_restore_state(&rstate);
		if (vm_restore_time(ctx) < 0)
			err(EX_OSERR, "Unable to restore time");

#ifdef __amd64__
		for (int vcpuid = 0; vcpuid < guest_ncpus; vcpuid++)
			vm_resume_cpu(vcpu_info[vcpuid].vcpu);
#else
		/* Only vCPUs powered on in the checkpoint may run. */
		if (bhyve_resume_powered_cpus(ctx) != 0)
			err(EX_OSERR, "Unable to resume restored vCPUs");
#endif
	} else if (migrate_recv_fd >= 0) {
		/*
		 * The migration coordinator resumed the vCPUs before sending
		 * RELEASE_ACK.  A vsock relay owner holds its own copy of the
		 * stream after RELEASE; this process no longer needs it.
		 */
		close(migrate_recv_fd);
		migrate_recv_fd = -1;
	} else if (!migrate_reconstruct)
		/* Reconstruction resumes the guest through authenticated recovery. */
#endif
		vm_resume_cpu(bsp);

	/* Commands may retire ctx; main must finish all VM startup use first. */
	ipc_startup_complete();

	/*
	 * Head off to the main event dispatch loop
	 */
	mevent_dispatch();

	exit(BHYVE_EXIT_ERROR);
}
