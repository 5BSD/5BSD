/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Flavius Anton
 * Copyright (c) 2016 Mihai Tiganus
 * Copyright (c) 2016-2019 Mihai Carabas
 * Copyright (c) 2017-2019 Darius Mihai
 * Copyright (c) 2017-2019 Elena Mihailescu
 * Copyright (c) 2018-2019 Sergiu Weisz
 * All rights reserved.
 * The bhyve-snapshot feature was developed under sponsorships
 * from Matthew Grooms.
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
#include "bhyve_trace.h"
#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sha256.h>
#include <sysexits.h>
#include <stdbool.h>
#include <time.h>
#include <sys/ioctl.h>

/*
 * The checkpoint session is a private bhyve/kernel ABI.  During a source
 * build the installed machine headers can legitimately describe an older
 * kernel, so include the matching source definitions rather than allowing
 * the host's vmmapi.h forward declaration to become the effective ABI.
 */
#ifdef __amd64__
#include <amd64/include/vmm.h>
#include <amd64/include/vmm_snapshot.h>
#include <amd64/include/vmm_dev.h>
#else
#include <machine/vmm_snapshot.h>
#include <machine/vmm_dev.h>
#endif
#include <machine/vmm.h>
#include <vmmapi.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/virtio/virtio.h>

#include "bhyverun.h"
#include "acpi.h"
#include "checkpoint_manifest.h"
#include "checkpoint_compat.h"
#include "checkpoint_machine.h"
#include "checkpoint_cpu.h"
#include "console.h"
#include "snapshot_metadata.h"
#include "checkpoint_numa.h"
#include "checkpoint_topology.h"
#ifdef __amd64__
#include "amd64/atkbdc.h"
#endif
#include "debug.h"
#include "hypertrace.h"
#include "ipc.h"
#include "mem.h"
#include "migration_session.h"
#include "pci_emul.h"
#include "qemu_fwcfg.h"
#include "qemu_fwcfg_snapshot.h"
#include "snapshot.h"
#include "snapshot_devmem.h"
#include "snapshot_md.h"
#include "snapshot_portable.h"
#include "tpm_device.h"
#include "vmgenc.h"

#include <libxo/xo.h>
#include <ucl.h>

_Static_assert(CHECKPOINT_RELEASE_WIRE_SIZE ==
    DTRACED_RELEASE_ATTESTED_SIZE, "HSA1 checkpoint member size mismatch");

/*
 * Keep bhyve-only incremental builds usable when the installed vmmapi header
 * predates the matching source/library declaration.  A source-paired world
 * build sees the identical prototype through vmmapi.h.
 */
int vm_get_devmem_info(struct vmctx *, int, void **, size_t *, char *, size_t);

extern int guest_ncpus;
extern uint16_t cpu_cores, cpu_sockets, cpu_threads;

static struct winsize winsize;
static sig_t old_winch_handler;

#define	KB		(1024UL)
#define	MB		(1024UL * KB)
#define	GB		(1024UL * MB)

#define	SNAPSHOT_CHUNK	(4 * MB)
#define	PROG_BUF_SZ	(8192)

#define	SNAPSHOT_BUFFER_SIZE (40 * MB)
#define	SNAPSHOT_DEVICE_EXTRA_MAX (160 * MB)

#define	JSON_KERNEL_ARR_KEY		"kern_structs"
#define	JSON_DEV_ARR_KEY		"devices"
#define	JSON_BASIC_METADATA_KEY 	"basic metadata"
#define	JSON_HYPERTRACE_HANDOFF_VERSION_KEY "hypertrace_handoff_version"
#define	JSON_SNAPSHOT_REQ_KEY		"device"
#define	JSON_SIZE_KEY			"size"
#define	JSON_FILE_OFFSET_KEY		"file_offset"
#define	JSON_COMPAT_VERSION_KEY		"compatibility_version"
#define	JSON_COMPAT_SCHEMA_KEY		"compat_schema"
#define	JSON_COMPAT_TRANSPORT_KEY	"compat_transport"
#define	JSON_COMPAT_QUEUE_COUNT_KEY	"compat_queue_count"
#define	JSON_COMPAT_MSIX_COUNT_KEY	"compat_msix_count"
#define	JSON_COMPAT_CONFIG_SIZE_KEY	"compat_config_size"
#define	JSON_COMPAT_OFFERED_KEY		"compat_offered_features"
#define	JSON_COMPAT_NEGOTIATED_KEY	"compat_negotiated_features"
#define	JSON_COMPAT_PAYLOAD_CRC32_KEY	"compat_payload_crc32"
#define	JSON_COMPAT_QUEUE_SIZES_KEY	"compat_queue_sizes"
#define	JSON_COMPAT_SHARED_MEMORY_KEY	"compat_shared_memory"
#define	JSON_MACHINE_TOPOLOGY_VERSION_KEY "machine_topology_version"
#define	JSON_MACHINE_TOPOLOGY_DIGEST_KEY "machine_topology_digest"

#define	JSON_NCPUS_KEY			"ncpus"
#define	JSON_CPU_SOCKETS_KEY		"cpu_sockets"
#define	JSON_CPU_CORES_KEY		"cpu_cores"
#define	JSON_CPU_THREADS_KEY		"cpu_threads"
#define	JSON_CPU_CONTRACT_KEY		"cpu_contract"
#define	JSON_NUMA_VERSION_KEY		"numa_topology_version"
#define	JSON_NUMA_SIZES_KEY		"numa_domain_sizes"
#define	JSON_NUMA_MAPPING_KEY		"numa_vcpu_domains"
#define	JSON_MEMORY_GEOMETRY_VERSION_KEY	"memory_geometry_version"
#define	JSON_MEMORY_PAGE_SIZE_KEY	"memory_page_size"
#define	JSON_MEMORY_LOWMEM_SIZE_KEY	"memory_lowmem_size"
#define	JSON_MEMORY_HIGHMEM_BASE_KEY	"memory_highmem_base"
#define	JSON_MEMORY_HIGHMEM_SIZE_KEY	"memory_highmem_size"
#define	JSON_VMNAME_KEY 		"vmname"
#define	JSON_MEMSIZE_KEY		"memsize"
#define	JSON_MEMFLAGS_KEY		"memflags"
#define	JSON_VMGENID_STATE_KEY		"vmgenid_state"

#define min(a,b)		\
({				\
 __typeof__ (a) _a = (a);	\
 __typeof__ (b) _b = (b); 	\
 _a < _b ? _a : _b;       	\
 })

static const struct vm_snapshot_kern_info snapshot_kern_structs[] = {
#if defined(__aarch64__)
	/* VMS2: vCPU/system registers, FP/SIMD, timers, guest counter. */
	{ "vm",		STRUCT_VM	},
	/* VMS2: GICv3 distributor, SPIs and per-CPU interfaces. */
	{ "vgic",	STRUCT_VGIC	},
#elif defined(__riscv)
	/* VMS2: GPRs, VS CSRs, FP, SBI timer and pending interrupts. */
	{ "vm",		STRUCT_VM	},
	/* VMS2: APLIC domain, sources and targets. */
	{ "aplic",	STRUCT_APLIC	},
#else
	{ "vhpet",	STRUCT_VHPET	},
	{ "vioapic",	STRUCT_VIOAPIC	},
	{ "vlapic",	STRUCT_VLAPIC	},
	/* VMS2 validates x2APIC mode against the restored LAPIC image. */
	{ "vm",		STRUCT_VM	},
	{ "vmcx",	STRUCT_VMCX	},
	{ "vatpit",	STRUCT_VATPIT	},
	{ "vatpic",	STRUCT_VATPIC	},
	{ "vpmtmr",	STRUCT_VPMTMR	},
	{ "vrtc",	STRUCT_VRTC	},
#endif
};

#ifndef __amd64__
static size_t
snapshot_md_device_count(void)
{
	size_t count;

	(void)bhyve_snapshot_md_devices(&count);
	return (count);
}
#endif

static cpuset_t vcpus_active, vcpus_suspended;
static pthread_mutex_t vcpu_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vcpus_idle = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vcpus_can_run = PTHREAD_COND_INITIALIZER;
static bool checkpoint_active;
static bool restore_startup_hold;

static char *
strcat_extension(const char *base_str, const char *ext)
{
	char *res;
	size_t base_len, ext_len;

	base_len = strnlen(base_str, NAME_MAX);
	ext_len = strnlen(ext, NAME_MAX);

	if (base_len == NAME_MAX || ext_len == NAME_MAX ||
	    base_len > NAME_MAX - ext_len) {
		EPRINTLN("Filename exceeds maximum length.");
		errno = ENAMETOOLONG;
		return (NULL);
	}

	res = malloc(base_len + ext_len + 1);
	if (res == NULL) {
		EPRINTLN("Failed to allocate memory: %s", strerror(errno));
		return (NULL);
	}

	memcpy(res, base_str, base_len);
	memcpy(res + base_len, ext, ext_len);
	res[base_len + ext_len] = 0;

	return (res);
}

static int
checkpoint_lock(int fd, int operation)
{
	int error;

	do {
		error = flock(fd, operation);
	} while (error != 0 && errno == EINTR);
	return (error == 0 ? 0 : errno != 0 ? errno : EIO);
}

static int
checkpoint_regular_fd(int fd)
{
	struct stat sb;

	if (fstat(fd, &sb) != 0)
		return (errno != 0 ? errno : EIO);
	return (S_ISREG(sb.st_mode) ? 0 : EINVAL);
}

void
destroy_restore_state(struct restore_state *rstate)
{
	if (rstate == NULL) {
		EPRINTLN("Attempting to destroy NULL restore struct.");
		return;
	}

	if (rstate->kdata_map != MAP_FAILED)
		munmap(rstate->kdata_map, rstate->kdata_len);

	if (rstate->kdata_fd >= 0)
		close(rstate->kdata_fd);
	if (rstate->vmmem_fd >= 0)
		close(rstate->vmmem_fd);
	if (rstate->checkpoint_lock_fd >= 0)
		close(rstate->checkpoint_lock_fd);

	if (rstate->meta_root_obj != NULL)
		ucl_object_unref(rstate->meta_root_obj);
	if (rstate->meta_parser != NULL)
		ucl_parser_free(rstate->meta_parser);
	explicit_bzero(rstate->handoff_token, sizeof(rstate->handoff_token));
	explicit_bzero(rstate->handoff_digest, sizeof(rstate->handoff_digest));
	if (rstate->hypertrace_transfer != NULL) {
		explicit_bzero(rstate->hypertrace_transfer,
		    rstate->hypertrace_transfer_length);
		free(rstate->hypertrace_transfer);
	}
	rstate->hypertrace_transfer = NULL;
	rstate->hypertrace_transfer_length = 0;
	rstate->hypertrace_session_present = false;
	explicit_bzero(rstate->hypertrace_session, sizeof(rstate->hypertrace_session));
	rstate->checkpoint_format_version = 0;
	rstate->handoff_identity_valid = false;
	rstate->hypertrace_private_image = NULL;
	rstate->hypertrace_private_length = 0;
	rstate->hypertrace_private_dev = NULL;
}

static int
load_vmmem_fd(int fd, struct restore_state *rstate)
{
	struct stat sb;
	int err;

	assert(fd >= 0);
	rstate->vmmem_fd = fd;

	err = fstat(rstate->vmmem_fd, &sb);
	if (err < 0) {
		perror("Failed to stat restore file");
		goto err_load_vmmem;
	}
	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "Restore file is not a regular file.\n");
		goto err_load_vmmem;
	}

	if (sb.st_size <= 0 || (uintmax_t)sb.st_size > SIZE_MAX) {
		fprintf(stderr, "Restore file has an invalid size.\n");
		goto err_load_vmmem;
	}

	rstate->vmmem_len = sb.st_size;

	return (0);

err_load_vmmem:
	if (rstate->vmmem_fd >= 0)
		close(rstate->vmmem_fd);
	rstate->vmmem_fd = -1;
	return (-1);
}

static int
load_kdata_fd(int fd, struct restore_state *rstate)
{
	struct stat sb;
	int err;

	assert(fd >= 0);
	rstate->kdata_fd = fd;

	err = fstat(rstate->kdata_fd, &sb);
	if (err < 0) {
		perror("Failed to stat kernel data file");
		goto err_load_kdata;
	}
	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "Kernel data file is not a regular file.\n");
		goto err_load_kdata;
	}

	if (sb.st_size <= 0 || (uintmax_t)sb.st_size > SIZE_MAX) {
		fprintf(stderr, "Kernel data file has an invalid size.\n");
		goto err_load_kdata;
	}

	rstate->kdata_len = sb.st_size;
	rstate->kdata_map = mmap(NULL, rstate->kdata_len, PROT_READ,
				 MAP_SHARED, rstate->kdata_fd, 0);
	if (rstate->kdata_map == MAP_FAILED) {
		perror("Failed to map restore file");
		goto err_load_kdata;
	}

	return (0);

err_load_kdata:
	if (rstate->kdata_fd >= 0)
		close(rstate->kdata_fd);
	rstate->kdata_fd = -1;
	return (-1);
}

static int
load_metadata_fd(int fd, struct restore_state *rstate)
{
	ucl_object_t *obj;
	struct ucl_parser *parser;
	int err;

	assert(fd >= 0);
	if (checkpoint_regular_fd(fd) != 0) {
		fprintf(stderr, "Metadata file is not a regular file.\n");
		return (-1);
	}
	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		fprintf(stderr, "Failed to initialize UCL parser.\n");
		err = -1;
		goto err_load_metadata;
	}

	err = ucl_parser_add_fd(parser, fd);
	if (err == 0) {
		fprintf(stderr, "Failed to parse metadata file descriptor.\n");
		err = -1;
		goto err_load_metadata;
	}

	obj = ucl_parser_get_object(parser);
	if (obj == NULL) {
		fprintf(stderr, "Failed to parse object.\n");
		err = -1;
		goto err_load_metadata;
	}

	rstate->meta_parser = parser;
	rstate->meta_root_obj = (ucl_object_t *)obj;

	return (0);

err_load_metadata:
	if (parser != NULL)
		ucl_parser_free(parser);
	return (err);
}

static int
load_hypertrace_transfer_fd(int fd, const uint8_t token[16],
    const char expected_digest[CHECKPOINT_SHA256_HEX_LEN + 1],
    struct restore_state *rstate)
{
	struct stat sb;
	char actual_digest[SHA256_DIGEST_STRING_LENGTH];
	uint8_t *bytes;
	size_t length, offset;
	ssize_t nread;
	int error;

	if (fstat(fd, &sb) != 0)
		return (errno != 0 ? errno : EIO);
	bool fresh = rstate->checkpoint_format_version == 5;
	if (!S_ISREG(sb.st_mode) || (fresh ?
	    sb.st_size != HYPERTRACE_SESSION_RECORD_SIZE :
	    sb.st_size < (off_t)HYPERTRACE_TRANSFER_MIN_BYTES) ||
	    (uintmax_t)sb.st_size > HYPERTRACE_TRANSFER_MAX_BYTES)
		return (EPROTO);
	length = (size_t)sb.st_size;
	bytes = malloc(length);
	if (bytes == NULL)
		return (ENOMEM);
	if (lseek(fd, 0, SEEK_SET) < 0) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	offset = 0;
	while (offset < length) {
		nread = read(fd, bytes + offset, length - offset);
		if (nread < 0 && errno == EINTR)
			continue;
		if (nread <= 0) {
			error = nread < 0 ? errno : EIO;
			goto fail;
		}
		offset += (size_t)nread;
	}
	if (SHA256_Data(bytes, length, actual_digest) == NULL ||
	    strcmp(actual_digest, expected_digest) != 0) {
		error = EILSEQ;
		goto fail;
	}
	bool has_transfer_state;
	if (fresh) {
		struct hypertrace_session_record record;
		error = hypertrace_session_record_decode(bytes, length, &record);
		if (error != 0)
			goto fail;
		memcpy(rstate->hypertrace_session, bytes, length);
		rstate->hypertrace_session_present = true;
		explicit_bzero(bytes, length);
		free(bytes);
		return (0);
	}
	if (hypertrace_transfer_inspect(bytes, length, token,
	    &has_transfer_state) != 0) {
		error = errno != 0 ? errno : EIO;
		goto fail;
	}
	rstate->hypertrace_transfer = bytes;
	rstate->hypertrace_transfer_length = length;
	return (0);
fail:
	explicit_bzero(bytes, length);
	free(bytes);
	return (error);
}

int
load_restore_file(const char *filename, struct restore_state *rstate)
{
	struct checkpoint_manifest manifest;
	int err;
	bool exists, is_manifest;
	char *base_copy, *lock_filename, *manifest_directory_copy;
	int lock_fd, manifest_data_fd, manifest_dirfd, manifest_kern_fd;
	int manifest_meta_fd, manifest_trace_fd;

	assert(filename != NULL);
	assert(rstate != NULL);

	memset(rstate, 0, sizeof(*rstate));
	rstate->checkpoint_lock_fd = -1;
	rstate->kdata_fd = -1;
	rstate->vmmem_fd = -1;
	rstate->kdata_map = MAP_FAILED;

	base_copy = NULL;
	lock_filename = NULL;
	manifest_directory_copy = NULL;
	lock_fd = -1;
	manifest_data_fd = -1;
	manifest_dirfd = -1;
	manifest_kern_fd = -1;
	manifest_meta_fd = -1;
	manifest_trace_fd = -1;
	/*
	 * Keep the checkpoint lock, manifest, and its named generation members
	 * rooted at one directory file descriptor.  Looking up the manifest by
	 * pathname and opening its directory afterwards leaves a rename window in
	 * which the two lookups can refer to different directories.
	 */
	base_copy = strdup(filename);
	manifest_directory_copy = strdup(filename);
	if (base_copy == NULL || manifest_directory_copy == NULL ||
	    !checkpoint_member_valid(basename(base_copy)))
		goto err_restore;
	manifest_dirfd = open(dirname(manifest_directory_copy),
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (manifest_dirfd < 0) {
		fprintf(stderr, "Failed to open checkpoint generation directory: %s\n",
		    strerror(errno));
		goto err_restore;
	}
	if (asprintf(&lock_filename, "%s.lock", basename(base_copy)) < 0)
		goto err_restore;
	lock_fd = openat(manifest_dirfd, lock_filename,
	    O_RDONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
	if (lock_fd < 0) {
		fprintf(stderr, "Failed to open checkpoint lock: %s\n",
		    strerror(errno));
		goto err_restore;
	}
	if (checkpoint_regular_fd(lock_fd) != 0) {
		fprintf(stderr, "Checkpoint lock is not a regular file.\n");
		goto err_restore;
	}
	err = checkpoint_lock(lock_fd, LOCK_SH);
	if (err != 0) {
		fprintf(stderr, "Failed to lock checkpoint: %s\n", strerror(err));
		goto err_restore;
	}
	err = checkpoint_manifest_read_at(manifest_dirfd, basename(base_copy),
	    &manifest, &exists, &is_manifest);
	if (err != 0) {
		fprintf(stderr, "Failed to read checkpoint manifest: %s\n",
		    strerror(err));
		goto err_restore;
	}
	if (!exists || !is_manifest) {
		fprintf(stderr, "Checkpoint is not a current manifest.\n");
		goto err_restore;
	}
	if (!checkpoint_manifest_valid_for(basename(base_copy), &manifest)) {
		fprintf(stderr, "Checkpoint manifest has invalid members.\n");
		goto err_restore;
	}
	/* Previous-ABI admission requires an explicit destination opt-in. */
	if (!checkpoint_manifest_restore_compatible(&manifest,
	    get_config_bool_default("checkpoint.restore_abi_v2", false))) {
		fprintf(stderr,
		    "Checkpoint architecture or machine ABI is incompatible.\n");
		goto err_restore;
	}
	/*
	 * Trace continuity across restore/migration is a future feature,
	 * disabled because the current product contract is fresh-session.
	 * Format 4 carries a HyperTrace transfer ticket for continuity.
	 */
	if (manifest.format_version == 4) {
		fprintf(stderr, "Checkpoint uses the trace-continuity format "
		    "(manifest format 4), which this bhyve does not restore; "
		    "restore requires a fresh-session checkpoint.\n");
		errno = ENOTSUP;
		goto err_restore;
	}
	err = checkpoint_manifest_open_verified_trace_at(manifest_dirfd,
	    &manifest, &manifest_data_fd, &manifest_kern_fd,
	    &manifest_meta_fd, &manifest_trace_fd);
	if (err != 0) {
		fprintf(stderr,
		    "Checkpoint generation integrity verification failed: %s\n",
		    strerror(err));
		goto err_restore;
	}

	err = load_vmmem_fd(manifest_data_fd, rstate);
	manifest_data_fd = -1;
	if (err != 0) {
		fprintf(stderr, "Failed to load guest RAM file.\n");
		goto err_restore;
	}

	err = load_kdata_fd(manifest_kern_fd, rstate);
	manifest_kern_fd = -1;
	if (err != 0) {
		fprintf(stderr, "Failed to load guest kernel data file.\n");
		goto err_restore;
	}

	err = load_metadata_fd(manifest_meta_fd, rstate);
	if (close(manifest_meta_fd) != 0 && err == 0)
		err = -1;
	manifest_meta_fd = -1;
	if (err != 0) {
		fprintf(stderr, "Failed to load guest metadata file.\n");
		goto err_restore;
	}
	err = checkpoint_manifest_handoff_identity(basename(base_copy),
	    &manifest, rstate->handoff_token, rstate->handoff_digest);
	if (err != 0) {
		fprintf(stderr, "Failed to derive checkpoint handoff identity: %s\n",
		    strerror(err));
		goto err_restore;
	}
	rstate->handoff_identity_valid = true;
	rstate->checkpoint_format_version = manifest.format_version;
	/* Trace continuity (disabled future feature): format 4 was refused
	 * above; intentionally unreachable until enabled. */
	if (manifest.format_version == 4) {
		err = checkpoint_release_read_at(manifest_dirfd,
		    rstate->handoff_token, rstate->hypertrace_release);
		if (err == ENOENT) {
			uint8_t recovered[CHECKPOINT_RELEASE_WIRE_SIZE];
			if (hypertrace_release_recover(rstate->handoff_token,
			    rstate->handoff_digest, recovered) == 0) {
				err = checkpoint_release_publish_at(manifest_dirfd,
				    rstate->handoff_token, recovered);
				if (err == 0) {
					memcpy(rstate->hypertrace_release,
					    recovered, sizeof(recovered));
					rstate->hypertrace_release_present = true;
				}
			} else {
				/* Another host or an unsigned local checkpoint has no
				 * source-side recovery credential. Admission remains fenced. */
				err = 0;
			}
		} else if (err == 0) {
			if (hypertrace_release_attestation_inspect(
			    rstate->hypertrace_release, rstate->handoff_token,
			    rstate->handoff_digest) != 0)
				err = EPROTO;
			else
				rstate->hypertrace_release_present = true;
		}
		if (err != 0) {
			fprintf(stderr, "HyperTrace source release is invalid: %s\n",
			    strerror(err));
			goto err_restore;
		}
	}
	if (manifest_trace_fd >= 0) {
		err = load_hypertrace_transfer_fd(manifest_trace_fd,
		    rstate->handoff_token, manifest.trace_sha256, rstate);
		if (close(manifest_trace_fd) != 0 && err == 0)
			err = errno != 0 ? errno : EIO;
		manifest_trace_fd = -1;
		if (err != 0) {
			fprintf(stderr, "Failed to load HyperTrace transfer: %s\n",
			    strerror(err));
			goto err_restore;
		}
	}
	if (rstate->hypertrace_release_present &&
	    hypertrace_release_transfer_inspect(rstate->hypertrace_release,
	    rstate->handoff_token, rstate->handoff_digest,
	    rstate->hypertrace_transfer,
	    rstate->hypertrace_transfer_length) != 0) {
		fprintf(stderr, "Signed HyperTrace release disagrees with "
		    "checkpoint transfer member.\n");
		goto err_restore;
	}

	free(base_copy);
	free(lock_filename);
	free(manifest_directory_copy);
	if (manifest_dirfd >= 0)
		close(manifest_dirfd);
	rstate->checkpoint_lock_fd = lock_fd;
	lock_fd = -1;
	return (0);

err_restore:
	destroy_restore_state(rstate);
	free(base_copy);
	free(lock_filename);
	free(manifest_directory_copy);
	if (manifest_dirfd >= 0)
		close(manifest_dirfd);
	if (manifest_data_fd >= 0)
		close(manifest_data_fd);
	if (manifest_kern_fd >= 0)
		close(manifest_kern_fd);
	if (manifest_meta_fd >= 0)
		close(manifest_meta_fd);
	if (manifest_trace_fd >= 0)
		close(manifest_trace_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	return (-1);
}

#define JSON_GET_INT_OR_RETURN(key, obj, result_ptr, ret)			\
do {										\
	const ucl_object_t *obj__;						\
	obj__ = ucl_object_lookup(obj, key);					\
	if (obj__ == NULL) {							\
		fprintf(stderr, "Missing key: '%s'", key);			\
		return (ret);							\
	}									\
	if (!ucl_object_toint_safe(obj__, result_ptr)) {			\
		fprintf(stderr, "Cannot convert '%s' value to int.", key);	\
		return (ret);							\
	}									\
} while(0)

#define JSON_GET_STRING_OR_RETURN(key, obj, result_ptr, ret)			\
do {										\
	const ucl_object_t *obj__;						\
	obj__ = ucl_object_lookup(obj, key);					\
	if (obj__ == NULL) {							\
		fprintf(stderr, "Missing key: '%s'", key);			\
		return (ret);							\
	}									\
	if (!ucl_object_tostring_safe(obj__, result_ptr)) {			\
		fprintf(stderr, "Cannot convert '%s' value to string.", key);	\
		return (ret);							\
	}									\
} while(0)

static void *
lookup_check_dev(const char *dev_name, struct restore_state *rstate,
		 const ucl_object_t *obj, size_t *data_size)
{
	const char *snapshot_req;
	int64_t size, file_offset;

	snapshot_req = NULL;
	JSON_GET_STRING_OR_RETURN(JSON_SNAPSHOT_REQ_KEY, obj,
				  &snapshot_req, NULL);
	if (!strcmp(snapshot_req, dev_name)) {
		JSON_GET_INT_OR_RETURN(JSON_SIZE_KEY, obj,
				       &size, NULL);
		if (size < 0 || (uint64_t)size > SIZE_MAX) {
			fprintf(stderr, "Invalid snapshot size for '%s'.\n",
			    dev_name);
			return (NULL);
		}

		JSON_GET_INT_OR_RETURN(JSON_FILE_OFFSET_KEY, obj,
				       &file_offset, NULL);
		if (file_offset < 0 ||
		    (uint64_t)file_offset > rstate->kdata_len ||
		    (uint64_t)size >
		    rstate->kdata_len - (uint64_t)file_offset) {
			fprintf(stderr, "Invalid snapshot range for '%s'.\n",
			    dev_name);
			return (NULL);
		}

		*data_size = (size_t)size;
		return ((uint8_t *)rstate->kdata_map + file_offset);
	}

	return (NULL);
}

static const ucl_object_t *
lookup_dev_object(const char *dev_name, const char *key,
    struct restore_state *rstate)
{
	const ucl_object_t *devs, *obj;
	ucl_object_iter_t it;

	devs = ucl_object_lookup(rstate->meta_root_obj, key);
	if (devs == NULL || ucl_object_type(devs) != UCL_ARRAY)
		return (NULL);
	it = NULL;
	while ((obj = ucl_object_iterate(devs, &it, true)) != NULL) {
		const ucl_object_t *field;
		const char *name;

		field = ucl_object_lookup(obj, JSON_SNAPSHOT_REQ_KEY);
		if (field != NULL && ucl_object_tostring_safe(field, &name) &&
		    strcmp(name, dev_name) == 0)
			return (obj);
	}
	return (NULL);
}

static void *
lookup_dev(const char *dev_name, const char *key, struct restore_state *rstate,
    size_t *data_size)
{
	const ucl_object_t *devs = NULL, *obj = NULL;
	ucl_object_iter_t it = NULL;
	void *ret;

	devs = ucl_object_lookup(rstate->meta_root_obj, key);
	if (devs == NULL) {
		fprintf(stderr, "Failed to find '%s' object.\n",
			key);
		return (NULL);
	}

	if (ucl_object_type(devs) != UCL_ARRAY) {
		fprintf(stderr, "Object '%s' is not an array.\n",
			key);
		return (NULL);
	}

	while ((obj = ucl_object_iterate(devs, &it, true)) != NULL) {
		ret = lookup_check_dev(dev_name, rstate, obj, data_size);
		if (ret != NULL)
			return (ret);
	}

	return (NULL);
}

static int
vm_restore_named_topology(struct restore_state *rstate, const char *key,
    const char * const *destination, size_t destination_count)
{
	const ucl_object_t *entries, *object;
	const char **source;
	ucl_object_iter_t iterator;
	const char *name;
	char reason[256];
	size_t collect, source_capacity, source_count;
	int error;

	entries = ucl_object_lookup(rstate->meta_root_obj, key);
	if (entries == NULL || ucl_object_type(entries) != UCL_ARRAY) {
		EPRINTLN("Checkpoint '%s' manifest is missing or invalid", key);
		return (EINVAL);
	}
	source_capacity = ucl_array_size(entries);
	/*
	 * The destination topology is already known and is the authoritative
	 * bound for this array.  Never allocate more than one entry beyond it
	 * from checkpoint metadata: on a cardinality mismatch, destination_count
	 * + 1 source names always suffice to name the first unmatched device,
	 * and the validation proper only runs when the counts agree.
	 */
	if (destination_count >= SIZE_MAX / sizeof(*source))
		return (EOVERFLOW);
	collect = source_capacity;
	if (collect > destination_count + 1)
		collect = destination_count + 1;
	source = calloc(collect != 0 ? collect : 1, sizeof(*source));
	if (source == NULL)
		return (ENOMEM);

	iterator = NULL;
	source_count = 0;
	error = 0;
	while (source_count < collect &&
	    (object = ucl_object_iterate(entries, &iterator, true)) != NULL) {
		const ucl_object_t *field;

		field = ucl_object_lookup(object, JSON_SNAPSHOT_REQ_KEY);
		if (field == NULL || !ucl_object_tostring_safe(field, &name)) {
			EPRINTLN("Checkpoint '%s' entry %zu has no device name",
			    key, source_count);
			error = EINVAL;
			goto done;
		}
		source[source_count++] = name;
	}
	if (source_count != collect) {
		error = EINVAL;
		goto done;
	}
	if (source_capacity != destination_count)
		error = ENODEV;
	else
		error = checkpoint_topology_validate(source, source_count,
		    destination, destination_count);
	if (error != 0) {
		if (checkpoint_topology_describe_mismatch(source, source_count,
		    source_capacity, destination, destination_count, reason,
		    sizeof(reason)) != 0 && reason[0] != '\0')
			EPRINTLN("Checkpoint '%s' topology is incompatible: %s",
			    key, reason);
		else
			EPRINTLN("Checkpoint '%s' topology is incompatible: %s",
			    key, strerror(error));
	}

done:
	free(source);
	return (error);
}

static const ucl_object_t *
lookup_basic_metadata_object(struct restore_state *rstate)
{
	const ucl_object_t *basic_meta_obj = NULL;

	basic_meta_obj = ucl_object_lookup(rstate->meta_root_obj,
					   JSON_BASIC_METADATA_KEY);
	if (basic_meta_obj == NULL) {
		fprintf(stderr, "Failed to find '%s' object.\n",
			JSON_BASIC_METADATA_KEY);
		return (NULL);
	}

	if (ucl_object_type(basic_meta_obj) != UCL_OBJECT) {
		fprintf(stderr, "Object '%s' is not a JSON object.\n",
		JSON_BASIC_METADATA_KEY);
		return (NULL);
	}

	return (basic_meta_obj);
}

static int
lookup_hypertrace_handoff(struct restore_state *rstate, bool *required)
{
	const ucl_object_t *basic, *version_obj;
	int64_t version;

	if (rstate == NULL || required == NULL || rstate->meta_root_obj == NULL)
		return (EINVAL);
	*required = false;
	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	version_obj = ucl_object_lookup(basic,
	    JSON_HYPERTRACE_HANDOFF_VERSION_KEY);
	/* Earlier images could not carry a restorable HyperTrace device. */
	if (version_obj == NULL)
		return (rstate->checkpoint_format_version == 5 ? EPROTO : 0);
	if (!ucl_object_toint_safe(version_obj, &version) ||
	    (version != 0 && version != 1 && version != 2))
		return (EINVAL);
	if ((version == 2) != (rstate->checkpoint_format_version == 5) ||
	    (version == 2 && !rstate->hypertrace_session_present))
		return (EPROTO);
	*required = version == 1;
	return (0);
}

/* The optional VM generation record; absent in images from older peers. */
static int
lookup_vmgenid_state(struct restore_state *rstate)
{
	const ucl_object_t *basic, *obj;
	const char *text;

	rstate->vmgenid_present = false;
	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	obj = ucl_object_lookup(basic, JSON_VMGENID_STATE_KEY);
	if (obj == NULL)
		return (0);
	if (!ucl_object_tostring_safe(obj, &text) ||
	    checkpoint_vmgenid_decode(text, &rstate->vmgenid) != 0) {
		EPRINTLN("Checkpoint '%s' is malformed.", JSON_VMGENID_STATE_KEY);
		return (EINVAL);
	}
	rstate->vmgenid_present = true;
	return (0);
}

static int
vmgenid_entropy(void *buf, size_t len)
{
	return (getentropy(buf, len) == 0 ? 0 : EIO);
}

/*
 * Give the destination its VM generation ID before any vCPU runs: a fresh
 * ID with an ACPI notification for a checkpoint restore, the source's ID
 * for a live migration.  Runs after the kernel structures are restored so
 * the SCI level matches the restored interrupt controllers.  The record was
 * decoded by the preflight.
 */
static int
vm_restore_vmgenid(struct vmctx *ctx, struct restore_state *rstate,
    enum checkpoint_vmgenid_restore kind)
{
	const struct checkpoint_vmgenid *saved;
	uint8_t current[CHECKPOINT_VMGENID_ID_SIZE];
	uint8_t next[CHECKPOINT_VMGENID_ID_SIZE];
	bool notify;
	int error;

	/* No generation device on this destination: nothing to present. */
	if (vmgenc_current_id(ctx, current) != 0)
		return (0);
	saved = rstate->vmgenid_present ? &rstate->vmgenid : NULL;
	error = checkpoint_vmgenid_plan(kind, saved, current, vmgenid_entropy,
	    next, &notify);
	if (error == 0)
		error = vmgenc_restore_apply(ctx, next,
		    saved != NULL ? &saved->pm : NULL, notify);
	if (error != 0)
		EPRINTLN("Could not restore the VM generation ID: %s",
		    strerror(error));
	return (error);
}

const char *
lookup_vmname(struct restore_state *rstate)
{
	const char *vmname;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (NULL);

	JSON_GET_STRING_OR_RETURN(JSON_VMNAME_KEY, obj, &vmname, NULL);
	return (vmname);
}

int
lookup_memflags(struct restore_state *rstate, int *memflagsp)
{
	int64_t memflags;
	const ucl_object_t *obj;

	if (rstate == NULL || memflagsp == NULL)
		return (EINVAL);
	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (EINVAL);

	JSON_GET_INT_OR_RETURN(JSON_MEMFLAGS_KEY, obj, &memflags, EINVAL);
	if (memflags < 0 ||
	    (memflags & ~(VM_MEM_F_INCORE | VM_MEM_F_WIRED)) != 0) {
		fprintf(stderr, "Invalid memory flags in checkpoint metadata.\n");
		return (EINVAL);
	}

	*memflagsp = (int)memflags;
	return (0);
}

size_t
lookup_memsize(struct restore_state *rstate)
{
	int64_t memsize;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (0);

	JSON_GET_INT_OR_RETURN(JSON_MEMSIZE_KEY, obj, &memsize, 0);
	if (memsize <= 0 || (uint64_t)memsize > SIZE_MAX) {
		fprintf(stderr, "Invalid memory size in checkpoint metadata.\n");
		return (0);
	}

	return ((size_t)memsize);
}


int
lookup_guest_ncpus(struct restore_state *rstate)
{
	int64_t ncpus;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (0);

	JSON_GET_INT_OR_RETURN(JSON_NCPUS_KEY, obj, &ncpus, 0);
	if (ncpus < 1 || ncpus > INT_MAX) {
		fprintf(stderr, "Invalid vCPU count in checkpoint metadata.\n");
		return (0);
	}
	return ((int)ncpus);
}

int
lookup_cpu_topology(struct restore_state *rstate, int *ncpusp,
    uint16_t *socketsp, uint16_t *coresp, uint16_t *threadsp)
{
	const ucl_object_t *cores_obj, *obj, *sockets_obj, *threads_obj;
	int64_t cores, ncpus, sockets, threads;
	int error;

	if (rstate == NULL || ncpusp == NULL || socketsp == NULL ||
	    coresp == NULL || threadsp == NULL)
		return (EINVAL);
	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (EINVAL);
	sockets_obj = ucl_object_lookup(obj, JSON_CPU_SOCKETS_KEY);
	cores_obj = ucl_object_lookup(obj, JSON_CPU_CORES_KEY);
	threads_obj = ucl_object_lookup(obj, JSON_CPU_THREADS_KEY);
	if (sockets_obj == NULL || cores_obj == NULL || threads_obj == NULL ||
	    !ucl_object_toint_safe(sockets_obj, &sockets) ||
	    !ucl_object_toint_safe(cores_obj, &cores) ||
	    !ucl_object_toint_safe(threads_obj, &threads))
		return (EINVAL);
	JSON_GET_INT_OR_RETURN(JSON_NCPUS_KEY, obj, &ncpus, EINVAL);
	if (ncpus < 0 || sockets < 0 || cores < 0 || threads < 0)
		return (EINVAL);
	error = checkpoint_cpu_topology_validate((uint64_t)ncpus,
	    (uint64_t)sockets, (uint64_t)cores, (uint64_t)threads);
	if (error != 0)
		return (error);
	*ncpusp = (int)ncpus;
	*socketsp = (uint16_t)sockets;
	*coresp = (uint16_t)cores;
	*threadsp = (uint16_t)threads;
	return (0);
}

int
lookup_cpu_contract(struct restore_state *rstate,
    struct checkpoint_cpu_contract *contract)
{
	const ucl_object_t *basic, *object;
	const char *text;

	if (rstate == NULL || contract == NULL)
		return (EINVAL);
	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	object = ucl_object_lookup(basic, JSON_CPU_CONTRACT_KEY);
	if (object == NULL)
		return (EINVAL);
	if (!ucl_object_tostring_safe(object, &text))
		return (EINVAL);
	return (checkpoint_cpu_contract_decode(text, contract));
}

int
checkpoint_restore_cpu_contract(struct restore_state *rstate,
    struct vcpu *bsp)
{
	struct checkpoint_cpu_contract destination, source;
	char detail[192];
	int error;

	if (rstate == NULL || bsp == NULL)
		return (EINVAL);
	error = lookup_cpu_contract(rstate, &source);
	if (error != 0) {
		EPRINTLN("Checkpoint CPU contract is missing or malformed: %s",
		    strerror(error));
		return (error);
	}
	error = checkpoint_cpu_contract_capture(bsp, &destination);
	if (error != 0) {
		EPRINTLN("Cannot capture the destination CPU contract: %s",
		    strerror(error));
		return (error);
	}
	error = checkpoint_cpu_contract_match(&source, &destination);
	if (error == EXDEV) {
		/* Name the field so a refused restore is diagnosable. */
		if (checkpoint_cpu_contract_describe_mismatch(&source,
		    &destination, detail, sizeof(detail)) != EXDEV)
			strlcpy(detail, "unidentified field", sizeof(detail));
		EPRINTLN("Checkpoint CPU contract differs at %s", detail);
	} else if (error != 0)
		EPRINTLN("Checkpoint CPU contract is invalid: %s",
		    strerror(error));
	return (error);
}

int
lookup_numa_topology(struct restore_state *rstate, size_t expected_vcpus,
    uint64_t expected_memory,
    uint64_t domain_sizes[CHECKPOINT_NUMA_MAX_DOMAINS],
    size_t *domain_count, uint16_t *vcpu_domains)
{
	const ucl_object_t *basic, *mapping_object, *sizes_object;
	const char *mapping_text, *sizes_text;
	int64_t version;

	if (rstate == NULL || domain_sizes == NULL || domain_count == NULL ||
	    vcpu_domains == NULL)
		return (EINVAL);
	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	sizes_object = ucl_object_lookup(basic, JSON_NUMA_SIZES_KEY);
	mapping_object = ucl_object_lookup(basic, JSON_NUMA_MAPPING_KEY);
	if (sizes_object == NULL || mapping_object == NULL ||
	    ucl_object_lookup(basic, JSON_NUMA_VERSION_KEY) == NULL)
		return (EINVAL);
	JSON_GET_INT_OR_RETURN(JSON_NUMA_VERSION_KEY, basic, &version, EINVAL);
	if (version != 1 ||
	    !ucl_object_tostring_safe(sizes_object, &sizes_text) ||
	    !ucl_object_tostring_safe(mapping_object, &mapping_text))
		return (EINVAL);
	return (checkpoint_numa_decode(sizes_text, mapping_text,
	    expected_vcpus, expected_memory, domain_sizes, domain_count,
	    vcpu_domains));
}

int
lookup_memory_geometry(struct restore_state *rstate,
    struct checkpoint_memory_geometry *geometry)
{
	const ucl_object_t *basic, *high_base_obj, *high_size_obj;
	const ucl_object_t *low_size_obj, *page_size_obj, *version_obj;
	int64_t high_base, high_size, low_size, page_size, version;

	if (rstate == NULL || geometry == NULL)
		return (EINVAL);
	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	version_obj = ucl_object_lookup(basic,
	    JSON_MEMORY_GEOMETRY_VERSION_KEY);
	page_size_obj = ucl_object_lookup(basic, JSON_MEMORY_PAGE_SIZE_KEY);
	low_size_obj = ucl_object_lookup(basic, JSON_MEMORY_LOWMEM_SIZE_KEY);
	high_base_obj = ucl_object_lookup(basic,
	    JSON_MEMORY_HIGHMEM_BASE_KEY);
	high_size_obj = ucl_object_lookup(basic,
	    JSON_MEMORY_HIGHMEM_SIZE_KEY);
	if (version_obj == NULL || page_size_obj == NULL ||
	    low_size_obj == NULL || high_base_obj == NULL ||
	    high_size_obj == NULL ||
	    !ucl_object_toint_safe(version_obj, &version) ||
	    !ucl_object_toint_safe(page_size_obj, &page_size) ||
	    !ucl_object_toint_safe(low_size_obj, &low_size) ||
	    !ucl_object_toint_safe(high_base_obj, &high_base) ||
	    !ucl_object_toint_safe(high_size_obj, &high_size) ||
	    version != 1 || page_size <= 0 || low_size < 0 ||
	    high_base < 0 || high_size < 0)
		return (EINVAL);
	*geometry = (struct checkpoint_memory_geometry) {
		.page_size = (uint64_t)page_size,
		.lowmem_size = (uint64_t)low_size,
		.highmem_base = (uint64_t)high_base,
		.highmem_size = (uint64_t)high_size,
	};
	return (0);
}

static void
winch_handler(int signal __unused)
{
#ifdef TIOCGWINSZ
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize);
#endif /* TIOCGWINSZ */
}

static int
print_progress(size_t crtval, const size_t maxval)
{
	double crtval_gb, maxval_gb;
	size_t i, output_len, win_width, prog_start, prog_done, prog_end;
	ssize_t written;
	int mval_len, rc;

	static char prog_buf[PROG_BUF_SZ];
	static const size_t len = sizeof(prog_buf);

	static size_t div;
	static const char *div_str;

	static char wip_bar[] = { '/', '-', '\\', '|' };
	static int wip_idx = 0;

	if (maxval == 0) {
		printf("[0B / 0B]\r\n");
		return (0);
	}

	if (crtval > maxval)
		crtval = maxval;

	if (maxval > 10 * GB) {
		div = GB;
		div_str = "GiB";
	} else if (maxval > 10 * MB) {
		div = MB;
		div_str = "MiB";
	} else {
		div = KB;
		div_str = "KiB";
	}

	crtval_gb = (double) crtval / div;
	maxval_gb = (double) maxval / div;

	rc = snprintf(prog_buf, len, "%.03lf", maxval_gb);
	if (rc < 0 || (size_t)rc >= len) {
		fprintf(stderr, "Maxval too big\n");
		return (-1);
	}
	mval_len = rc;

	rc = snprintf(prog_buf, len, "\r[%*.03lf%s / %.03lf%s] |",
		mval_len, crtval_gb, div_str, maxval_gb, div_str);

	if (rc < 0 || (size_t)rc >= len) {
		fprintf(stderr, "Buffer too small to print progress\n");
		return (-1);
	}

	win_width = min(winsize.ws_col, len);
	prog_start = (size_t)rc;

	if (win_width >= 3 && prog_start < win_width - 2) {
		prog_end = win_width - prog_start - 2;
		prog_done = prog_end * (crtval_gb / maxval_gb);

		for (i = prog_start; i < prog_start + prog_done; i++)
			prog_buf[i] = '#';

		if (crtval != maxval) {
			prog_buf[i] = wip_bar[wip_idx];
			wip_idx = (wip_idx + 1) % sizeof(wip_bar);
			i++;
		} else {
			prog_buf[i++] = '#';
		}

		for (; i < win_width - 2; i++)
			prog_buf[i] = '_';

		prog_buf[win_width - 2] = '|';
		/* Drop what a wider window left in the static buffer. */
		prog_buf[win_width - 1] = '\0';
	}

	output_len = strnlen(prog_buf, win_width);
	do {
		written = write(STDOUT_FILENO, prog_buf, output_len);
	} while (written < 0 && errno == EINTR);
	if (written < 0 || (size_t)written != output_len)
		return (-1);

	return (0);
}

static int
vm_snapshot_mem_part(const int snapfd, const size_t foff, void *src,
		     const size_t len, const size_t totalmem, const bool op_wr)
{
	size_t part_done, todo, rem;
	ssize_t done;
	bool show_progress;

	if (lseek(snapfd, foff, SEEK_SET) < 0) {
		perror("Failed to change file offset");
		return (-1);
	}

	show_progress = false;
	if (isatty(STDOUT_FILENO) && (winsize.ws_col != 0))
		show_progress = true;

	part_done = foff;
	rem = len;

	if (show_progress && print_progress(part_done, totalmem) < 0)
		show_progress = false;

	while (rem > 0) {
		todo = min(SNAPSHOT_CHUNK, rem);

		if (op_wr)
			done = write(snapfd, src, todo);
		else
			done = read(snapfd, src, todo);
		if (done < 0) {
			if (errno == EINTR)
				continue;
			perror(op_wr ? "Failed to write snapshot memory" :
			    "Failed to read snapshot memory");
			return (-1);
		}
		if (done == 0) {
			errno = EIO;
			perror(op_wr ? "Snapshot memory write made no progress" :
			    "Unexpected end of snapshot memory");
			return (-1);
		}

		src = (uint8_t *)src + done;
		part_done += done;
		rem -= done;
		if (show_progress && print_progress(part_done, totalmem) < 0)
			show_progress = false;
	}

	return (0);
}

static size_t
vm_snapshot_mem(struct vmctx *ctx, int snapfd, size_t memsz, const bool op_wr)
{
	int ret;
	size_t lowmem, highmem, totalmem;
	char *baseaddr;

	ret = vm_get_guestmem_from_ctx(ctx, &baseaddr, &lowmem, &highmem);
	if (ret) {
		fprintf(stderr, "%s: unable to retrieve guest memory size\r\n",
			__func__);
		return (0);
	}
	totalmem = lowmem + highmem;

	if ((op_wr == false) && (totalmem != memsz)) {
		fprintf(stderr, "%s: mem size mismatch: %ld vs %ld\r\n",
			__func__, totalmem, memsz);
		return (0);
	}

	winsize.ws_col = 80;
#ifdef TIOCGWINSZ
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize);
#endif /* TIOCGWINSZ */
	old_winch_handler = signal(SIGWINCH, winch_handler);

	ret = vm_snapshot_mem_part(snapfd, 0, baseaddr, lowmem,
		totalmem, op_wr);
	if (ret) {
		fprintf(stderr, "%s: Could not %s lowmem\r\n",
			__func__, op_wr ? "write" : "read");
		totalmem = 0;
		goto done;
	}

	if (highmem == 0)
		goto done;

	ret = vm_snapshot_mem_part(snapfd, lowmem,
	    baseaddr + vm_get_highmem_base(ctx), highmem, totalmem, op_wr);
	if (ret) {
		fprintf(stderr, "%s: Could not %s highmem\r\n",
		        __func__, op_wr ? "write" : "read");
		totalmem = 0;
		goto done;
	}

done:
	printf("\r\n");
	signal(SIGWINCH, old_winch_handler);

	return (totalmem);
}

static int
collect_checkpoint_devmem(struct vmctx *ctx,
    struct bhyve_devmem_region **regionsp, size_t *countp)
{
	struct bhyve_devmem_region *regions;
	size_t count, length;
	void *host_base;

	if (ctx == NULL || regionsp == NULL || countp == NULL)
		return (EINVAL);
	*regionsp = NULL;
	*countp = 0;
	regions = calloc(VM_DEVMEM_END - VM_BOOTROM, sizeof(*regions));
	if (regions == NULL)
		return (ENOMEM);

	count = 0;
	for (int segid = VM_BOOTROM; segid < VM_DEVMEM_END; segid++) {
		/* Framebuffer contents belong to its device snapshot codec. */
		if (segid == VM_FRAMEBUFFER)
			continue;
		if (vm_get_devmem_info(ctx, segid, &host_base, &length,
		    regions[count].name, sizeof(regions[count].name)) != 0) {
			if (errno == ENOENT)
				continue;
			int error = errno != 0 ? errno : EIO;

			free(regions);
			return (error);
		}
		regions[count].host_base = host_base;
		regions[count].length = length;
		if (segid == VM_BOOTROM || segid == VM_PCIROM)
			regions[count].flags = BHYVE_DEVMEM_REGION_F_FIXED_ROM;
		count++;
	}
	if (count == 0) {
		free(regions);
		regions = NULL;
	}
	*regionsp = regions;
	*countp = count;
	return (0);
}

int
restore_vm_mem(struct vmctx *ctx, struct restore_state *rstate)
{
	struct bhyve_devmem_region *regions;
	size_t memsize, region_count, restored;
	int error;

	/*
	 * The restore coordinator preflights memory before it calls us, but this
	 * exported helper must preserve the same all-or-nothing boundary for any
	 * future caller.  In particular, an incompatible device-memory
	 * extension must not be discovered after ordinary guest RAM has changed.
	 */
	BHYVE_PHASE_START(__func__, "vm_restore_memory_preflight");
	error = vm_restore_memory_preflight(ctx, rstate);
	BHYVE_PHASE_DONE(__func__, "vm_restore_memory_preflight",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	memsize = lookup_memsize(rstate);
	if (memsize == 0 || memsize > INT64_MAX ||
	    rstate->vmmem_len < memsize) {
		errno = EINVAL;
		return (-1);
	}
	errno = 0;
	restored = vm_snapshot_mem(ctx, rstate->vmmem_fd, memsize, false);
	if (restored != memsize) {
		if (errno == 0)
			errno = EIO;
		return (-1);
	}

	error = collect_checkpoint_devmem(ctx, &regions, &region_count);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = bhyve_devmem_snapshot_restore(rstate->vmmem_fd, memsize,
	    rstate->vmmem_len, regions, region_count);
	free(regions);
	if (error != 0) {
		errno = error;
		return (-1);
	}

	return (0);
}

int
vm_restore_memory_preflight(struct vmctx *ctx, struct restore_state *rstate)
{
	struct bhyve_devmem_region *regions;
	size_t memsize, region_count;
	int error;

	if (ctx == NULL || rstate == NULL)
		return (EINVAL);
	memsize = lookup_memsize(rstate);
	if (memsize == 0 || memsize > INT64_MAX ||
	    rstate->vmmem_len < memsize)
		return (EINVAL);
	error = collect_checkpoint_devmem(ctx, &regions, &region_count);
	if (error != 0)
		return (error);
	error = bhyve_devmem_snapshot_validate(rstate->vmmem_fd, memsize,
	    rstate->vmmem_len, regions, region_count);
	free(regions);
	return (error);
}

static int
vm_restore_kern_topology(struct restore_state *rstate)
{
	const char *required[nitems(snapshot_kern_structs)];

	for (size_t i = 0; i < nitems(snapshot_kern_structs); i++)
		required[i] = snapshot_kern_structs[i].struct_name;
	return (vm_restore_named_topology(rstate, JSON_KERNEL_ARR_KEY, required,
	    nitems(required)));
}

int
vm_restore_kern_structs(struct vmctx *ctx, struct restore_state *rstate)
{
	int error;

	error = vm_restore_kern_topology(rstate);
	if (error != 0)
		return (error);

	for (unsigned i = 0; i < nitems(snapshot_kern_structs); i++) {
		const struct vm_snapshot_kern_info *info;
		struct vm_snapshot_meta *meta;
		void *data;
		size_t size;

		info = &snapshot_kern_structs[i];
		data = lookup_dev(info->struct_name, JSON_KERNEL_ARR_KEY, rstate, &size);
		if (data == NULL || size == 0) {
			EPRINTLN("Kernel restore record '%s' is %s",
			    info->struct_name,
			    data == NULL ? "missing" : "empty");
			return (EINVAL);
		}

		meta = &(struct vm_snapshot_meta) {
			.dev_name = info->struct_name,
			.dev_req  = info->req,

			.buffer.buf_start = data,
			.buffer.buf_size = size,

			.buffer.buf = data,
			.buffer.buf_rem = size,

			.op = VM_SNAPSHOT_RESTORE,
		};

		if (vm_snapshot_req(ctx, meta)) {
			error = errno != 0 ? errno : EIO;
			EPRINTLN("Failed to restore kernel record %s: %s",
			    info->struct_name, strerror(error));
			return (error);
		}
		error = checkpoint_record_consumption_validate(size,
		    meta->buffer.buf_rem);
		if (error != 0) {
			EPRINTLN("Kernel record %s has %zu trailing bytes",
			    info->struct_name, meta->buffer.buf_rem);
			return (error);
		}
	}
	return (0);
}

static int
vm_restore_record_presence(struct restore_state *rstate)
{
	struct pci_devinst *pdi;
	size_t size;

	for (size_t i = 0; i < nitems(snapshot_kern_structs); i++) {
		if (lookup_dev(snapshot_kern_structs[i].struct_name,
		    JSON_KERNEL_ARR_KEY, rstate, &size) == NULL || size == 0)
			return (EINVAL);
	}
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		if (lookup_dev(pdi->pi_name, JSON_DEV_ARR_KEY, rstate,
		    &size) == NULL || size == 0)
			return (EINVAL);
	}
#ifdef __amd64__
	if (lookup_dev("atkbdc", JSON_DEV_ARR_KEY, rstate, &size) == NULL ||
	    size == 0)
		return (EINVAL);
#else
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; i < md_count; i++) {
			if (lookup_dev(md[i].name, JSON_DEV_ARR_KEY, rstate,
			    &size) == NULL || size == 0)
				return (EINVAL);
		}
	}
#endif
	if (qemu_fwcfg_enabled() &&
	    (lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY, rstate,
	    &size) == NULL || size == 0))
		return (EINVAL);
	return (0);
}

static int
vm_restore_record_layout(struct restore_state *rstate)
{
	static const char * const keys[] = {
		JSON_KERNEL_ARR_KEY,
		JSON_DEV_ARR_KEY,
	};
	const ucl_object_t *entries, *field, *object;
	struct checkpoint_record_range *ranges;
	ucl_object_iter_t iterator;
	int64_t length, offset;
	size_t count, index;
	int error;

	count = 0;
	for (size_t i = 0; i < nitems(keys); i++) {
		entries = ucl_object_lookup(rstate->meta_root_obj, keys[i]);
		if (entries == NULL || ucl_object_type(entries) != UCL_ARRAY)
			return (EINVAL);
		if (ucl_array_size(entries) > SIZE_MAX - count)
			return (EOVERFLOW);
		count += ucl_array_size(entries);
	}
	if (count > SIZE_MAX / sizeof(*ranges))
		return (EOVERFLOW);
	ranges = calloc(count, sizeof(*ranges));
	if (count != 0 && ranges == NULL)
		return (ENOMEM);

	index = 0;
	for (size_t i = 0; i < nitems(keys); i++) {
		entries = ucl_object_lookup(rstate->meta_root_obj, keys[i]);
		iterator = NULL;
		while ((object = ucl_object_iterate(entries, &iterator,
		    true)) != NULL) {
			field = ucl_object_lookup(object, JSON_FILE_OFFSET_KEY);
			if (field == NULL ||
			    !ucl_object_toint_safe(field, &offset) ||
			    offset < 0) {
				error = EINVAL;
				goto done;
			}
			field = ucl_object_lookup(object, JSON_SIZE_KEY);
			if (field == NULL ||
			    !ucl_object_toint_safe(field, &length) ||
			    length <= 0) {
				error = EINVAL;
				goto done;
			}
			if (index == count) {
				error = EINVAL;
				goto done;
			}
			ranges[index].offset = (uint64_t)offset;
			ranges[index].length = (uint64_t)length;
			index++;
		}
	}
	if (index != count)
		error = EINVAL;
	else
		error = checkpoint_record_layout_validate(ranges, count,
		    rstate->kdata_len);

done:
	free(ranges);
	return (error);
}

static int
vm_restore_device(struct restore_state *rstate, vm_snapshot_dev_cb func,
    const char *name, void *data)
{
	const ucl_object_t *basic, *field;
	struct pci_snapshot_compat compatibility;
	void *dev_ptr;
	size_t dev_size;
	int64_t version;
	int error, ret;
	struct vm_snapshot_meta *meta;

	dev_ptr = lookup_dev(name, JSON_DEV_ARR_KEY, rstate, &dev_size);

	/*
	 * The restore preflight validated these same bytes: the metadata is
	 * the ucl tree parsed once by load_metadata_fd(), and the record lives
	 * in the digest-verified kern mapping taken once.  Nothing is re-read
	 * from the file between the two passes, so a failure here is a caller
	 * that skipped the preflight, not a bad checkpoint.
	 */
	assert(dev_ptr != NULL && dev_size != 0);
	basic = lookup_basic_metadata_object(rstate);
	assert(basic != NULL);
	field = ucl_object_lookup(basic, JSON_COMPAT_VERSION_KEY);
	assert(field != NULL);
	version = 0;
	(void)ucl_object_toint_safe(field, &version);
	assert(version == PCI_SNAPSHOT_COMPAT_SCHEMA);
	if (func == pci_snapshot) {
		error = pci_snapshot_compat(data, &compatibility);
		if (error == 0) {
			error = checkpoint_compat_decode(dev_ptr, dev_size,
			    &compatibility);
			if (error != 0)
				return (error);
			dev_ptr = (uint8_t *)dev_ptr +
			    CHECKPOINT_COMPAT_ENVELOPE_SIZE;
			dev_size -= CHECKPOINT_COMPAT_ENVELOPE_SIZE;
		} else if (error != ENOENT)
			return (error);
	}

	meta = &(struct vm_snapshot_meta) {
		.dev_name = name,
		.dev_data = data,

		.buffer.buf_start = dev_ptr,
		.buffer.buf_size = dev_size,

		.buffer.buf = dev_ptr,
		.buffer.buf_rem = dev_size,

		.op = VM_SNAPSHOT_RESTORE,
	};

	BHYVE_PHASE_START(__func__, name);
	ret = func(meta);
	BHYVE_PHASE_DONE(__func__, name, ret,
	    ret < 0 ? errno : 0);
	if (ret != 0) {
		EPRINTLN("Failed to restore dev: %s %d", name, ret);
		return (ret);
	}
	ret = checkpoint_record_consumption_validate(dev_size,
	    meta->buffer.buf_rem);
	if (ret != 0) {
		EPRINTLN("Restore device has trailing state: %s (%zu bytes)",
		    name, meta->buffer.buf_rem);
		return (ret);
	}

	return (0);
}

static int
vm_restore_device_topology(struct restore_state *rstate)
{
	const char **destination;
	struct pci_devinst *pdi;
	size_t destination_count;
	int error;

	destination_count = 0;
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL)
		destination_count++;
#ifdef __amd64__
	destination_count++;
#else
	destination_count += snapshot_md_device_count();
#endif
	if (qemu_fwcfg_enabled())
		destination_count++;
	if (tpm_device_present())
		destination_count++;
	if (destination_count > SIZE_MAX / sizeof(*destination))
		return (EOVERFLOW);
	destination = calloc(destination_count, sizeof(*destination));
	if (destination_count != 0 && destination == NULL)
		return (ENOMEM);
	destination_count = 0;
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL)
		destination[destination_count++] = pdi->pi_name;
#ifdef __amd64__
	destination[destination_count++] = "atkbdc";
#else
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; i < md_count; i++)
			destination[destination_count++] = md[i].name;
	}
#endif
	if (qemu_fwcfg_enabled())
		destination[destination_count++] = QEMU_FWCFG_SNAPSHOT_NAME;
	if (tpm_device_present())
		destination[destination_count++] = TPM_SNAPSHOT_NAME;
	error = vm_restore_named_topology(rstate, JSON_DEV_ARR_KEY, destination,
	    destination_count);

	free(destination);
	return (error);
}

static int
vm_machine_topology_digest_current(char *digest, size_t capacity)
{
	struct checkpoint_machine_device *devices;
	struct pci_snapshot_compat *compats;
	struct pci_devinst *pdi;
	size_t count, index;
	int error;

	count = 0;
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL)
		count++;
#ifdef __amd64__
	count++;
#else
	count += snapshot_md_device_count();
#endif
	if (qemu_fwcfg_enabled())
		count++;
	if (tpm_device_present())
		count++;
	devices = calloc(count, sizeof(*devices));
	compats = calloc(count, sizeof(*compats));
	if (count != 0 && (devices == NULL || compats == NULL)) {
		error = ENOMEM;
		goto out;
	}
	index = 0;
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		devices[index].name = pdi->pi_name;
		error = pci_snapshot_compat(pdi, &compats[index]);
		if (error == 0)
			devices[index].compat = &compats[index];
		else if (error != ENOENT)
			goto out;
		index++;
	}
#ifdef __amd64__
	devices[index++].name = "atkbdc";
#else
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; i < md_count; i++)
			devices[index++].name = md[i].name;
	}
#endif
	if (qemu_fwcfg_enabled()) {
		devices[index].name = QEMU_FWCFG_SNAPSHOT_NAME;
		error = qemu_fwcfg_snapshot_compat(&compats[index]);
		if (error != 0)
			goto out;
		devices[index].compat = &compats[index];
		index++;
	}
	if (tpm_device_present())
		devices[index++].name = TPM_SNAPSHOT_NAME;
	if (index != count) {
		error = EINVAL;
		goto out;
	}
	error = checkpoint_machine_topology_digest(devices, count, digest,
	    capacity);
out:
	free(compats);
	free(devices);
	return (error);
}

static int
vm_machine_topology_digest_source(struct restore_state *rstate, char *digest,
    size_t capacity)
{
	struct checkpoint_machine_device *devices;
	struct pci_snapshot_compat destination, *compats;
	struct pci_devinst *pdi;
	void *record;
	size_t count, index, record_size;
	int error;

	count = 0;
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL)
		count++;
#ifdef __amd64__
	count++;
#else
	count += snapshot_md_device_count();
#endif
	if (qemu_fwcfg_enabled())
		count++;
	if (tpm_device_present())
		count++;
	devices = calloc(count, sizeof(*devices));
	compats = calloc(count, sizeof(*compats));
	if (count != 0 && (devices == NULL || compats == NULL)) {
		error = ENOMEM;
		goto out;
	}
	index = 0;
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		devices[index].name = pdi->pi_name;
		error = pci_snapshot_compat(pdi, &destination);
		if (error == 0) {
			record = lookup_dev(pdi->pi_name, JSON_DEV_ARR_KEY,
			    rstate, &record_size);
			if (record == NULL) {
				error = EINVAL;
				goto out;
			}
			error = checkpoint_compat_decode(record, record_size,
			    &compats[index]);
			if (error != 0)
				goto out;
			devices[index].compat = &compats[index];
		} else if (error != ENOENT)
			goto out;
		index++;
	}
#ifdef __amd64__
	devices[index++].name = "atkbdc";
#else
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; i < md_count; i++)
			devices[index++].name = md[i].name;
	}
#endif
	if (qemu_fwcfg_enabled()) {
		devices[index].name = QEMU_FWCFG_SNAPSHOT_NAME;
		record = lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY,
		    rstate, &record_size);
		if (record == NULL) {
			error = EINVAL;
			goto out;
		}
		error = qemu_fwcfg_snapshot_compat_record(record, record_size,
		    &compats[index]);
		if (error != 0)
			goto out;
		devices[index].compat = &compats[index];
		index++;
	}
	if (tpm_device_present())
		devices[index++].name = TPM_SNAPSHOT_NAME;
	if (index != count) {
		error = EINVAL;
		goto out;
	}
	error = checkpoint_machine_topology_digest(devices, count, digest,
	    capacity);
out:
	free(compats);
	free(devices);
	return (error);
}

static int vm_restore_device_compatibility(struct restore_state *);

static int
vm_restore_machine_topology_digest(struct restore_state *rstate)
{
	const ucl_object_t *basic, *digest_field, *version_field;
	const char *recorded;
	char destination[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	char source[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	int64_t version;
	int error;

	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	version_field = ucl_object_lookup(basic,
	    JSON_MACHINE_TOPOLOGY_VERSION_KEY);
	digest_field = ucl_object_lookup(basic,
	    JSON_MACHINE_TOPOLOGY_DIGEST_KEY);
	if (version_field == NULL || digest_field == NULL ||
	    !ucl_object_toint_safe(version_field, &version) ||
	    version != CHECKPOINT_MACHINE_TOPOLOGY_VERSION ||
	    !ucl_object_tostring_safe(digest_field, &recorded) ||
	    !checkpoint_machine_digest_canonical(recorded))
		return (EINVAL);
	error = vm_machine_topology_digest_source(rstate, source,
	    sizeof(source));
	if (error != 0)
		return (error);
	if (strcmp(recorded, source) != 0)
		return (EINVAL);
	error = vm_machine_topology_digest_current(destination,
	    sizeof(destination));
	if (error != 0)
		return (error);
	if (strcmp(source, destination) != 0) {
		/*
		 * The digest covers device names and their compatibility
		 * contracts.  Name the device and field which differ: the
		 * per-device compatibility check logs the first one it refuses.
		 */
		if (vm_restore_device_compatibility(rstate) == 0)
			EPRINTLN("Checkpoint machine topology is incompatible "
			    "(digest: source %s, destination %s)", source,
			    destination);
		return (ENOTSUP);
	}
	return (0);
}

static int
vm_restore_compat_uint(const ucl_object_t *object, const char *key,
    uint64_t maximum, uint64_t *value)
{
	const ucl_object_t *field;
	int64_t parsed;

	field = ucl_object_lookup(object, key);
	if (field == NULL || !ucl_object_toint_safe(field, &parsed) ||
	    parsed < 0 || (uint64_t)parsed > maximum)
		return (EINVAL);
	*value = (uint64_t)parsed;
	return (0);
}

static int
vm_restore_compat_hex(const ucl_object_t *object, const char *key,
    uint64_t *value)
{
	const ucl_object_t *field;
	const char *string;

	field = ucl_object_lookup(object, key);
	if (field == NULL || !ucl_object_tostring_safe(field, &string))
		return (EINVAL);
	return (vm_snapshot_parse_fixed_hex(string, 16, UINT64_MAX, value));
}

static int
vm_restore_compat_hex32(const ucl_object_t *object, const char *key,
    uint32_t *value)
{
	const ucl_object_t *field;
	const char *string;
	uint64_t parsed;
	int error;

	field = ucl_object_lookup(object, key);
	if (field == NULL || !ucl_object_tostring_safe(field, &string))
		return (EINVAL);
	error = vm_snapshot_parse_fixed_hex(string, 8, UINT32_MAX, &parsed);
	if (error != 0)
		return (error);
	*value = (uint32_t)parsed;
	return (0);
}

static int
vm_restore_compat_string(const ucl_object_t *object, const char *key,
    char *destination, size_t capacity)
{
	const ucl_object_t *field;
	const char *string;

	field = ucl_object_lookup(object, key);
	if (field == NULL || !ucl_object_tostring_safe(field, &string) ||
	    strlcpy(destination, string, capacity) >= capacity)
		return (EINVAL);
	return (0);
}

static int
vm_restore_device_compatibility(struct restore_state *rstate)
{
	const ucl_object_t *basic, *field, *object;
	struct pci_snapshot_compat destination, payload, source;
	struct pci_devinst *pdi;
	void *record;
	size_t record_size;
	int64_t version;
	uint64_t value;
	int error;
	const char *stage;
	char reason[160];

	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	version = -1;
	field = ucl_object_lookup(basic, JSON_COMPAT_VERSION_KEY);
	if (field == NULL)
		return (EINVAL);
	if (!ucl_object_toint_safe(field, &version) ||
	    version != PCI_SNAPSHOT_COMPAT_SCHEMA) {
		EPRINTLN("Checkpoint device compatibility schema is "
		    "unsupported: source %jd, destination %d",
		    (intmax_t)version, PCI_SNAPSHOT_COMPAT_SCHEMA);
		return (ENOTSUP);
	}

	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		object = lookup_dev_object(pdi->pi_name, JSON_DEV_ARR_KEY,
		    rstate);
		if (object == NULL)
			return (EINVAL);
		field = ucl_object_lookup(object, JSON_COMPAT_SCHEMA_KEY);
		error = pci_snapshot_compat(pdi, &destination);
		if (error == ENOENT) {
			if (field != NULL) {
				EPRINTLN("Checkpoint device '%s' is "
				    "incompatible: checkpoint carries a "
				    "compatibility record but the destination "
				    "device has no contract", pdi->pi_name);
				return (ENOTSUP);
			}
			continue;
		}
		if (error != 0 || field == NULL) {
			EPRINTLN("Checkpoint device '%s' is incompatible: %s",
			    pdi->pi_name, error != 0 ? "destination contract is "
			    "unavailable" : "checkpoint has no compatibility "
			    "record for a device that requires one");
			return (error != 0 ? error : EINVAL);
		}

		memset(&source, 0, sizeof(source));
		stage = NULL;
		reason[0] = '\0';
		error = vm_restore_compat_uint(object, JSON_COMPAT_SCHEMA_KEY,
		    UINT32_MAX, &value);
		if (error == 0)
			source.schema = (uint32_t)value;
		if (error == 0)
			error = vm_restore_compat_uint(object,
			    JSON_COMPAT_TRANSPORT_KEY, UINT32_MAX, &value);
		if (error == 0)
			source.transport = (uint32_t)value;
		if (error == 0)
			error = vm_restore_compat_uint(object,
			    JSON_COMPAT_QUEUE_COUNT_KEY, UINT32_MAX, &value);
		if (error == 0)
			source.queue_count = (uint32_t)value;
		if (error == 0)
			error = vm_restore_compat_uint(object,
			    JSON_COMPAT_MSIX_COUNT_KEY, UINT32_MAX, &value);
		if (error == 0)
			source.msix_table_count = (uint32_t)value;
		if (error == 0)
			error = vm_restore_compat_uint(object,
			    JSON_COMPAT_CONFIG_SIZE_KEY, UINT64_MAX, &value);
		if (error == 0)
			source.config_size = value;
		if (error == 0)
			error = vm_restore_compat_hex(object,
			    JSON_COMPAT_OFFERED_KEY,
			    &source.offered_features);
		if (error == 0)
			error = vm_restore_compat_hex(object,
			    JSON_COMPAT_NEGOTIATED_KEY,
			    &source.negotiated_features);
		if (error == 0)
			error = vm_restore_compat_hex32(object,
			    JSON_COMPAT_PAYLOAD_CRC32_KEY,
			    &source.payload_crc32);
		if (error == 0)
			error = vm_restore_compat_string(object,
			    JSON_COMPAT_QUEUE_SIZES_KEY, source.queue_sizes,
			    sizeof(source.queue_sizes));
		if (error == 0)
			error = vm_restore_compat_string(object,
			    JSON_COMPAT_SHARED_MEMORY_KEY,
			    source.shared_memory,
			    sizeof(source.shared_memory));
		record = NULL;
		record_size = 0;
		if (error == 0) {
			record = lookup_dev(pdi->pi_name, JSON_DEV_ARR_KEY,
			    rstate, &record_size);
			if (record == NULL)
				error = EINVAL;
		}
		if (error == 0)
			error = checkpoint_compat_decode(record, record_size,
			    &payload);
		if (error != 0) {
			stage = "payload envelope is unreadable";
		} else if (payload.payload_crc32 !=
		    checkpoint_compat_payload_crc32((const uint8_t *)record +
		    CHECKPOINT_COMPAT_ENVELOPE_SIZE,
		    record_size - CHECKPOINT_COMPAT_ENVELOPE_SIZE)) {
			stage = "payload CRC32 does not match its envelope";
			error = EINVAL;
		} else if (!checkpoint_compat_equal(&source, &payload)) {
			/* source: checkpoint metadata; destination: payload. */
			checkpoint_compat_describe_mismatch(&source, &payload,
			    true, reason, sizeof(reason));
			stage = "metadata disagrees with the payload envelope";
			error = EINVAL;
		} else if ((error = pci_snapshot_compat_validate(&payload,
		    &destination)) != 0) {
			checkpoint_compat_describe_mismatch(&payload,
			    &destination, false, reason, sizeof(reason));
			stage = "device contract differs from the destination";
		} else if (pci_vtdtr_checkpoint_is_device(pdi) &&
		    (error = pci_vtdtr_checkpoint_features_validate(
		    payload.negotiated_features)) != 0) {
			snprintf(reason, sizeof(reason),
			    "negotiated_features %#jx",
			    (uintmax_t)payload.negotiated_features);
			stage = "virtio-dtrace features are not restorable";
		}
		if (error != 0) {
			EPRINTLN("Checkpoint device '%s' is incompatible: %s%s%s "
			    "(%s)", pdi->pi_name,
			    stage != NULL ? stage : "compatibility metadata is "
			    "invalid", reason[0] != '\0' ? ": " : "", reason,
			    strerror(error));
			return (error);
		}
	}
	return (0);
}

static int
vm_restore_device_payload_validate_one(struct restore_state *rstate,
    struct pci_devinst *pdi, int64_t version, bool capture_hypertrace)
{
	struct pci_snapshot_compat compatibility;
	void *record;
	size_t record_size;
	int error;
	bool capture, complete = false;
	const void *private_image = NULL;
	size_t private_length = 0;

	record = lookup_dev(pdi->pi_name, JSON_DEV_ARR_KEY, rstate,
	    &record_size);
	if (record == NULL || record_size == 0)
		return (EINVAL);
	if (version != PCI_SNAPSHOT_COMPAT_SCHEMA)
		return (EINVAL);
	error = pci_snapshot_compat(pdi, &compatibility);
	if (error == 0) {
		error = checkpoint_compat_decode(record, record_size,
		    &compatibility);
		if (error != 0)
			return (error);
		record = (uint8_t *)record + CHECKPOINT_COMPAT_ENVELOPE_SIZE;
		record_size -= CHECKPOINT_COMPAT_ENVELOPE_SIZE;
	} else if (error != ENOENT)
		return (error);
	struct vm_snapshot_meta meta = {
		.dev_name = pdi->pi_name,
		.dev_data = pdi,
		.buffer = {
			.buf_start = record,
			.buf_size = record_size,
			.buf = record,
			.buf_rem = record_size,
		},
		.op = VM_SNAPSHOT_VALIDATE,
	};

	capture = capture_hypertrace && pci_vtdtr_checkpoint_is_device(pdi);
	if (capture) {
		error = pci_vtdtr_checkpoint_capture_begin(pdi);
		if (error != 0)
			return (error);
	}
	error = pci_snapshot_validate(&meta);
	if (capture) {
		int capture_error = pci_vtdtr_checkpoint_capture_end(pdi,
		    &private_image, &private_length, &complete);
		if (capture_error != 0)
			return (capture_error);
		/* This device's deliberate EOPNOTSUPP follows a completed generic
		 * validator. No other EOPNOTSUPP may open the preflight gate. */
		if (error == EOPNOTSUPP && complete)
			error = 0;
	}
	if (error != 0) {
		EPRINTLN("Checkpoint device '%s' payload is invalid: %s",
		    pdi->pi_name, strerror(error));
		return (error);
	}
	error = checkpoint_record_consumption_validate(record_size,
	    meta.buffer.buf_rem);
	if (error != 0) {
		EPRINTLN("Checkpoint device '%s' has %zu trailing bytes",
		    pdi->pi_name, meta.buffer.buf_rem);
		return (error);
	}
	if (capture) {
		uintptr_t begin = (uintptr_t)record;
		uintptr_t selected = (uintptr_t)private_image;
		if (!complete || private_image == NULL || private_length == 0 ||
		    selected < begin || selected - begin > record_size ||
		    private_length > record_size - (selected - begin) ||
		    rstate->hypertrace_private_image != NULL)
			return (EPROTO);
		rstate->hypertrace_private_image = private_image;
		rstate->hypertrace_private_length = private_length;
		rstate->hypertrace_private_dev = pdi;
	}
	return (0);
}

static int
vm_restore_device_payloads_validate(struct restore_state *rstate,
    bool capture_hypertrace)
{
	const ucl_object_t *basic, *field;
	enum pci_restore_phase phase;
	struct pci_devinst *pdi;
	int64_t version;
	int error;

	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	field = ucl_object_lookup(basic, JSON_COMPAT_VERSION_KEY);
	if (field == NULL || !ucl_object_toint_safe(field, &version) ||
	    version != PCI_SNAPSHOT_COMPAT_SCHEMA)
		return (EINVAL);

	error = 0;
	for (phase = PCI_RESTORE_FABRIC;; phase--) {
		pdi = NULL;
		while ((pdi = pci_next(pdi)) != NULL) {
			if (!pci_snapshot_restore_in_phase(pdi, phase))
				continue;
			if (!pci_snapshot_restore_supported(pdi)) {
				EPRINTLN("Checkpoint device '%s' has no complete "
				    "restore validator", pdi->pi_name);
				error = ENOTSUP;
				goto cleanup;
			}
			error = vm_restore_device_payload_validate_one(rstate,
			    pdi, version, capture_hypertrace);
			if (error != 0)
				goto cleanup;
		}
		if (phase == PCI_RESTORE_NORMAL)
			break;
	}
#ifdef __amd64__
	if (error == 0) {
		void *record;
		size_t record_size;

		record = lookup_dev("atkbdc", JSON_DEV_ARR_KEY, rstate,
		    &record_size);
		if (record == NULL || record_size == 0) {
			error = EINVAL;
			goto cleanup;
		}
		struct vm_snapshot_meta meta = {
			.dev_name = "atkbdc",
			.dev_data = NULL,
			.buffer = {
				.buf_start = record,
				.buf_size = record_size,
				.buf = record,
				.buf_rem = record_size,
			},
			.op = VM_SNAPSHOT_VALIDATE,
		};
		error = atkbdc_snapshot(&meta);
		if (error == 0)
			error = checkpoint_record_consumption_validate(record_size,
			    meta.buffer.buf_rem);
		if (error != 0) {
			EPRINTLN("Checkpoint device 'atkbdc' payload is invalid: %s",
			    strerror(error));
			goto cleanup;
		}
	}
#else
	if (error == 0) {
		const struct snapshot_md_device *md;
		size_t md_count;

		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; error == 0 && i < md_count; i++) {
			void *record;
			size_t record_size;

			record = lookup_dev(md[i].name, JSON_DEV_ARR_KEY,
			    rstate, &record_size);
			if (record == NULL || record_size == 0) {
				error = EINVAL;
				goto cleanup;
			}
			struct vm_snapshot_meta meta = {
				.dev_name = md[i].name,
				.dev_data = NULL,
				.buffer = {
					.buf_start = record,
					.buf_size = record_size,
					.buf = record,
					.buf_rem = record_size,
				},
				.op = VM_SNAPSHOT_VALIDATE,
			};
			error = md[i].snapshot(&meta);
			if (error == 0)
				error = checkpoint_record_consumption_validate(
				    record_size, meta.buffer.buf_rem);
			if (error != 0) {
				EPRINTLN("Checkpoint device '%s' payload is "
				    "invalid: %s", md[i].name, strerror(error));
				goto cleanup;
			}
		}
	}
#endif
	if (error == 0 && qemu_fwcfg_enabled()) {
		void *record;
		size_t record_size;

		record = lookup_dev(QEMU_FWCFG_SNAPSHOT_NAME, JSON_DEV_ARR_KEY,
		    rstate, &record_size);
		if (record == NULL || record_size == 0) {
			error = EINVAL;
			goto cleanup;
		}
		struct vm_snapshot_meta meta = {
			.dev_name = QEMU_FWCFG_SNAPSHOT_NAME,
			.dev_data = NULL,
			.buffer = {
				.buf_start = record,
				.buf_size = record_size,
				.buf = record,
				.buf_rem = record_size,
			},
			.op = VM_SNAPSHOT_VALIDATE,
		};
		error = qemu_fwcfg_snapshot(&meta);
		if (error == 0)
			error = checkpoint_record_consumption_validate(record_size,
			    meta.buffer.buf_rem);
		if (error != 0) {
			EPRINTLN("Checkpoint device '%s' payload is invalid: %s",
			    QEMU_FWCFG_SNAPSHOT_NAME, strerror(error));
			goto cleanup;
		}
	}
	if (error == 0 && tpm_device_present()) {
		void *record;
		size_t record_size;

		record = lookup_dev(TPM_SNAPSHOT_NAME, JSON_DEV_ARR_KEY,
		    rstate, &record_size);
		if (record == NULL || record_size == 0) {
			error = EINVAL;
			goto cleanup;
		}
		struct vm_snapshot_meta meta = {
			.dev_name = TPM_SNAPSHOT_NAME,
			.dev_data = NULL,
			.buffer = {
				.buf_start = record,
				.buf_size = record_size,
				.buf = record,
				.buf_rem = record_size,
			},
			.op = VM_SNAPSHOT_VALIDATE,
		};
		error = tpm_device_snapshot(&meta);
		if (error == 0)
			error = checkpoint_record_consumption_validate(record_size,
			    meta.buffer.buf_rem);
		if (error != 0) {
			EPRINTLN("Checkpoint TPM payload is invalid: %s",
			    strerror(error));
			goto cleanup;
		}
	}
cleanup:
	/*
	 * Fabric validation can stage an immutable incoming translation view.
	 * Keep it alive through all dependent endpoint validators, then destroy
	 * it on both success and every failure path before any restore commit.
	 */
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL)
		pci_snapshot_validate_cleanup(pdi);
	return (error);
}

static int
vm_restore_preflight_internal(struct restore_state *rstate,
    bool capture_hypertrace)
{
	int error;

	if (rstate == NULL)
		return (EINVAL);
	rstate->hypertrace_private_image = NULL;
	rstate->hypertrace_private_length = 0;
	rstate->hypertrace_private_dev = NULL;
	error = tpm_device_migration_check();
	if (error != 0)
		return (error);
	error = vm_restore_kern_topology(rstate);
	if (error == 0)
		error = vm_restore_device_topology(rstate);
	if (error == 0)
		error = vm_restore_machine_topology_digest(rstate);
	if (error == 0)
		error = vm_restore_record_layout(rstate);
	if (error == 0)
		error = vm_restore_record_presence(rstate);
	if (error == 0)
		error = vm_restore_device_compatibility(rstate);
	if (error == 0)
		error = vm_restore_device_payloads_validate(rstate,
		    capture_hypertrace);
	if (error == 0)
		error = lookup_vmgenid_state(rstate);
	if (error != 0) {
		rstate->hypertrace_private_image = NULL;
		rstate->hypertrace_private_length = 0;
		rstate->hypertrace_private_dev = NULL;
	}
	return (error);
}

int
vm_restore_preflight(struct restore_state *rstate)
{

	return (vm_restore_preflight_internal(rstate, false));
}

/* The restore transaction already performed the complete device preflight
 * before any destination mutation. Repeating the ordinary public preflight
 * here would reject a captured HyperTrace private image at its deliberate
 * EOPNOTSUPP boundary, after the transaction had begun. */
static int
vm_restore_devices_prevalidated(struct restore_state *rstate)
{
	enum pci_restore_phase phase;
	int ret;
	struct pci_devinst *pdi;

	/*
	 * Restore cross-device fabrics before endpoints.  In particular,
	 * ACCESS_PLATFORM virtqueues must be remapped only after the
	 * destination IOMMU has recovered its attachment and mapping state.
	 * Preserve normal PCI enumeration order within each phase.
	 */
	for (phase = PCI_RESTORE_FABRIC;; phase--) {
		pdi = NULL;
		while ((pdi = pci_next(pdi)) != NULL) {
			if (!pci_snapshot_restore_in_phase(pdi, phase))
				continue;
			ret = vm_restore_device(rstate, pci_snapshot,
			    pdi->pi_name, pdi);
			if (ret)
				return (ret);
		}
		if (phase == PCI_RESTORE_NORMAL)
			break;
	}

#ifdef __amd64__
	ret = vm_restore_device(rstate, atkbdc_snapshot, "atkbdc", NULL);
#else
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		ret = 0;
		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; ret == 0 && i < md_count; i++)
			ret = vm_restore_device(rstate, md[i].snapshot,
			    md[i].name, NULL);
	}
#endif
	if (ret == 0 && qemu_fwcfg_enabled())
		ret = vm_restore_device(rstate, qemu_fwcfg_snapshot,
		    QEMU_FWCFG_SNAPSHOT_NAME, NULL);
	if (ret == 0 && tpm_device_present())
		ret = vm_restore_device(rstate, tpm_device_snapshot,
		    TPM_SNAPSHOT_NAME, NULL);
	return (ret);
}


int
vm_pause_devices(void)
{
	enum pci_restore_phase phase;
	int ret;
	struct pci_devinst *pdi;

	for (unsigned int i = 0; i < PCI_RESTORE_PHASE_COUNT; i++) {
		phase = pci_checkpoint_lifecycle_phase(i, false);
		pdi = NULL;
		while ((pdi = pci_next(pdi)) != NULL) {
			if (!pci_snapshot_restore_in_phase(pdi, phase))
				continue;
			ret = pci_pause(pdi);
			if (ret) {
				int resume_error;

				EPRINTLN("Cannot pause dev %s: %d",
				    pdi->pi_name, ret);
				/*
				 * pci_checkpoint_pause() records ownership per device.  A
				 * later failure must therefore unwind the already-paused
				 * prefix before returning; callers which abort before their
				 * normal cleanup otherwise strand those devices behind the
				 * checkpoint fence.  vm_resume_devices() uses the reverse
				 * dependency order and is a no-op for devices which never
				 * acquired pause ownership.
				 */
				resume_error = vm_resume_devices();
				if (resume_error != 0) {
					EPRINTLN("Cannot unwind paused devices: %d",
					    resume_error);
					return (resume_error);
				}
				return (ret);
			}
		}
	}
#ifndef __amd64__
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; i < md_count; i++) {
			if (md[i].pause == NULL)
				continue;
			ret = md[i].pause();
			if (ret != 0) {
				EPRINTLN("Cannot pause dev %s: %d", md[i].name,
				    ret);
				/* Resume hooks are idempotent; unwind all. */
				if (vm_resume_devices() != 0)
					EPRINTLN("Cannot unwind paused devices");
				return (ret);
			}
		}
	}
#endif
	/* Drain TPM writes before the checkpoint copies guest memory. */
	if (tpm_device_present()) {
		ret = tpm_device_state_begin_read();
		if (ret != 0) {
			int resume_error;

			resume_error = vm_resume_devices();
			return (resume_error != 0 ? resume_error : ret);
		}
	}

	return (0);
}

int
vm_resume_devices(void)
{
	enum pci_restore_phase phase;
	int error, ret;
	struct pci_devinst *pdi;

	/* A failed TPM restart must keep every vCPU behind the outer fence. */
	ret = tpm_device_state_end_if_active();
	if (ret != 0)
		return (ret);
#ifndef __amd64__
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		/* Platform devices pause last, so they resume first. */
		error = 0;
		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = md_count; i != 0; i--) {
			if (md[i - 1].resume == NULL)
				continue;
			ret = md[i - 1].resume();
			if (ret != 0) {
				EPRINTLN("Cannot resume '%s': %d",
				    md[i - 1].name, ret);
				if (error == 0)
					error = ret;
			}
		}
		if (error != 0)
			return (error);
	}
#endif
	for (unsigned int i = 0; i < PCI_RESTORE_PHASE_COUNT; i++) {
		phase = pci_checkpoint_lifecycle_phase(i, true);
		pdi = NULL;
		error = 0;
		while ((pdi = pci_next(pdi)) != NULL) {
			if (!pci_snapshot_restore_in_phase(pdi, phase))
				continue;
			ret = pci_resume(pdi);
			if (ret) {
				EPRINTLN("Cannot resume '%s': %d",
				    pdi->pi_name, ret);
				if (error == 0)
					error = ret;
			}
		}
		/*
		 * An unavailable fabric makes every endpoint resume unsafe.
		 * Keep their ownership and all vCPUs stopped for a later retry.
		 */
		if (error != 0)
			return (error);
	}

	return (0);
}

/*
 * BEGIN returns a kernel-issued identity through an IOWR buffer.  If only
 * that copyout fails, userspace cannot name the live owner.  Recover through
 * the descriptor-scoped ABORT_CURRENT operation and retry it once: success
 * consumes a live owner, while ESTALE proves that no owner remains on this
 * descriptor.  Other BEGIN errors occur before publication and require no
 * descriptor-wide cleanup.
 */
static int
vm_snapshot_session_begin_exact(struct vmctx *ctx,
    struct vm_snapshot_session *session, bool *resolvedp)
{
	int error, retry_error;

	if (resolvedp != NULL)
		*resolvedp = true;
	if (ctx == NULL || session == NULL || resolvedp == NULL)
		return (EINVAL);
	memset(session, 0, sizeof(*session));
	session->version = VM_SNAPSHOT_SESSION_VERSION;
	session->op = VM_SNAPSHOT_SESSION_BEGIN;
	if (vm_snapshot_session(ctx, session) == 0) {
		*resolvedp = false;
		return (0);
	}
	error = errno != 0 ? errno : EIO;
	if (error != EFAULT)
		return (error);

	session->op = VM_SNAPSHOT_SESSION_ABORT_CURRENT;
	session->session_id = 0;
	if (vm_snapshot_session(ctx, session) == 0)
		return (error);
	retry_error = errno != 0 ? errno : EIO;
	if (retry_error == ESTALE)
		return (error);

	/* Resolve an ABORT_CURRENT copyout ambiguity exactly once. */
	if (vm_snapshot_session(ctx, session) == 0 || errno == ESTALE)
		return (error);
	*resolvedp = false;
	return (error);
}

/*
 * Resolve the descriptor-owned kernel event fence despite the ambiguous
 * IOWR copyout edge.  A failed COMMIT may either have left the exact session
 * live or consumed it before copyout failed.  Retrying as ABORT distinguishes
 * those cases: success releases a still-live owner, while ESTALE proves that
 * the original operation already consumed this descriptor's identity.
 *
 * This helper reports the first ioctl error even when the ownership retry
 * resolves the session.  Callers must not mistake ownership resolution for a
 * successful checkpoint or restore operation.
 */
static int
vm_snapshot_session_release_exact(struct vmctx *ctx,
    struct vm_snapshot_session *session, bool committing, bool *releasedp)
{
	int error, retry_error;

	if (releasedp != NULL)
		*releasedp = false;
	if (ctx == NULL || session == NULL || releasedp == NULL ||
	    session->version != VM_SNAPSHOT_SESSION_VERSION ||
	    session->session_id == 0)
		return (EINVAL);
	session->op = committing ? VM_SNAPSHOT_SESSION_COMMIT :
	    VM_SNAPSHOT_SESSION_ABORT;
	if (vm_snapshot_session(ctx, session) == 0) {
		*releasedp = true;
		return (0);
	}
	error = errno != 0 ? errno : EIO;

	/* An exact ABORT is both rollback and copyout-ambiguity resolution. */
	session->op = VM_SNAPSHOT_SESSION_ABORT;
	if (vm_snapshot_session(ctx, session) == 0) {
		*releasedp = true;
		return (error);
	}
	retry_error = errno != 0 ? errno : EIO;
	if (retry_error == ESTALE) {
		*releasedp = true;
		return (error);
	}

	/*
	 * ABORT is itself an IOWR operation.  Its first attempt can consume the
	 * descriptor-owned identity and still report EFAULT when the final
	 * copyout fails.  Repeat the same idempotent credential once: success
	 * releases an owner which the first attempt did not consume, while
	 * ESTALE proves that an earlier attempt did.  No other result proves
	 * release, so the caller must keep execution stopped.
	 */
	if (vm_snapshot_session(ctx, session) == 0 || errno == ESTALE)
		*releasedp = true;
	return (error);
}

/*
 * Restore is one destination publication transaction.  Preflight every
 * user-space record before acquiring the kernel event fence, then retain the
 * descriptor-owned all-vCPU lease from the first memory mutation through
 * device and kernel publication.  Devices cannot resume until COMMIT has
 * consumed that exact lease.  On every failure, ABORT merges any idempotent
 * destination event deferred after the restore cut and reopens ingress; a
 * destination with partially restored memory never executes because this
 * routine returns with its vCPUs stopped.
 */
static void
hypertrace_private_image_digest(const struct restore_state *rstate,
    uint8_t digest[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX hash;

	SHA256_Init(&hash);
	SHA256_Update(&hash, rstate->hypertrace_private_image,
	    rstate->hypertrace_private_length);
	SHA256_Final(digest, &hash);
}

static int
hypertrace_private_image_unchanged(const struct restore_state *rstate,
    const uint8_t expected[SHA256_DIGEST_LENGTH])
{
	uint8_t actual[SHA256_DIGEST_LENGTH];
	int error;

	if (rstate->hypertrace_private_image == NULL ||
	    rstate->hypertrace_private_length == 0)
		return (EINVAL);
	hypertrace_private_image_digest(rstate, actual);
	error = timingsafe_bcmp(actual, expected, sizeof(actual)) == 0 ?
	    0 : EPROTO;
	explicit_bzero(actual, sizeof(actual));
	return (error);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* No kernel restore session or vCPU release may precede this handoff cut.
 * A fresh reservation remains cancelable until the caller starts MUTATE. */
static int
hypertrace_restore_prepare_handoff(struct vmctx *ctx,
    struct restore_state *rstate, bool has_transfer_state,
    const uint8_t private_digest[SHA256_DIGEST_LENGTH], bool *rebinding,
    bool *reserved)
{
	int error;

	*rebinding = false;
	*reserved = false;
	if (hypertrace_handoff_rebind_begin_optional(ctx,
	    rstate->handoff_token, rstate->handoff_digest, rebinding) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("Could not classify HyperTrace restore ticket: %s",
		    strerror(error));
		return (error);
	}
	if (*rebinding) {
		if (hypertrace_handoff_rebind_stage(ctx, rstate->handoff_token,
		    rstate->handoff_digest) != 0 ||
		    (has_transfer_state ?
		    (hypertrace_handoff_rebind_pending(ctx,
		    rstate->handoff_token, rstate->handoff_digest) != 0 ||
		    hypertrace_handoff_rebind_nonempty_preflight(ctx,
		    rstate->handoff_token, rstate->handoff_digest) != 0) :
		    hypertrace_handoff_rebind_empty_ready(ctx,
		    rstate->handoff_token, rstate->handoff_digest) != 0)) {
			error = errno != 0 ? errno : EIO;
			EPRINTLN("Could not stage HyperTrace rebind plan: %s",
			    strerror(error));
			return (error);
		}
		/* Nonempty HRP1/HTD5 lacks a recoverable owner commit. */
		if (has_transfer_state)
			return (EOPNOTSUPP);
	} else {
		if (hypertrace_handoff_destination_ensure(ctx,
		    DTRACED_HANDOFF_RESERVE, rstate->handoff_token,
		    rstate->handoff_digest) != 0) {
			error = errno != 0 ? errno : EIO;
			EPRINTLN("Could not reserve HyperTrace checkpoint "
			    "ticket: %s", strerror(error));
			return (error);
		}
		*reserved = true;
	}
	/* The saved device query needs the staged foreign journal to answer
	 * source-delivery, KILL, and cleanup status accurately. */
	if (has_transfer_state && !*rebinding &&
	    hypertrace_handoff_destination_import_prestart(ctx,
	    rstate->handoff_token, rstate->handoff_digest,
	    rstate->hypertrace_transfer,
	    rstate->hypertrace_transfer_length) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("Could not stage HyperTrace destination import: %s",
		    strerror(error));
		return (error);
	}
	if (rstate->hypertrace_private_image != NULL) {
		if (rstate->checkpoint_format_version != 4 ||
		    !pci_vtdtr_checkpoint_is_device(
		    rstate->hypertrace_private_dev))
			return (EPROTO);
		error = hypertrace_private_image_unchanged(rstate,
		    private_digest);
		if (error != 0)
			return (error);
		error = pci_vtdtr_checkpoint_private_image_query(
		    __DECONST(void *, rstate->hypertrace_private_image),
		    rstate->hypertrace_private_length, ctx,
		    rstate->handoff_token, rstate->handoff_digest);
		if (error != 0) {
			EPRINTLN("HyperTrace device image failed "
			    "handoff query: %s", strerror(error));
			return (error);
		}
	}
	/* Pending import is inspectable, but its execution lease is not yet
	 * complete. The caller can still CANCEL before kernel mutation. */
	return (has_transfer_state ? EOPNOTSUPP : 0);
}

/* A fresh ticket is reversible only before MUTATE or CLAIM. Report a
 * failed cancellation as the restore error: the caller must not mistake
 * the original preflight failure for a clean rollback. */
static int
hypertrace_restore_cancel_if_safe(struct vmctx *ctx,
    const struct restore_state *rstate, bool reserved, bool mutating,
    bool claimed)
{
	if (!reserved || mutating || claimed)
		return (0);
	if (hypertrace_handoff_destination_ensure(ctx, DTRACED_HANDOFF_CANCEL,
	    rstate->handoff_token, rstate->handoff_digest) != 0)
		return (errno != 0 ? errno : EIO);
	return (0);
}

/* Trace continuity across restore/migration is a future feature, disabled
 * because the current product contract is fresh-session.  Destination-side
 * handoff: restore refuses continuity (format-4 / handoff v1) images, so
 * this is intentionally unreachable until enabled. */
/* A lost MUTATE reply can mean the daemon already advanced the ticket.
 * Set the irreversible boundary before sending, so failure recovery never
 * races an in-flight MUTATE with CANCEL. */
static int
hypertrace_restore_begin_mutation(struct vmctx *ctx,
    const struct restore_state *rstate, bool *mutating)
{
	*mutating = true;
	if (hypertrace_handoff_destination_ensure(ctx, DTRACED_HANDOFF_MUTATE,
	    rstate->handoff_token, rstate->handoff_digest) != 0)
		return (errno != 0 ? errno : EIO);
	return (0);
}

int
vm_restore_transaction(struct vmctx *ctx, struct restore_state *rstate)
{
	struct vm_snapshot_session session;
	dtraced_replay_kill_t *replay_kills = NULL;
	size_t replay_count = 0;
	uint8_t private_digest[SHA256_DIGEST_LENGTH] = { 0 };
	bool released, resolved, session_active;
	bool handoff_required = false, handoff_reserved = false;
	bool fresh_session;
	bool handoff_rebinding = false;
	bool handoff_has_transfer_state = false;
	size_t handoff_replay_controls = 0;
	bool handoff_mutating = false, handoff_claimed = false;
	bool ticket_attached = false;
	bool devices_paused = false;
	int error, release_error;

	BHYVE_TRACE(RESTORE_BEGIN, (uintptr_t)ctx);
	if (ctx == NULL || rstate == NULL) {
		BHYVE_TRACE(RESTORE_RESULT, EINVAL);
		return (EINVAL);
	}
	error = tpm_device_migration_check();
	if (error != 0) {
		BHYVE_TRACE(RESTORE_RESULT, error);
		return (error);
	}
	fresh_session = rstate->checkpoint_format_version == 5;
	/*
	 * bhyverun must have fenced every newly created vCPU before this
	 * transaction starts.  Refuse a direct caller rather than allowing a
	 * destination-local instruction to run before the saved state commits.
	 */
	if (!checkpoint_restore_startup_held()) {
		BHYVE_TRACE(RESTORE_RESULT, EBUSY);
		return (EBUSY);
	}
	error = lookup_hypertrace_handoff(rstate, &handoff_required);
	/*
	 * Trace continuity across restore/migration is a future feature,
	 * disabled because the current product contract is fresh-session:
	 * refuse a transfer-ticket image (format 4, or handoff metadata
	 * version 1) before any mutation.  The handoff code below is
	 * intentionally unreachable until enabled.
	 */
	if (rstate->checkpoint_format_version == 4 ||
	    (error == 0 && handoff_required)) {
		EPRINTLN("Trace-continuity checkpoints are not restored; "
		    "restore requires a fresh-session checkpoint.");
		BHYVE_TRACE(RESTORE_RESULT, ENOTSUP);
		return (ENOTSUP);
	}
	if (error != 0 || ((handoff_required || fresh_session) &&
	    (!hypertrace_initialized() || !rstate->handoff_identity_valid ||
	    rstate->checkpoint_lock_fd < 0 ||
	    checkpoint_regular_fd(rstate->checkpoint_lock_fd) != 0))) {
		error = error != 0 ? error : ENOTSUP;
		BHYVE_TRACE(RESTORE_RESULT, error);
		return (error);
	}
	if (fresh_session && (!rstate->hypertrace_session_present ||
	    handoff_required || rstate->hypertrace_transfer != NULL ||
	    rstate->hypertrace_release_present)) {
		BHYVE_TRACE(RESTORE_RESULT, EPROTO);
		return (EPROTO);
	}
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (rstate->checkpoint_format_version == 4) {
		if (!handoff_required || rstate->hypertrace_transfer == NULL ||
		    rstate->hypertrace_transfer_length <
		    HYPERTRACE_TRANSFER_MIN_BYTES ||
		    hypertrace_transfer_inspect(rstate->hypertrace_transfer,
		    rstate->hypertrace_transfer_length,
		    rstate->handoff_token, &handoff_has_transfer_state) != 0) {
			BHYVE_TRACE(RESTORE_RESULT, EPROTO);
			return (EPROTO);
		}
		if (hypertrace_transfer_replay_controls(
		    rstate->hypertrace_transfer,
		    rstate->hypertrace_transfer_length,
		    rstate->handoff_token, &handoff_replay_controls) != 0) {
			BHYVE_TRACE(RESTORE_RESULT, EPROTO);
			return (EPROTO);
		}
	}
	session_active = false;
	memset(&session, 0, sizeof(session));

	BHYVE_PHASE_START(__func__, "vm_pause_devices");
	error = vm_pause_devices();
	BHYVE_PHASE_DONE(__func__, "vm_pause_devices",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Failed to pause PCI device state.");
		BHYVE_TRACE(RESTORE_RESULT, error);
		return (error);
	}
	devices_paused = true;
	BHYVE_PHASE_START(__func__, "vm_restore_preflight");
	error = vm_restore_preflight_internal(rstate,
	    handoff_required || fresh_session);
	BHYVE_PHASE_DONE(__func__, "vm_restore_preflight",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Checkpoint topology or device contract is invalid.");
		goto failed;
	}
	/* A nonempty import must fit its saved device queue and every
	 * projected HJX1 replay control before the daemon enters MUTATE. */
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_has_transfer_state) {
		if (rstate->hypertrace_private_image == NULL) {
			error = EPROTO;
			goto failed;
		}
		error = pci_vtdtr_checkpoint_private_image_replay_room(
		    __DECONST(void *, rstate->hypertrace_private_image),
		    rstate->hypertrace_private_length, handoff_replay_controls);
		if (error != 0) {
			EPRINTLN("HyperTrace replay exceeds restored device queue: %s",
			    strerror(error));
			goto failed;
		}
	}
	if ((handoff_required || fresh_session) &&
	    rstate->hypertrace_private_image != NULL)
		hypertrace_private_image_digest(rstate, private_digest);
	BHYVE_PHASE_START(__func__, "vm_restore_memory_preflight");
	error = vm_restore_memory_preflight(ctx, rstate);
	BHYVE_PHASE_DONE(__func__, "vm_restore_memory_preflight",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Checkpoint memory layout is invalid.");
		goto failed;
	}
	/* Complete read-only device, queue, and memory preflight before
	 * reserving a destination ticket or staging a transfer. */
	if (fresh_session) {
		error = pci_vtdtr_session_restore_stage_paused(
		    rstate->hypertrace_private_dev, rstate->hypertrace_session,
		    sizeof(rstate->hypertrace_session),
		    __DECONST(void *, rstate->hypertrace_private_image),
		    rstate->hypertrace_private_length);
		if (error != 0)
			goto failed;
	}
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required && rstate->hypertrace_release_present &&
	    hypertrace_handoff_destination_stage_release_prestart(ctx,
	    rstate->handoff_token, rstate->handoff_digest,
	    rstate->hypertrace_release) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("Could not stage signed HyperTrace source release: %s",
		    strerror(error));
		goto failed;
	}
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required) {
		error = hypertrace_restore_prepare_handoff(ctx, rstate,
		    handoff_has_transfer_state, private_digest,
		    &handoff_rebinding, &handoff_reserved);
		if (error != 0)
			goto failed;
	}

	BHYVE_PHASE_START(__func__, "vm_snapshot_session_begin_exact");
	error = vm_snapshot_session_begin_exact(ctx, &session, &resolved);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Could not begin kernel restore session: %s",
		    strerror(error));
		if (!resolved)
			EPRINTLN("Kernel restore session ownership is unresolved; "
			    "the destination must remain stopped until exit.");
		goto failed;
	}
	session_active = true;
	/* Once memory changes, CANCEL is no longer a valid rollback.  Publish
	 * that transition durably before the first destination mutation. */
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required && !handoff_rebinding) {
		error = hypertrace_restore_begin_mutation(ctx, rstate,
		    &handoff_mutating);
		if (error != 0) {
			EPRINTLN("Could not begin HyperTrace destination mutation: %s",
			    strerror(error));
			goto failed;
		}
	}

	FPRINTLN(stdout, "Restoring vm mem...");
	BHYVE_PHASE_START(__func__, "restore_vm_mem");
	error = restore_vm_mem(ctx, rstate);
	BHYVE_PHASE_DONE(__func__, "restore_vm_mem", error,
	    error != 0 ? errno : 0);
	if (error != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("Failed to restore VM memory.");
		goto failed;
	}
	if ((handoff_required || fresh_session) &&
	    rstate->hypertrace_private_image != NULL) {
		error = hypertrace_private_image_unchanged(rstate,
		    private_digest);
		if (error != 0) {
			EPRINTLN("HyperTrace private image changed before device "
			    "restore.");
			goto failed;
		}
	}
	FPRINTLN(stdout, "Restoring pci devs...");
	BHYVE_PHASE_START(__func__, "vm_restore_devices");
	error = vm_restore_devices_prevalidated(rstate);
	BHYVE_PHASE_DONE(__func__, "vm_restore_devices",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Failed to restore PCI device state.");
		goto failed;
	}
	if ((handoff_required || fresh_session) &&
	    rstate->hypertrace_private_image != NULL) {
		error = hypertrace_private_image_unchanged(rstate,
		    private_digest);
		if (error != 0) {
			EPRINTLN("HyperTrace private image changed during device "
			    "restore.");
			goto failed;
		}
	}
	FPRINTLN(stdout, "Restoring kernel structs...");
	BHYVE_PHASE_START(__func__, "vm_restore_kern_structs");
	error = vm_restore_kern_structs(ctx, rstate);
	BHYVE_PHASE_DONE(__func__, "vm_restore_kern_structs",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Failed to restore kernel structs.");
		goto failed;
	}
	if (fresh_session) {
		error = pci_vtdtr_session_discard_paused(
		    rstate->hypertrace_private_dev);
		if (error != 0)
			goto failed;
	}

	BHYVE_PHASE_START(__func__, "vm_snapshot_session_release_exact");
	release_error = vm_snapshot_session_release_exact(ctx, &session, true,
	    &released);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",
	    release_error, release_error < 0 ? errno : 0);
	if (released)
		session_active = false;
	if (release_error != 0) {
		error = release_error;
		EPRINTLN("Could not commit kernel restore session: %s",
		    strerror(error));
		goto failed;
	}
	/* A restored checkpoint is a new generation (also on its next restore). */
	error = vm_restore_vmgenid(ctx, rstate, CHECKPOINT_VMGENID_RESTORE);
	if (error != 0)
		goto failed;
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required) {
		int handoff_error = handoff_rebinding ?
		    hypertrace_handoff_rebind_commit_empty(ctx,
		    rstate->handoff_token, rstate->handoff_digest) :
		    hypertrace_handoff_destination_ensure(ctx,
		    DTRACED_HANDOFF_CLAIM, rstate->handoff_token,
		    rstate->handoff_digest);
		if (handoff_error != 0) {
			error = errno != 0 ? errno : EIO;
			EPRINTLN("Could not commit HyperTrace destination "
			    "ticket: %s", strerror(error));
			goto failed;
		}
		handoff_claimed = true;
		/* Committed ticket ownership does not prove that source KILLs are
		 * present in the destination incarnation. Hold device and vCPU
		 * startup until the attested daemon has durably copied every source
		 * revocation. An
		 * uncertain reply permits an exact retry: the bind is idempotent. */
		if (hypertrace_handoff_destination_prestart(ctx,
		    DTRACED_HANDOFF_BIND_KILLS_ALL, rstate->handoff_token,
		    rstate->handoff_digest) != 0 &&
		    hypertrace_handoff_destination_prestart(ctx,
		    DTRACED_HANDOFF_BIND_KILLS_ALL, rstate->handoff_token,
		    rstate->handoff_digest) != 0) {
			error = errno != 0 ? errno : EIO;
			EPRINTLN("Could not bind HyperTrace destination KILLs: %s",
			    strerror(error));
			goto failed;
		}
		/* The saved device queue can contain host-bound ELF deliveries.
		 * Bind their exact source receipts to this claimed destination
		 * before daemon admission or any guest vCPU release. The operation
		 * is idempotent after a reply is lost. */
		if (rstate->hypertrace_private_image != NULL) {
			error = hypertrace_private_image_unchanged(rstate,
			    private_digest);
			if (error != 0) {
				EPRINTLN("HyperTrace private image changed before "
				    "delivery binding.");
				goto failed;
			}
			error = pci_vtdtr_checkpoint_private_image_bind(
			    __DECONST(void *, rstate->hypertrace_private_image),
			    rstate->hypertrace_private_length, ctx,
			    rstate->handoff_token, rstate->handoff_digest);
			if (error != 0)
				error = pci_vtdtr_checkpoint_private_image_bind(
				    __DECONST(void *,
				    rstate->hypertrace_private_image),
				    rstate->hypertrace_private_length, ctx,
				    rstate->handoff_token, rstate->handoff_digest);
			if (error != 0) {
				EPRINTLN("Could not bind HyperTrace device deliveries: %s",
				    strerror(error));
				goto failed;
			}
		}
		/* The empty transfer is an exact no-op; a later nonempty import
		 * needs HLC1 before the connector or guest can run. Ask the daemon
		 * for the same durable promotion barrier in both cases. */
		if (hypertrace_handoff_destination_promote_prestart(ctx,
		    rstate->handoff_token, rstate->handoff_digest) != 0) {
			error = errno != 0 ? errno : EIO;
			EPRINTLN("Could not promote HyperTrace destination import: %s",
			    strerror(error));
			goto failed;
		}
	}
	if (hypertrace_initialized() &&
	    hypertrace_start_ready(ctx, 30000) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("HyperTrace daemon did not admit the restored VM: %s",
		    strerror(error));
		goto failed;
	}
	/* Take the attested journal cut and attach it before the device reader
	 * can inspect the restored queue. The pause still owns its mutex. */
	if (hypertrace_initialized() &&
	    (error = hypertrace_take_replay_kills(ctx,
	    &replay_kills, &replay_count)) != 0) {
		EPRINTLN("Could not obtain HyperTrace admission replay: %s",
		    strerror(error));
		goto failed;
	}
	if (replay_count != 0 &&
	    (fresh_session || rstate->hypertrace_private_dev == NULL)) {
		error = EPROTO;
		EPRINTLN("HyperTrace replay KILLs have no destination device.");
		goto failed;
	}
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required && rstate->hypertrace_private_dev != NULL) {
		error = pci_vtdtr_handoff_ticket_attach_paused(
		    rstate->hypertrace_private_dev, rstate->handoff_token,
		    rstate->handoff_digest, replay_kills, replay_count);
		if (error != 0) {
			EPRINTLN("Could not attach HyperTrace handoff ticket: %s",
			    strerror(error));
			goto failed;
		}
		ticket_attached = true;
		/* Admission KILLs were inserted into the private saved queue.
		 * Publish the queue and attested ticket as one paused-device cut,
		 * after every daemon binding and the complete admission manifest. */
		error = pci_vtdtr_checkpoint_publish_paused(
		    rstate->hypertrace_private_dev);
		if (error != 0) {
			EPRINTLN("Could not publish HyperTrace device queue: %s",
			    strerror(error));
			goto failed;
		}
	}
	FPRINTLN(stdout, "Resuming pci devs...");
	BHYVE_PHASE_START(__func__, "vm_resume_devices");
	error = vm_resume_devices();
	BHYVE_PHASE_DONE(__func__, "vm_resume_devices",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Failed to resume PCI device state.");
		goto failed;
	}
	devices_paused = false;
	/* Guest replies require running vCPUs. Queue PREPARE now; the device
	 * communicator authorizes the new session only after guest ACTIVE. */
	if (fresh_session &&
	    (error = pci_vtdtr_session_attach_begin(ctx)) != 0)
		goto failed;
	/* The VirtIO-DTrace reader could not ACK imported ELF work while the
	 * device was paused. It may now drain the claimed replay into the
	 * published queue, but no guest vCPU runs before this durable cut. */
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required && hypertrace_handoff_replay_drain(ctx,
	    rstate->handoff_token, rstate->handoff_digest, 30000) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("HyperTrace imported ELF replay is not durable: %s",
		    strerror(error));
		if (ticket_attached)
			pci_vtdtr_handoff_ticket_clear(
			    rstate->hypertrace_private_dev);
		goto failed;
	}
	/* Record the exact claimed VM lifetime before any restored vCPU can
	 * run. An absent marker then proves a failed claim never crossed the
	 * execution boundary; a present or uncertain one forbids rebinding. */
	/* Trace continuity (disabled future feature): continuity images are refused above. */
	if (handoff_required && hypertrace_handoff_execution_start(ctx,
	    rstate->handoff_token, rstate->handoff_digest) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("Could not mark HyperTrace execution start: %s",
		    strerror(error));
		if (ticket_attached)
			pci_vtdtr_handoff_ticket_clear(
			    rstate->hypertrace_private_dev);
		goto failed;
	}
	BHYVE_PHASE_START(__func__, "checkpoint_restore_startup_release");
	error = checkpoint_restore_startup_release();
	BHYVE_PHASE_DONE(__func__, "checkpoint_restore_startup_release",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		EPRINTLN("Failed to release restore startup fence.");
		/* Trace continuity (disabled future feature): continuity images are refused above. */
		if (ticket_attached)
			pci_vtdtr_handoff_ticket_clear(
			    rstate->hypertrace_private_dev);
	}
	free(replay_kills);
	BHYVE_TRACE(RESTORE_RESULT, error);
	return (error);

failed:
	free(replay_kills);
	if (session_active) {
		BHYVE_PHASE_START(__func__, "vm_snapshot_session_release_exact");
		release_error = vm_snapshot_session_release_exact(ctx, &session,
		    false, &released);
		BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",
		    release_error, release_error < 0 ? errno : 0);
		if (release_error != 0) {
			EPRINTLN("Could not abort kernel restore session: %s",
			    strerror(release_error));
			if (error == 0)
				error = release_error;
		}
	}
	release_error = hypertrace_restore_cancel_if_safe(ctx, rstate,
	    handoff_reserved, handoff_mutating, handoff_claimed);
	if (release_error != 0) {
		EPRINTLN("Could not cancel HyperTrace checkpoint reservation; "
		    "the destination remains stopped: %s",
		    strerror(release_error));
		error = release_error;
	}
	/* The failed destination exits with vCPUs fenced. Release the DTrace
	 * pause owner before its atexit handler joins the device workers. */
	if (devices_paused)
		(void)pci_vtdtr_checkpoint_stop();
	BHYVE_TRACE(RESTORE_RESULT, error != 0 ? error : EIO);
	return (error != 0 ? error : EIO);
}

static int
snapshot_write_all(int fd, const void *buffer, size_t length)
{
	const uint8_t *cursor;
	ssize_t written;

	cursor = buffer;
	while (length != 0) {
		written = write(fd, cursor, length);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (written == 0) {
			errno = EIO;
			return (-1);
		}
		cursor += written;
		length -= (size_t)written;
	}
	return (0);
}

static void
checkpoint_remove_old_generation(int fddir, const char *checkpoint_file,
    const struct checkpoint_manifest *old)
{
	const char *members[4];
	uint8_t token[16];

	members[0] = old->data;
	members[1] = old->kern;
	members[2] = old->meta;
	members[3] = old->trace;
	for (unsigned int i = 0;
	    i < (old->format_version == 4 || old->format_version == 5 ?
	    nitems(members) : 3); i++) {
		if (unlinkat(fddir, members[i], 0) != 0 && errno != ENOENT)
			EPRINTLN("Cannot remove old checkpoint member '%s': %s",
			    members[i], strerror(errno));
	}
	if (old->format_version == 4 &&
	    checkpoint_manifest_handoff_token(checkpoint_file, old, token) == 0) {
		int release_error = checkpoint_release_remove_at(fddir, token);
		if (release_error != 0)
			EPRINTLN("Cannot remove old HyperTrace release: %s",
			    strerror(release_error));
	}
	if (fsync(fddir) != 0)
		EPRINTLN("Cannot persist old checkpoint cleanup: %s",
		    strerror(errno));
}

static int
vm_save_kern_struct(struct vmctx *ctx, int data_fd, xo_handle_t *xop,
    const char *array_key, struct vm_snapshot_meta *meta, off_t *offset)
{
	int error, ret;
	size_t data_size;

	BHYVE_PHASE_START(__func__, "vm_snapshot_req");
	ret = vm_snapshot_req(ctx, meta);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_req",
	    ret, ret < 0 ? errno : 0);
	if (ret != 0) {
		error = errno != 0 ? errno : EIO;
		fprintf(stderr, "%s: Failed to snapshot struct %s: %s\r\n",
		    __func__, meta->dev_name, strerror(error));
		ret = error;
		goto done;
	}

	data_size = vm_get_snapshot_size(meta);

	if (snapshot_write_all(data_fd, meta->buffer.buf_start, data_size) != 0) {
		error = errno != 0 ? errno : EIO;
		perror("Failed to write all snapshotted data.");
		ret = error;
		goto done;
	}

	/* Write metadata. */
	xo_open_instance_h(xop, array_key);
	xo_emit_h(xop, "{:" JSON_SNAPSHOT_REQ_KEY "/%s}\n",
	    meta->dev_name);
	xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%zu}\n", data_size);
	xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%jd}\n",
	    (intmax_t)*offset);
	xo_close_instance_h(xop, array_key);

	*offset += data_size;

done:
	return (ret);
}

static int
vm_save_kern_structs(struct vmctx *ctx, int data_fd, xo_handle_t *xop)
{
	int ret, error;
	off_t offset;
	size_t buf_size, i;
	char *buffer;
	struct vm_snapshot_meta *meta;

	error = 0;
	offset = 0;
	buf_size = SNAPSHOT_BUFFER_SIZE;

	buffer = malloc(SNAPSHOT_BUFFER_SIZE * sizeof(char));
	if (buffer == NULL) {
		error = ENOMEM;
		perror("Failed to allocate memory for snapshot buffer");
		goto err_vm_snapshot_kern_data;
	}

	meta = &(struct vm_snapshot_meta) {
		.buffer.buf_start = buffer,
		.buffer.buf_size = buf_size,

		.op = VM_SNAPSHOT_SAVE,
	};

	xo_open_list_h(xop, JSON_KERNEL_ARR_KEY);
	for (i = 0; i < nitems(snapshot_kern_structs); i++) {
		meta->dev_name = snapshot_kern_structs[i].struct_name;
		meta->dev_req  = snapshot_kern_structs[i].req;

		memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
		meta->buffer.buf = meta->buffer.buf_start;
		meta->buffer.buf_rem = meta->buffer.buf_size;

		ret = vm_save_kern_struct(ctx, data_fd, xop,
		    JSON_KERNEL_ARR_KEY, meta, &offset);
		if (ret != 0) {
			error = ret;
			goto err_vm_snapshot_kern_data;
		}
	}
	xo_close_list_h(xop, JSON_KERNEL_ARR_KEY);

err_vm_snapshot_kern_data:
	if (buffer != NULL)
		free(buffer);
	return (error);
}

static int
vm_snapshot_basic_metadata(struct vmctx *ctx, xo_handle_t *xop, size_t memsz)
{
	struct checkpoint_cpu_contract cpu_contract;
	struct checkpoint_memory_geometry geometry;
	uint64_t domain_sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint16_t *vcpu_domains;
	char topology_digest[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	char vmgenid_text[CHECKPOINT_VMGENID_TEXT_SIZE];
	struct checkpoint_vmgenid vmgenid;
	char *cpu_contract_text, *mapping_text, *sizes_text;
	size_t domain_count;
	int error;

	/*
	 * UCL stores these JSON metadata values as signed 64-bit integers.
	 * Reject an image which could be written but never parsed by restore.
	 */
	if (ctx == NULL || xop == NULL || memsz == 0 || memsz > INT64_MAX)
		return (memsz > INT64_MAX ? EOVERFLOW : EINVAL);
	/* Optional record: a VM without a generation device carries none.
	 * Capturing it reads only; a running checkpoint keeps its ID. */
	vmgenid_text[0] = '\0';
	if (vmgenc_checkpoint_state(ctx, &vmgenid) == 0 &&
	    (error = checkpoint_vmgenid_encode(&vmgenid, vmgenid_text,
	    sizeof(vmgenid_text))) != 0)
		return (error);
	cpu_contract_text = NULL;
	error = checkpoint_cpu_contract_capture(fbsdrun_vcpu(0),
	    &cpu_contract);
	if (error == 0)
		error = checkpoint_cpu_contract_encode(&cpu_contract,
		    &cpu_contract_text);
	/*
	 * A missing CPU-contract codec is not a valid image.  The sole current
	 * format must bind its CPU execution contract before publication.
	 */
	if (error != 0)
		return (error);
	vcpu_domains = calloc((size_t)guest_ncpus, sizeof(*vcpu_domains));
	if (vcpu_domains == NULL) {
		free(cpu_contract_text);
		return (ENOMEM);
	}
	error = bhyve_numa_checkpoint_export(domain_sizes,
	    nitems(domain_sizes), vcpu_domains, (size_t)guest_ncpus,
	    &domain_count);
	if (error == 0)
		error = checkpoint_numa_mapping_validate(domain_sizes,
		    domain_count, vcpu_domains, (size_t)guest_ncpus, memsz);
	sizes_text = NULL;
	mapping_text = NULL;
	if (error == 0)
		error = checkpoint_numa_encode(domain_sizes, domain_count,
		    vcpu_domains, (size_t)guest_ncpus, &sizes_text,
		    &mapping_text);
	free(vcpu_domains);
	if (error != 0) {
		free(cpu_contract_text);
		return (error);
	}
	geometry = (struct checkpoint_memory_geometry) {
		.page_size = PAGE_SIZE,
		.lowmem_size = vm_get_lowmem_size(ctx),
		.highmem_base = vm_get_highmem_base(ctx),
		.highmem_size = vm_get_highmem_size(ctx),
	};
	error = checkpoint_memory_geometry_validate(&geometry, memsz);
	if (error == 0)
		error = vm_machine_topology_digest_current(topology_digest,
		    sizeof(topology_digest));
	if (error != 0) {
		free(cpu_contract_text);
		free(sizes_text);
		free(mapping_text);
		return (error);
	}
	xo_open_container_h(xop, JSON_BASIC_METADATA_KEY);
	xo_emit_h(xop, "{:" JSON_HYPERTRACE_HANDOFF_VERSION_KEY "/%u}\n",
	    hypertrace_initialized() ? 2U : 0U);
	xo_emit_h(xop, "{:" JSON_NCPUS_KEY "/%d}\n", guest_ncpus);
	xo_emit_h(xop, "{:" JSON_CPU_SOCKETS_KEY "/%u}\n",
	    (unsigned int)cpu_sockets);
	xo_emit_h(xop, "{:" JSON_CPU_CORES_KEY "/%u}\n",
	    (unsigned int)cpu_cores);
	xo_emit_h(xop, "{:" JSON_CPU_THREADS_KEY "/%u}\n",
	    (unsigned int)cpu_threads);
	if (cpu_contract_text != NULL)
		xo_emit_h(xop, "{:" JSON_CPU_CONTRACT_KEY "/%s}\n",
		    cpu_contract_text);
	xo_emit_h(xop, "{:" JSON_NUMA_VERSION_KEY "/%u}\n", 1U);
	xo_emit_h(xop, "{:" JSON_NUMA_SIZES_KEY "/%s}\n", sizes_text);
	xo_emit_h(xop, "{:" JSON_NUMA_MAPPING_KEY "/%s}\n", mapping_text);
	xo_emit_h(xop, "{:" JSON_MEMORY_GEOMETRY_VERSION_KEY "/%u}\n", 1U);
	xo_emit_h(xop, "{:" JSON_MEMORY_PAGE_SIZE_KEY "/%ju}\n",
	    (uintmax_t)geometry.page_size);
	xo_emit_h(xop, "{:" JSON_MEMORY_LOWMEM_SIZE_KEY "/%ju}\n",
	    (uintmax_t)geometry.lowmem_size);
	xo_emit_h(xop, "{:" JSON_MEMORY_HIGHMEM_BASE_KEY "/%ju}\n",
	    (uintmax_t)geometry.highmem_base);
	xo_emit_h(xop, "{:" JSON_MEMORY_HIGHMEM_SIZE_KEY "/%ju}\n",
	    (uintmax_t)geometry.highmem_size);
	xo_emit_h(xop, "{:" JSON_VMNAME_KEY "/%s}\n", vm_get_name(ctx));
	xo_emit_h(xop, "{:" JSON_MEMSIZE_KEY "/%zu}\n", memsz);
	xo_emit_h(xop, "{:" JSON_MEMFLAGS_KEY "/%d}\n", vm_get_memflags(ctx));
	xo_emit_h(xop, "{:" JSON_COMPAT_VERSION_KEY "/%u}\n",
	    PCI_SNAPSHOT_COMPAT_SCHEMA);
	xo_emit_h(xop, "{:" JSON_MACHINE_TOPOLOGY_VERSION_KEY "/%u}\n",
	    CHECKPOINT_MACHINE_TOPOLOGY_VERSION);
	xo_emit_h(xop, "{:" JSON_MACHINE_TOPOLOGY_DIGEST_KEY "/%s}\n",
	    topology_digest);
	if (vmgenid_text[0] != '\0')
		xo_emit_h(xop, "{:" JSON_VMGENID_STATE_KEY "/%s}\n",
		    vmgenid_text);
	xo_close_container_h(xop, JSON_BASIC_METADATA_KEY);
	free(cpu_contract_text);
	free(sizes_text);
	free(mapping_text);

	return (0);
}

static int
vm_snapshot_dev_write_data(int data_fd, xo_handle_t *xop, const char *array_key,
    struct vm_snapshot_meta *meta, off_t *offset,
    const struct pci_snapshot_compat *compat)
{
	char negotiated[17], offered[17], payload_crc32[9];
	size_t data_size;

	data_size = vm_get_snapshot_size(meta);

	if (snapshot_write_all(data_fd, meta->buffer.buf_start, data_size) != 0) {
		perror("Failed to write all snapshotted data.");
		return (-1);
	}

	/* Write metadata. */
	xo_open_instance_h(xop, array_key);
	xo_emit_h(xop, "{:" JSON_SNAPSHOT_REQ_KEY "/%s}\n", meta->dev_name);
	xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%zu}\n", data_size);
	xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%jd}\n",
	    (intmax_t)*offset);
	if (compat != NULL) {
		(void)snprintf(offered, sizeof(offered), "%016jx",
		    (uintmax_t)compat->offered_features);
		(void)snprintf(negotiated, sizeof(negotiated), "%016jx",
		    (uintmax_t)compat->negotiated_features);
		(void)snprintf(payload_crc32, sizeof(payload_crc32), "%08x",
		    compat->payload_crc32);
		xo_emit_h(xop, "{:" JSON_COMPAT_SCHEMA_KEY "/%u}\n",
		    compat->schema);
		xo_emit_h(xop, "{:" JSON_COMPAT_TRANSPORT_KEY "/%u}\n",
		    compat->transport);
		xo_emit_h(xop, "{:" JSON_COMPAT_QUEUE_COUNT_KEY "/%u}\n",
		    compat->queue_count);
		xo_emit_h(xop, "{:" JSON_COMPAT_MSIX_COUNT_KEY "/%u}\n",
		    compat->msix_table_count);
		xo_emit_h(xop, "{:" JSON_COMPAT_CONFIG_SIZE_KEY "/%ju}\n",
		    (uintmax_t)compat->config_size);
		xo_emit_h(xop, "{:" JSON_COMPAT_OFFERED_KEY "/%s}\n",
		    offered);
		xo_emit_h(xop, "{:" JSON_COMPAT_NEGOTIATED_KEY "/%s}\n",
		    negotiated);
		xo_emit_h(xop, "{:" JSON_COMPAT_PAYLOAD_CRC32_KEY "/%s}\n",
		    payload_crc32);
		xo_emit_h(xop, "{:" JSON_COMPAT_QUEUE_SIZES_KEY "/%s}\n",
		    compat->queue_sizes);
		xo_emit_h(xop, "{:" JSON_COMPAT_SHARED_MEMORY_KEY "/%s}\n",
		    compat->shared_memory);
	}
	xo_close_instance_h(xop, array_key);

	*offset += data_size;

	return (0);
}

static int
vm_snapshot_device(vm_snapshot_dev_cb func, const char *dev_name,
    void *devdata, int data_fd, xo_handle_t *xop,
    struct vm_snapshot_meta *meta, off_t *offset)
{
	struct pci_snapshot_compat compat;
	const struct pci_snapshot_compat *compatp;
	int ret;

	memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
	meta->buffer.buf = meta->buffer.buf_start;
	meta->buffer.buf_rem = meta->buffer.buf_size;
	meta->dev_name = dev_name;
	meta->dev_data = devdata;

	compatp = NULL;
	if (func == pci_snapshot) {
		ret = pci_snapshot_compat(devdata, &compat);
		if (ret == 0) {
			compatp = &compat;
			meta->buffer.buf =
			    (uint8_t *)meta->buffer.buf +
			    CHECKPOINT_COMPAT_ENVELOPE_SIZE;
			meta->buffer.buf_rem -=
			    CHECKPOINT_COMPAT_ENVELOPE_SIZE;
		} else if (ret != ENOENT) {
			EPRINTLN("Failed to describe snapshot compatibility for "
			    "%s; ret=%d", dev_name, ret);
			return (ret);
		}
	}
	BHYVE_PHASE_START(__func__, dev_name);
	ret = func(meta);
	BHYVE_PHASE_DONE(__func__, dev_name, ret, ret < 0 ? errno : 0);
	if (ret != 0) {
		EPRINTLN("Failed to snapshot %s; ret=%d", dev_name, ret);
		return (ret);
	}
	if (compatp != NULL) {
		size_t data_size;

		data_size = vm_get_snapshot_size(meta);
		if (data_size < CHECKPOINT_COMPAT_ENVELOPE_SIZE)
			return (EINVAL);
		compat.payload_crc32 = checkpoint_compat_payload_crc32(
		    (const uint8_t *)meta->buffer.buf_start +
		    CHECKPOINT_COMPAT_ENVELOPE_SIZE,
		    data_size - CHECKPOINT_COMPAT_ENVELOPE_SIZE);
		ret = checkpoint_compat_encode(&compat,
		    meta->buffer.buf_start, meta->buffer.buf_size);
		if (ret != 0)
			return (ret);
	}

	ret = vm_snapshot_dev_write_data(data_fd, xop, JSON_DEV_ARR_KEY, meta,
	    offset, compatp);
	if (ret != 0)
		return (ret);

	return (0);
}

static int
vm_snapshot_devices(int data_fd, xo_handle_t *xop)
{
	int ret;
	off_t offset;
	void *buffer;
	size_t buf_size;
	struct vm_snapshot_meta *meta;
	struct pci_devinst *pdi;

	buf_size = SNAPSHOT_BUFFER_SIZE;

	offset = lseek(data_fd, 0, SEEK_CUR);
	if (offset < 0) {
		perror("Failed to get data file current offset.");
		return (-1);
	}

	buffer = malloc(buf_size);
	if (buffer == NULL) {
		perror("Failed to allocate memory for snapshot buffer");
		ret = ENOSPC;
		goto snapshot_err;
	}

	meta = &(struct vm_snapshot_meta) {
		.buffer.buf_start = buffer,
		.buffer.buf_size = buf_size,

		.op = VM_SNAPSHOT_SAVE,
	};

	xo_open_list_h(xop, JSON_DEV_ARR_KEY);

	/* Save PCI devices */
	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		size_t extra = 0;
		if (pdi->pi_d->pe_snapshot_extra_capacity != NULL) {
			ret = pdi->pi_d->pe_snapshot_extra_capacity(pdi, &extra);
			if (ret != 0)
				goto snapshot_err;
		}
		if (extra > SNAPSHOT_DEVICE_EXTRA_MAX ||
		    extra > SIZE_MAX - buf_size) {
			ret = E2BIG;
			goto snapshot_err;
		}
		if (extra == 0) {
			ret = vm_snapshot_device(pci_snapshot, pdi->pi_name,
			    pdi, data_fd, xop, meta, &offset);
		} else {
			uint8_t *large = malloc(buf_size + extra);
			if (large == NULL) {
				ret = ENOMEM;
				goto snapshot_err;
			}
			struct vm_snapshot_meta expanded = {
				.buffer.buf_start = large,
				.buffer.buf_size = buf_size + extra,
				.op = VM_SNAPSHOT_SAVE,
			};
			ret = vm_snapshot_device(pci_snapshot, pdi->pi_name,
			    pdi, data_fd, xop, &expanded, &offset);
			free(large);
		}
		if (ret != 0)
			goto snapshot_err;
	}

#ifdef __amd64__
	ret = vm_snapshot_device(atkbdc_snapshot, "atkbdc", NULL,
	    data_fd, xop, meta, &offset);
#else
	{
		const struct snapshot_md_device *md;
		size_t md_count;

		ret = 0;
		md = bhyve_snapshot_md_devices(&md_count);
		for (size_t i = 0; ret == 0 && i < md_count; i++)
			ret = vm_snapshot_device(md[i].snapshot, md[i].name,
			    NULL, data_fd, xop, meta, &offset);
	}
#endif
	if (ret == 0 && qemu_fwcfg_enabled())
		ret = vm_snapshot_device(qemu_fwcfg_snapshot,
		    QEMU_FWCFG_SNAPSHOT_NAME, NULL, data_fd, xop, meta, &offset);
	if (ret == 0 && tpm_device_present())
		ret = vm_snapshot_device(tpm_device_snapshot, TPM_SNAPSHOT_NAME,
		    NULL, data_fd, xop, meta, &offset);

	xo_close_list_h(xop, JSON_DEV_ARR_KEY);

snapshot_err:
	if (buffer != NULL) {
		/* Device records can contain TPM state and other guest secrets. */
		explicit_bzero(buffer, buf_size);
		free(buffer);
	}
	return (ret);
}

void
checkpoint_cpu_add(int vcpu)
{

	pthread_mutex_lock(&vcpu_lock);
	CPU_SET(vcpu, &vcpus_active);

	if (checkpoint_active) {
		CPU_SET(vcpu, &vcpus_suspended);
		/*
		 * A vCPU can be added after checkpoint_vcpu_pause() has set the
		 * checkpoint fence but before it has observed every active vCPU as
		 * suspended.  This thread never enters vm_loop() while the fence is
		 * held, so it is already quiescent; nevertheless it must wake the
		 * checkpoint owner if it is the last member needed to satisfy its
		 * active-set predicate.  checkpoint_cpu_suspend() performs the same
		 * notification for an already-running vCPU.
		 */
		if (CPU_CMP(&vcpus_active, &vcpus_suspended) == 0)
			pthread_cond_signal(&vcpus_idle);
		while (checkpoint_active)
			pthread_cond_wait(&vcpus_can_run, &vcpu_lock);
		CPU_CLR(vcpu, &vcpus_suspended);
	}
	pthread_mutex_unlock(&vcpu_lock);
}

/*
 * The restore path arms this before bhyve creates any vCPU thread.  A thread
 * which reaches checkpoint_cpu_add() thereafter records itself as suspended
 * and waits without ever entering vm_loop().  This is an initial-execution
 * fence, not a normal checkpoint: there is no guest state to suspend and no
 * VM suspend ioctl is needed.
 */
void
checkpoint_restore_startup_hold(void)
{

	pthread_mutex_lock(&vcpu_lock);
	assert(!checkpoint_active);
	assert(!restore_startup_hold);
	checkpoint_active = true;
	restore_startup_hold = true;
	pthread_mutex_unlock(&vcpu_lock);
}

bool
checkpoint_restore_startup_held(void)
{
	bool held;

	pthread_mutex_lock(&vcpu_lock);
	held = restore_startup_hold;
	pthread_mutex_unlock(&vcpu_lock);
	return (held);
}

/*
 * Release the initial execution fence only after the exact destination
 * session has committed and all restored device callbacks have resumed.  On
 * any restore failure bhyverun exits with the fence still held, so a partially
 * restored destination cannot execute.
 */
int
checkpoint_restore_startup_release(void)
{
	int error;

	pthread_mutex_lock(&vcpu_lock);
	if (!checkpoint_active || !restore_startup_hold)
		error = EINVAL;
	else {
		restore_startup_hold = false;
		checkpoint_active = false;
		pthread_cond_broadcast(&vcpus_can_run);
		error = 0;
	}
	pthread_mutex_unlock(&vcpu_lock);
	return (error);
}

/*
 * When a vCPU is suspended for any reason, it calls
 * checkpoint_cpu_suspend().  This records that the vCPU is idle.
 * Before returning from suspension, checkpoint_cpu_resume() is
 * called.  In suspend we note that the vCPU is idle.  In resume we
 * pause the vCPU thread until the checkpoint is complete.  The reason
 * for the two-step process is that vCPUs might already be stopped in
 * the debug server when a checkpoint is requested.  This approach
 * allows us to account for and handle those vCPUs.
 */
void
checkpoint_cpu_suspend(int vcpu)
{

	pthread_mutex_lock(&vcpu_lock);
	CPU_SET(vcpu, &vcpus_suspended);
	if (checkpoint_active && CPU_CMP(&vcpus_active, &vcpus_suspended) == 0)
		pthread_cond_signal(&vcpus_idle);
	pthread_mutex_unlock(&vcpu_lock);
}

void
checkpoint_cpu_resume(int vcpu)
{

	pthread_mutex_lock(&vcpu_lock);
	while (checkpoint_active)
		pthread_cond_wait(&vcpus_can_run, &vcpu_lock);
	CPU_CLR(vcpu, &vcpus_suspended);
	pthread_mutex_unlock(&vcpu_lock);
}

int
checkpoint_vcpu_pause(struct vmctx *ctx, bool *runnable, bool *owned)
{
	int error;

	/*
	 * VM_SUSPEND_CPU requests debug exits but returns before the vCPU
	 * threads reach them.  The userspace rendezvous below is the actual
	 * memory/device snapshot boundary.
	 */
	if (ctx == NULL || runnable == NULL || owned == NULL)
		return (EINVAL);
	*runnable = false;
	*owned = false;
	pthread_mutex_lock(&vcpu_lock);
	if (checkpoint_active) {
		pthread_mutex_unlock(&vcpu_lock);
		return (EBUSY);
	}
	checkpoint_active = true;
	*owned = true;
	if (vm_suspend_all_cpus(ctx) != 0) {
		error = errno != 0 ? errno : EIO;
		if (vm_resume_all_cpus(ctx) == 0) {
			checkpoint_active = false;
			pthread_cond_broadcast(&vcpus_can_run);
			*runnable = true;
			*owned = false;
		}
		pthread_mutex_unlock(&vcpu_lock);
		return (error);
	}
	while (CPU_CMP(&vcpus_active, &vcpus_suspended) != 0)
		pthread_cond_wait(&vcpus_idle, &vcpu_lock);
	pthread_mutex_unlock(&vcpu_lock);
	return (0);
}

int
checkpoint_vcpu_resume(struct vmctx *ctx)
{
	int error;

	/* Keep the userspace gate closed if the kernel resume ioctl fails. */
	if (ctx == NULL)
		return (EINVAL);
	pthread_mutex_lock(&vcpu_lock);
	if (!checkpoint_active || restore_startup_hold) {
		pthread_mutex_unlock(&vcpu_lock);
		return (EINVAL);
	}
#ifdef __amd64__
	if (vm_resume_all_cpus(ctx) != 0) {
#else
	/* Only vCPUs powered on in the checkpoint may run. */
	if (bhyve_resume_powered_cpus(ctx) != 0) {
#endif
		error = errno != 0 ? errno : EIO;
		pthread_mutex_unlock(&vcpu_lock);
		return (error);
	}
	checkpoint_active = false;
	/*
	 * Publish the wakeup while holding the same mutex that protects
	 * checkpoint_active.  A vCPU either observes the cleared predicate or
	 * is already enrolled in the condition wait before this broadcast.
	 */
	pthread_cond_broadcast(&vcpus_can_run);
	pthread_mutex_unlock(&vcpu_lock);
	return (0);
}

/* Run while guest CPUs and VirtIO workers can still deliver STOPPED. A
 * failure never releases the tracing gate or replays the abandoned session. */
static int
hypertrace_checkpoint_stop(struct vmctx *ctx,
    uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE])
{
	struct timespec now, deadline, delay = {.tv_nsec = 10000000};
	struct timespec collector_delay = {.tv_nsec = 100000000};
	bool complete = false;
	int error;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		return (errno != 0 ? errno : EIO);
	deadline.tv_sec += 600;
	error = pci_vtdtr_session_checkpoint_begin(ctx);
	if (error != 0)
		return (error);
	for (;;) {
		error = pci_vtdtr_session_stop_status(ctx);
		if (error != EBUSY)
			break;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return (errno != 0 ? errno : EIO);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
			return (ETIMEDOUT);
		if (nanosleep(&delay, NULL) != 0 && errno != EINTR)
			return (errno != 0 ? errno : EIO);
	}
	if (error != 0)
		return (error);
	while (!complete) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return (errno != 0 ? errno : EIO);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
			return (ETIMEDOUT);
		error = pci_vtdtr_session_collectors_stop_step(ctx, &complete);
		if (error != 0)
			return (error);
		if (!complete && nanosleep(&collector_delay, NULL) != 0 &&
		    errno != EINTR)
			return (errno != 0 ? errno : EIO);
	}
	return (pci_vtdtr_session_checkpoint_export(ctx, record,
	    HYPERTRACE_SESSION_RECORD_SIZE));
}

static int
vm_checkpoint(struct vmctx *ctx, int fddir, const char *checkpoint_file,
    bool stop_vm)
{
	struct vm_snapshot_session snapshot_session;
	struct checkpoint_manifest manifest, old_manifest;
	int fd_checkpoint = -1, kdata_fd = -1, fd_meta = -1;
	int fd_trace = -1;
	int release_fd = -1;
	int lock_fd = -1;
	int ret = 0;
	int error = 0;
	struct bhyve_devmem_region *devmem_regions = NULL;
	size_t devmem_count, devmem_extension_size, memsz;
	bool devices_paused = false;
	bool devices_resumed = true;
	bool data_created = false;
	bool kern_created = false;
	bool meta_created = false;
	bool trace_created = false;
	bool old_exists = false;
	bool old_is_manifest = false;
	bool published = false;
	bool snapshot_session_active = false;
	bool snapshot_session_unresolved = false;
	bool vcpus_paused = false;
	bool handoff_prepared = false;
	bool handoff_committed = false;
	bool handoff_unresolved = false;
	bool source_gate_active = false;
	bool fresh_session = hypertrace_initialized();
	/*
	 * Trace continuity across restore/migration is a future feature,
	 * disabled because the current product contract is fresh-session (no
	 * trace continuity across restore or migration).  New checkpoints use
	 * stopped-session metadata instead of transfer tickets; every
	 * handoff_enabled block below is intentionally unreachable until enabled.
	 */
	bool handoff_enabled = false;
	uint8_t fresh_record[HYPERTRACE_SESSION_RECORD_SIZE];
	uint8_t handoff_token[16], handoff_digest[32];
	uint8_t release_wire[CHECKPOINT_RELEASE_WIRE_SIZE];
	bool signed_release = false;
	uint8_t handoff_transfer_digest[32];
	void *transfer_bytes = NULL;
	size_t transfer_length = 0;
	bool vcpus_runnable = false;
	xo_handle_t *xop = NULL;
	char *lock_filename = NULL, *manifest_tmp = NULL;
	FILE *meta_file = NULL;

	BHYVE_TRACE(CHECKPOINT_BEGIN, stop_vm);
	/* Validate TPM state support before creating files or stopping the guest. */
	error = tpm_device_migration_check();
	if (error != 0) {
		EPRINTLN("TPM state is not configured for checkpoint: %s",
		    strerror(error));
		BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, false, error);
		return (error);
	}
	/*
	 * A guest held by the restore startup fence (an inbound migration that
	 * is retained or not yet released) has never run.  The checkpoint's
	 * resume path would release the parked vCPUs, so refuse before touching
	 * anything; migrate_resolve owns that decision.
	 */
	if (checkpoint_restore_startup_held()) {
		EPRINTLN("Cannot checkpoint a guest held by the startup fence; "
		    "resolve the inbound migration first.");
		BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, false, EBUSY);
		return (EBUSY);
	}
	/* A running source cannot share a committed tracing ticket with its
	 * checkpoint copy.  Clone semantics need a separate ticket protocol. */
	if ((handoff_enabled || fresh_session) && !stop_vm) {
		EPRINTLN("HyperTrace checkpoints require stop_vm.");
		BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, false, ENOTSUP);
		return (ENOTSUP);
	}
	memset(&manifest, 0, sizeof(manifest));
	memset(&old_manifest, 0, sizeof(old_manifest));
	lock_filename = strcat_extension(checkpoint_file, ".lock");
	if (lock_filename == NULL) {
		error = errno != 0 ? errno : ENOMEM;
		BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, false, error);
		return (error);
	}
	lock_fd = openat(fddir, lock_filename,
	    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock_fd < 0) {
		error = errno != 0 ? errno : EIO;
		fprintf(stderr, "Failed to open checkpoint lock: %s\n",
		    strerror(error));
		goto done;
	}
	if (checkpoint_regular_fd(lock_fd) != 0) {
		error = EINVAL;
		fprintf(stderr, "Checkpoint lock is not a regular file.\n");
		goto done;
	}
	error = checkpoint_lock(lock_fd, LOCK_EX);
	if (error != 0) {
		fprintf(stderr, "Failed to lock checkpoint: %s\n",
		    strerror(error));
		goto done;
	}
	error = checkpoint_manifest_read_at(fddir, checkpoint_file,
	    &old_manifest, &old_exists, &old_is_manifest);
	if (error != 0) {
		fprintf(stderr, "Failed to read existing checkpoint manifest: %s\n",
		    strerror(error));
		goto done;
	}
	if (old_is_manifest &&
	    !checkpoint_manifest_valid_for(checkpoint_file, &old_manifest)) {
		fprintf(stderr, "Existing checkpoint manifest has invalid members.\n");
		error = EINVAL;
		goto done;
	}
	error = fresh_session ?
	    checkpoint_generation_names_fresh(checkpoint_file, &manifest,
	    &manifest_tmp) : handoff_enabled ?
	    checkpoint_generation_names_trace(checkpoint_file, &manifest,
	    &manifest_tmp) :
	    checkpoint_generation_names(checkpoint_file, &manifest,
	    &manifest_tmp);
	if (error != 0) {
		fprintf(stderr, "Failed to construct checkpoint generation names.\n");
		goto done;
	}
	/* Trace continuity (disabled future feature): unreachable until
	 * handoff_enabled; see its definition. */
	if (handoff_enabled) {
		error = checkpoint_manifest_handoff_token(checkpoint_file,
		    &manifest, handoff_token);
		if (error != 0)
			goto done;
	}

	kdata_fd = openat(fddir, manifest.kern,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (kdata_fd < 0) {
		perror("Failed to open kernel data snapshot file.");
		error = errno != 0 ? errno : EIO;
		goto done;
	}
	kern_created = true;

	fd_checkpoint = openat(fddir, manifest.data,
	    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd_checkpoint < 0) {
		perror("Failed to create checkpoint file");
		error = errno != 0 ? errno : EIO;
		goto done;
	}
	data_created = true;

	fd_meta = openat(fddir, manifest.meta,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd_meta >= 0)
		meta_created = true;
	if (handoff_enabled || fresh_session) {
		fd_trace = openat(fddir, manifest.trace,
		    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
		if (fd_trace < 0) {
			error = errno != 0 ? errno : EIO;
			goto done;
		}
		trace_created = true;
	}
	if (fd_meta != -1)
		meta_file = fdopen(fd_meta, "w");
	if (meta_file == NULL) {
		error = errno != 0 ? errno : EIO;
		perror("Failed to open vm metadata snapshot file.");
		if (fd_meta >= 0)
			close(fd_meta);
		fd_meta = -1;
		goto done;
	}
	xop = xo_create_to_file(meta_file, XO_STYLE_JSON, XOF_PRETTY);
	if (xop == NULL) {
		perror("Failed to get libxo handle on metadata file.");
		error = ENOMEM;
		goto done;
	}

	if (fresh_session) {
		error = hypertrace_checkpoint_stop(ctx, fresh_record);
		if (error != 0) {
			fprintf(stderr, "Could not stop HyperTrace session: %s\n",
			    strerror(error));
			goto done;
		}
		if (snapshot_write_all(fd_trace, fresh_record, sizeof(fresh_record)) != 0 ||
		    fsync(fd_trace) != 0) {
			error = errno != 0 ? errno : EIO;
			goto done;
		}
	}
	BHYVE_PHASE_START(__func__, "vm_vcpu_pause");
	ret = checkpoint_vcpu_pause(ctx, &vcpus_runnable, &vcpus_paused);
	BHYVE_PHASE_DONE(__func__, "vm_vcpu_pause", ret,
	    ret != 0 ? ret : 0);
	if (ret != 0) {
		error = ret;
		goto done;
	}

	/* The HTX1 export and PREPARE digest must describe the same device and
	 * kernel-ingress cut as the checkpoint image.  In particular, the
	 * virtio-dtrace reader must stop before the daemon snapshots its accepted
	 * ingress and program evidence. */
	BHYVE_PHASE_START(__func__, "vm_pause_devices");
	ret = vm_pause_devices();
	BHYVE_PHASE_DONE(__func__, "vm_pause_devices",
	    ret, ret < 0 ? errno : 0);
	if (ret != 0) {
		fprintf(stderr, "Could not pause devices\r\n");
		error = ret;
		goto done;
	}
	devices_paused = true;

	{
		bool resolved = true;

		BHYVE_PHASE_START(__func__, "vm_snapshot_session_begin_exact");
		error = vm_snapshot_session_begin_exact(ctx, &snapshot_session,
		    &resolved);
		BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",
		    error, error < 0 ? errno : 0);
		/* EBUSY means another descriptor still owns VM-wide ingress. */
		snapshot_session_unresolved = error != 0 &&
		    (!resolved || error == EBUSY);
	}
	if (error != 0) {
		fprintf(stderr, "Could not begin kernel checkpoint session: %s\n",
		    strerror(error));
		if (snapshot_session_unresolved)
			fprintf(stderr, "Kernel checkpoint session ownership is "
			    "unresolved; the VM will remain stopped.\n");
		goto done;
	}
	snapshot_session_active = true;

	/* Trace continuity (disabled future feature): unreachable until
	 * handoff_enabled; see its definition. */
	if (handoff_enabled) {
		bool absent = false;
		/* Journal the exact source epoch before exporting any accepted
		 * ingress. An uncertain ACK keeps the VM stopped: the daemon may
		 * have suspended the kernel gate after the connection failed. */
		if (hypertrace_handoff_source_gate_ensure(ctx,
		    DTRACED_HANDOFF_SOURCE_GATE_BEGIN,
		    handoff_token) != 0) {
			error = errno != 0 ? errno : EIO;
			handoff_unresolved = true;
			fprintf(stderr, "Could not establish HyperTrace source gate: %s\n",
			    strerror(error));
			goto done;
		}
		source_gate_active = true;
		if (hypertrace_handoff_source_bundle_fresh(ctx, handoff_token,
		    &transfer_bytes, &transfer_length) != 0 ||
		    transfer_bytes == NULL ||
		    transfer_length < HYPERTRACE_TRANSFER_MIN_BYTES) {
			error = errno != 0 ? errno : EIO;
			fprintf(stderr,
			    "Could not export HyperTrace ingress bundle: %s\n",
			    strerror(error));
			goto done;
		}
		{
			struct pci_devinst *trace_pi = NULL;
			size_t replay_controls;

			while ((trace_pi = pci_next(trace_pi)) != NULL &&
			    !pci_vtdtr_checkpoint_is_device(trace_pi))
				;
			if (trace_pi == NULL) {
				error = ENODEV;
				fprintf(stderr,
				    "HyperTrace device missing from paused source\n");
				goto done;
			}
			if (hypertrace_transfer_replay_controls(transfer_bytes,
			    transfer_length, handoff_token, &replay_controls) != 0) {
				error = errno != 0 ? errno : EPROTO;
				fprintf(stderr,
				    "Could not inspect HyperTrace replay budget: %s\n",
				    strerror(error));
				goto done;
			}
			error = pci_vtdtr_checkpoint_source_replay_room(trace_pi,
			    replay_controls);
			if (error != 0) {
				fprintf(stderr,
				    "HyperTrace replay exceeds paused device queue: %s\n",
				    strerror(error));
				goto done;
			}
		}
		if (snapshot_write_all(fd_trace, transfer_bytes,
		    transfer_length) != 0 ||
		    fsync(fd_trace) != 0 || fsync(fddir) != 0) {
			error = errno != 0 ? errno : EIO;
			fprintf(stderr,
			    "Could not durably save HyperTrace ingress bundle: %s\n",
			    strerror(error));
			goto done;
		}
		memcpy(handoff_transfer_digest,
		    (const uint8_t *)transfer_bytes + transfer_length -
		    sizeof(handoff_transfer_digest), sizeof(handoff_transfer_digest));
		free(transfer_bytes);
		transfer_bytes = NULL;
		transfer_length = 0;
		/* Challenge each exact HCP1 consumer on a separate attested
		 * request. HGD1 is durable before a step replies; PREPARE still
		 * enforces the destination execution-state lease. */
		if (hypertrace_handoff_source_drain(ctx, handoff_token,
		    handoff_transfer_digest) != 0) {
			error = errno != 0 ? errno : EIO;
			fprintf(stderr,
			    "Could not drain HyperTrace consumers: %s\n",
			    strerror(error));
			goto done;
		}

		if (hypertrace_handoff_source_ensure(ctx,
		    DTRACED_HANDOFF_PREPARE, handoff_token,
		    handoff_transfer_digest, &absent) != 0) {
			error = errno != 0 ? errno : EIO;
			handoff_unresolved = !absent;
			fprintf(stderr, "Could not prepare HyperTrace source ticket: %s\n",
			    strerror(error));
			goto done;
		}
		handoff_prepared = true;
	}

	BHYVE_PHASE_START(__func__, "vm_snapshot_mem");
	memsz = vm_snapshot_mem(ctx, fd_checkpoint, 0, true);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_mem",
	    memsz == 0 ? -1 : 0, memsz == 0 ? errno : 0);
	if (memsz == 0) {
		perror("Could not write guest memory to file");
		error = errno != 0 ? errno : EIO;
		goto done;
	}
	ret = collect_checkpoint_devmem(ctx, &devmem_regions, &devmem_count);
	if (ret != 0) {
		fprintf(stderr, "Could not enumerate checkpoint device memory.\n");
		error = ret;
		goto done;
	}
	ret = bhyve_devmem_snapshot_save(fd_checkpoint, memsz,
	    devmem_regions, devmem_count, &devmem_extension_size);
	free(devmem_regions);
	devmem_regions = NULL;
	if (ret != 0) {
		fprintf(stderr, "Could not snapshot checkpoint device memory.\n");
		error = ret;
		goto done;
	}

	ret = vm_snapshot_basic_metadata(ctx, xop, memsz);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot vm basic metadata.\n");
		error = ret > 0 ? ret : EIO;
		goto done;
	}

	BHYVE_PHASE_START(__func__, "vm_save_kern_structs");
	ret = vm_save_kern_structs(ctx, kdata_fd, xop);
	BHYVE_PHASE_DONE(__func__, "vm_save_kern_structs",
	    ret, ret < 0 ? errno : 0);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot vm kernel data.\n");
		error = ret > 0 ? ret : EIO;
		goto done;
	}

	BHYVE_PHASE_START(__func__, "vm_snapshot_devices");
	ret = vm_snapshot_devices(kdata_fd, xop);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_devices",
	    ret, ret < 0 ? errno : 0);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot device state.\n");
		error = ret > 0 ? ret : EIO;
		goto done;
	}

	if (xo_finish_h(xop) < 0) {
		fprintf(stderr, "Failed to finish vm metadata snapshot file.\n");
		error = EIO;
		goto done;
	}

done:
	free(devmem_regions);
	free(transfer_bytes);
	/*
	 * Complete and durably flush every generation member before publishing
	 * the manifest.  Until renameat() below, an older manifest remains the
	 * only visible checkpoint and an interrupted generation is unreachable.
	 */
	if (xop != NULL)
		xo_destroy(xop);
	if (meta_file != NULL) {
		if (fflush(meta_file) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
		if (error == 0 && fsync(fileno(meta_file)) != 0)
			error = errno != 0 ? errno : EIO;
		if (fclose(meta_file) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
		meta_file = NULL;
	} else if (fd_meta >= 0) {
		if (close(fd_meta) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
	}
	if (fd_checkpoint >= 0) {
		if (error == 0 && fsync(fd_checkpoint) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(fd_checkpoint) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
	}
	if (kdata_fd >= 0) {
		if (error == 0 && fsync(kdata_fd) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(kdata_fd) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
	}
	if (fd_trace >= 0) {
		if (error == 0 && fsync(fd_trace) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(fd_trace) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
	}
	if (error == 0 && fsync(fddir) != 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0) {
		BHYVE_PHASE_START(__func__, "checkpoint_publish");
		error = checkpoint_publish(fddir, checkpoint_file, manifest_tmp,
		    &manifest, &published);
		BHYVE_PHASE_DONE(__func__, "checkpoint_publish", error, 0);
		BHYVE_TRACE(CHECKPOINT_PUBLISH, published, error);
	}
	/* Trace continuity (disabled future feature): handoff_prepared and
	 * source_gate_active are set only under handoff_enabled. */
	if (handoff_prepared) {
		int handoff_error;
		bool absent = false;

		if (published) {
			uint8_t published_token[16];

			handoff_error = checkpoint_manifest_handoff_identity(
			    checkpoint_file, &manifest, published_token,
			    handoff_digest);
			if (handoff_error == 0 && memcmp(published_token,
			    handoff_token, sizeof(handoff_token)) != 0)
				handoff_error = EPROTO;
			if (handoff_error == 0 &&
			    hypertrace_handoff_source_ensure(ctx,
			    DTRACED_HANDOFF_COMMIT, handoff_token,
			    handoff_digest, &absent) != 0)
				handoff_error = errno != 0 ? errno : EIO;
			handoff_committed = handoff_error == 0;
		} else {
			handoff_error = hypertrace_handoff_source_ensure(ctx,
			    DTRACED_HANDOFF_ABORT, handoff_token,
			    (const uint8_t[32]){0}, &absent) == 0 ? 0 :
			    (errno != 0 ? errno : EIO);
		}
		if (handoff_error != 0) {
			handoff_unresolved = true;
			fprintf(stderr, "Could not settle HyperTrace source ticket: %s\n",
			    strerror(handoff_error));
			if (error == 0)
				error = handoff_error;
		}
	}
	/* Trace continuity (disabled future feature): source_gate_active is
	 * set only under handoff_enabled. */
	if (source_gate_active && !handoff_committed &&
	    !handoff_unresolved) {
		if (hypertrace_handoff_source_gate_ensure(ctx,
		    DTRACED_HANDOFF_SOURCE_GATE_ABORT,
		    handoff_token) != 0) {
			int gate_error = errno != 0 ? errno : EIO;
			handoff_unresolved = true;
			fprintf(stderr, "Could not release HyperTrace source gate: %s\n",
			    strerror(gate_error));
			if (error == 0)
				error = gate_error;
		} else {
			source_gate_active = false;
		}
	}
	/* A published manifest can precede an uncertain daemon COMMIT. Keep
	 * the previous generation's files for recovery until this checkpoint's
	 * ticket is confirmed. A legacy checkpoint has no generated members. */
	if (published && error == 0 && old_is_manifest &&
	    (!handoff_enabled || handoff_committed))
		checkpoint_remove_old_generation(fddir, checkpoint_file,
		    &old_manifest);
	/*
	 * Retain the kernel event-ingress fence until every generation member is
	 * durable and the manifest rename has published the checkpoint.  A
	 * directory fsync error can be reported after that rename: the result is
	 * not durable across host failure, but the new generation is already the
	 * visible checkpoint and must retain the capture-side event cut.  Commit
	 * the fence whenever publication occurred.  Abort is only for a generation
	 * which never became visible; it merges events deferred after the capture
	 * point into the running source.
	 */
	if (snapshot_session_active && !handoff_unresolved) {
		int session_error;
		bool released = false;

		BHYVE_PHASE_START(__func__, "vm_snapshot_session_release_exact");
		session_error = vm_snapshot_session_release_exact(ctx,
		    &snapshot_session, published, &released);
		BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",
		    session_error, session_error < 0 ? errno : 0);
		if (released)
			snapshot_session_active = false;
		if (session_error != 0) {
			fprintf(stderr, "Could not release kernel checkpoint "
			    "session: %s\n", strerror(session_error));
			if (error == 0)
				error = session_error;
		}
	}

	if (stop_vm && published && error == 0) {
		/* Authenticate a dedicated daemon channel while the VMM identity
		 * still exists. VirtIO shutdown closes the normal forwarder socket. */
		/* Trace continuity (disabled future feature): unreachable
		 * until handoff_enabled. */
		if (handoff_enabled) {
			if (!handoff_committed) {
				error = EPROTO;
			} else {
				release_fd = hypertrace_handoff_source_release_open(ctx);
				if (release_fd < 0)
					error = errno != 0 ? errno : EIO;
			}
		}
		/* The DTrace device owns its mutex through checkpoint pause;
		 * stop its workers before exit runs their shutdown handler. */
		if (error == 0)
			error = pci_vtdtr_checkpoint_stop();
		if (error == 0) {
			if (vm_destroy_checked(ctx) != 0) {
				error = errno != 0 ? errno : EIO;
				EPRINTLN("Could not destroy checkpoint source VM: %s",
				    strerror(error));
			} else {
				/* Trace continuity (disabled future feature):
				 * release_fd is opened only under handoff_enabled. */
				if (release_fd >= 0) {
					if (hypertrace_handoff_source_release_finish(
					    release_fd, handoff_token, handoff_digest,
					    release_wire, &signed_release) != 0) {
						EPRINTLN("Could not record HyperTrace source release: %s",
						    strerror(errno));
						exit(1);
					}
					release_fd = -1;
					if (signed_release) {
						int release_error =
						    checkpoint_release_publish_at(fddir,
						    handoff_token, release_wire);
						if (release_error != 0) {
							EPRINTLN("Could not publish HyperTrace release: %s",
							    strerror(release_error));
							exit(1);
						}
					}
				}
				release_fd = -1;
				BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, published, 0);
				/* The checkpoint is published and the VM destroyed:
				 * tell bhyvectl --suspend it succeeded before the
				 * exit closes its connection unanswered. */
				ipc_reply_success_before_exit();
				exit(BHYVE_EXIT_SUSPEND);
			}
		}
		if (release_fd >= 0)
			close(release_fd);
	}
	if (stop_vm && published) {
		/*
		 * The stopped-session checkpoint is durable and the guest was to
		 * terminate after it.  Failing to stop the tracing workers or to
		 * destroy the VM must not resume a source whose session is
		 * recorded as stopped: report it and end the process.  The saved
		 * checkpoint is the surviving copy.
		 */
		EPRINTLN("Checkpoint published but the source could not be "
		    "stopped cleanly: %s. Not resuming it.", strerror(error));
		BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, published, error);
		exit(BHYVE_EXIT_ERROR);
	}

	/*
	 * pci_resume() tracks ownership per device, so a failed pause walk can
	 * safely release just the devices which were acquired before the error.
	 * Do not run either cleanup path for failures which happened before the
	 * corresponding pause operation started.
	 */
	if (!snapshot_session_active && !snapshot_session_unresolved &&
	    !handoff_unresolved && !handoff_committed &&
	    (devices_paused || vcpus_paused)) {
		BHYVE_PHASE_START(__func__, "vm_resume_devices");
		ret = vm_resume_devices();
		BHYVE_PHASE_DONE(__func__, "vm_resume_devices",
		    ret, ret < 0 ? errno : 0);
		if (ret != 0) {
			fprintf(stderr, "Could not resume devices\r\n");
			devices_resumed = false;
			if (error == 0)
				error = ret;
		}
	} else if (snapshot_session_active || snapshot_session_unresolved ||
	    handoff_unresolved || handoff_committed) {
		devices_resumed = false;
	}
	/*
	 * Never restart guest execution while a backend still owns checkpoint
	 * pause state.  The per-device ownership markers allow a later
	 * checkpoint request to retry just the failed resume safely.
	 */
	if (vcpus_paused && devices_resumed) {
		ret = checkpoint_vcpu_resume(ctx);
		if (ret != 0 && error == 0)
			error = ret;
	}
	if (!published) {
		if (data_created)
			(void)unlinkat(fddir, manifest.data, 0);
		if (kern_created)
			(void)unlinkat(fddir, manifest.kern, 0);
		if (meta_created)
			(void)unlinkat(fddir, manifest.meta, 0);
		if (trace_created)
			(void)unlinkat(fddir, manifest.trace, 0);
		if (manifest_tmp != NULL)
			(void)unlinkat(fddir, manifest_tmp, 0);
	}
	if (lock_fd >= 0)
		close(lock_fd);
	free(lock_filename);
	free(manifest_tmp);
	BHYVE_TRACE(CHECKPOINT_RESULT, stop_vm, published, error);
	return (error);
}

/*
 * ------------------------------------------------------------------------
 * Live-migration bridge to the whole-machine save/restore machinery.
 *
 * These functions reuse the existing device/kernel serialization and restore
 * steps (vm_snapshot_basic_metadata / vm_save_kern_structs / vm_snapshot_devices
 * on save; vm_restore_preflight / vm_restore_devices_prevalidated /
 * vm_restore_kern_structs
 * on restore) but move the container from on-disk checkpoint generation files
 * to an in-memory blob streamed over the migration session.  Guest RAM is NOT
 * part of this blob: it is carried separately as pre-copy memory generations,
 * so the destination skips restore_vm_mem() and only replays device + CPU/vCPU/
 * kernel structure state.  The existing vm_checkpoint()/vm_restore_transaction()
 * paths are left untouched.
 *
 * Wire layout of the blob (fixed-width little-endian, no host pointers/fds):
 *   [u64 meta_len][u64 kdata_len][meta bytes (UCL/JSON)][kdata bytes]
 * Fresh tracing appends one canonical 40-byte FSS1 record. It is permitted
 * only with MIGRATION_CAP_HYPERTRACE_FRESH; legacy receivers reject the tail.
 * FSS1 describes a stopped session, not proof of source VM retirement.
 * ------------------------------------------------------------------------
 */

#include "migration_snapshot.h"

int
vm_migrate_stop_tracing(struct vmctx *ctx,
    uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE])
{
	if (ctx == NULL || record == NULL)
		return (EINVAL);
	memset(record, 0, HYPERTRACE_SESSION_RECORD_SIZE);
	if (!hypertrace_initialized())
		return (ENXIO);
	return (hypertrace_checkpoint_stop(ctx, record));
}

/*
 * Create an anonymous, regular, mmap-able temp file seeded with buf.
 *
 * This must not touch the global filesystem namespace: the source-side
 * "migrate" IPC command runs on the IPC thread after cap_enter(), where
 * any absolute-path open (e.g. mkstemp(3) in /tmp) fails with ECAPMODE.
 * memfd_create(2) is anonymous (capability-mode safe), grows on write, and
 * yields an fd that fstat(2) reports as a regular file and that supports
 * lseek/read/write/mmap, which is all load_kdata_fd()/load_metadata_fd() need.
 */
static int
migrate_tempfd(const void *buf, size_t len)
{
	int fd, saved_errno;

	fd = memfd_create("bhyve-migrate", MFD_CLOEXEC);
	if (fd < 0)
		return (-1);
	if (len != 0 && snapshot_write_all(fd, buf, len) != 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return (-1);
	}
	if (lseek(fd, 0, SEEK_SET) != 0) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return (-1);
	}
	return (fd);
}

static int
migrate_pread_all(int fd, void *buffer, size_t length)
{
	uint8_t *cursor;
	size_t done;
	ssize_t nread;

	cursor = buffer;
	done = 0;
	while (done < length) {
		nread = pread(fd, cursor + done, length - done, (off_t)done);
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			return (errno != 0 ? errno : EIO);
		}
		if (nread == 0)
			return (EIO);
		done += (size_t)nread;
	}
	return (0);
}

static int
vm_snapshot_dev_state_capture(struct vmctx *ctx, const uint8_t *fresh_record,
    uint8_t **blob_out, size_t *len_out, struct vm_snapshot_capture *capture)
{
	FILE *meta_file;
	xo_handle_t *xop;
	uint8_t *meta_buf, *kdata_buf, *blob;
	long meta_len_l;
	size_t meta_len, kdata_len, blob_len;
	off_t kdata_size;
	int kdata_fd, meta_fd, error;
	bool resolved, released;
	size_t trace_len = fresh_record != NULL ? HYPERTRACE_SESSION_RECORD_SIZE : 0;

	if (ctx == NULL || blob_out == NULL || len_out == NULL ||
	    capture == NULL)
		return (EINVAL);
	error = tpm_device_migration_check();
	if (error != 0)
		return (error);
	if (capture->active || capture->unresolved)
		return (EBUSY);
	*blob_out = NULL;
	*len_out = 0;
	/* Fresh tracing must be explicitly selected; never silently strip it. */
	if (hypertrace_initialized() != (fresh_record != NULL))
		return (EOPNOTSUPP);
	if (fresh_record != NULL) {
		struct hypertrace_session_record record;
		uint16_t vmid;
		uint64_t epoch;

		error = hypertrace_session_record_decode(fresh_record, trace_len, &record);
		if (error != 0)
			return (error);
		if (vm_get_identity(ctx, &vmid, &epoch) != 0)
			return (errno != 0 ? errno : EIO);
		if (record.vmid != vmid || record.epoch != epoch)
			return (ESTALE);
	}
	memset(capture, 0, sizeof(*capture));
	meta_buf = kdata_buf = blob = NULL;
	meta_len = kdata_len = blob_len = 0;
	meta_file = NULL;
	xop = NULL;
	kdata_fd = meta_fd = -1;

	kdata_fd = migrate_tempfd(NULL, 0);
	meta_fd = migrate_tempfd(NULL, 0);
	if (kdata_fd < 0 || meta_fd < 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	meta_file = fdopen(meta_fd, "w+");
	if (meta_file == NULL) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	meta_fd = -1;	/* owned by meta_file now */
	xop = xo_create_to_file(meta_file, XO_STYLE_JSON, XOF_PRETTY);
	if (xop == NULL) {
		error = ENOMEM;
		goto out;
	}

	/*
	 * Fence VM-wide event ingress exactly as a checkpoint would, then reuse
	 * the checkpoint serializers.  The caller has already quiesced vCPUs and
	 * devices for the cutover.  Keep the fence through the network handoff:
	 * an event arriving after capture must not be admitted to the source
	 * after the state blob has been sent to the destination.
	 */
	BHYVE_PHASE_START(__func__, "vm_snapshot_session_begin_exact");
	error = vm_snapshot_session_begin_exact(ctx, &capture->session,
	    &resolved);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",
	    error, error < 0 ? errno : 0);
	if (error != 0) {
		/* Another descriptor's live lease is not ours to release. */
		capture->unresolved = !resolved || error == EBUSY;
		goto out;
	}
	capture->active = true;

	error = vm_snapshot_basic_metadata(ctx, xop,
	    vm_get_lowmem_size(ctx) + vm_get_highmem_size(ctx));
	if (error != 0)
		goto out;
	BHYVE_PHASE_START(__func__, "vm_save_kern_structs");
	error = vm_save_kern_structs(ctx, kdata_fd, xop);
	BHYVE_PHASE_DONE(__func__, "vm_save_kern_structs",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	BHYVE_PHASE_START(__func__, "vm_snapshot_devices");
	error = vm_snapshot_devices(kdata_fd, xop);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_devices",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	if (xo_finish_h(xop) < 0) {
		error = EIO;
		goto out;
	}
	xo_destroy(xop);
	xop = NULL;
	if (fflush(meta_file) != 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}

	/* Slurp the two container members back into memory. */
	if (fseek(meta_file, 0, SEEK_END) != 0 ||
	    (meta_len_l = ftell(meta_file)) < 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	meta_len = (size_t)meta_len_l;
	rewind(meta_file);
	if (fstat(kdata_fd, &(struct stat){0}) != 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	kdata_size = lseek(kdata_fd, 0, SEEK_END);
	if (kdata_size < 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	kdata_len = (size_t)kdata_size;
	/* Reject an oversized capture before allocating copies of the members;
	 * the single pread of kernel data must also be representable. */
	if ((uintmax_t)kdata_size > SSIZE_MAX ||
	    meta_len > MIGRATION_MAX_DEV_STATE - MIGRATE_BLOB_HDR - trace_len ||
	    kdata_len > MIGRATION_MAX_DEV_STATE - MIGRATE_BLOB_HDR - trace_len -
	    meta_len) {
		error = EMSGSIZE;
		goto out;
	}
	meta_buf = malloc(meta_len != 0 ? meta_len : 1);
	kdata_buf = malloc(kdata_len != 0 ? kdata_len : 1);
	if (meta_buf == NULL || kdata_buf == NULL) {
		error = ENOMEM;
		goto out;
	}
	if (meta_len != 0 && fread(meta_buf, 1, meta_len, meta_file) != meta_len) {
		error = EIO;
		goto out;
	}
	if (kdata_len != 0 &&
	    (error = migrate_pread_all(kdata_fd, kdata_buf, kdata_len)) != 0) {
		goto out;
	}

	blob_len = MIGRATE_BLOB_HDR + meta_len + kdata_len + trace_len;
	blob = malloc(blob_len);
	if (blob == NULL) {
		error = ENOMEM;
		goto out;
	}
	le64enc(blob + 0, (uint64_t)meta_len);
	le64enc(blob + 8, (uint64_t)kdata_len);
	memcpy(blob + MIGRATE_BLOB_HDR, meta_buf, meta_len);
	memcpy(blob + MIGRATE_BLOB_HDR + meta_len, kdata_buf, kdata_len);
	if (trace_len != 0)
		memcpy(blob + MIGRATE_BLOB_HDR + meta_len + kdata_len,
		    fresh_record, trace_len);
	error = 0;

out:
	if (error != 0 && capture->active) {
		/* The return value is only consumed by the optional phase probe. */
		int rel __unused;

		BHYVE_PHASE_START(__func__, "vm_snapshot_session_release_exact");
		rel = vm_snapshot_session_release_exact(ctx, &capture->session,
		    false, &released);
		BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",
		    rel, rel < 0 ? errno : 0);
		if (released)
			capture->active = false;
		else
			capture->unresolved = true;
	}
	if (error != 0) {
		free(*blob_out);
		*blob_out = NULL;
		*len_out = 0;
	}
	/* A failed kernel fence release invalidates this capture. Do not hand a
	 * blob to migration until the source cut has settled successfully. */
	if (error == 0) {
		*blob_out = blob;
		*len_out = blob_len;
		blob = NULL;
	}
	if (xop != NULL)
		xo_destroy(xop);
	if (meta_file != NULL)
		fclose(meta_file);
	if (meta_fd >= 0)
		close(meta_fd);
	if (kdata_fd >= 0)
		close(kdata_fd);
	if (meta_buf != NULL)
		explicit_bzero(meta_buf, meta_len);
	if (kdata_buf != NULL)
		explicit_bzero(kdata_buf, kdata_len);
	if (blob != NULL)
		explicit_bzero(blob, blob_len);
	free(meta_buf);
	free(kdata_buf);
	free(blob);
	return (error);
}

int
vm_snapshot_dev_state_to_mem(struct vmctx *ctx, uint8_t **blob, size_t *len,
    struct vm_snapshot_capture *capture)
{
	return (vm_snapshot_dev_state_capture(ctx, NULL, blob, len, capture));
}

int
vm_snapshot_fresh_dev_state_to_mem(struct vmctx *ctx,
    const uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE], uint8_t **blob,
    size_t *len, struct vm_snapshot_capture *capture)
{
	if (record == NULL)
		return (EINVAL);
	return (vm_snapshot_dev_state_capture(ctx, record, blob, len, capture));
}

int
vm_snapshot_dev_state_finish(struct vmctx *ctx,
    struct vm_snapshot_capture *capture, bool commit)
{
	bool released;
	int error;

	if (ctx == NULL || capture == NULL || capture->unresolved)
		return (EINVAL);
	if (!capture->active)
		return (0);
	error = vm_snapshot_session_release_exact(ctx, &capture->session,
	    commit, &released);
	if (released)
		capture->active = false;
	else
		capture->unresolved = true;
	return (error);
}

/*
 * Reconstruct device + CPU/vCPU/kernel state on the destination from an
 * in-memory blob produced by vm_snapshot_dev_state_to_mem().  Guest RAM has
 * already been staged into guest memory by the migration session, so this
 * deliberately does NOT run restore_vm_mem().  On success devices are left
 * PAUSED and the restore startup fence remains held; the guest is not yet
 * running.  Call vm_migrate_resume() after RELEASE to start it.
 */
static int
vm_migrate_commit_state_impl(struct vmctx *ctx, const uint8_t *blob, size_t len,
    struct pci_devinst **fresh_device)
{
	struct restore_state rstate;
	struct vm_snapshot_session session;
	struct migration_snapshot_view view;
	int meta_fd, kdata_fd, error, rel;
	bool resolved, released, session_active, handoff_required;
	bool fresh = fresh_device != NULL;
	uint8_t private_digest[SHA256_DIGEST_LENGTH];

	if (fresh)
		*fresh_device = NULL;
	if (ctx == NULL || blob == NULL || len < MIGRATE_BLOB_HDR)
		return (EINVAL);
	if (len > MIGRATION_MAX_DEV_STATE)
		return (EMSGSIZE);
	error = tpm_device_migration_check();
	if (error != 0)
		return (error);
	if (!checkpoint_restore_startup_held())
		return (EBUSY);
	if (hypertrace_initialized() != fresh)
		return (EOPNOTSUPP);
	error = migration_snapshot_decode(blob, len, fresh, &view);
	if (error != 0)
		return (error);

	memset(&rstate, 0, sizeof(rstate));
	if (fresh) {
		rstate.checkpoint_format_version = 5;
		rstate.hypertrace_session_present = true;
		memcpy(rstate.hypertrace_session, view.fresh_record,
		    sizeof(rstate.hypertrace_session));
	}
	rstate.checkpoint_lock_fd = -1;
	rstate.kdata_fd = -1;
	rstate.vmmem_fd = -1;
	rstate.kdata_map = MAP_FAILED;
	meta_fd = kdata_fd = -1;
	session_active = false;

	meta_fd = migrate_tempfd(view.metadata, view.metadata_length);
	kdata_fd = migrate_tempfd(view.kernel, view.kernel_length);
	if (meta_fd < 0 || kdata_fd < 0) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}
	/*
	 * load_kdata_fd() takes ownership of the descriptor on both success
	 * (stored in rstate) and failure (it closes fd itself).  Drop our
	 * copy in both cases so the 'out' path cannot close the same fd
	 * number a second time.
	 */
	if (load_kdata_fd(kdata_fd, &rstate) != 0) {
		kdata_fd = -1;
		error = EIO;
		goto out;
	}
	kdata_fd = -1;	/* owned by rstate now */
	if (load_metadata_fd(meta_fd, &rstate) != 0) {
		error = EIO;
		goto out;
	}
	/* An older sender can still carry a HyperTrace checkpoint marker.
	 * Reject it before pausing devices or mutating destination state. */
	error = lookup_hypertrace_handoff(&rstate, &handoff_required);
	if (error != 0 || handoff_required) {
		error = error != 0 ? error : EOPNOTSUPP;
		goto out;
	}
	/* HELLO binds host CPU fields; the saved guest CPU contract is separate. */
	error = checkpoint_restore_cpu_contract(&rstate, fbsdrun_vcpu(0));
	if (error != 0)
		goto out;

	/* The startup CPU fence does not stop external keyboard/pointer input.
	 * Drain it before taking device pause locks or restoring device state. */
	console_input_pause();
	BHYVE_PHASE_START(__func__, "vm_pause_devices");
	error = vm_pause_devices();
	BHYVE_PHASE_DONE(__func__, "vm_pause_devices",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	BHYVE_PHASE_START(__func__, "vm_restore_preflight");
	error = vm_restore_preflight_internal(&rstate, fresh);
	BHYVE_PHASE_DONE(__func__, "vm_restore_preflight",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	if (fresh) {
		if (rstate.hypertrace_private_dev == NULL ||
		    rstate.hypertrace_private_image == NULL) {
			error = EPROTO;
			goto out;
		}
		hypertrace_private_image_digest(&rstate, private_digest);
		error = pci_vtdtr_session_migration_stage_paused(
		    rstate.hypertrace_private_dev, rstate.hypertrace_session,
		    sizeof(rstate.hypertrace_session),
		    __DECONST(void *, rstate.hypertrace_private_image),
		    rstate.hypertrace_private_length);
		if (error != 0)
			goto out;
	}
	BHYVE_PHASE_START(__func__, "vm_snapshot_session_begin_exact");
	error = vm_snapshot_session_begin_exact(ctx, &session, &resolved);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_begin_exact",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	session_active = true;
	/* Guest RAM is already present; only devices and kernel structs. */
	if (fresh && (error = hypertrace_private_image_unchanged(&rstate,
	    private_digest)) != 0)
		goto out;
	BHYVE_PHASE_START(__func__, "vm_restore_devices");
	error = vm_restore_devices_prevalidated(&rstate);
	BHYVE_PHASE_DONE(__func__, "vm_restore_devices",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	if (fresh && (error = hypertrace_private_image_unchanged(&rstate,
	    private_digest)) != 0)
		goto out;
	BHYVE_PHASE_START(__func__, "vm_restore_kern_structs");
	error = vm_restore_kern_structs(ctx, &rstate);
	BHYVE_PHASE_DONE(__func__, "vm_restore_kern_structs",
	    error, error < 0 ? errno : 0);
	if (error != 0)
		goto out;
	if (fresh && (error = pci_vtdtr_session_discard_paused(
	    rstate.hypertrace_private_dev)) != 0)
		goto out;
	BHYVE_PHASE_START(__func__, "vm_snapshot_session_release_exact");
	rel = vm_snapshot_session_release_exact(ctx, &session, true, &released);
	BHYVE_PHASE_DONE(__func__, "vm_snapshot_session_release_exact",
	    rel, rel < 0 ? errno : 0);
	if (released)
		session_active = false;
	if (rel != 0) {
		error = rel;
		goto out;
	}
	/* Live migration keeps the source's generation; no notification. */
	error = vm_restore_vmgenid(ctx, &rstate, CHECKPOINT_VMGENID_MIGRATE);
	if (error != 0)
		goto out;
	if (fresh)
		*fresh_device = rstate.hypertrace_private_dev;

out:
	if (session_active)
		(void)vm_snapshot_session_release_exact(ctx, &session, false,
		    &released);
	destroy_restore_state(&rstate);
	if (meta_fd >= 0)
		close(meta_fd);
	if (kdata_fd >= 0)
		close(kdata_fd);
	return (error);
}

int
vm_migrate_commit_state(struct vmctx *ctx, const uint8_t *blob, size_t len)
{
	return (vm_migrate_commit_state_impl(ctx, blob, len, NULL));
}

int
vm_migrate_fresh_commit_state(struct vmctx *ctx, const uint8_t *blob,
    size_t len, struct pci_devinst **device)
{
	if (device == NULL)
		return (EINVAL);
	return (vm_migrate_commit_state_impl(ctx, blob, len, device));
}

int
vm_migrate_fresh_resume(struct vmctx *ctx, struct pci_devinst *device,
    const uint8_t record[HYPERTRACE_SESSION_RECORD_SIZE])
{
	dtraced_replay_kill_t *kills = NULL;
	size_t count = 0;
	int error;

	if (ctx == NULL || device == NULL || record == NULL)
		return (EINVAL);
	if (!hypertrace_initialized() || !checkpoint_restore_startup_held())
		return (EBUSY);
	if (hypertrace_start_ready(ctx, 30000) != 0)
		return (errno != 0 ? errno : EIO);
	error = hypertrace_take_replay_kills(ctx, &kills, &count);
	free(kills);
	if (error != 0 || count != 0)
		return (error != 0 ? error : EPROTO);
	if (vm_restore_time(ctx) < 0)
		return (errno != 0 ? errno : EIO);
	error = pci_vtdtr_session_migration_release_paused(device, record,
	    HYPERTRACE_SESSION_RECORD_SIZE);
	if (error == 0)
		error = vm_resume_devices();
	if (error == 0)
		error = pci_vtdtr_session_attach_begin(ctx);
	/* Kernel CPUs remain behind the userspace startup fence until this
	 * checked resume succeeds. Never report RUNNING before both gates open. */
#ifdef __amd64__
	if (error == 0 && vm_resume_all_cpus(ctx) != 0)
#else
	if (error == 0 && bhyve_resume_powered_cpus(ctx) != 0)
#endif
		error = errno != 0 ? errno : EIO;
	if (error == 0)
		error = checkpoint_restore_startup_release();
	if (error == 0)
		console_input_resume();
	return (error);
}

/* Release the destination for execution after a committed migration. */
int
vm_migrate_resume(struct vmctx *ctx)
{
	int error;

	if (hypertrace_initialized())
		return (EOPNOTSUPP);
	if (!checkpoint_restore_startup_held())
		return (EBUSY);
	/* Consume the committed restore's one-shot time-rebase credential first. */
	if (vm_restore_time(ctx) < 0)
		return (errno != 0 ? errno : EIO);
	BHYVE_PHASE_START(__func__, "vm_resume_devices");
	error = vm_resume_devices();
	BHYVE_PHASE_DONE(__func__, "vm_resume_devices",
	    error, error < 0 ? errno : 0);
#ifdef __amd64__
	if (error == 0 && vm_resume_all_cpus(ctx) != 0)
#else
	if (error == 0 && bhyve_resume_powered_cpus(ctx) != 0)
#endif
		error = errno != 0 ? errno : EIO;
	if (error == 0) {
		BHYVE_PHASE_START(__func__, "checkpoint_restore_startup_release");
		error = checkpoint_restore_startup_release();
		BHYVE_PHASE_DONE(__func__, "checkpoint_restore_startup_release",
		    error, error < 0 ? errno : 0);
	}
	if (error == 0)
		console_input_resume();
	return (error);
}

static nvlist_t *
vm_do_checkpoint(struct vmctx *ctx, const nvlist_t *nvl)
{
	int error;
	nvlist_t *reply;

	reply = nvlist_create(0);
	if (!nvlist_exists_string(nvl, "filename") ||
	    !nvlist_exists_bool(nvl, "suspend") ||
	    !nvlist_exists_descriptor(nvl, "fddir"))
		error = EINVAL;
	else
		error = vm_checkpoint(ctx,
		    nvlist_get_descriptor(nvl, "fddir"),
		    nvlist_get_string(nvl, "filename"),
		    nvlist_get_bool(nvl, "suspend"));
	if (error != 0)
		nvlist_add_string(reply, "error", strerror(error));

	return (reply);
}
IPC_COMMAND(checkpoint, vm_do_checkpoint);

void
vm_snapshot_buf_err(const char *bufname, const enum vm_snapshot_op op)
{
	const char *__op;

	if (op == VM_SNAPSHOT_SAVE)
		__op = "save";
	else if (op == VM_SNAPSHOT_RESTORE)
		__op = "restore";
	else if (op == VM_SNAPSHOT_VALIDATE)
		__op = "validate";
	else
		__op = "unknown";

	fprintf(stderr, "%s: snapshot-%s failed for %s\r\n",
		__func__, __op, bufname);
}

int
vm_snapshot_buf(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;
	int op;

	buffer = &meta->buffer;
	op = meta->op;

	if (buffer->buf_rem < data_size) {
		fprintf(stderr, "%s: buffer too small\r\n", __func__);
		return (E2BIG);
	}

	if (op == VM_SNAPSHOT_SAVE)
		memcpy(buffer->buf, data, data_size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

	return (0);
}

int
vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{

	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int
vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[2];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le16(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le16(bytes);
	return (error);
}

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[4];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le32(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le32(bytes);
	return (error);
}

int
vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		snapshot_store_le64(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = snapshot_load_le64(bytes);
	return (error);
}

int
vm_snapshot_nonnegative_int(int *value, struct vm_snapshot_meta *meta)
{
	uint32_t encoded;
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		if (*value < 0)
			return (EINVAL);
		encoded = (uint32_t)*value;
	} else {
		encoded = 0;
	}
	error = vm_snapshot_le32(&encoded, meta);
	if (error != 0)
		return (error);
	if (vm_snapshot_is_loading(meta)) {
		if (encoded > INT_MAX)
			return (EINVAL);
		*value = (int)encoded;
	}
	return (0);
}

size_t
vm_get_snapshot_size(struct vm_snapshot_meta *meta)
{
	size_t length;
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;

	if (buffer->buf_size < buffer->buf_rem) {
		fprintf(stderr, "%s: Invalid buffer: size = %zu, rem = %zu\r\n",
			__func__, buffer->buf_size, buffer->buf_rem);
		length = 0;
	} else {
		length = buffer->buf_size - buffer->buf_rem;
	}

	return (length);
}

int
vm_snapshot_guest2host_addr(struct vmctx *ctx, void **addrp, size_t len,
    bool restore_null, struct vm_snapshot_meta *meta)
{
	void *hostaddr;
	int ret;
	vm_paddr_t gaddr;
	uint64_t wire_gaddr;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		gaddr = paddr_host2guest(ctx, *addrp);
		if (gaddr == (vm_paddr_t) -1) {
			if (!restore_null ||
			    (restore_null && (*addrp != NULL))) {
				ret = EFAULT;
				goto done;
			}
		} else if (paddr_guest2host(ctx, gaddr, len) != *addrp) {
			/* Validate the complete range before saving the pointer. */
			ret = EFAULT;
			goto done;
		}

		wire_gaddr = (uint64_t)gaddr;
		SNAPSHOT_LE64_OR_LEAVE(wire_gaddr, meta, ret, done);
	} else if (vm_snapshot_is_loading(meta)) {
		wire_gaddr = 0;
		SNAPSHOT_LE64_OR_LEAVE(wire_gaddr, meta, ret, done);
		gaddr = (vm_paddr_t)wire_gaddr;
		if ((uint64_t)gaddr != wire_gaddr) {
			ret = EOVERFLOW;
			goto done;
		}
		if (gaddr == (vm_paddr_t) -1) {
			if (!restore_null) {
				ret = EFAULT;
				goto done;
			}
		}

		hostaddr = gaddr == (vm_paddr_t)-1 ? NULL :
		    paddr_guest2host(ctx, gaddr, len);
		if (gaddr != (vm_paddr_t)-1 && hostaddr == NULL) {
			ret = EFAULT;
			goto done;
		}
		if (vm_snapshot_is_restoring(meta))
			*addrp = hostaddr;
	} else {
		ret = EINVAL;
	}

done:
	return (ret);
}

int
vm_snapshot_buf_cmp(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;
	int op;
	int ret;

	buffer = &meta->buffer;
	op = meta->op;

	if (buffer->buf_rem < data_size) {
		fprintf(stderr, "%s: buffer too small\r\n", __func__);
		ret = E2BIG;
		goto done;
	}

	if (op == VM_SNAPSHOT_SAVE) {
		ret = 0;
		memcpy(buffer->buf, data, data_size);
	} else if (vm_snapshot_is_loading(meta)) {
		ret = memcmp(data, buffer->buf, data_size);
	} else {
		ret = EINVAL;
		goto done;
	}

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

done:
	return (ret);
}
