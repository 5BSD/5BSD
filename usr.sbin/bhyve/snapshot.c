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
#include <sysexits.h>
#include <stdbool.h>
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
#include "snapshot_metadata.h"
#include "checkpoint_numa.h"
#include "checkpoint_topology.h"
#ifdef __amd64__
#include "amd64/atkbdc.h"
#endif
#include "debug.h"
#include "ipc.h"
#include "mem.h"
#include "pci_emul.h"
#include "qemu_fwcfg.h"
#include "qemu_fwcfg_snapshot.h"
#include "snapshot.h"
#include "snapshot_devmem.h"
#include "snapshot_portable.h"
#include "tpm_device.h"

#include <libxo/xo.h>
#include <ucl.h>

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

/* One stalled controller must not monopolize the checkpoint command thread. */
#define	CHECKPOINT_CLIENT_TIMEOUT_SEC	30

#define	JSON_KERNEL_ARR_KEY		"kern_structs"
#define	JSON_DEV_ARR_KEY		"devices"
#define	JSON_BASIC_METADATA_KEY 	"basic metadata"
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

#define min(a,b)		\
({				\
 __typeof__ (a) _a = (a);	\
 __typeof__ (b) _b = (b); 	\
 _a < _b ? _a : _b;       	\
 })

static const struct vm_snapshot_kern_info snapshot_kern_structs[] = {
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
};

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
	return (error == 0 ? 0 : errno);
}

static int
checkpoint_regular_fd(int fd)
{
	struct stat sb;

	if (fstat(fd, &sb) != 0)
		return (errno);
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

	if (rstate->meta_root_obj != NULL)
		ucl_object_unref(rstate->meta_root_obj);
	if (rstate->meta_parser != NULL)
		ucl_parser_free(rstate->meta_parser);
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

int
load_restore_file(const char *filename, struct restore_state *rstate)
{
	struct checkpoint_manifest manifest;
	int err;
	bool exists, is_manifest;
	char *base_copy, *lock_filename, *manifest_directory_copy;
	int lock_fd, manifest_data_fd, manifest_dirfd, manifest_kern_fd;
	int manifest_meta_fd;

	assert(filename != NULL);
	assert(rstate != NULL);

	memset(rstate, 0, sizeof(*rstate));
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
	if (!checkpoint_manifest_compatible(&manifest)) {
		fprintf(stderr,
		    "Checkpoint architecture or machine ABI is incompatible.\n");
		goto err_restore;
	}
	err = checkpoint_manifest_open_verified_at(manifest_dirfd,
	    &manifest, &manifest_data_fd, &manifest_kern_fd,
	    &manifest_meta_fd);
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

	free(base_copy);
	free(lock_filename);
	free(manifest_directory_copy);
	if (manifest_dirfd >= 0)
		close(manifest_dirfd);
	close(lock_fd);
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
	size_t source_capacity, source_count;
	int error;

	entries = ucl_object_lookup(rstate->meta_root_obj, key);
	if (entries == NULL || ucl_object_type(entries) != UCL_ARRAY) {
		EPRINTLN("Checkpoint '%s' manifest is missing or invalid", key);
		return (EINVAL);
	}
	source_capacity = ucl_array_size(entries);
	/*
	 * The destination topology is already known and is the authoritative
	 * bound for this array.  Reject a cardinality mismatch before allocating
	 * storage controlled by checkpoint metadata.  Besides failing earlier,
	 * this bounds the duplicate-name and record-layout validation which
	 * follows to the actual machine topology.
	 */
	if (source_capacity != destination_count)
		return (ENODEV);
	if (source_capacity > SIZE_MAX / sizeof(*source))
		return (EOVERFLOW);
	source = calloc(source_capacity, sizeof(*source));
	if (source_capacity != 0 && source == NULL)
		return (ENOMEM);

	iterator = NULL;
	source_count = 0;
	while ((object = ucl_object_iterate(entries, &iterator, true)) != NULL) {
		const ucl_object_t *field;

		if (source_count == source_capacity) {
			error = EINVAL;
			goto done;
		}
		field = ucl_object_lookup(object, JSON_SNAPSHOT_REQ_KEY);
		if (field == NULL || !ucl_object_tostring_safe(field, &name)) {
			error = EINVAL;
			goto done;
		}
		source[source_count++] = name;
	}
	error = checkpoint_topology_validate(source, source_count, destination,
	    destination_count);
	if (error != 0)
		EPRINTLN("Checkpoint '%s' topology is incompatible: %s", key,
		    strerror(error));

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
		if (show_progress)
			todo = min(SNAPSHOT_CHUNK, rem);
		else
			todo = rem;

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
collect_generic_devmem(struct vmctx *ctx,
    struct bhyve_devmem_region **regionsp, size_t *countp)
{
	struct bhyve_devmem_region *regions;
	size_t count, length;
	void *host_base;

	if (ctx == NULL || regionsp == NULL || countp == NULL)
		return (EINVAL);
	*regionsp = NULL;
	*countp = 0;
	regions = calloc(VM_DEVMEM_END - VM_DEVMEM_START, sizeof(*regions));
	if (regions == NULL)
		return (ENOMEM);

	count = 0;
	for (int segid = VM_DEVMEM_START; segid < VM_DEVMEM_END; segid++) {
		if (vm_get_devmem_info(ctx, segid, &host_base, &length,
		    regions[count].name, sizeof(regions[count].name)) != 0) {
			if (errno == ENOENT)
				continue;
			int error = errno;

			free(regions);
			return (error);
		}
		regions[count].host_base = host_base;
		regions[count].length = length;
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
	 * future caller.  In particular, an incompatible generic-device-memory
	 * extension must not be discovered after ordinary guest RAM has changed.
	 */
	error = vm_restore_memory_preflight(ctx, rstate);
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

	error = collect_generic_devmem(ctx, &regions, &region_count);
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
	error = collect_generic_devmem(ctx, &regions, &region_count);
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

	if (dev_ptr == NULL) {
		EPRINTLN("Failed to lookup dev: %s", name);
		return (EINVAL);
	}

	if (dev_size == 0) {
		EPRINTLN("Restore device size is 0: %s", name);
		return (EINVAL);
	}

	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	field = ucl_object_lookup(basic, JSON_COMPAT_VERSION_KEY);
	if (field == NULL || !ucl_object_toint_safe(field, &version) ||
	    version != PCI_SNAPSHOT_COMPAT_SCHEMA)
		return (EINVAL);
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

	ret = func(meta);
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
#endif
	if (qemu_fwcfg_enabled())
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
#endif
	if (qemu_fwcfg_enabled())
		destination[destination_count++] = QEMU_FWCFG_SNAPSHOT_NAME;
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
#endif
	if (qemu_fwcfg_enabled())
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
#endif
	if (qemu_fwcfg_enabled()) {
		devices[index].name = QEMU_FWCFG_SNAPSHOT_NAME;
		error = qemu_fwcfg_snapshot_compat(&compats[index]);
		if (error != 0)
			goto out;
		devices[index].compat = &compats[index];
		index++;
	}
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
#endif
	if (qemu_fwcfg_enabled())
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
		EPRINTLN("Checkpoint machine topology is incompatible");
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

	basic = lookup_basic_metadata_object(rstate);
	if (basic == NULL)
		return (EINVAL);
	field = ucl_object_lookup(basic, JSON_COMPAT_VERSION_KEY);
	if (field == NULL)
		return (EINVAL);
	if (!ucl_object_toint_safe(field, &version) ||
	    version != PCI_SNAPSHOT_COMPAT_SCHEMA)
		return (ENOTSUP);

	pdi = NULL;
	while ((pdi = pci_next(pdi)) != NULL) {
		object = lookup_dev_object(pdi->pi_name, JSON_DEV_ARR_KEY,
		    rstate);
		if (object == NULL)
			return (EINVAL);
		field = ucl_object_lookup(object, JSON_COMPAT_SCHEMA_KEY);
		error = pci_snapshot_compat(pdi, &destination);
		if (error == ENOENT) {
			if (field != NULL)
				return (ENOTSUP);
			continue;
		}
		if (error != 0 || field == NULL)
			return (error != 0 ? error : EINVAL);

		memset(&source, 0, sizeof(source));
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
		if (error == 0 &&
		    payload.payload_crc32 != checkpoint_compat_payload_crc32(
		    (const uint8_t *)record +
		    CHECKPOINT_COMPAT_ENVELOPE_SIZE,
		    record_size - CHECKPOINT_COMPAT_ENVELOPE_SIZE))
			error = EINVAL;
		if (error == 0 &&
		    !checkpoint_compat_equal(&source, &payload))
			error = EINVAL;
		if (error == 0)
			error = pci_snapshot_compat_validate(&payload,
			    &destination);
		if (error != 0) {
			EPRINTLN("Checkpoint device '%s' is incompatible: %s",
			    pdi->pi_name, strerror(error));
			return (error);
		}
	}
	return (0);
}

static int
vm_restore_device_payload_validate_one(struct restore_state *rstate,
    struct pci_devinst *pdi, int64_t version)
{
	struct pci_snapshot_compat compatibility;
	void *record;
	size_t record_size;
	int error;

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

	error = pci_snapshot_validate(&meta);
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
	return (0);
}

static int
vm_restore_device_payloads_validate(struct restore_state *rstate)
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
			    pdi, version);
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

int
vm_restore_preflight(struct restore_state *rstate)
{
	int error;

	if (rstate == NULL)
		return (EINVAL);
	/*
	 * CRB, PPI, and backend state do not yet have one atomic portable
	 * checkpoint contract.  Refuse before publishing any incoming state.
	 */
	if (tpm_device_present())
		return (ENOTSUP);
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
		error = vm_restore_device_payloads_validate(rstate);
	return (error);
}

int
vm_restore_devices(struct restore_state *rstate)
{
	enum pci_restore_phase phase;
	int ret;
	struct pci_devinst *pdi;

	ret = vm_restore_preflight(rstate);
	if (ret != 0)
		return (ret);

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
	ret = 0;
#endif
	if (ret == 0 && qemu_fwcfg_enabled())
		ret = vm_restore_device(rstate, qemu_fwcfg_snapshot,
		    QEMU_FWCFG_SNAPSHOT_NAME, NULL);
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

	return (0);
}

int
vm_resume_devices(void)
{
	enum pci_restore_phase phase;
	int error, ret;
	struct pci_devinst *pdi;

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
int
vm_restore_transaction(struct vmctx *ctx, struct restore_state *rstate)
{
	struct vm_snapshot_session session;
	bool released, resolved, session_active;
	int error, release_error;

	if (ctx == NULL || rstate == NULL)
		return (EINVAL);
	/*
	 * bhyverun must have fenced every newly created vCPU before this
	 * transaction starts.  Refuse a direct caller rather than allowing a
	 * destination-local instruction to run before the saved state commits.
	 */
	if (!checkpoint_restore_startup_held())
		return (EBUSY);
	session_active = false;
	memset(&session, 0, sizeof(session));

	error = vm_pause_devices();
	if (error != 0) {
		EPRINTLN("Failed to pause PCI device state.");
		return (error);
	}
	error = vm_restore_preflight(rstate);
	if (error != 0) {
		EPRINTLN("Checkpoint topology or device contract is invalid.");
		goto failed;
	}
	error = vm_restore_memory_preflight(ctx, rstate);
	if (error != 0) {
		EPRINTLN("Checkpoint memory layout is invalid.");
		goto failed;
	}

	error = vm_snapshot_session_begin_exact(ctx, &session, &resolved);
	if (error != 0) {
		EPRINTLN("Could not begin kernel restore session: %s",
		    strerror(error));
		if (!resolved)
			EPRINTLN("Kernel restore session ownership is unresolved; "
			    "the destination must remain stopped until exit.");
		goto failed;
	}
	session_active = true;

	FPRINTLN(stdout, "Restoring vm mem...");
	if (restore_vm_mem(ctx, rstate) != 0) {
		error = errno != 0 ? errno : EIO;
		EPRINTLN("Failed to restore VM memory.");
		goto failed;
	}
	FPRINTLN(stdout, "Restoring pci devs...");
	error = vm_restore_devices(rstate);
	if (error != 0) {
		EPRINTLN("Failed to restore PCI device state.");
		goto failed;
	}
	FPRINTLN(stdout, "Restoring kernel structs...");
	error = vm_restore_kern_structs(ctx, rstate);
	if (error != 0) {
		EPRINTLN("Failed to restore kernel structs.");
		goto failed;
	}

	release_error = vm_snapshot_session_release_exact(ctx, &session, true,
	    &released);
	if (released)
		session_active = false;
	if (release_error != 0) {
		error = release_error;
		EPRINTLN("Could not commit kernel restore session: %s",
		    strerror(error));
		goto failed;
	}
	FPRINTLN(stdout, "Resuming pci devs...");
	error = vm_resume_devices();
	if (error != 0)
		EPRINTLN("Failed to resume PCI device state.");
	else {
		error = checkpoint_restore_startup_release();
		if (error != 0)
			EPRINTLN("Failed to release restore startup fence.");
	}
	return (error);

failed:
	if (session_active) {
		release_error = vm_snapshot_session_release_exact(ctx, &session,
		    false, &released);
		if (release_error != 0) {
			EPRINTLN("Could not abort kernel restore session: %s",
			    strerror(release_error));
			if (error == 0)
				error = release_error;
		}
	}
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
checkpoint_remove_old_generation(int fddir,
    const struct checkpoint_manifest *old)
{
	const char *members[3];

	members[0] = old->data;
	members[1] = old->kern;
	members[2] = old->meta;
	for (unsigned int i = 0; i < nitems(members); i++) {
		if (unlinkat(fddir, members[i], 0) != 0 && errno != ENOENT)
			EPRINTLN("Cannot remove old checkpoint member '%s': %s",
			    members[i], strerror(errno));
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

	ret = vm_snapshot_req(ctx, meta);
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
	char *cpu_contract_text, *mapping_text, *sizes_text;
	size_t domain_count;
	int error;

	/*
	 * UCL stores these JSON metadata values as signed 64-bit integers.
	 * Reject an image which could be written but never parsed by restore.
	 */
	if (ctx == NULL || xop == NULL || memsz == 0 || memsz > INT64_MAX)
		return (memsz > INT64_MAX ? EOVERFLOW : EINVAL);
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
	ret = func(meta);
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
		ret = vm_snapshot_device(pci_snapshot, pdi->pi_name, pdi,
		    data_fd, xop, meta, &offset);
		if (ret != 0)
			goto snapshot_err;
	}

#ifdef __amd64__
	ret = vm_snapshot_device(atkbdc_snapshot, "atkbdc", NULL,
	    data_fd, xop, meta, &offset);
#else
	ret = 0;
#endif
	if (ret == 0 && qemu_fwcfg_enabled())
		ret = vm_snapshot_device(qemu_fwcfg_snapshot,
		    QEMU_FWCFG_SNAPSHOT_NAME, NULL, data_fd, xop, meta, &offset);

	xo_close_list_h(xop, JSON_DEV_ARR_KEY);

snapshot_err:
	if (buffer != NULL)
		free(buffer);
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
		 * A vCPU can be added after vm_vcpu_pause() has set the
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

static void
vm_vcpu_pause(struct vmctx *ctx)
{

	pthread_mutex_lock(&vcpu_lock);
	checkpoint_active = true;
	vm_suspend_all_cpus(ctx);
	while (CPU_CMP(&vcpus_active, &vcpus_suspended) != 0)
		pthread_cond_wait(&vcpus_idle, &vcpu_lock);
	pthread_mutex_unlock(&vcpu_lock);
}

static void
vm_vcpu_resume(struct vmctx *ctx)
{

	pthread_mutex_lock(&vcpu_lock);
	checkpoint_active = false;
	pthread_mutex_unlock(&vcpu_lock);
	vm_resume_all_cpus(ctx);
	/*
	 * Publish the wakeup while holding the same mutex that protects
	 * checkpoint_active.  A vCPU either observes the cleared predicate or
	 * is already enrolled in the condition wait before this broadcast; doing
	 * the broadcast unlocked makes that relationship depend on condvar
	 * implementation timing.
	 */
	pthread_mutex_lock(&vcpu_lock);
	pthread_cond_broadcast(&vcpus_can_run);
	pthread_mutex_unlock(&vcpu_lock);
}

static int
vm_checkpoint(struct vmctx *ctx, int fddir, const char *checkpoint_file,
    bool stop_vm)
{
	struct vm_snapshot_session snapshot_session;
	struct checkpoint_manifest manifest, old_manifest;
	int fd_checkpoint = -1, kdata_fd = -1, fd_meta = -1;
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
	bool old_exists = false;
	bool old_is_manifest = false;
	bool published = false;
	bool snapshot_session_active = false;
	bool snapshot_session_unresolved = false;
	bool vcpus_paused = false;
	xo_handle_t *xop = NULL;
	char *lock_filename = NULL, *manifest_tmp = NULL;
	FILE *meta_file = NULL;

	/* Fail before creating files or stopping the guest. */
	if (tpm_device_present()) {
		EPRINTLN("TPM-equipped VMs cannot be checkpointed safely yet.");
		return (ENOTSUP);
	}
	memset(&manifest, 0, sizeof(manifest));
	memset(&old_manifest, 0, sizeof(old_manifest));
	lock_filename = strcat_extension(checkpoint_file, ".lock");
	if (lock_filename == NULL)
		return (errno != 0 ? errno : ENOMEM);
	lock_fd = openat(fddir, lock_filename,
	    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock_fd < 0) {
		error = errno;
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
	error = checkpoint_generation_names(checkpoint_file, &manifest,
	    &manifest_tmp);
	if (error != 0) {
		fprintf(stderr, "Failed to construct checkpoint generation names.\n");
		goto done;
	}

	kdata_fd = openat(fddir, manifest.kern,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (kdata_fd < 0) {
		perror("Failed to open kernel data snapshot file.");
		error = errno;
		goto done;
	}
	kern_created = true;

	fd_checkpoint = openat(fddir, manifest.data,
	    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (fd_checkpoint < 0) {
		perror("Failed to create checkpoint file");
		error = errno;
		goto done;
	}
	data_created = true;

	fd_meta = openat(fddir, manifest.meta,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (fd_meta >= 0)
		meta_created = true;
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

	vm_vcpu_pause(ctx);
	vcpus_paused = true;

	ret = vm_pause_devices();
	if (ret != 0) {
		fprintf(stderr, "Could not pause devices\r\n");
		error = ret;
		goto done;
	}
	devices_paused = true;

	{
		bool resolved = true;

		error = vm_snapshot_session_begin_exact(ctx, &snapshot_session,
		    &resolved);
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

	memsz = vm_snapshot_mem(ctx, fd_checkpoint, 0, true);
	if (memsz == 0) {
		perror("Could not write guest memory to file");
		error = errno != 0 ? errno : EIO;
		goto done;
	}
	ret = collect_generic_devmem(ctx, &devmem_regions, &devmem_count);
	if (ret != 0) {
		fprintf(stderr, "Could not enumerate generic device memory.\n");
		error = ret;
		goto done;
	}
	ret = bhyve_devmem_snapshot_save(fd_checkpoint, memsz,
	    devmem_regions, devmem_count, &devmem_extension_size);
	free(devmem_regions);
	devmem_regions = NULL;
	if (ret != 0) {
		fprintf(stderr, "Could not snapshot generic device memory.\n");
		error = ret;
		goto done;
	}

	ret = vm_snapshot_basic_metadata(ctx, xop, memsz);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot vm basic metadata.\n");
		error = ret > 0 ? ret : EIO;
		goto done;
	}

	ret = vm_save_kern_structs(ctx, kdata_fd, xop);
	if (ret != 0) {
		fprintf(stderr, "Failed to snapshot vm kernel data.\n");
		error = ret > 0 ? ret : EIO;
		goto done;
	}

	ret = vm_snapshot_devices(kdata_fd, xop);
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
	if (error == 0 && fsync(fddir) != 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0) {
		error = checkpoint_publish(fddir, checkpoint_file, manifest_tmp,
		    &manifest, &published);
		if (published && error == 0 && old_exists)
			checkpoint_remove_old_generation(fddir, &old_manifest);
	}
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
	if (snapshot_session_active) {
		int session_error;
		bool released = false;

		session_error = vm_snapshot_session_release_exact(ctx,
		    &snapshot_session, published, &released);
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
		vm_destroy(ctx);
		exit(BHYVE_EXIT_SUSPEND);
	}

	/*
	 * pci_resume() tracks ownership per device, so a failed pause walk can
	 * safely release just the devices which were acquired before the error.
	 * Do not run either cleanup path for failures which happened before the
	 * corresponding pause operation started.
	 */
	if (!snapshot_session_active && !snapshot_session_unresolved &&
	    (devices_paused || vcpus_paused)) {
		ret = vm_resume_devices();
		if (ret != 0) {
			fprintf(stderr, "Could not resume devices\r\n");
			devices_resumed = false;
			if (error == 0)
				error = ret;
		}
	} else if (snapshot_session_active || snapshot_session_unresolved) {
		devices_resumed = false;
	}
	/*
	 * Never restart guest execution while a backend still owns checkpoint
	 * pause state.  The per-device ownership markers allow a later
	 * checkpoint request to retry just the failed resume safely.
	 */
	if (vcpus_paused && devices_resumed)
		vm_vcpu_resume(ctx);
	if (!published) {
		if (data_created)
			(void)unlinkat(fddir, manifest.data, 0);
		if (kern_created)
			(void)unlinkat(fddir, manifest.kern, 0);
		if (meta_created)
			(void)unlinkat(fddir, manifest.meta, 0);
		if (manifest_tmp != NULL)
			(void)unlinkat(fddir, manifest_tmp, 0);
	}
	if (lock_fd >= 0)
		close(lock_fd);
	free(lock_filename);
	free(manifest_tmp);
	return (error);
}

/*
 * ------------------------------------------------------------------------
 * Live-migration bridge to the whole-machine save/restore machinery.
 *
 * These functions reuse the existing device/kernel serialization and restore
 * steps (vm_snapshot_basic_metadata / vm_save_kern_structs / vm_snapshot_devices
 * on save; vm_restore_preflight / vm_restore_devices / vm_restore_kern_structs
 * on restore) but move the container from on-disk checkpoint generation files
 * to an in-memory blob streamed over the migration session.  Guest RAM is NOT
 * part of this blob: it is carried separately as pre-copy memory generations,
 * so the destination skips restore_vm_mem() and only replays device + CPU/vCPU/
 * kernel structure state.  The existing vm_checkpoint()/vm_restore_transaction()
 * paths are left untouched.
 *
 * Wire layout of the blob (fixed-width little-endian, no host pointers/fds):
 *   [u64 meta_len][u64 kdata_len][meta bytes (UCL/JSON)][kdata bytes]
 * ------------------------------------------------------------------------
 */

#define	MIGRATE_BLOB_HDR	16u	/* two le64 length fields */

/*
 * Create an anonymous, regular, mmap-able temp file seeded with buf.
 *
 * This must not touch the global filesystem namespace: the source-side
 * "migrate" IPC command runs on the checkpoint thread after cap_enter(), where
 * any absolute-path open (e.g. mkstemp(3) in /tmp) fails with ECAPMODE.
 * memfd_create(2) is anonymous (capability-mode safe), grows on write, and
 * yields an fd that fstat(2) reports as a regular file and that supports
 * lseek/read/write/mmap, which is all load_kdata_fd()/load_metadata_fd() need.
 */
static int
migrate_tempfd(const void *buf, size_t len)
{
	int fd;

	fd = memfd_create("bhyve-migrate", MFD_CLOEXEC);
	if (fd < 0)
		return (-1);
	if (len != 0 && snapshot_write_all(fd, buf, len) != 0) {
		close(fd);
		return (-1);
	}
	if (lseek(fd, 0, SEEK_SET) != 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

int
vm_snapshot_dev_state_to_mem(struct vmctx *ctx, uint8_t **blob_out,
    size_t *len_out)
{
	struct vm_snapshot_session session;
	FILE *meta_file;
	xo_handle_t *xop;
	uint8_t *meta_buf, *kdata_buf, *blob;
	long meta_len_l;
	size_t meta_len, kdata_len, blob_len;
	off_t kdata_size;
	int kdata_fd, meta_fd, error;
	bool resolved, released, session_active;

	if (ctx == NULL || blob_out == NULL || len_out == NULL)
		return (EINVAL);
	*blob_out = NULL;
	*len_out = 0;
	meta_buf = kdata_buf = blob = NULL;
	meta_file = NULL;
	xop = NULL;
	kdata_fd = meta_fd = -1;
	session_active = false;

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
	 * devices for the cutover.  We release the fence unpublished: the source
	 * stays consistent whether the cutover commits (source goes defunct) or
	 * rolls back (source resumes).
	 */
	error = vm_snapshot_session_begin_exact(ctx, &session, &resolved);
	if (error != 0)
		goto out;
	session_active = true;

	error = vm_snapshot_basic_metadata(ctx, xop,
	    vm_get_lowmem_size(ctx) + vm_get_highmem_size(ctx));
	if (error != 0)
		goto out;
	error = vm_save_kern_structs(ctx, kdata_fd, xop);
	if (error != 0)
		goto out;
	error = vm_snapshot_devices(kdata_fd, xop);
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
	    pread(kdata_fd, kdata_buf, kdata_len, 0) != (ssize_t)kdata_len) {
		error = errno != 0 ? errno : EIO;
		goto out;
	}

	blob_len = MIGRATE_BLOB_HDR + meta_len + kdata_len;
	blob = malloc(blob_len);
	if (blob == NULL) {
		error = ENOMEM;
		goto out;
	}
	le64enc(blob + 0, (uint64_t)meta_len);
	le64enc(blob + 8, (uint64_t)kdata_len);
	memcpy(blob + MIGRATE_BLOB_HDR, meta_buf, meta_len);
	memcpy(blob + MIGRATE_BLOB_HDR + meta_len, kdata_buf, kdata_len);
	*blob_out = blob;
	*len_out = blob_len;
	blob = NULL;
	error = 0;

out:
	if (session_active) {
		int rel;

		rel = vm_snapshot_session_release_exact(ctx, &session, false,
		    &released);
		if (rel != 0 && error == 0)
			error = rel;
	}
	if (xop != NULL)
		xo_destroy(xop);
	if (meta_file != NULL)
		fclose(meta_file);
	if (meta_fd >= 0)
		close(meta_fd);
	if (kdata_fd >= 0)
		close(kdata_fd);
	free(meta_buf);
	free(kdata_buf);
	free(blob);
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
int
vm_migrate_commit_state(struct vmctx *ctx, const uint8_t *blob, size_t len)
{
	struct restore_state rstate;
	struct vm_snapshot_session session;
	uint64_t meta_len, kdata_len;
	int meta_fd, kdata_fd, error, rel;
	bool resolved, released, session_active;

	if (ctx == NULL || blob == NULL || len < MIGRATE_BLOB_HDR)
		return (EINVAL);
	if (!checkpoint_restore_startup_held())
		return (EBUSY);
	meta_len = le64dec(blob + 0);
	kdata_len = le64dec(blob + 8);
	if (meta_len > len - MIGRATE_BLOB_HDR ||
	    kdata_len > len - MIGRATE_BLOB_HDR - meta_len)
		return (EBADMSG);
	/* The framed state blob is one exact record, not a prefix container. */
	if (meta_len + kdata_len != len - MIGRATE_BLOB_HDR)
		return (EBADMSG);

	memset(&rstate, 0, sizeof(rstate));
	rstate.kdata_fd = -1;
	rstate.vmmem_fd = -1;
	rstate.kdata_map = MAP_FAILED;
	meta_fd = kdata_fd = -1;
	session_active = false;

	meta_fd = migrate_tempfd(blob + MIGRATE_BLOB_HDR, (size_t)meta_len);
	kdata_fd = migrate_tempfd(blob + MIGRATE_BLOB_HDR + meta_len,
	    (size_t)kdata_len);
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

	error = vm_pause_devices();
	if (error != 0)
		goto out;
	error = vm_restore_preflight(&rstate);
	if (error != 0)
		goto out;
	error = vm_snapshot_session_begin_exact(ctx, &session, &resolved);
	if (error != 0)
		goto out;
	session_active = true;
	/* Guest RAM is already present; only devices and kernel structs. */
	error = vm_restore_devices(&rstate);
	if (error != 0)
		goto out;
	error = vm_restore_kern_structs(ctx, &rstate);
	if (error != 0)
		goto out;
	rel = vm_snapshot_session_release_exact(ctx, &session, true, &released);
	if (released)
		session_active = false;
	if (rel != 0) {
		error = rel;
		goto out;
	}
	error = 0;

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

/* Release the destination for execution after a committed migration. */
int
vm_migrate_resume(struct vmctx *ctx)
{
	int error;

	/* Consume the committed restore's one-shot time-rebase credential first. */
	if (vm_restore_time(ctx) < 0)
		return (errno != 0 ? errno : EIO);
	error = vm_resume_devices();
	if (error == 0)
		error = checkpoint_restore_startup_release();
	return (error);
}

static int
handle_message(struct vmctx *ctx, nvlist_t *nvl)
{
	const char *cmd;
	struct ipc_command **ipc_cmd;

	if (!nvlist_exists_string(nvl, "cmd"))
		return (EINVAL);

	cmd = nvlist_get_string(nvl, "cmd");
	IPC_COMMAND_FOREACH(ipc_cmd, ipc_cmd_set) {
		if (strcmp(cmd, (*ipc_cmd)->name) == 0)
			return ((*ipc_cmd)->handler(ctx, nvl));
	}

	return (EOPNOTSUPP);
}

/*
 * Listen for commands from bhyvectl
 */
void *
checkpoint_thread(void *param)
{
	int error, fd;
	struct checkpoint_thread_info *thread_info;
	nvlist_t *nvl;

	pthread_set_name_np(pthread_self(), "checkpoint thread");
	thread_info = (struct checkpoint_thread_info *)param;

	for (;;) {
		fd = accept4(thread_info->socket_fd, NULL, NULL, SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			EPRINTLN("checkpoint accept failed: %s",
			    strerror(errno));
			break;
		}
		nvl = nvlist_recv(fd, 0);
		if (nvl != NULL) {
			error = handle_message(thread_info->ctx, nvl);
			if (error != 0)
				EPRINTLN("checkpoint command failed: %s",
				    strerror(error));
		} else
			EPRINTLN("nvlist_recv() failed: %s", strerror(errno));

		close(fd);
		nvlist_destroy(nvl);
	}

	return (NULL);
}

static int
vm_do_checkpoint(struct vmctx *ctx, const nvlist_t *nvl)
{
	int error;

	if (!nvlist_exists_string(nvl, "filename") ||
	    !nvlist_exists_bool(nvl, "suspend") ||
	    !nvlist_exists_descriptor(nvl, "fddir"))
		error = EINVAL;
	else
		error = vm_checkpoint(ctx,
		    nvlist_get_descriptor(nvl, "fddir"),
		    nvlist_get_string(nvl, "filename"),
		    nvlist_get_bool(nvl, "suspend"));

	return (error);
}
IPC_COMMAND(ipc_cmd_set, checkpoint, vm_do_checkpoint);

/*
 * Create the listening socket for IPC with bhyvectl
 */
int
init_checkpoint_thread(struct vmctx *ctx)
{
	struct checkpoint_thread_info *checkpoint_info = NULL;
	struct sockaddr_un addr;
	struct timeval receive_timeout;
	int socket_fd = -1;
	pthread_t checkpoint_pthread;
	int err, pathlen;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	memset(&addr, 0, sizeof(addr));

	socket_fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (socket_fd < 0) {
		EPRINTLN("Socket creation failed: %s", strerror(errno));
		err = -1;
		goto fail;
	}

	addr.sun_family = AF_UNIX;

	pathlen = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s%s",
	    BHYVE_RUN_DIR, vm_get_name(ctx));
	if (pathlen < 0 || (size_t)pathlen >= sizeof(addr.sun_path)) {
		EPRINTLN("Checkpoint socket path is too long");
		err = ENAMETOOLONG;
		goto fail;
	}
	addr.sun_len = SUN_LEN(&addr);
	unlink(addr.sun_path);

	if (bind(socket_fd, (struct sockaddr *)&addr, addr.sun_len) != 0) {
		EPRINTLN("Failed to bind socket \"%s\": %s\n",
		    addr.sun_path, strerror(errno));
		err = -1;
		goto fail;
	}
	/*
	 * Control operations can replace guest state; keep the endpoint
	 * private.  Use lchmod() so that if the run directory is writable by
	 * an unprivileged user who races a symlink into our path between
	 * bind() and here, we retarget the symlink itself rather than handing
	 * that user an arbitrary-file chmod primitive.
	 */
	if (lchmod(addr.sun_path, S_IRUSR | S_IWUSR) != 0) {
		EPRINTLN("Failed to restrict checkpoint socket \"%s\": %s\n",
		    addr.sun_path, strerror(errno));
		err = errno;
		goto fail;
	}
	/* Accepted Unix sockets inherit this deadline for nvlist_recv(). */
	receive_timeout = (struct timeval) {
		.tv_sec = CHECKPOINT_CLIENT_TIMEOUT_SEC,
		.tv_usec = 0,
	};
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
	    sizeof(receive_timeout)) != 0) {
		EPRINTLN("Failed to set checkpoint client timeout: %s\n",
		    strerror(errno));
		err = errno;
		goto fail;
	}

	if (listen(socket_fd, 10) < 0) {
		EPRINTLN("ipc socket listen: %s\n", strerror(errno));
		err = errno;
		goto fail;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_ACCEPT, CAP_READ, CAP_RECV, CAP_WRITE,
	    CAP_SEND, CAP_GETSOCKOPT);

	if (caph_rights_limit(socket_fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif
	checkpoint_info = calloc(1, sizeof(*checkpoint_info));
	if (checkpoint_info == NULL) {
		err = ENOMEM;
		goto fail;
	}
	checkpoint_info->ctx = ctx;
	checkpoint_info->socket_fd = socket_fd;

	err = pthread_create(&checkpoint_pthread, NULL, checkpoint_thread,
		checkpoint_info);
	if (err != 0)
		goto fail;

	return (0);
fail:
	free(checkpoint_info);
	if (socket_fd >= 0)
		close(socket_fd);
	unlink(addr.sun_path);

	return (err);
}

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
