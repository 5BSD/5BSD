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
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sysexits.h>
#include <stdbool.h>
#include <sys/ioctl.h>

#include <machine/vmm.h>
#ifndef WITHOUT_CAPSICUM
#include <machine/vmm_dev.h>
#endif
#include <machine/vmm_snapshot.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "acpi.h"
#include "checkpoint_manifest.h"
#ifdef __amd64__
#include "amd64/atkbdc.h"
#endif
#include "debug.h"
#include "ipc.h"
#include "mem.h"
#include "pci_emul.h"
#include "snapshot.h"

#include <libxo/xo.h>
#include <ucl.h>

extern int guest_ncpus;

static struct winsize winsize;
static sig_t old_winch_handler;

#define	KB		(1024UL)
#define	MB		(1024UL * KB)
#define	GB		(1024UL * MB)

#define	SNAPSHOT_CHUNK	(4 * MB)
#define	PROG_BUF_SZ	(8192)

#define	SNAPSHOT_BUFFER_SIZE (40 * MB)

#define	JSON_KERNEL_ARR_KEY		"kern_structs"
#define	JSON_DEV_ARR_KEY		"devices"
#define	JSON_BASIC_METADATA_KEY 	"basic metadata"
#define	JSON_SNAPSHOT_REQ_KEY		"device"
#define	JSON_SIZE_KEY			"size"
#define	JSON_FILE_OFFSET_KEY		"file_offset"

#define	JSON_NCPUS_KEY			"ncpus"
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
	{ "vm",		STRUCT_VM	},
	{ "vioapic",	STRUCT_VIOAPIC	},
	{ "vlapic",	STRUCT_VLAPIC	},
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
load_vmmem_file(const char *filename, struct restore_state *rstate)
{
	struct stat sb;
	int err;

	rstate->vmmem_fd = open(filename, O_RDONLY);
	if (rstate->vmmem_fd < 0) {
		perror("Failed to open restore file");
		return (-1);
	}

	err = fstat(rstate->vmmem_fd, &sb);
	if (err < 0) {
		perror("Failed to stat restore file");
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
load_kdata_file(const char *filename, struct restore_state *rstate)
{
	struct stat sb;
	int err;

	rstate->kdata_fd = open(filename, O_RDONLY);
	if (rstate->kdata_fd < 0) {
		perror("Failed to open kernel data file");
		return (-1);
	}

	err = fstat(rstate->kdata_fd, &sb);
	if (err < 0) {
		perror("Failed to stat kernel data file");
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
load_metadata_file(const char *filename, struct restore_state *rstate)
{
	ucl_object_t *obj;
	struct ucl_parser *parser;
	int err;

	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		fprintf(stderr, "Failed to initialize UCL parser.\n");
		err = -1;
		goto err_load_metadata;
	}

	err = ucl_parser_add_file(parser, filename);
	if (err == 0) {
		fprintf(stderr, "Failed to parse metadata file: '%s'\n",
			filename);
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
	const char *vmmem_filename;
	int err;
	bool is_manifest;
	char *base_copy, *data_filename, *kdata_filename, *lock_filename;
	char *meta_filename;
	int lock_fd;

	assert(filename != NULL);
	assert(rstate != NULL);

	memset(rstate, 0, sizeof(*rstate));
	rstate->kdata_fd = -1;
	rstate->vmmem_fd = -1;
	rstate->kdata_map = MAP_FAILED;

	data_filename = NULL;
	base_copy = NULL;
	kdata_filename = NULL;
	lock_filename = NULL;
	meta_filename = NULL;
	lock_fd = -1;
	if (asprintf(&lock_filename, "%s.lock", filename) < 0)
		goto err_restore;
	lock_fd = open(lock_filename,
	    O_RDONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock_fd < 0) {
		fprintf(stderr, "Failed to open checkpoint lock: %s\n",
		    strerror(errno));
		goto err_restore;
	}
	err = checkpoint_lock(lock_fd, LOCK_SH);
	if (err != 0) {
		fprintf(stderr, "Failed to lock checkpoint: %s\n", strerror(err));
		goto err_restore;
	}
	err = checkpoint_manifest_read(filename, &manifest, &is_manifest);
	if (err != 0) {
		fprintf(stderr, "Failed to read checkpoint manifest: %s\n",
		    strerror(err));
		goto err_restore;
	}
	if (is_manifest) {
		base_copy = strdup(filename);
		if (base_copy == NULL ||
		    !checkpoint_manifest_valid_for(basename(base_copy),
		    &manifest)) {
			fprintf(stderr, "Checkpoint manifest has invalid members.\n");
			goto err_restore;
		}
		data_filename = checkpoint_member_path(filename, manifest.data);
		kdata_filename = checkpoint_member_path(filename, manifest.kern);
		meta_filename = checkpoint_member_path(filename, manifest.meta);
		if (data_filename == NULL || kdata_filename == NULL ||
		    meta_filename == NULL) {
			fprintf(stderr, "Failed to construct checkpoint member paths.\n");
			goto err_restore;
		}
		vmmem_filename = data_filename;
	} else {
		vmmem_filename = filename;
		kdata_filename = strcat_extension(filename, ".kern");
		meta_filename = strcat_extension(filename, ".meta");
		if (kdata_filename == NULL || meta_filename == NULL) {
			fprintf(stderr, "Failed to construct legacy checkpoint paths.\n");
			goto err_restore;
		}
	}

	err = load_vmmem_file(vmmem_filename, rstate);
	if (err != 0) {
		fprintf(stderr, "Failed to load guest RAM file.\n");
		goto err_restore;
	}

	err = load_kdata_file(kdata_filename, rstate);
	if (err != 0) {
		fprintf(stderr, "Failed to load guest kernel data file.\n");
		goto err_restore;
	}

	err = load_metadata_file(meta_filename, rstate);
	if (err != 0) {
		fprintf(stderr, "Failed to load guest metadata file.\n");
		goto err_restore;
	}

	free(data_filename);
	free(base_copy);
	free(kdata_filename);
	free(lock_filename);
	free(meta_filename);
	close(lock_fd);
	return (0);

err_restore:
	destroy_restore_state(rstate);
	free(data_filename);
	free(base_copy);
	free(kdata_filename);
	free(lock_filename);
	free(meta_filename);
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
			JSON_DEV_ARR_KEY);
		return (NULL);
	}

	if (ucl_object_type(devs) != UCL_ARRAY) {
		fprintf(stderr, "Object '%s' is not an array.\n",
			JSON_DEV_ARR_KEY);
		return (NULL);
	}

	while ((obj = ucl_object_iterate(devs, &it, true)) != NULL) {
		ret = lookup_check_dev(dev_name, rstate, obj, data_size);
		if (ret != NULL)
			return (ret);
	}

	return (NULL);
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
lookup_memflags(struct restore_state *rstate)
{
	int64_t memflags;
	const ucl_object_t *obj;

	obj = lookup_basic_metadata_object(rstate);
	if (obj == NULL)
		return (0);

	JSON_GET_INT_OR_RETURN(JSON_MEMFLAGS_KEY, obj, &memflags, 0);
	if (memflags < INT_MIN || memflags > INT_MAX) {
		fprintf(stderr, "Invalid memory flags in checkpoint metadata.\n");
		return (0);
	}

	return ((int)memflags);
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

int
restore_vm_mem(struct vmctx *ctx, struct restore_state *rstate)
{
	size_t restored;

	restored = vm_snapshot_mem(ctx, rstate->vmmem_fd, rstate->vmmem_len,
				   false);

	if (restored != rstate->vmmem_len)
		return (-1);

	return (0);
}

int
vm_restore_kern_structs(struct vmctx *ctx, struct restore_state *rstate)
{
	for (unsigned i = 0; i < nitems(snapshot_kern_structs); i++) {
		const struct vm_snapshot_kern_info *info;
		struct vm_snapshot_meta *meta;
		void *data;
		size_t size;

		info = &snapshot_kern_structs[i];
		data = lookup_dev(info->struct_name, JSON_KERNEL_ARR_KEY, rstate, &size);
		if (data == NULL)
			errx(EX_DATAERR, "Cannot find kern struct %s",
			    info->struct_name);

		if (size == 0)
			errx(EX_DATAERR, "data with zero size for %s",
			    info->struct_name);

		meta = &(struct vm_snapshot_meta) {
			.dev_name = info->struct_name,
			.dev_req  = info->req,

			.buffer.buf_start = data,
			.buffer.buf_size = size,

			.buffer.buf = data,
			.buffer.buf_rem = size,

			.op = VM_SNAPSHOT_RESTORE,
		};

		if (vm_snapshot_req(ctx, meta))
			err(EX_DATAERR, "Failed to restore %s",
			    info->struct_name);
	}
	return (0);
}

static int
vm_restore_device(struct restore_state *rstate, vm_snapshot_dev_cb func,
    const char *name, void *data)
{
	void *dev_ptr;
	size_t dev_size;
	int ret;
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

	return (0);
}

int
vm_restore_devices(struct restore_state *rstate)
{
	int ret;
	struct pci_devinst *pdi = NULL;

	while ((pdi = pci_next(pdi)) != NULL) {
		ret = vm_restore_device(rstate, pci_snapshot, pdi->pi_name, pdi);
		if (ret)
			return (ret);
	}

#ifdef __amd64__
	ret = vm_restore_device(rstate, atkbdc_snapshot, "atkbdc", NULL);
#else
	ret = 0;
#endif
	return (ret);
}

int
vm_pause_devices(void)
{
	int ret;
	struct pci_devinst *pdi = NULL;

	while ((pdi = pci_next(pdi)) != NULL) {
		ret = pci_pause(pdi);
		if (ret) {
			EPRINTLN("Cannot pause dev %s: %d", pdi->pi_name, ret);
			return (ret);
		}
	}

	return (0);
}

int
vm_resume_devices(void)
{
	int error, ret;
	struct pci_devinst *pdi = NULL;

	error = 0;
	while ((pdi = pci_next(pdi)) != NULL) {
		ret = pci_resume(pdi);
		if (ret) {
			EPRINTLN("Cannot resume '%s': %d", pdi->pi_name, ret);
			if (error == 0)
				error = ret;
		}
	}

	return (error);
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
    const struct checkpoint_manifest *old, bool old_is_manifest)
{
	char *legacy_kern, *legacy_meta;
	const char *members[3];

	if (old_is_manifest) {
		members[0] = old->data;
		members[1] = old->kern;
		members[2] = old->meta;
		for (unsigned int i = 0; i < nitems(members); i++) {
			if (unlinkat(fddir, members[i], 0) != 0 && errno != ENOENT)
				EPRINTLN("Cannot remove old checkpoint member '%s': %s",
				    members[i], strerror(errno));
		}
	} else {
		legacy_kern = strcat_extension(checkpoint_file, ".kern");
		legacy_meta = strcat_extension(checkpoint_file, ".meta");
		if (legacy_kern != NULL &&
		    unlinkat(fddir, legacy_kern, 0) != 0 && errno != ENOENT)
			EPRINTLN("Cannot remove old checkpoint member '%s': %s",
			    legacy_kern, strerror(errno));
		if (legacy_meta != NULL &&
		    unlinkat(fddir, legacy_meta, 0) != 0 && errno != ENOENT)
			EPRINTLN("Cannot remove old checkpoint member '%s': %s",
			    legacy_meta, strerror(errno));
		free(legacy_kern);
		free(legacy_meta);
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
	xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%lu}\n", data_size);
	xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%lu}\n", *offset);
	xo_close_instance_h(xop, JSON_KERNEL_ARR_KEY);

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
		    JSON_DEV_ARR_KEY, meta, &offset);
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

	xo_open_container_h(xop, JSON_BASIC_METADATA_KEY);
	xo_emit_h(xop, "{:" JSON_NCPUS_KEY "/%ld}\n", guest_ncpus);
	xo_emit_h(xop, "{:" JSON_VMNAME_KEY "/%s}\n", vm_get_name(ctx));
	xo_emit_h(xop, "{:" JSON_MEMSIZE_KEY "/%lu}\n", memsz);
	xo_emit_h(xop, "{:" JSON_MEMFLAGS_KEY "/%d}\n", vm_get_memflags(ctx));
	xo_close_container_h(xop, JSON_BASIC_METADATA_KEY);

	return (0);
}

static int
vm_snapshot_dev_write_data(int data_fd, xo_handle_t *xop, const char *array_key,
			   struct vm_snapshot_meta *meta, off_t *offset)
{
	size_t data_size;

	data_size = vm_get_snapshot_size(meta);

	if (snapshot_write_all(data_fd, meta->buffer.buf_start, data_size) != 0) {
		perror("Failed to write all snapshotted data.");
		return (-1);
	}

	/* Write metadata. */
	xo_open_instance_h(xop, array_key);
	xo_emit_h(xop, "{:" JSON_SNAPSHOT_REQ_KEY "/%s}\n", meta->dev_name);
	xo_emit_h(xop, "{:" JSON_SIZE_KEY "/%lu}\n", data_size);
	xo_emit_h(xop, "{:" JSON_FILE_OFFSET_KEY "/%lu}\n", *offset);
	xo_close_instance_h(xop, array_key);

	*offset += data_size;

	return (0);
}

static int
vm_snapshot_device(vm_snapshot_dev_cb func, const char *dev_name,
    void *devdata, int data_fd, xo_handle_t *xop,
    struct vm_snapshot_meta *meta, off_t *offset)
{
	int ret;

	memset(meta->buffer.buf_start, 0, meta->buffer.buf_size);
	meta->buffer.buf = meta->buffer.buf_start;
	meta->buffer.buf_rem = meta->buffer.buf_size;
	meta->dev_name = dev_name;
	meta->dev_data = devdata;

	ret = func(meta);
	if (ret != 0) {
		EPRINTLN("Failed to snapshot %s; ret=%d", dev_name, ret);
		return (ret);
	}

	ret = vm_snapshot_dev_write_data(data_fd, xop, JSON_DEV_ARR_KEY, meta,
					 offset);
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
		while (checkpoint_active)
			pthread_cond_wait(&vcpus_can_run, &vcpu_lock);
		CPU_CLR(vcpu, &vcpus_suspended);
	}
	pthread_mutex_unlock(&vcpu_lock);
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
	pthread_cond_broadcast(&vcpus_can_run);
}

static int
vm_checkpoint(struct vmctx *ctx, int fddir, const char *checkpoint_file,
    bool stop_vm)
{
	struct checkpoint_manifest manifest, old_manifest;
	int fd_checkpoint = -1, kdata_fd = -1, fd_meta = -1;
	int lock_fd = -1;
	int ret = 0;
	int error = 0;
	size_t memsz;
	bool devices_paused = false;
	bool devices_resumed = true;
	bool data_created = false;
	bool kern_created = false;
	bool meta_created = false;
	bool old_exists = false;
	bool old_is_manifest = false;
	bool published = false;
	bool vcpus_paused = false;
	xo_handle_t *xop = NULL;
	char *lock_filename = NULL, *manifest_tmp = NULL;
	FILE *meta_file = NULL;

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

	memsz = vm_snapshot_mem(ctx, fd_checkpoint, 0, true);
	if (memsz == 0) {
		perror("Could not write guest memory to file");
		error = errno != 0 ? errno : EIO;
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
		fd_meta = -1;
	} else if (fd_meta >= 0) {
		if (close(fd_meta) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
		fd_meta = -1;
	}
	if (fd_checkpoint >= 0) {
		if (error == 0 && fsync(fd_checkpoint) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(fd_checkpoint) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
		fd_checkpoint = -1;
	}
	if (kdata_fd >= 0) {
		if (error == 0 && fsync(kdata_fd) != 0)
			error = errno != 0 ? errno : EIO;
		if (close(kdata_fd) != 0 && error == 0)
			error = errno != 0 ? errno : EIO;
		kdata_fd = -1;
	}
	if (error == 0 && fsync(fddir) != 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0) {
		error = checkpoint_publish(fddir, checkpoint_file, manifest_tmp,
		    &manifest, &published);
		if (published && error == 0 && old_exists)
			checkpoint_remove_old_generation(fddir, checkpoint_file,
			    &old_manifest, old_is_manifest);
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
	if (devices_paused || vcpus_paused) {
		ret = vm_resume_devices();
		if (ret != 0) {
			fprintf(stderr, "Could not resume devices\r\n");
			devices_resumed = false;
			if (error == 0)
				error = ret;
		}
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
		fd = accept(thread_info->socket_fd, NULL, NULL);
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
	int socket_fd = -1;
	pthread_t checkpoint_pthread;
	int err, pathlen;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	memset(&addr, 0, sizeof(addr));

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
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
	else if (op == VM_SNAPSHOT_RESTORE)
		memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);

	buffer->buf += data_size;
	buffer->buf_rem -= data_size;

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
	int ret;
	vm_paddr_t gaddr;

	if (meta->op == VM_SNAPSHOT_SAVE) {
		gaddr = paddr_host2guest(ctx, *addrp);
		if (gaddr == (vm_paddr_t) -1) {
			if (!restore_null ||
			    (restore_null && (*addrp != NULL))) {
				ret = EFAULT;
				goto done;
			}
		}

		SNAPSHOT_VAR_OR_LEAVE(gaddr, meta, ret, done);
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		SNAPSHOT_VAR_OR_LEAVE(gaddr, meta, ret, done);
		if (gaddr == (vm_paddr_t) -1) {
			if (!restore_null) {
				ret = EFAULT;
				goto done;
			}
		}

		*addrp = paddr_guest2host(ctx, gaddr, len);
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
	} else if (op == VM_SNAPSHOT_RESTORE) {
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
