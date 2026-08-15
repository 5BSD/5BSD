/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "acpi_device.h"
#include "bhyverun.h"
#ifdef __amd64__
#include "amd64/inout.h"
#include "amd64/pci_lpc.h"
#endif
#include "qemu_fwcfg.h"

#define QEMU_FWCFG_ACPI_DEVICE_NAME "FWCF"
#define QEMU_FWCFG_ACPI_HARDWARE_ID "QEMU0002"

#define QEMU_FWCFG_SELECTOR_PORT_NUMBER 0x510
#define QEMU_FWCFG_SELECTOR_PORT_SIZE 1
#define QEMU_FWCFG_SELECTOR_PORT_FLAGS IOPORT_F_INOUT
#define QEMU_FWCFG_DATA_PORT_NUMBER 0x511
#define QEMU_FWCFG_DATA_PORT_SIZE 1
#define QEMU_FWCFG_DATA_PORT_FLAGS \
	IOPORT_F_INOUT /* QEMU v2.4+ ignores writes */

#define QEMU_FWCFG_ARCHITECTURE_MASK 0x0001
#define QEMU_FWCFG_INDEX_MASK 0x3FFF

#define QEMU_FWCFG_SELECT_READ 0
#define QEMU_FWCFG_SELECT_WRITE 1

#define QEMU_FWCFG_ARCHITECTURE_GENERIC 0
#define QEMU_FWCFG_ARCHITECTURE_SPECIFIC 1

#define QEMU_FWCFG_INDEX_SIGNATURE 0x00
#define QEMU_FWCFG_INDEX_ID 0x01
#define QEMU_FWCFG_INDEX_NB_CPUS 0x05
#define QEMU_FWCFG_INDEX_MAX_CPUS 0x0F
#define QEMU_FWCFG_INDEX_FILE_DIR 0x19

#define QEMU_FWCFG_FIRST_FILE_INDEX 0x20

#define QEMU_FWCFG_MIN_FILES 10

#pragma pack(1)

union qemu_fwcfg_selector {
	struct {
		uint16_t index : 14;
		uint16_t writeable : 1;
		uint16_t architecture : 1;
	};
	uint16_t bits;
};

struct qemu_fwcfg_signature {
	uint8_t signature[4];
};

struct qemu_fwcfg_id {
	uint32_t interface : 1; /* always set */
	uint32_t DMA : 1;
	uint32_t reserved : 30;
};

struct qemu_fwcfg_file {
	uint32_t be_size;
	uint16_t be_selector;
	uint16_t reserved;
	uint8_t name[QEMU_FWCFG_MAX_NAME];
};

struct qemu_fwcfg_directory {
	uint32_t be_count;
	struct qemu_fwcfg_file files[0];
};

#pragma pack()

struct qemu_fwcfg_softc {
	struct acpi_device *acpi_dev;

	uint32_t data_offset;
	union qemu_fwcfg_selector selector;
	struct qemu_fwcfg_item items[QEMU_FWCFG_MAX_ARCHS]
				    [QEMU_FWCFG_MAX_ENTRIES];
	struct qemu_fwcfg_directory *directory;
};

static struct qemu_fwcfg_softc fwcfg_sc;

struct qemu_fwcfg_user_file {
	STAILQ_ENTRY(qemu_fwcfg_user_file) chain;
	uint8_t name[QEMU_FWCFG_MAX_NAME];
	uint32_t size;
	void *data;
};
static STAILQ_HEAD(qemu_fwcfg_user_file_list,
    qemu_fwcfg_user_file) user_files = STAILQ_HEAD_INITIALIZER(user_files);

#ifdef __amd64__
static int
qemu_fwcfg_selector_port_handler(struct vmctx *const ctx __unused, const int in,
    const int port __unused, const int bytes, uint32_t *const eax,
    void *const arg __unused)
{
	if (bytes != sizeof(uint16_t)) {
		warnx("%s: invalid size (%d) of IO port access", __func__,
		    bytes);
		return (-1);
	}

	if (in) {
		*eax = htole16(fwcfg_sc.selector.bits);
		return (0);
	}

	fwcfg_sc.data_offset = 0;
	fwcfg_sc.selector.bits = le16toh(*eax);

	return (0);
}

static int
qemu_fwcfg_data_port_handler(struct vmctx *const ctx __unused, const int in,
    const int port __unused, const int bytes, uint32_t *const eax,
    void *const arg __unused)
{
	if (bytes != sizeof(uint8_t)) {
		warnx("%s: invalid size (%d) of IO port access", __func__,
		    bytes);
		return (-1);
	}

	if (!in) {
		warnx("%s: Writes to qemu fwcfg data port aren't allowed",
		    __func__);
		return (-1);
	}

	/* get fwcfg item */
	struct qemu_fwcfg_item *const item =
	    &fwcfg_sc.items[fwcfg_sc.selector.architecture]
			   [fwcfg_sc.selector.index];
	if (item->data == NULL) {
		warnx(
		    "%s: qemu fwcfg item doesn't exist (architecture %s index 0x%x)",
		    __func__,
		    fwcfg_sc.selector.architecture ? "specific" : "generic",
		    fwcfg_sc.selector.index);
		*eax = 0x00;
		return (0);
	} else if (fwcfg_sc.data_offset >= item->size) {
		warnx(
		    "%s: qemu fwcfg item read exceeds size (architecture %s index 0x%x size 0x%x offset 0x%x)",
		    __func__,
		    fwcfg_sc.selector.architecture ? "specific" : "generic",
		    fwcfg_sc.selector.index, item->size, fwcfg_sc.data_offset);
		*eax = 0x00;
		return (0);
	}

	/* return item data */
	*eax = item->data[fwcfg_sc.data_offset];
	fwcfg_sc.data_offset++;

	return (0);
}
#endif

static int
qemu_fwcfg_add_item(const uint16_t architecture, const uint16_t index,
    const uint32_t size, void *const data)
{
	uint16_t arch, idx;

	if (architecture >= QEMU_FWCFG_MAX_ARCHS ||
	    index >= QEMU_FWCFG_MAX_ENTRIES || data == NULL)
		return (EINVAL);
	arch = architecture;
	idx = index;

	/* get pointer to item specified by selector */
	struct qemu_fwcfg_item *const fwcfg_item = &fwcfg_sc.items[arch][idx];

	/* check if item is already used */
	if (fwcfg_item->data != NULL) {
		warnx("%s: qemu fwcfg item exists (architecture %s index 0x%x)",
		    __func__, arch ? "specific" : "generic", idx);
		return (EEXIST);
	}

	/* save data of the item */
	fwcfg_item->size = size;
	fwcfg_item->data = data;

	return (0);
}

static int
qemu_fwcfg_add_item_file_dir(void)
{
	const size_t size = sizeof(struct qemu_fwcfg_directory) +
	    QEMU_FWCFG_MIN_FILES * sizeof(struct qemu_fwcfg_file);
	struct qemu_fwcfg_directory *const fwcfg_directory = calloc(1, size);
	int error;

	if (fwcfg_directory == NULL) {
		return (ENOMEM);
	}

	error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_FILE_DIR, sizeof(struct qemu_fwcfg_directory),
	    (uint8_t *)fwcfg_directory);
	if (error != 0) {
		free(fwcfg_directory);
		return (error);
	}
	fwcfg_sc.directory = fwcfg_directory;
	return (0);
}

static int
qemu_fwcfg_add_item_id(void)
{
	struct qemu_fwcfg_id *const fwcfg_id = calloc(1,
	    sizeof(struct qemu_fwcfg_id));
	int error;

	if (fwcfg_id == NULL) {
		return (ENOMEM);
	}

	fwcfg_id->interface = 1;
	fwcfg_id->DMA = 0;

	uint32_t *const le_fwcfg_id_ptr = (uint32_t *)fwcfg_id;
	*le_fwcfg_id_ptr = htole32(*le_fwcfg_id_ptr);

	error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_ID, sizeof(struct qemu_fwcfg_id),
	    (uint8_t *)fwcfg_id);
	if (error != 0)
		free(fwcfg_id);
	return (error);
}

static int
qemu_fwcfg_add_item_max_cpus(void)
{
	uint16_t *fwcfg_max_cpus = calloc(1, sizeof(uint16_t));
	int error;

	if (fwcfg_max_cpus == NULL) {
		return (ENOMEM);
	}

	/*
	 * We don't support cpu hotplug yet. For that reason, use guest_ncpus instead
	 * of maxcpus.
	 */
	*fwcfg_max_cpus = htole16(guest_ncpus);

	error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_MAX_CPUS, sizeof(uint16_t), fwcfg_max_cpus);
	if (error != 0)
		free(fwcfg_max_cpus);
	return (error);
}

static int
qemu_fwcfg_add_item_nb_cpus(void)
{
	uint16_t *fwcfg_max_cpus = calloc(1, sizeof(uint16_t));
	int error;

	if (fwcfg_max_cpus == NULL) {
		return (ENOMEM);
	}

	*fwcfg_max_cpus = htole16(guest_ncpus);

	error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_NB_CPUS, sizeof(uint16_t), fwcfg_max_cpus);
	if (error != 0)
		free(fwcfg_max_cpus);
	return (error);
}

static int
qemu_fwcfg_add_item_signature(void)
{
	struct qemu_fwcfg_signature *const fwcfg_signature = calloc(1,
	    sizeof(struct qemu_fwcfg_signature));
	int error;

	if (fwcfg_signature == NULL) {
		return (ENOMEM);
	}

	fwcfg_signature->signature[0] = 'Q';
	fwcfg_signature->signature[1] = 'E';
	fwcfg_signature->signature[2] = 'M';
	fwcfg_signature->signature[3] = 'U';

	error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_SIGNATURE, sizeof(struct qemu_fwcfg_signature),
	    (uint8_t *)fwcfg_signature);
	if (error != 0)
		free(fwcfg_signature);
	return (error);
}

#ifdef __amd64__
static int
qemu_fwcfg_register_port(const char *const name, const int port, const int size,
    const int flags, const inout_func_t handler)
{
	struct inout_port iop;

	bzero(&iop, sizeof(iop));
	iop.name = name;
	iop.port = port;
	iop.size = size;
	iop.flags = flags;
	iop.handler = handler;

	return (register_inout(&iop));
}
#endif

int
qemu_fwcfg_add_file(const char *name, const uint32_t size, void *const data)
{
	struct qemu_fwcfg_directory *new_directory;
	uint32_t count, file_index, index, old_count;
	size_t new_size;
	int error;

	if (name == NULL || name[0] == '\0' || data == NULL ||
	    fwcfg_sc.directory == NULL || strlen(name) >= QEMU_FWCFG_MAX_NAME)
		return (EINVAL);

	/*
	 * QEMU specifies count as big endian.
	 * Convert it to host endian to work with it.
	 */
	old_count = be32toh(fwcfg_sc.directory->be_count);
	if (old_count >= QEMU_FWCFG_MAX_ENTRIES - QEMU_FWCFG_FIRST_FILE_INDEX)
		return (ENOSPC);
	count = old_count + 1;
	index = QEMU_FWCFG_FIRST_FILE_INDEX + old_count;

	/*
	 * files should be sorted alphabetical, get index for new file
	 */
	for (file_index = 0; file_index < old_count; ++file_index) {
		int comparison;

		comparison = strcmp(name,
		    fwcfg_sc.directory->files[file_index].name);
		if (comparison == 0)
			return (EEXIST);
		if (comparison < 0)
			break;
	}

	new_directory = NULL;
	if (count > QEMU_FWCFG_MIN_FILES) {
		/* alloc new file directory */
		new_size = sizeof(struct qemu_fwcfg_directory) +
		    (size_t)count * sizeof(struct qemu_fwcfg_file);
		new_directory = calloc(1, new_size);
		if (new_directory == NULL) {
			warnx(
			    "%s: Unable to allocate a new qemu fwcfg files directory (count %d)",
			    __func__, count);
			return (ENOMEM);
		}

		/* copy files below file_index to new directory */
		memcpy(new_directory->files, fwcfg_sc.directory->files,
		    file_index * sizeof(struct qemu_fwcfg_file));

		/* copy files above file_index to directory */
		memcpy(&new_directory->files[file_index + 1],
		    &fwcfg_sc.directory->files[file_index],
		    (count - file_index - 1) * sizeof(struct qemu_fwcfg_file));

	}

	error = qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    index, size, data);
	if (error != 0) {
		free(new_directory);
		return (error);
	}
	if (new_directory != NULL) {
		free(fwcfg_sc.directory);
		fwcfg_sc.directory = new_directory;
		fwcfg_sc.items[0][QEMU_FWCFG_INDEX_FILE_DIR].data =
		    (uint8_t *)fwcfg_sc.directory;
	} else {
		/* shift files behind file_index */
		for (uint32_t i = QEMU_FWCFG_MIN_FILES - 1; i > file_index;
		     --i) {
			memcpy(&fwcfg_sc.directory->files[i],
			    &fwcfg_sc.directory->files[i - 1],
			    sizeof(struct qemu_fwcfg_file));
		}
	}

	/*
	 * QEMU specifies count, size and index as big endian.
	 * Save these values in big endian to simplify guest reads of these
	 * values.
	 */
	fwcfg_sc.directory->be_count = htobe32(count);
	fwcfg_sc.directory->files[file_index].be_size = htobe32(size);
	fwcfg_sc.directory->files[file_index].be_selector = htobe16(index);
	strcpy(fwcfg_sc.directory->files[file_index].name, name);

	/* set new size for the fwcfg_file_directory */
	fwcfg_sc.items[0][QEMU_FWCFG_INDEX_FILE_DIR].size =
	    sizeof(struct qemu_fwcfg_directory) +
	    count * sizeof(struct qemu_fwcfg_file);

	return (0);
}

static int
qemu_fwcfg_add_user_files(void)
{
	const struct qemu_fwcfg_user_file *fwcfg_file;
	int error;

	STAILQ_FOREACH(fwcfg_file, &user_files, chain) {
		error = qemu_fwcfg_add_file(fwcfg_file->name, fwcfg_file->size,
		    fwcfg_file->data);
		if (error)
			return (error);
	}

	return (0);
}

static const struct acpi_device_emul qemu_fwcfg_acpi_device_emul = {
	.name = QEMU_FWCFG_ACPI_DEVICE_NAME,
	.hid = QEMU_FWCFG_ACPI_HARDWARE_ID,
};

int
qemu_fwcfg_init(struct vmctx *const ctx)
{
	int error;
	bool fwcfg_enabled;

	/*
	 * The fwcfg implementation currently only provides an I/O port
	 * interface and thus is amd64-specific for now.  An MMIO interface is
	 * required for other platforms.
	 */
#ifdef __amd64__
	fwcfg_enabled = strcmp(lpc_fwcfg(), "qemu") == 0;
#else
	fwcfg_enabled = false;
#endif

	/*
	 * Bhyve supports fwctl (bhyve) and fwcfg (qemu) as firmware interfaces.
	 * Both are using the same ports. So, it's not possible to provide both
	 * interfaces at the same time to the guest. Therefore, only create acpi
	 * tables and register io ports for fwcfg, if it's used.
	 */
	if (fwcfg_enabled) {
		error = acpi_device_create(&fwcfg_sc.acpi_dev, &fwcfg_sc, ctx,
		    &qemu_fwcfg_acpi_device_emul);
		if (error) {
			warnx("%s: failed to create ACPI device for QEMU FwCfg",
			    __func__);
			goto done;
		}

		error = acpi_device_add_res_fixed_ioport(fwcfg_sc.acpi_dev,
		    QEMU_FWCFG_SELECTOR_PORT_NUMBER, 2);
		if (error) {
			warnx("%s: failed to add fixed IO port for QEMU FwCfg",
			    __func__);
			goto done;
		}

#ifdef __amd64__
		if ((error = qemu_fwcfg_register_port("qemu_fwcfg_selector",
		    QEMU_FWCFG_SELECTOR_PORT_NUMBER,
		    QEMU_FWCFG_SELECTOR_PORT_SIZE,
		    QEMU_FWCFG_SELECTOR_PORT_FLAGS,
		    qemu_fwcfg_selector_port_handler)) != 0) {
			warnx(
			    "%s: Unable to register qemu fwcfg selector port 0x%x",
			    __func__, QEMU_FWCFG_SELECTOR_PORT_NUMBER);
			goto done;
		}
		if ((error = qemu_fwcfg_register_port("qemu_fwcfg_data",
		    QEMU_FWCFG_DATA_PORT_NUMBER, QEMU_FWCFG_DATA_PORT_SIZE,
		    QEMU_FWCFG_DATA_PORT_FLAGS,
		    qemu_fwcfg_data_port_handler)) != 0) {
			warnx(
			    "%s: Unable to register qemu fwcfg data port 0x%x",
			    __func__, QEMU_FWCFG_DATA_PORT_NUMBER);
			goto done;
		}
#endif
	}

	/* add common fwcfg items */
	if ((error = qemu_fwcfg_add_item_signature()) != 0) {
		warnx("%s: Unable to add signature item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_id()) != 0) {
		warnx("%s: Unable to add id item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_nb_cpus()) != 0) {
		warnx("%s: Unable to add nb_cpus item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_max_cpus()) != 0) {
		warnx("%s: Unable to add max_cpus item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_file_dir()) != 0) {
		warnx("%s: Unable to add file_dir item", __func__);
		goto done;
	}

	/* add user defined fwcfg files */
	if ((error = qemu_fwcfg_add_user_files()) != 0) {
		warnx("%s: Unable to add user files", __func__);
		goto done;
	}

done:
	if (error && fwcfg_sc.acpi_dev != NULL) {
		acpi_device_destroy(fwcfg_sc.acpi_dev);
	}

	return (error);
}

static void
qemu_fwcfg_usage(const char *opt)
{
	warnx("Invalid fw_cfg option \"%s\"", opt);
	warnx("-f [name=]<name>,(string|file)=<value>");
}

/*
 * Parses the cmdline argument for user defined fw_cfg items. The cmdline
 * argument has the format:
 * "-f [name=]<name>,(string|file)=<value>"
 *
 * E.g.: "-f opt/com.page/example,string=Hello"
 */
int
qemu_fwcfg_parse_cmdline_arg(const char *opt)
{
	struct qemu_fwcfg_user_file *fwcfg_file;
	struct stat sb;
	const char *opt_ptr, *opt_end;
	size_t offset, size, string_size;
	ssize_t bytes_read;
	int error, fd;
	
	if (opt == NULL)
		return (EINVAL);
	fwcfg_file = calloc(1, sizeof(*fwcfg_file));
	if (fwcfg_file == NULL) {
		warnx("Unable to allocate fw_cfg_user_file");
		return (ENOMEM);
	}

	/* get pointer to <name> */
	opt_ptr = opt;
	/* If [name=] is specified, skip it */
	if (strncmp(opt_ptr, "name=", sizeof("name=") - 1) == 0) {
		opt_ptr += sizeof("name=") - 1;
	}

	/* get the end of <name> */
	opt_end = strchr(opt_ptr, ',');
	if (opt_end == NULL) {
		qemu_fwcfg_usage(opt);
		error = EINVAL;
		goto fail;
	}

	/* check if <name> is too long */
	if (opt_end - opt_ptr >= QEMU_FWCFG_MAX_NAME) {
		warnx("fw_cfg name too long: \"%s\"", opt);
		error = EINVAL;
		goto fail;
	}

	/* save <name> */
	strncpy(fwcfg_file->name, opt_ptr, opt_end - opt_ptr);
	fwcfg_file->name[opt_end - opt_ptr] = '\0';

	/* set opt_ptr and opt_end to <value> */
	opt_ptr = opt_end + 1;
	opt_end = opt_ptr + strlen(opt_ptr);

	if (strncmp(opt_ptr, "string=", sizeof("string=") - 1) == 0) {
		opt_ptr += sizeof("string=") - 1;
		string_size = strlen(opt_ptr);
		if (string_size >= UINT32_MAX) {
			error = EOVERFLOW;
			goto fail;
		}
		fwcfg_file->data = strdup(opt_ptr);
		if (fwcfg_file->data == NULL) {
			warnx("Can't duplicate fw_cfg_user_file string \"%s\"",
			    opt_ptr);
			error = ENOMEM;
			goto fail;
		}
		fwcfg_file->size = (uint32_t)string_size + 1;
	} else if (strncmp(opt_ptr, "file=", sizeof("file=") - 1) == 0) {
		opt_ptr += sizeof("file=") - 1;

		fd = open(opt_ptr,
		    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
		if (fd < 0) {
			warn("Can't open fw_cfg_user_file file \"%s\"",
			    opt_ptr);
			error = errno;
			goto fail;
		}

		if (fstat(fd, &sb) < 0) {
			warn("Unable to get size of file \"%s\"", opt_ptr);
			error = errno;
			close(fd);
			goto fail;
		}
		if (!S_ISREG(sb.st_mode) || sb.st_size < 0 ||
		    (uintmax_t)sb.st_size > UINT32_MAX) {
			warnx("Invalid fw_cfg_user_file file \"%s\"", opt_ptr);
			error = EINVAL;
			close(fd);
			goto fail;
		}
		size = (size_t)sb.st_size;
		fwcfg_file->data = malloc(MAX(size, 1));
		if (fwcfg_file->data == NULL) {
			warnx(
			    "Can't allocate fw_cfg_user_file file \"%s\" (size: 0x%16lx)",
			    opt_ptr, sb.st_size);
			error = ENOMEM;
			close(fd);
			goto fail;
		}
		offset = 0;
		while (offset < size) {
			bytes_read = read(fd, (uint8_t *)fwcfg_file->data + offset,
			    size - offset);
			if (bytes_read < 0 && errno == EINTR)
				continue;
			if (bytes_read <= 0) {
				warn("Unable to read file \"%s\"", opt_ptr);
				error = bytes_read < 0 ? errno : EIO;
				close(fd);
				goto fail;
			}
			offset += (size_t)bytes_read;
		}
		fwcfg_file->size = (uint32_t)size;
		if (close(fd) != 0) {
			error = errno;
			goto fail;
		}
	} else {
		qemu_fwcfg_usage(opt);
		error = EINVAL;
		goto fail;
	}

	STAILQ_INSERT_TAIL(&user_files, fwcfg_file, chain);

	return (0);

fail:
	free(fwcfg_file->data);
	free(fwcfg_file);
	return (error);
}
