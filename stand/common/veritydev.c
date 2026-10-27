/* SPDX-License-Identifier: BSD-2-Clause */
#include <stand.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>
#include <sys/disk.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <disk.h>
#include <verity_read.h>
#include "veritydev.h"

struct verity_device {
	LIST_ENTRY(verity_device) link;
	struct verity_file reader;
	void *buffers;
	int unit;
	unsigned opens;
};
static LIST_HEAD(, verity_device) verity_devices = LIST_HEAD_INITIALIZER(verity_devices);
static uint64_t verity_next_unit;

static struct verity_device *
verity_lookup(int unit)
{
	struct verity_device *device;

	LIST_FOREACH(device, &verity_devices, link)
		if (device->unit == unit)
			return (device);
	return (NULL);
}

int
verity_dev_attach(int fd, const struct g_verity_root *root, size_t entries,
    size_t budget, int *unit)
{
	struct verity_device *device;
	struct g_verity_cache check;
	uint64_t *tags;
	void *blocks, *data, *hashes;
	size_t block, bytes;
	int error;

	if (root == NULL || unit == NULL || fd < 0)
		return (EINVAL);
	if (verity_next_unit > INT_MAX)
		return (ENOSPC);
	error = g_verity_cache_init(&check, root, NULL, NULL, 0);
	if (error != 0)
		return (error);
	block = root->layout.block_size;
	if (entries > (SIZE_MAX - 2 * block) / (block + sizeof(*tags)))
		return (EOVERFLOW);
	bytes = entries * (block + sizeof(*tags)) + 2 * block;
	if (budget < sizeof(*device) || bytes > budget - sizeof(*device))
		return (ENOMEM);
	device = calloc(1, sizeof(*device));
	if (device == NULL)
		return (ENOMEM);
	device->buffers = malloc(bytes);
	if (device->buffers == NULL) {
		free(device);
		return (ENOMEM);
	}
	tags = device->buffers;
	blocks = (char *)tags + entries * sizeof(*tags);
	data = (char *)blocks + entries * block;
	hashes = (char *)data + block;
	error = verity_file_init(&device->reader, fd, root, tags, blocks,
	    entries, data, hashes);
	if (error != 0) {
		free(device->buffers);
		free(device);
		return (error);
	}
	device->unit = verity_next_unit++;
	LIST_INSERT_HEAD(&verity_devices, device, link);
	*unit = device->unit;
	return (0);
}

int
verity_dev_detach(int unit)
{
	struct verity_device *device = verity_lookup(unit);
	int error;

	if (device == NULL)
		return (ENOENT);
	if (device->opens != 0 || device->reader.busy != 0)
		return (EBUSY);
	LIST_REMOVE(device, link);
	/* libsa close releases the descriptor even when a close hook fails. */
	error = close(device->reader.fd) == 0 ? 0 : errno;
	free(device->buffers);
	free(device);
	return (error);
}

static int
verity_strategy(void *arg, int rw, daddr_t blk, size_t size, char *buffer,
    size_t *read_size)
{
	struct disk_devdesc *dev = arg;
	struct verity_device *device;
	uint64_t sector, offset, bytes;
	int error;

	if (read_size != NULL)
		*read_size = 0;
	if (dev == NULL || dev->dd.d_dev != &verity_dev || buffer == NULL ||
	    blk < 0 || size % DEV_BSIZE != 0)
		return (EINVAL);
	if ((rw & F_MASK) != F_READ)
		return ((rw & F_MASK) == F_WRITE ? EROFS : EOPNOTSUPP);
	device = verity_lookup(dev->dd.d_unit);
	if (device == NULL)
		return (ENXIO);
	bytes = device->reader.cache.root.layout.data_bytes;
	/* d_offset and strategy blocks are both in DEV_BSIZE sectors. */
	if ((uint64_t)blk > bytes / DEV_BSIZE ||
	    dev->d_offset > bytes / DEV_BSIZE - (uint64_t)blk)
		return (EINVAL);
	sector = (uint64_t)blk + dev->d_offset;
	offset = sector * DEV_BSIZE;
	if (size > bytes - offset)
		return (EINVAL);
	error = verity_file_read(&device->reader, offset, size, buffer);
	if (error == 0 && read_size != NULL)
		*read_size = size;
	return (error);
}

static int
verity_open(struct open_file *file, ...)
{
	struct disk_devdesc *dev;
	struct verity_device *device;
	va_list args;
	int error;

	va_start(args, file);
	dev = va_arg(args, struct disk_devdesc *);
	va_end(args);
	if (dev == NULL || dev->dd.d_dev != &verity_dev)
		return (EINVAL);
	device = verity_lookup(dev->dd.d_unit);
	if (device == NULL)
		return (ENXIO);
	if (device->opens == UINT_MAX)
		return (EOVERFLOW);
	/* Pin before disk_open parses partition metadata via our strategy. */
	device->opens++;
	error = disk_open(dev, device->reader.cache.root.layout.data_bytes,
	    DEV_BSIZE);
	if (error != 0)
		device->opens--;
	return (error);
}

static int
verity_close(struct open_file *file)
{
	struct disk_devdesc *dev = file->f_devdata;
	struct verity_device *device;
	int error;

	if (dev == NULL || dev->dd.d_dev != &verity_dev)
		return (EINVAL);
	device = verity_lookup(dev->dd.d_unit);
	if (device == NULL || device->opens == 0)
		return (EINVAL);
	error = disk_close(dev);
	device->opens--;
	return (error);
}

static int
verity_ioctl(struct open_file *file, u_long command, void *data)
{
	struct disk_devdesc *dev = file->f_devdata;

	if (dev == NULL || dev->dd.d_dev != &verity_dev || data == NULL ||
	    verity_lookup(dev->dd.d_unit) == NULL)
		return (EINVAL);
	/* No backing-file ioctl may bypass the verified read strategy. */
	if (command != DIOCGSECTORSIZE && command != DIOCGMEDIASIZE)
		return (ENOTTY);
	return (disk_ioctl(dev, command, data));
}

static int
verity_parsedev(struct devdesc **dev, const char *spec, const char **path)
{
	struct disk_devdesc *disk;
	const char *suffix;
	int error;

	error = disk_parsedev_named(dev, spec, path, "verity");
	if (error != 0)
		return (error);
	/*
	 * The verified base is a filesystem image, not a partitioned disk.
	 * An unqualified unit names that whole extent even with a file path.
	 * Preserve explicit partition syntax, including wildcard slice zero.
	 */
	suffix = spec + strlen("verity");
	if (*suffix == '+' || *suffix == '-')
		suffix++;
	while (*suffix >= '0' && *suffix <= '9')
		suffix++;
	if (*suffix == ':' || *suffix == '\0') {
		disk = (struct disk_devdesc *)*dev;
		disk->d_slice = D_SLICENONE;
		disk->d_partition = D_PARTNONE;
	}
	return (0);
}

struct devsw verity_dev = {
	.dv_name = "verity",
	.dv_type = DEVT_DISK,
	.dv_strategy = verity_strategy,
	.dv_open = verity_open,
	.dv_close = verity_close,
	.dv_ioctl = verity_ioctl,
	.dv_fmtdev = disk_fmtdev,
	.dv_parsedev = verity_parsedev,
};
