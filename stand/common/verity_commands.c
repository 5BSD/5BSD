/* SPDX-License-Identifier: BSD-2-Clause */
#include <stand.h>
#include <stdint.h>
#include <bootstrap.h>
#include "veritydev.h"
#include "verified_root.h"
#include <crypto/sha2/sha256.h>

/* One selected root per loader session; no trust decision is stored in kenv. */
static int verity_selected = -1;
/* One-way boot-policy requirement, never sourced from mutable environment. */
static int verity_required;
static char *verity_previous, *verity_descriptor_name;
static unsigned char verity_descriptor[G_VERITY_ROOT_BYTES];
static char verity_selected_name[32];
static char *verity_transition_name;
static unsigned char verity_transition[G_VERITY_TRANSITION_BYTES];

/* Admission on the opened object, before executable bytes are consumed. */
int
verity_check_source(int fd)
{
	struct open_file *file;
	struct devdesc *dev;

	if (verity_selected < 0)
		return (verity_required ? EAUTH : 0);
	if (fd < 0)
		return (EAUTH);
	file = fd2open_file(fd);
	if (file == NULL || (file->f_flags & F_READ) == 0 || file->f_ops == NULL)
		return (EAUTH);
	/* A transform's outer devdesc need not describe its payload source. */
	if (file->f_ops->fo_source != NULL) {
		fd = file->f_ops->fo_source(file);
		if (fd < 0)
			return (EAUTH);
		file = fd2open_file(fd);
	}
	/* The selected descriptor currently specifies a UFS filesystem image.
	 * Existing decompressors have one direct backing file, not transform chains.
	 */
	if (file == NULL || file->f_ops != &ufs_fsops ||
	    (file->f_flags & F_READ) == 0 ||
	    file->f_dev != &verity_dev || file->f_devdata == NULL)
		return (EAUTH);
	dev = file->f_devdata;
	if (dev->d_dev != &verity_dev || dev->d_unit != verity_selected)
		return (EAUTH);
	return (0);
}

/* Positive provenance proof; ordinary admission success alone is insufficient. */
int
verity_source_verified(int fd)
{
	return (verity_selected >= 0 && verity_check_source(fd) == 0);
}

/* Compare unique final preload bytes with the private authenticated selection. */
static int
verity_handoff_record(const char *type, const unsigned char *expected, size_t size)
{
	unsigned char wire[G_VERITY_TRANSITION_BYTES];
	struct preloaded_file *file, *selected = NULL;

	if (size > sizeof(wire))
		return (EINVAL);
	for (file = preloaded_files; file != NULL; file = file->f_next) {
		if (file->f_type == NULL || strcmp(file->f_type, type) != 0)
			continue;
		if (selected != NULL)
			return (EAUTH);
		selected = file;
	}
	if (selected == NULL || selected->f_size != size ||
	    selected->f_addr > (vm_offset_t)-1 - size)
		return (EAUTH);
	if (archsw.arch_copyout(selected->f_addr, wire, size) != (ssize_t)size)
		return (EIO);
	return (memcmp(wire, expected, size) == 0 ? 0 : EAUTH);
}

int
verity_check_handoff(void)
{
	int error;

	if (verity_selected < 0)
		return (verity_required ? EAUTH : 0);
	error = verity_handoff_record(G_VERITY_ROOT_TYPE, verity_descriptor,
	    sizeof(verity_descriptor));
	if (error != 0)
		return (error);
	if (verity_transition_name == NULL)
		return (file_findfile(NULL, G_VERITY_TRANSITION_TYPE) != NULL ? EAUTH : 0);
	return (verity_handoff_record(G_VERITY_TRANSITION_TYPE, verity_transition,
	    sizeof(verity_transition)));
}

/* Policy must commit before any executable or raw preload is admitted. */
static int
verity_require(void)
{
	if (verity_required)
		return (0);
	if (file_findfile(NULL, NULL) != NULL)
		return (EBUSY);
	verity_required = 1;
	return (0);
}

static int
verity_number(const char *text, size_t *value)
{
	size_t result = 0;
	unsigned digit;

	if (*text == '\0')
		return (EINVAL);
	for (; *text != '\0'; text++) {
		if (*text < '0' || *text > '9')
			return (EINVAL);
		digit = *text - '0';
		if (result > (SIZE_MAX - digit) / 10)
			return (EOVERFLOW);
		result = result * 10 + digit;
	}
	*value = result;
	return (0);
}

static int
verity_digest(const char *text, unsigned char digest[32])
{
	unsigned value, digit;
	size_t i, j;

	if (strnlen(text, 65) != 64)
		return (EINVAL);
	for (i = 0; i < 32; i++) {
		value = 0;
		for (j = 0; j < 2; j++) {
			unsigned char c = text[2 * i + j];
			if (c >= '0' && c <= '9')
				digit = c - '0';
			else if (c >= 'a' && c <= 'f')
				digit = c - 'a' + 10;
			else
				return (EINVAL);
			value = value * 16 + digit;
		}
		digest[i] = value;
	}
	return (0);
}

static int
verity_select(const char *image, const char *descriptor,
    const unsigned char *expected_digest, size_t entries,
    size_t budget)
{
	unsigned char wire[G_VERITY_ROOT_BYTES];
	char device[sizeof(verity_selected_name)];
	char *previous, *name;
	const char *current;
	int fd, rootfd, unit, error;

	if (expected_digest == NULL)
		return (EINVAL);
	if (verity_selected >= 0 || file_findfile(NULL, NULL) != NULL)
		return (EBUSY);
	current = getenv("currdev");
	if (current == NULL || current[0] == '\0')
		return (ENXIO);
	previous = strdup(current);
	name = strdup(descriptor);
	if (previous == NULL || name == NULL) {
		free(previous);
		free(name);
		return (ENOMEM);
	}
	fd = open(image, O_RDONLY);
	if (fd < 0) {
		error = errno;
		goto fail;
	}
	rootfd = open(descriptor, O_RDONLY);
	if (rootfd < 0) {
		error = errno;
		close(fd);
		goto fail;
	}
	error = verity_dev_attach_verified(fd, rootfd, descriptor, expected_digest, entries,
	    budget, &unit, wire);
	if (error != 0) {
		close(rootfd);
		close(fd);
		goto fail;
	}
	if (close(rootfd) != 0) {
		error = errno;
		verity_dev_detach(unit);
		goto fail;
	}
	snprintf(device, sizeof(device), "verity%d:", unit);
	/* Use the normal currdev hook to manage filesystem mount references. */
	error = setenv("currdev", device, 1);
	if (error != 0) {
		verity_dev_detach(unit);
		goto fail;
	}
	verity_selected = unit;
	verity_previous = previous;
	verity_descriptor_name = name;
	memcpy(verity_descriptor, wire, sizeof(wire));
	strcpy(verity_selected_name, device);
	return (0);
fail:
	free(previous);
	free(name);
	return (error);
}

/* Authenticate before currdev changes; publish only with successful selection. */
static int
verity_select_transition(const char *image, const char *descriptor,
    const unsigned char *digest, size_t entries, size_t budget,
    const char *path, const unsigned char *plan_digest)
{
	unsigned char wire[G_VERITY_TRANSITION_BYTES], actual[SHA256_DIGEST_LENGTH];
	struct g_verity_transition plan;
	SHA256_CTX context;
	char *name;
	int fd, error;

	if (verity_selected >= 0 || file_findfile(NULL, NULL) != NULL)
		return (EBUSY);
	name = strdup(path);
	if (name == NULL)
		return (ENOMEM);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		error = errno;
		goto fail;
	}
	error = verified_transition_read(fd, path, wire) < 0 ? errno : 0;
	if (close(fd) != 0 && error == 0)
		error = errno;
	if (error != 0)
		goto fail;
	SHA256_Init(&context);
	SHA256_Update(&context, wire, sizeof(wire));
	SHA256_Final(actual, &context);
	if (memcmp(actual, plan_digest, sizeof(actual)) != 0) {
		error = EAUTH;
		goto fail;
	}
	error = g_verity_transition_decode(wire, sizeof(wire), &plan);
	if (error != 0)
		goto fail;
	if (strcmp(plan.image, image) != 0 ||
	    memcmp(plan.descriptor_sha256, digest, sizeof(plan.descriptor_sha256)) != 0) {
		error = EAUTH;
		goto fail;
	}
	error = verity_select(image, descriptor, digest, entries, budget);
	if (error != 0)
		goto fail;
	verity_transition_name = name;
	memcpy(verity_transition, wire, sizeof(wire));
	return (0);
fail:
	free(name);
	return (error);
}

static int
verity_preload(void)
{
	const char *current;

	if (verity_selected < 0)
		return (ENOENT);
	current = getenv("currdev");
	if (current == NULL || strcmp(current, verity_selected_name) != 0)
		return (EINVAL);
	if (file_findfile(NULL, NULL) == NULL)
		return (ENOENT);
	if (file_findfile(NULL, G_VERITY_ROOT_TYPE) != NULL ||
	    file_findfile(NULL, G_VERITY_TRANSITION_TYPE) != NULL)
		return (EEXIST);
	if (file_addbuf(verity_descriptor_name, G_VERITY_ROOT_TYPE,
	    sizeof(verity_descriptor), verity_descriptor) != 0)
		return (EIO);
	if (verity_transition_name != NULL &&
	    file_addbuf(verity_transition_name, G_VERITY_TRANSITION_TYPE,
	    sizeof(verity_transition), verity_transition) != 0)
		return (EIO);
	return (0);
}

static int
verity_clear(void)
{
	int error;

	if (verity_required)
		return (EPERM);
	if (verity_selected < 0)
		return (ENOENT);
	if (file_findfile(NULL, NULL) != NULL)
		return (EBUSY);
	error = setenv("currdev", verity_previous, 1);
	if (error != 0)
		return (error);
	error = verity_dev_detach(verity_selected);
	if (error == EBUSY)
		return (error); /* Other open files still pin the device; retry later. */
	verity_selected = -1;
	free(verity_transition_name);
	verity_transition_name = NULL;
	memset(verity_transition, 0, sizeof(verity_transition));
	free(verity_previous);
	free(verity_descriptor_name);
	verity_previous = verity_descriptor_name = NULL;
	memset(verity_descriptor, 0, sizeof(verity_descriptor));
	verity_selected_name[0] = '\0';
	return (error);
}

static int
command_verity_require(int argc, char *argv[] __unused)
{
	int error = argc == 1 ? verity_require() : EINVAL;

	if (error != 0) {
		snprintf(command_errbuf, sizeof(command_errbuf),
		    "verified image requirement failed: %s", strerror(error));
		return (CMD_ERROR);
	}
	return (CMD_OK);
}

static int
command_verity_select(int argc, char *argv[])
{
	unsigned char digest[32], plan_digest[32];
	size_t entries, budget;
	int error;

	if (argc != 6 && argc != 8) {
		command_errmsg = "usage: verity-select image descriptor descriptor-sha256 cache-blocks heap-bytes [transition transition-sha256]";
		return (CMD_ERROR);
	}
	error = verity_digest(argv[3], digest);
	if (error == 0)
		error = verity_number(argv[4], &entries);
	if (error == 0)
		error = verity_number(argv[5], &budget);
	if (error == 0 && argc == 8)
		error = verity_digest(argv[7], plan_digest);
	if (error == 0) {
		if (argc == 8)
			error = verity_select_transition(argv[1], argv[2], digest,
			    entries, budget, argv[6], plan_digest);
		else
			error = verity_select(argv[1], argv[2], digest, entries, budget);
	}
	if (error != 0) {
		snprintf(command_errbuf, sizeof(command_errbuf),
		    "verified image selection failed: %s", strerror(error));
		return (CMD_ERROR);
	}
	return (CMD_OK);
}

static int
command_verity_preload(int argc, char *argv[] __unused)
{
	int error = argc == 1 ? verity_preload() : EINVAL;

	if (error != 0) {
		snprintf(command_errbuf, sizeof(command_errbuf),
		    "verified root preload failed: %s", strerror(error));
		return (CMD_ERROR);
	}
	return (CMD_OK);
}

static int
command_verity_clear(int argc, char *argv[] __unused)
{
	int error = argc == 1 ? verity_clear() : EINVAL;

	if (error != 0) {
		snprintf(command_errbuf, sizeof(command_errbuf),
		    "verified image release failed: %s", strerror(error));
		return (CMD_ERROR);
	}
	return (CMD_OK);
}

COMMAND_SET(verity_select, "verity-select", "select authenticated filesystem image",
    command_verity_select);
COMMAND_SET(verity_preload, "verity-preload", "preload selected root descriptor",
    command_verity_preload);
COMMAND_SET(verity_clear, "verity-clear", "release selected filesystem image",
    command_verity_clear);

COMMAND_SET(verity_require, "verity-require", "require a verified image for this boot",
    command_verity_require);
