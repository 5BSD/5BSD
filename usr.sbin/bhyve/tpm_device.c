/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <corvink@FreeBSD.org>
 */

#include <sys/types.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <vmmapi.h>

#include "acpi.h"
#include "acpi_device.h"
#include "config.h"
#include "tpm_device.h"
#include "tpm_checkpoint_state.h"
#include "tpm_emul.h"
#include "tpm_intf.h"
#include "tpm_local_state.h"
#include "tpm_ppi.h"
#include "tpm_state_transaction.h"
#include "tpm_swtpm_control.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

#define TPM_ACPI_DEVICE_NAME "TPM"
#define TPM_ACPI_HARDWARE_ID "MSFT0101"

SET_DECLARE(tpm_emul_set, struct tpm_emul);
SET_DECLARE(tpm_intf_set, struct tpm_intf);
SET_DECLARE(tpm_ppi_set, struct tpm_ppi);

struct tpm_device {
	struct vmctx *vm_ctx;
	struct acpi_device *acpi_dev;
	struct tpm_emul *emul;
	void *emul_sc;
	struct tpm_intf *intf;
	void *intf_sc;
	struct tpm_ppi *ppi;
	void *ppi_sc;
	pthread_mutex_t state_mtx;
	bool state_mtx_initialized;
	bool state_needs_relock;
	bool state_id_valid;
	bool state_key_id_valid;
	bool migration_enabled;
	uint8_t state_id[TPM_CHECKPOINT_STORAGE_ID_SIZE];
	uint8_t state_key_id[TPM_CHECKPOINT_KEY_ID_SIZE];
	struct tpm_state_transaction state_transaction;
};

static int
tpm_device_intf_pause(void *arg)
{
	struct tpm_device *dev = arg;

	return (dev->intf->pause(dev->intf_sc));
}

static int
tpm_device_intf_resume(void *arg)
{
	struct tpm_device *dev = arg;

	return (dev->intf->resume(dev->intf_sc));
}

static int
tpm_device_emul_stop(void *arg)
{
	struct tpm_device *dev = arg;

	return (dev->emul->state_stop(dev->emul_sc));
}

static int
tpm_device_emul_init(void *arg)
{
	struct tpm_device *dev = arg;

	return (dev->emul->state_init(dev->emul_sc));
}

static const struct tpm_state_transaction_ops tpm_device_state_ops = {
	.pause = tpm_device_intf_pause,
	.resume = tpm_device_intf_resume,
	.stop = tpm_device_emul_stop,
	.init = tpm_device_emul_init,
};

static int
tpm_device_state_end_locked(struct tpm_device *dev)
{
	int error;

	if (dev->state_transaction.phase == TPM_STATE_QUIESCED &&
	    dev->state_needs_relock) {
		error = dev->emul->state_lock(dev->emul_sc);
		if (error != 0) {
			dev->state_transaction.phase = TPM_STATE_UNCERTAIN;
			return (error);
		}
		dev->state_needs_relock = false;
	}
	return (tpm_state_transaction_end(&dev->state_transaction,
	    &tpm_device_state_ops, dev, dev));
}

static int
tpm_build_acpi_table(const struct acpi_device *const dev)
{
	const struct tpm_device *const tpm = acpi_device_get_softc(dev);

	if (tpm->intf->build_acpi_table == NULL) {
		return (0);
	}

	return (tpm->intf->build_acpi_table(tpm->intf_sc, tpm->vm_ctx));
}

static int
tpm_write_dsdt(const struct acpi_device *const dev)
{
	int error;

	const struct tpm_device *const tpm = acpi_device_get_softc(dev);
	const struct tpm_ppi *const ppi = tpm->ppi;

	/*
	 * packages for returns
	 */
	dsdt_line("Name(TPM2, Package(2) {0, 0})");
	dsdt_line("Name(TPM3, Package(3) {0, 0, 0})");

	if (ppi->write_dsdt_regions) {
		error = ppi->write_dsdt_regions(tpm->ppi_sc);
		if (error) {
			warnx("%s: failed to write ppi dsdt regions\n",
			    __func__);
			return (error);
		}
	}

	/*
	 * Device Specific Method
	 * Arg0: UUID
	 * Arg1: Revision ID
	 * Arg2: Function Index
	 * Arg3: Arguments
	 */
	dsdt_line("Method(_DSM, 4, Serialized)");
	dsdt_line("{");
	dsdt_indent(1);
	if (ppi->write_dsdt_dsm) {
		error = ppi->write_dsdt_dsm(tpm->ppi_sc);
		if (error) {
			warnx("%s: failed to write ppi dsdt dsm\n", __func__);
			return (error);
		}
	}
	dsdt_unindent(1);
	dsdt_line("}");

	return (0);
}

static const struct acpi_device_emul tpm_acpi_device_emul = {
	.name = TPM_ACPI_DEVICE_NAME,
	.hid = TPM_ACPI_HARDWARE_ID,
	.build_table = tpm_build_acpi_table,
	.write_dsdt = tpm_write_dsdt,
};

void
tpm_device_destroy(struct tpm_device *const dev)
{
	int error;

	if (dev == NULL)
		return;
	if (dev->state_mtx_initialized) {
		pthread_mutex_lock(&dev->state_mtx);
		if (dev->state_transaction.phase != TPM_STATE_RUNNING) {
			error = tpm_device_state_end_locked(dev);
			if (error != 0)
				warnc(error, "%s: TPM state restart failed",
				    __func__);
		}
		pthread_mutex_unlock(&dev->state_mtx);
		pthread_mutex_destroy(&dev->state_mtx);
	}

	if (dev->ppi != NULL && dev->ppi->deinit != NULL)
		dev->ppi->deinit(dev->ppi_sc);
	if (dev->intf != NULL && dev->intf->deinit != NULL)
		dev->intf->deinit(dev->intf_sc);
	if (dev->emul != NULL && dev->emul->deinit != NULL)
		dev->emul->deinit(dev->emul_sc);

	acpi_device_destroy(dev->acpi_dev);
	free(dev);
}

int
tpm_device_create(struct tpm_device **const new_dev, struct vmctx *const vm_ctx,
    nvlist_t *const nvl)
{
	struct tpm_device *dev = NULL;
	struct tpm_emul **ppemul;
	struct tpm_intf **ppintf;
	struct tpm_ppi **pp_ppi;
	const char *value;
	int error;

	if (new_dev == NULL || vm_ctx == NULL || nvl == NULL) {
		error = EINVAL;
		goto err_out;
	}
	*new_dev = NULL;

	set_config_value_node_if_unset(nvl, "intf", "crb");
	set_config_value_node_if_unset(nvl, "ppi", "qemu");

	value = get_config_value_node(nvl, "version");
	if (value == NULL) {
		warnx("%s: TPM version is required", __func__);
		error = EINVAL;
		goto err_out;
	}
	if (strcmp(value, "2.0")) {
		warnx("%s: unsupported tpm version %s", __func__, value);
		error = EINVAL;
		goto err_out;
	}

	dev = calloc(1, sizeof(*dev));
	if (dev == NULL) {
		error = ENOMEM;
		goto err_out;
	}

	dev->vm_ctx = vm_ctx;
	dev->migration_enabled = get_config_bool_node_default(nvl,
	    "migration", false);
	value = get_config_value_node(nvl, "state_id");
	if (value != NULL) {
		error = tpm_checkpoint_storage_id_parse(value, dev->state_id);
		if (error != 0) {
			warnx("%s: tpm.state_id must be a nonzero 128-bit value "
			    "in 32 lowercase hex digits", __func__);
			goto err_out;
		}
		dev->state_id_valid = true;
	}
	value = get_config_value_node(nvl, "migration_key_id");
	if (value != NULL) {
		error = tpm_checkpoint_storage_id_parse(value,
		    dev->state_key_id);
		if (error != 0) {
			warnx("%s: tpm.migration_key_id must be a nonzero "
			    "128-bit value in 32 lowercase hex digits", __func__);
			goto err_out;
		}
		dev->state_key_id_valid = true;
	}
	error = pthread_mutex_init(&dev->state_mtx, NULL);
	if (error != 0)
		goto err_out;
	dev->state_mtx_initialized = true;

	error = acpi_device_create(&dev->acpi_dev, dev, dev->vm_ctx,
	    &tpm_acpi_device_emul);
	if (error)
		goto err_out;

	value = get_config_value_node(nvl, "type");
	if (value == NULL) {
		warnx("%s: TPM backend type is required", __func__);
		error = EINVAL;
		goto err_out;
	}
	SET_FOREACH(ppemul, tpm_emul_set) {
		if (strcmp(value, (*ppemul)->name))
			continue;
		dev->emul = *ppemul;
		break;
	}
	if (dev->emul == NULL) {
		warnx("TPM emulation \"%s\" not found", value);
		error = EINVAL;
		goto err_out;
	}

	if (dev->emul->init) {
		error = dev->emul->init(&dev->emul_sc, nvl);
		if (error)
			goto err_out;
	}

	value = get_config_value_node(nvl, "intf");
	if (value == NULL) {
		error = EINVAL;
		goto err_out;
	}
	SET_FOREACH(ppintf, tpm_intf_set) {
		if (strcmp(value, (*ppintf)->name)) {
			continue;
		}
		dev->intf = *ppintf;
		break;
	}
	if (dev->intf == NULL) {
		warnx("TPM interface \"%s\" not found", value);
		error = EINVAL;
		goto err_out;
	}

	if (dev->intf->init) {
		error = dev->intf->init(&dev->intf_sc, dev->emul, dev->emul_sc,
		    dev->acpi_dev);
		if (error)
			goto err_out;
	}

	value = get_config_value_node(nvl, "ppi");
	if (value == NULL) {
		error = EINVAL;
		goto err_out;
	}
	SET_FOREACH(pp_ppi, tpm_ppi_set) {
		if (strcmp(value, (*pp_ppi)->name)) {
			continue;
		}
		dev->ppi = *pp_ppi;
		break;
	}
	if (dev->ppi == NULL) {
		warnx("TPM PPI \"%s\" not found\n", value);
		error = EINVAL;
		goto err_out;
	}

	if (dev->ppi->init) {
		error = dev->ppi->init(&dev->ppi_sc);
		if (error)
			goto err_out;
	}

	*new_dev = dev;

	return (0);

err_out:
	tpm_device_destroy(dev);

	return (error);
}

static struct tpm_device *lpc_tpm;

bool
tpm_device_present(void)
{

	return (lpc_tpm != NULL);
}

static bool
tpm_device_state_supported(const struct tpm_device *dev)
{

	return (dev->intf != NULL && dev->intf->pause != NULL &&
	    dev->intf->resume != NULL && dev->intf->state_size != 0 &&
	    dev->intf->state_get != NULL &&
	    dev->intf->state_validate != NULL &&
	    dev->intf->state_set != NULL && dev->ppi != NULL &&
	    dev->ppi->state_size != 0 && dev->ppi->state_get != NULL &&
	    dev->ppi->state_validate != NULL &&
	    dev->ppi->state_set != NULL && dev->emul != NULL &&
	    dev->emul->state_available != NULL &&
	    dev->emul->state_available(dev->emul_sc) &&
	    dev->emul->state_stop != NULL && dev->emul->state_init != NULL &&
	    dev->emul->state_lock != NULL &&
	    dev->emul->state_get_blob != NULL &&
	    dev->emul->state_set_blob != NULL);
}

static int
tpm_device_state_begin(bool write)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	pthread_mutex_lock(&dev->state_mtx);
	/* A SAVESTATE read must relock storage before any STOP/SET sequence. */
	if (write && dev->state_needs_relock)
		error = EBUSY;
	else
		error = write ? tpm_state_transaction_begin_write(
		    &dev->state_transaction, &tpm_device_state_ops, dev, dev) :
		    tpm_state_transaction_begin_read(&dev->state_transaction,
		    &tpm_device_state_ops, dev, dev);
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

int
tpm_device_state_begin_read(void)
{

	return (tpm_device_state_begin(false));
}

int
tpm_device_state_begin_write(void)
{

	return (tpm_device_state_begin(true));
}

int
tpm_device_state_end(void)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	pthread_mutex_lock(&dev->state_mtx);
	error = tpm_device_state_end_locked(dev);
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

int
tpm_device_state_end_if_active(void)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (dev == NULL)
		return (0);
	pthread_mutex_lock(&dev->state_mtx);
	if (dev->state_transaction.phase == TPM_STATE_RUNNING)
		error = 0;
	else if (!tpm_device_state_supported(dev))
		error = EOPNOTSUPP;
	else
		error = tpm_device_state_end_locked(dev);
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

int
tpm_device_state_get_blob(uint32_t type, uint8_t **blob,
    size_t *length, uint32_t *flags)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (blob == NULL || length == NULL || flags == NULL)
		return (EINVAL);
	*blob = NULL;
	*length = 0;
	*flags = 0;
	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	pthread_mutex_lock(&dev->state_mtx);
	error = dev->state_transaction.phase == TPM_STATE_QUIESCED &&
	    !dev->state_needs_relock ?
	    dev->emul->state_get_blob(dev->emul_sc, type, blob, length, flags) :
	    EBUSY;
	if (error == 0 && type == SWTPM_CONTROL_BLOB_SAVESTATE)
		dev->state_needs_relock = true;
	else if (error != 0 && error != EBUSY &&
	    dev->state_transaction.phase == TPM_STATE_QUIESCED)
		dev->state_transaction.phase = TPM_STATE_UNCERTAIN;
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

int
tpm_device_state_set_blob(uint32_t type, const uint8_t *blob,
    size_t length, uint32_t flags)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	pthread_mutex_lock(&dev->state_mtx);
	error = dev->state_transaction.phase == TPM_STATE_STOPPED ?
	    dev->emul->state_set_blob(dev->emul_sc, type, blob, length, flags) :
	    EBUSY;
	if (error != 0 && dev->state_transaction.phase == TPM_STATE_STOPPED)
		dev->state_transaction.phase = TPM_STATE_UNCERTAIN;
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

int
tpm_device_state_local_sizes(size_t *intf_size, size_t *ppi_size)
{
	struct tpm_device *dev = lpc_tpm;

	if (intf_size == NULL || ppi_size == NULL)
		return (EINVAL);
	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	*intf_size = dev->intf->state_size;
	*ppi_size = dev->ppi->state_size;
	return (0);
}

int
tpm_device_state_get_local(uint8_t *intf, size_t intf_size,
    uint8_t *ppi, size_t ppi_size)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (intf == NULL || ppi == NULL)
		return (EINVAL);
	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	if (intf_size != dev->intf->state_size ||
	    ppi_size != dev->ppi->state_size)
		return (EINVAL);
	pthread_mutex_lock(&dev->state_mtx);
	if (dev->state_transaction.phase != TPM_STATE_QUIESCED &&
	    dev->state_transaction.phase != TPM_STATE_STOPPED)
		error = EBUSY;
	else {
		error = dev->intf->state_get(dev->intf_sc, intf, intf_size);
		if (error == 0)
			error = dev->ppi->state_get(dev->ppi_sc, ppi, ppi_size);
	}
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

int
tpm_device_state_validate_local(const uint8_t *intf, size_t intf_size,
    const uint8_t *ppi, size_t ppi_size)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	if (intf == NULL || ppi == NULL)
		return (EINVAL);
	if (dev == NULL)
		return (ENOENT);
	if (!tpm_device_state_supported(dev))
		return (EOPNOTSUPP);
	if (intf_size != dev->intf->state_size ||
	    ppi_size != dev->ppi->state_size)
		return (EINVAL);
	error = dev->intf->state_validate(intf, intf_size);
	if (error == 0)
		error = dev->ppi->state_validate(ppi, ppi_size);
	return (error);
}

int
tpm_device_state_set_local(const uint8_t *intf, size_t intf_size,
    const uint8_t *ppi, size_t ppi_size)
{
	struct tpm_device *dev = lpc_tpm;
	int error;

	error = tpm_device_state_validate_local(intf, intf_size, ppi,
	    ppi_size);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&dev->state_mtx);
	if (dev->state_transaction.phase != TPM_STATE_STOPPED)
		error = EBUSY;
	else {
		error = dev->intf->state_set(dev->intf_sc, intf,
		    intf_size);
		if (error == 0)
			error = dev->ppi->state_set(dev->ppi_sc, ppi,
			    ppi_size);
		if (error != 0)
			dev->state_transaction.phase = TPM_STATE_UNCERTAIN;
	}
	pthread_mutex_unlock(&dev->state_mtx);
	return (error);
}

#ifdef BHYVE_SNAPSHOT
int
tpm_device_migration_check(void)
{

	if (lpc_tpm == NULL)
		return (0);
	if (!lpc_tpm->migration_enabled || !lpc_tpm->state_id_valid ||
	    !lpc_tpm->state_key_id_valid ||
	    !tpm_device_state_supported(lpc_tpm) ||
	    lpc_tpm->intf->state_size != TPM_CRB_LOCAL_STATE_SIZE ||
	    lpc_tpm->ppi->state_size != TPM_PPI_LOCAL_STATE_SIZE)
		return (ENOTSUP);
	return (0);
}

int
tpm_device_migration_identity(uint8_t identity[TPM_MIGRATION_IDENTITY_SIZE])
{
	const char *names[3];
	int error;

	if (identity == NULL || lpc_tpm == NULL)
		return (EINVAL);
	error = tpm_device_migration_check();
	if (error != 0)
		return (error);
	names[0] = lpc_tpm->emul->name;
	names[1] = lpc_tpm->intf->name;
	names[2] = lpc_tpm->ppi->name;
	for (size_t i = 0; i < 3; i++) {
		if (strlen(names[i]) >= 16)
			return (E2BIG);
	}
	memset(identity, 0, TPM_MIGRATION_IDENTITY_SIZE);
	memcpy(identity, lpc_tpm->state_key_id, 16);
	for (size_t i = 0; i < 3; i++)
		memcpy(identity + 16 + i * 16, names[i], strlen(names[i]));
	return (0);
}

static int
tpm_device_snapshot_save(struct vm_snapshot_meta *meta)
{
	struct tpm_checkpoint_view view = { 0 };
	uint8_t intf[TPM_CRB_LOCAL_STATE_SIZE];
	uint8_t ppi[TPM_PPI_LOCAL_STATE_SIZE];
	uint8_t *blobs[TPM_CHECKPOINT_BLOB_COUNT] = { 0 };
	size_t intf_size, ppi_size, record_size;
	int error;

	error = tpm_device_state_local_sizes(&intf_size, &ppi_size);
	if (error != 0)
		return (error);
	if (!lpc_tpm->state_id_valid || !lpc_tpm->state_key_id_valid)
		return (EOPNOTSUPP);
	if (intf_size != sizeof(intf) || ppi_size != sizeof(ppi))
		return (EOPNOTSUPP);
	/* vm_pause_devices() already drained the CRB worker before memory save. */
	error = tpm_device_state_get_local(intf, sizeof(intf), ppi,
	    sizeof(ppi));
	if (error != 0)
		goto out;
	view.intf = intf;
	memcpy(view.storage_id, lpc_tpm->state_id,
	    sizeof(view.storage_id));
	memcpy(view.key_id, lpc_tpm->state_key_id,
	    sizeof(view.key_id));
	view.intf_length = sizeof(intf);
	view.ppi = ppi;
	view.ppi_length = sizeof(ppi);
	for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
		error = tpm_device_state_get_blob(i + 1, &blobs[i],
		    &view.blobs[i].length, &view.blobs[i].flags);
		if (error != 0)
			goto out;
		view.blobs[i].data = blobs[i];
	}
	error = tpm_checkpoint_state_size(&view, &record_size);
	if (error != 0)
		goto out;
	if (record_size > meta->buffer.buf_rem) {
		error = E2BIG;
		goto out;
	}
	error = tpm_checkpoint_state_encode(&view, meta->buffer.buf,
	    meta->buffer.buf_rem);
	if (error == 0) {
		meta->buffer.buf += record_size;
		meta->buffer.buf_rem -= record_size;
	}
out:
	for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
		if (blobs[i] != NULL) {
			explicit_bzero(blobs[i], view.blobs[i].length);
			free(blobs[i]);
		}
	}
	explicit_bzero(intf, sizeof(intf));
	explicit_bzero(ppi, sizeof(ppi));
	return (error);
}

int
tpm_device_snapshot(struct vm_snapshot_meta *meta)
{
	struct tpm_checkpoint_view view;
	size_t size;
	int error;

	if (meta == NULL || !tpm_device_present())
		return (EINVAL);
	error = tpm_device_migration_check();
	if (error != 0)
		return (error);
	if (meta->op == VM_SNAPSHOT_SAVE)
		return (tpm_device_snapshot_save(meta));
	if (!vm_snapshot_is_loading(meta))
		return (EINVAL);
	size = meta->buffer.buf_rem;
	error = tpm_checkpoint_state_decode(meta->buffer.buf, size,
	    &view);
	if (error != 0)
		return (error);
	if (!lpc_tpm->state_id_valid || !lpc_tpm->state_key_id_valid ||
	    memcmp(view.key_id, lpc_tpm->state_key_id,
	    sizeof(view.key_id)) != 0 ||
	    memcmp(view.storage_id, lpc_tpm->state_id,
	    sizeof(view.storage_id)) == 0)
		return (EOPNOTSUPP);
	error = tpm_device_state_validate_local(view.intf,
	    view.intf_length, view.ppi, view.ppi_length);
	if (error != 0)
		return (error);
	if (vm_snapshot_is_restoring(meta)) {
		error = tpm_device_state_begin_write();
		if (error != 0)
			return (error);
		for (size_t i = 0; i < TPM_CHECKPOINT_BLOB_COUNT; i++) {
			error = tpm_device_state_set_blob(i + 1,
			    view.blobs[i].data, view.blobs[i].length,
			    view.blobs[i].flags);
			if (error != 0)
				return (error);
		}
		error = tpm_device_state_set_local(view.intf,
		    view.intf_length, view.ppi, view.ppi_length);
		if (error != 0)
			return (error);
	}
	meta->buffer.buf += size;
	meta->buffer.buf_rem = 0;
	return (0);
}
#endif

int
init_tpm(struct vmctx *ctx)
{
	nvlist_t *nvl;
	int error;

	nvl = find_config_node("tpm");
	if (nvl == NULL)
		return (0);

	error = tpm_device_create(&lpc_tpm, ctx, nvl);
	if (error) {
		warnx("%s: unable to create a TPM device (%d)",
		    __func__, error);
		return (error);
	}

	return (0);
}
