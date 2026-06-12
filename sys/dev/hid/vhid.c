/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * vhid - Virtual HID transport driver
 *
 * Provides /dev/vhidN character devices that accept HID report descriptors
 * and raw HID reports from userspace.  Each instance creates a hidbus child
 * so the kernel's hkbd/hms/hmt drivers process the reports natively.
 *
 * Designed for the BLE HOGP daemon (btled) running in a Capsicum sandbox.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <dev/evdev/input.h>
#include <dev/hid/hid.h>
#include <dev/hid/hidbus.h>
#include <dev/hid/vhid.h>

#include "hid_if.h"

MALLOC_DEFINE(M_VHID, "vhid", "Virtual HID device");

/*
 * Per-instance state for a virtual HID device.
 */
struct vhid_inst {
	struct mtx		mtx;
	struct cdev		*cdev;
	device_t		hidbus_dev;	/* hidbus child */

	struct hid_device_info	hdi;
	uint8_t			*rdesc;		/* report descriptor */
	hid_size_t		rdesc_len;

	hid_intr_t		*intr;		/* hidbus callback */
	void			*intr_ctx;
	bool			intr_on;
	bool			configured;	/* rdesc set, hidbus attached */
	bool			attaching;	/* VHID_ATTACH in progress */
	bool			open;		/* cdev is open */
	int			unit;
};

/*
 * Root device state (nexus child, acts as bus for hidbus children).
 * Singleton — only one vhid nexus device exists per system.
 */
struct vhid_softc {
	device_t		dev;
	struct vhid_inst	*insts[VHID_MAX_DEVICES];
	int			next_unit;
};

static struct vhid_softc *vhid_sc;
static struct cdev *vhid_ctl_dev;	/* /dev/vhid control device */

static d_open_t		vhid_inst_open;
static d_close_t	vhid_inst_close;
static d_write_t	vhid_inst_write;
static d_ioctl_t	vhid_inst_ioctl;

static struct cdevsw vhid_inst_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	vhid_inst_open,
	.d_close =	vhid_inst_close,
	.d_write =	vhid_inst_write,
	.d_ioctl =	vhid_inst_ioctl,
	.d_name =	"vhid",
};

static d_open_t		vhid_ctl_open;
static d_close_t	vhid_ctl_close;
static d_ioctl_t	vhid_ctl_ioctl;

static struct cdevsw vhid_ctl_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	vhid_ctl_open,
	.d_close =	vhid_ctl_close,
	.d_ioctl =	vhid_ctl_ioctl,
	.d_name =	"vhid",
};

/* ----------------------------------------------------------------
 * Instance cdev methods (/dev/vhidN)
 * ---------------------------------------------------------------- */

static int
vhid_inst_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct vhid_inst *vi = dev->si_drv1;

	mtx_lock(&vi->mtx);
	if (vi->open) {
		mtx_unlock(&vi->mtx);
		return (EBUSY);
	}
	vi->open = true;
	mtx_unlock(&vi->mtx);

	return (0);
}

static int
vhid_inst_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct vhid_inst *vi = dev->si_drv1;

	mtx_lock(&vi->mtx);
	vi->open = false;
	vi->intr_on = false;
	mtx_unlock(&vi->mtx);

	return (0);
}

/*
 * Write to a vhid instance:
 *   - Before VHID_ATTACH: accumulates the HID report descriptor.
 *   - After VHID_ATTACH: delivers HID reports to hidbus.
 */
static int
vhid_inst_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct vhid_inst *vi = dev->si_drv1;
	uint8_t buf[VHID_MAX_REPORT];
	int error;
	size_t len;

	mtx_lock(&vi->mtx);

	if (!vi->configured) {
		/* Reject writes while attach is in progress */
		if (vi->attaching) {
			mtx_unlock(&vi->mtx);
			return (EBUSY);
		}
		/* Pre-attach: accumulate report descriptor */
		if (vi->rdesc_len + uio->uio_resid > VHID_MAX_RDESC) {
			mtx_unlock(&vi->mtx);
			return (EFBIG);
		}
		mtx_unlock(&vi->mtx);

		len = uio->uio_resid;
		if (vi->rdesc == NULL)
			vi->rdesc = malloc(VHID_MAX_RDESC, M_VHID, M_WAITOK);

		error = uiomove(vi->rdesc + vi->rdesc_len, len, uio);
		if (error != 0)
			return (error);

		vi->rdesc_len += len;
		return (0);
	}

	mtx_unlock(&vi->mtx);

	/* Post-attach: deliver HID report */
	if (uio->uio_resid <= 0 || uio->uio_resid > VHID_MAX_REPORT)
		return (EINVAL);

	len = uio->uio_resid;
	error = uiomove(buf, len, uio);
	if (error != 0)
		return (error);

	mtx_lock(&vi->mtx);
	if (vi->intr != NULL && vi->intr_on)
		vi->intr(vi->intr_ctx, buf, len);
	mtx_unlock(&vi->mtx);

	return (0);
}

static int
vhid_inst_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct vhid_inst *vi = dev->si_drv1;
	struct vhid_attach_arg *arg;
	int error;

	switch (cmd) {
	case VHID_ATTACH:
		arg = (struct vhid_attach_arg *)data;

		mtx_lock(&vi->mtx);
		if (vi->configured) {
			mtx_unlock(&vi->mtx);
			return (EEXIST);
		}
		if (vi->rdesc == NULL || vi->rdesc_len == 0) {
			mtx_unlock(&vi->mtx);
			return (EINVAL);
		}

		/* Populate device info and block concurrent writes */
		vi->attaching = true;
		strlcpy(vi->hdi.name, arg->name, sizeof(vi->hdi.name));
		vi->hdi.idBus = BUS_BLUETOOTH;
		vi->hdi.idVendor = arg->idVendor;
		vi->hdi.idProduct = arg->idProduct;
		vi->hdi.idVersion = arg->idVersion;
		vi->hdi.rdescsize = vi->rdesc_len;
		mtx_unlock(&vi->mtx);

		/* Create hidbus child -- must be done without mutex */
		vi->hidbus_dev = device_add_child(vhid_sc->dev,
		    "hidbus", DEVICE_UNIT_ANY);
		if (vi->hidbus_dev == NULL) {
			mtx_lock(&vi->mtx);
			vi->attaching = false;
			free(vi->rdesc, M_VHID);
			vi->rdesc = NULL;
			vi->rdesc_len = 0;
			mtx_unlock(&vi->mtx);
			return (ENXIO);
		}

		device_set_ivars(vi->hidbus_dev, &vi->hdi);
		error = device_probe_and_attach(vi->hidbus_dev);
		if (error != 0) {
			device_delete_child(vhid_sc->dev, vi->hidbus_dev);
			vi->hidbus_dev = NULL;
			mtx_lock(&vi->mtx);
			vi->attaching = false;
			free(vi->rdesc, M_VHID);
			vi->rdesc = NULL;
			vi->rdesc_len = 0;
			mtx_unlock(&vi->mtx);
			return (error);
		}

		/* Mark configured only after successful probe */
		mtx_lock(&vi->mtx);
		vi->attaching = false;
		vi->configured = true;
		mtx_unlock(&vi->mtx);

		return (0);

	default:
		return (ENOTTY);
	}
}

/* ----------------------------------------------------------------
 * Control cdev methods (/dev/vhid)
 * ---------------------------------------------------------------- */

static int
vhid_ctl_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return (0);
}

static int
vhid_ctl_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	return (0);
}

static int
vhid_ctl_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct vhid_inst *vi;
	int unit, error;

	error = priv_check(td, PRIV_DRIVER);
	if (error != 0)
		return (error);

	switch (cmd) {
	case VHID_CREATE:
		unit = vhid_sc->next_unit;
		if (unit >= VHID_MAX_DEVICES)
			return (ENOSPC);

		vi = malloc(sizeof(*vi), M_VHID, M_WAITOK | M_ZERO);
		mtx_init(&vi->mtx, "vhid", NULL, MTX_DEF);
		vi->unit = unit;

		vi->cdev = make_dev(&vhid_inst_cdevsw, unit,
		    UID_ROOT, GID_WHEEL, 0660, "vhid%d", unit);
		if (vi->cdev == NULL) {
			mtx_destroy(&vi->mtx);
			free(vi, M_VHID);
			return (ENXIO);
		}
		vi->cdev->si_drv1 = vi;

		vhid_sc->insts[unit] = vi;
		vhid_sc->next_unit = unit + 1;

		*(int *)data = unit;
		return (0);

	case VHID_DESTROY:
		unit = *(int *)data;
		if (unit < 0 || unit >= VHID_MAX_DEVICES)
			return (EINVAL);

		vi = vhid_sc->insts[unit];
		if (vi == NULL)
			return (ENOENT);

		mtx_lock(&vi->mtx);
		if (vi->open) {
			mtx_unlock(&vi->mtx);
			return (EBUSY);
		}
		mtx_unlock(&vi->mtx);

		/* Detach hidbus child if present */
		if (vi->hidbus_dev != NULL) {
			error = device_delete_child(vhid_sc->dev,
			    vi->hidbus_dev);
			if (error != 0)
				return (error);
		}

		destroy_dev(vi->cdev);
		vhid_sc->insts[unit] = NULL;

		if (vi->rdesc != NULL)
			free(vi->rdesc, M_VHID);
		mtx_destroy(&vi->mtx);
		free(vi, M_VHID);

		return (0);

	default:
		return (ENOTTY);
	}
}

/* ----------------------------------------------------------------
 * hid_if methods -- called by hidbus on our child devices
 * ---------------------------------------------------------------- */

static struct vhid_inst *
vhid_inst_from_child(device_t child)
{
	struct hid_device_info *hdi;

	hdi = device_get_ivars(child);
	if (hdi == NULL)
		return (NULL);

	return (__containerof(hdi, struct vhid_inst, hdi));
}

static void
vhid_intr_setup(device_t dev, device_t child, hid_intr_t intr, void *context,
    struct hid_rdesc_info *rdesc)
{
	struct vhid_inst *vi;

	vi = vhid_inst_from_child(child);
	if (vi == NULL)
		return;

	mtx_lock(&vi->mtx);
	vi->intr = intr;
	vi->intr_ctx = context;
	if (rdesc != NULL)
		rdesc->rdsize = rdesc->isize;
	mtx_unlock(&vi->mtx);
}

static void
vhid_intr_unsetup(device_t dev, device_t child)
{
	struct vhid_inst *vi;

	vi = vhid_inst_from_child(child);
	if (vi == NULL)
		return;

	mtx_lock(&vi->mtx);
	vi->intr = NULL;
	vi->intr_ctx = NULL;
	vi->intr_on = false;
	mtx_unlock(&vi->mtx);
}

static int
vhid_intr_start(device_t dev, device_t child)
{
	struct vhid_inst *vi;

	vi = vhid_inst_from_child(child);
	if (vi == NULL)
		return (ENXIO);

	mtx_lock(&vi->mtx);
	vi->intr_on = true;
	mtx_unlock(&vi->mtx);

	return (0);
}

static int
vhid_intr_stop(device_t dev, device_t child)
{
	struct vhid_inst *vi;

	vi = vhid_inst_from_child(child);
	if (vi == NULL)
		return (ENXIO);

	mtx_lock(&vi->mtx);
	vi->intr_on = false;
	mtx_unlock(&vi->mtx);

	return (0);
}

static int
vhid_get_rdesc(device_t dev, device_t child, void *data, hid_size_t len)
{
	struct vhid_inst *vi;

	vi = vhid_inst_from_child(child);
	if (vi == NULL || vi->rdesc == NULL)
		return (ENXIO);

	if (len > vi->rdesc_len)
		len = vi->rdesc_len;

	memcpy(data, vi->rdesc, len);

	return (0);
}

/* ----------------------------------------------------------------
 * Bus methods -- so hidbus can read ivars
 * ---------------------------------------------------------------- */

static int
vhid_read_ivar(device_t dev, device_t child, int which, uintptr_t *result)
{
	return (BUS_READ_IVAR(device_get_parent(dev), dev, which, result));
}

/* ----------------------------------------------------------------
 * Newbus driver methods (nexus-attached pseudo-device)
 * ---------------------------------------------------------------- */

static void
vhid_identify(driver_t *driver, device_t parent)
{
	if (device_find_child(parent, "vhid", -1) == NULL)
		BUS_ADD_CHILD(parent, 0, "vhid", -1);
}

static int
vhid_probe(device_t dev)
{
	device_set_desc(dev, "Virtual HID transport");
	return (BUS_PROBE_NOWILDCARD);
}

static int
vhid_attach(device_t dev)
{
	struct vhid_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->next_unit = 0;
	vhid_sc = sc;

	/* Create /dev/vhid control device */
	vhid_ctl_dev = make_dev(&vhid_ctl_cdevsw, 0,
	    UID_ROOT, GID_WHEEL, 0660, "vhid");
	if (vhid_ctl_dev == NULL) {
		device_printf(dev, "failed to create /dev/vhid\n");
		return (ENXIO);
	}

	device_printf(dev, "Virtual HID transport ready\n");

	return (0);
}

static int
vhid_detach(device_t dev)
{
	struct vhid_softc *sc;
	struct vhid_inst *vi;
	int i;

	sc = device_get_softc(dev);

	for (i = 0; i < VHID_MAX_DEVICES; i++) {
		vi = sc->insts[i];
		if (vi == NULL)
			continue;

		if (vi->hidbus_dev != NULL)
			device_delete_child(dev, vi->hidbus_dev);

		destroy_dev(vi->cdev);

		if (vi->rdesc != NULL)
			free(vi->rdesc, M_VHID);
		mtx_destroy(&vi->mtx);
		free(vi, M_VHID);
		sc->insts[i] = NULL;
	}

	if (vhid_ctl_dev != NULL)
		destroy_dev(vhid_ctl_dev);

	vhid_sc = NULL;

	return (0);
}

static device_method_t vhid_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	vhid_identify),
	DEVMETHOD(device_probe,		vhid_probe),
	DEVMETHOD(device_attach,	vhid_attach),
	DEVMETHOD(device_detach,	vhid_detach),

	/* Bus interface */
	DEVMETHOD(bus_read_ivar,	vhid_read_ivar),

	/* HID interface */
	DEVMETHOD(hid_intr_setup,	vhid_intr_setup),
	DEVMETHOD(hid_intr_unsetup,	vhid_intr_unsetup),
	DEVMETHOD(hid_intr_start,	vhid_intr_start),
	DEVMETHOD(hid_intr_stop,	vhid_intr_stop),
	DEVMETHOD(hid_get_rdesc,	vhid_get_rdesc),

	DEVMETHOD_END
};

static driver_t vhid_driver = {
	"vhid",
	vhid_methods,
	sizeof(struct vhid_softc),
};

DRIVER_MODULE(vhid, nexus, vhid_driver, NULL, NULL);
MODULE_DEPEND(vhid, hidbus, 1, 1, 1);
MODULE_VERSION(vhid, 1);
