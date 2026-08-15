/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Guest driver for the QEMU/bhyve "pvpanic" paravirtual crash-notification
 * device.  The device is an LPC/ISA I/O port (default 0x505, length 1) that a
 * guest uses to tell the hypervisor it has crashed, so the host can log the
 * event and optionally change the VM's lifecycle instead of letting the guest
 * hang silently.
 *
 * The ABI is a single byte:
 *   - a READ of the port returns the bitmap of events the host understands
 *     (bit0 PANICKED = 0x01, bit1 CRASHLOADED = 0x02);
 *   - a WRITE tells the host which event just occurred (the guest writes the
 *     PANICKED bit when it panics).
 *
 * The device is described in the ACPI DSDT with _HID "QEMU0001", which is the
 * primary attachment path (and what the stock Linux pvpanic driver binds to).
 *
 * FreeBSD has no analog of the Linux "crash kernel" concept, so CRASHLOADED is
 * intentionally not implemented on the guest side; the host copes with its
 * absence.
 */

#include <sys/cdefs.h>
#include "opt_acpi.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/kassert.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/systm.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <dev/acpica/acpivar.h>

/* Hooks for the ACPI CA debugging infrastructure. */
#define	_COMPONENT	ACPI_BUS
ACPI_MODULE_NAME("PVPANIC")

/*
 * QEMU pvpanic event bits.  These are ABI and must match the host device
 * model (usr.sbin/bhyve/pvpanic_model.h) and QEMU's hw/misc/pvpanic.h.
 */
#define	PVPANIC_PANICKED	0x01	/* guest has panicked */
#define	PVPANIC_CRASHLOADED	0x02	/* guest is loading/running a crashkernel */

struct acpi_pvpanic_softc {
	device_t		 dev;
	struct resource		*port_res;	/* the event register */
	int			 port_rid;
	uint8_t			 supported;	/* host-advertised event mask */
	eventhandler_tag	 shutdown_tag;
};

static char *pvpanic_ids[] = { "QEMU0001", NULL };

static int	acpi_pvpanic_probe(device_t dev);
static int	acpi_pvpanic_attach(device_t dev);
static int	acpi_pvpanic_detach(device_t dev);
static void	acpi_pvpanic_shutdown(void *arg, int howto);

static device_method_t acpi_pvpanic_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		acpi_pvpanic_probe),
	DEVMETHOD(device_attach,	acpi_pvpanic_attach),
	DEVMETHOD(device_detach,	acpi_pvpanic_detach),
	DEVMETHOD_END
};

static driver_t acpi_pvpanic_driver = {
	"acpi_pvpanic",
	acpi_pvpanic_methods,
	sizeof(struct acpi_pvpanic_softc),
};

DRIVER_MODULE(acpi_pvpanic, acpi, acpi_pvpanic_driver, 0, 0);
MODULE_DEPEND(acpi_pvpanic, acpi, 1, 1, 1);
ACPI_PNP_INFO(pvpanic_ids);

static int
acpi_pvpanic_probe(device_t dev)
{
	int rv;

	if (acpi_disabled("pvpanic"))
		return (ENXIO);
	rv = ACPI_ID_PROBE(device_get_parent(dev), dev, pvpanic_ids, NULL);
	if (rv > 0)
		return (ENXIO);

	device_set_desc(dev, "QEMU pvpanic device");
	return (rv);
}

static int
acpi_pvpanic_attach(device_t dev)
{
	struct acpi_pvpanic_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	/*
	 * Grab the single I/O port described by the device's _CRS.  The ACPI
	 * bus has already parsed _CRS into the child's resource list, so a
	 * plain rid-0 allocation yields the event register at 0x505.
	 */
	sc->port_rid = 0;
	sc->port_res = bus_alloc_resource_any(dev, SYS_RES_IOPORT,
	    &sc->port_rid, RF_ACTIVE);
	if (sc->port_res == NULL) {
		device_printf(dev, "could not allocate I/O port\n");
		return (ENXIO);
	}

	/*
	 * A read of the register returns the bitmap of events the host
	 * understands.  Remember it so we only ever report events the host
	 * actually asked for.
	 */
	sc->supported = bus_read_1(sc->port_res, 0);
	if (bootverbose)
		device_printf(dev, "host supports events 0x%02x\n",
		    sc->supported);

	/*
	 * Register a panic-time notifier.  shutdown_final runs from
	 * kern_reboot(), i.e. also on the panic reboot path, and crucially it
	 * runs *after* the kernel crash dump has been taken (doadump() is
	 * invoked earlier in kern_reboot()).  That ordering is deliberate: if
	 * the host is configured to power off or reset on panic, we must not
	 * trip that action until the dump is safely on disk.  A single I/O
	 * port write needs no locks, interrupts, or allocation, so it is safe
	 * this late in shutdown.  SHUTDOWN_PRI_FIRST puts us ahead of the
	 * default halt/reset handlers that never return.
	 */
	if ((sc->supported & PVPANIC_PANICKED) != 0)
		sc->shutdown_tag = EVENTHANDLER_REGISTER(shutdown_final,
		    acpi_pvpanic_shutdown, sc, SHUTDOWN_PRI_FIRST);

	return (0);
}

static int
acpi_pvpanic_detach(device_t dev)
{
	struct acpi_pvpanic_softc *sc;

	sc = device_get_softc(dev);

	if (sc->shutdown_tag != NULL)
		EVENTHANDLER_DEREGISTER(shutdown_final, sc->shutdown_tag);
	if (sc->port_res != NULL)
		bus_release_resource(dev, SYS_RES_IOPORT, sc->port_rid,
		    sc->port_res);

	return (0);
}

/*
 * shutdown_final handler.  Fires on every kern_reboot(); only tell the host we
 * PANICKED when we actually are panicking.  panicstr is set by panic() before
 * it calls kern_reboot(), and is NULL for a clean reboot(8)/shutdown, so it is
 * the exact discriminator we need: writing PANICKED on a clean shutdown would
 * make the host wrongly believe the guest crashed (and, with action=poweroff,
 * kill the VM on an orderly reboot).
 */
static void
acpi_pvpanic_shutdown(void *arg, int howto __unused)
{
	struct acpi_pvpanic_softc *sc = arg;

	if (!KERNEL_PANICKED())
		return;

	bus_write_1(sc->port_res, 0, PVPANIC_PANICKED);
}
