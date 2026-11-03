/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Identity domains for VIRTIO_F_ACCESS_PLATFORM endpoints against a real
 * virtio-iommu (vtiommu0).  A kernel thread attaches and detaches an endpoint
 * through the virtio core while the test detaches and reattaches the
 * virtio-iommu.  An identity attach that reports success must stay in effect
 * until the matching detach: the virtio-iommu either refuses to detach while
 * the endpoint is attached or makes an attach still in flight fail.
 *
 * The endpoint is the PCI function of vtblk0.  It need not sit behind the
 * IOMMU's translation: attaching it to a bypass domain changes nothing for
 * its DMA.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>

#include <dev/pci/pcivar.h>

#include <dev/virtio/iommu/virtio_iommu.h>

#include <tests/ktest.h>

#define	RACE_DURATION	(5 * hz)

struct identity_race {
	struct mtx	mtx;
	uint32_t	endpoint;
	bool		stop;
	bool		done;
	u_int		attached;
	u_int		refused;
	u_int		lost;
	int		lost_error;
};

static device_t
find_device(const char *name, int unit)
{
	devclass_t dc;

	dc = devclass_find(name);
	if (dc == NULL)
		return (NULL);
	return (devclass_get_device(dc, unit));
}

static void
identity_race_thread(void *arg)
{
	struct identity_race *race;
	int error;

	race = arg;
	mtx_lock(&race->mtx);
	while (!race->stop) {
		mtx_unlock(&race->mtx);
		error = virtio_iommu_attach_identity(race->endpoint);
		if (error == 0) {
			error = virtio_iommu_detach_identity(race->endpoint);
			mtx_lock(&race->mtx);
			race->attached++;
			if (error != 0) {
				race->lost++;
				race->lost_error = error;
			}
		} else {
			mtx_lock(&race->mtx);
			race->refused++;
		}
		mtx_unlock(&race->mtx);
		maybe_yield();
		mtx_lock(&race->mtx);
	}
	race->done = true;
	wakeup(race);
	mtx_unlock(&race->mtx);
	kthread_exit();
}

static int
test_identity_detach_race(struct ktest_test_context *ctx)
{
	struct identity_race race;
	device_t blk, iommu, parent;
	driver_t *driver;
	u_int busy, detached;
	int deadline, error;

	blk = find_device("vtblk", 0);
	iommu = find_device("vtiommu", 0);
	if (blk == NULL || iommu == NULL || !device_is_attached(iommu)) {
		KTEST_ERR(ctx, "needs vtblk0 and an attached vtiommu0");
		return (ENXIO);
	}
	parent = device_get_parent(iommu);
	driver = device_get_driver(iommu);

	bzero(&race, sizeof(race));
	mtx_init(&race.mtx, "vtiommu race", NULL, MTX_DEF);
	race.endpoint = pci_get_rid(device_get_parent(blk));
	error = kthread_add(identity_race_thread, &race, NULL, NULL, 0, 0,
	    "vtiommu race");
	if (error != 0) {
		mtx_destroy(&race.mtx);
		return (error);
	}

	busy = detached = 0;
	deadline = ticks + RACE_DURATION;
	while (error == 0 && ticks - deadline < 0) {
		bus_topo_lock();
		if (device_detach(iommu) == 0) {
			detached++;
			BUS_DRIVER_ADDED(parent, driver);
			if (!device_is_attached(iommu))
				error = ENXIO;
		} else
			busy++;
		bus_topo_unlock();
		pause("vtirace", 1);
	}

	mtx_lock(&race.mtx);
	race.stop = true;
	while (!race.done)
		msleep(&race, &race.mtx, 0, "vtirace", 0);
	mtx_unlock(&race.mtx);
	mtx_destroy(&race.mtx);

	KTEST_LOG(ctx, "endpoint %#x: %u attached, %u refused, %u lost; "
	    "virtio-iommu detached %u times, busy %u times", race.endpoint,
	    race.attached, race.refused, race.lost, detached, busy);
	if (error != 0) {
		KTEST_ERR(ctx, "vtiommu0 did not attach again");
		return (error);
	}
	if (race.lost != 0) {
		KTEST_ERR(ctx, "%u identity attaches reported success but "
		    "were gone before their detach (error %d)", race.lost,
		    race.lost_error);
		return (EINVAL);
	}
	if (race.attached == 0 || detached == 0) {
		KTEST_ERR(ctx, "the attach and detach loops did not overlap");
		return (EINVAL);
	}

	/* With every identity attach undone the virtio-iommu can detach. */
	bus_topo_lock();
	error = device_detach(iommu);
	if (error == 0)
		BUS_DRIVER_ADDED(parent, driver);
	bus_topo_unlock();
	if (error != 0) {
		KTEST_ERR(ctx, "vtiommu0 still busy after the last detach: %d",
		    error);
		return (error);
	}
	return (0);
}

static const struct ktest_test_info tests[] = {
	{
		.name = "identity_detach_race",
		.desc = "an identity attach racing a virtio-iommu detach either fails or keeps the virtio-iommu attached",
		.func = test_identity_detach_race,
	},
};

KTEST_MODULE_DECLARE(ktest_virtio_iommu, tests);
KTEST_MODULE_DEPEND(ktest_virtio_iommu, virtio_iommu);
