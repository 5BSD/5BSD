/*
 * Contract tests for bhyve's public VirtIO PCI identity constants.
 *
 * This test intentionally compares the production header directly with the
 * independent VirtIO 1.4 oracle.  Device-model tests separately verify that
 * the corresponding initialization paths use these constants.
 */
#include <sys/param.h>
#include <sys/types.h>

#include <pthread.h>
#include <stdint.h>

#include <dev/virtio/virtio_ids.h>

#include <atf-c.h>

#include <bhyve/net_backends.h>
#include <bhyve/pci_emul.h>
#include <bhyve/virtio.h>

#include "bhyve_virtio_compat.h"
#include "virtio_1_4_spec.h"

ATF_TC_WITHOUT_HEAD(pci_identity_constants);
ATF_TC_BODY(pci_identity_constants, tc)
{

	ATF_CHECK_EQ(VIRTIO_VENDOR, VIRTIO14_PCI_VENDOR_ID);
	ATF_CHECK_EQ(VIRTIO_PCI_MODERN_DEVICE_BASE,
	    VIRTIO14_PCI_MODERN_DEVICE_BASE);
	ATF_CHECK(VIRTIO_PCI_MODERN_SUBDEV_BASE >=
	    VIRTIO14_PCI_MODERN_SUBDEVICE_MIN);
	ATF_CHECK_EQ(VIRTIO_PCI_MODERN_REVISION, VIRTIO14_PCI_REVISION);

	ATF_CHECK_EQ(VIRTIO_PCI_TRANSITIONAL_NET,
	    VIRTIO14_PCI_TRANSITIONAL_NETWORK);
	ATF_CHECK_EQ(VIRTIO_PCI_TRANSITIONAL_BLOCK,
	    VIRTIO14_PCI_TRANSITIONAL_BLOCK);
	ATF_CHECK_EQ(VIRTIO_PCI_TRANSITIONAL_CONSOLE,
	    VIRTIO14_PCI_TRANSITIONAL_CONSOLE);
	ATF_CHECK_EQ(VIRTIO_PCI_TRANSITIONAL_SCSI,
	    VIRTIO14_PCI_TRANSITIONAL_SCSI);
	ATF_CHECK_EQ(VIRTIO_PCI_TRANSITIONAL_ENTROPY,
	    VIRTIO14_PCI_TRANSITIONAL_ENTROPY);
	ATF_CHECK_EQ(VIRTIO_PCI_TRANSITIONAL_9P,
	    VIRTIO14_PCI_TRANSITIONAL_9P);
}

ATF_TC_WITHOUT_HEAD(net_record_limit);
ATF_TC_BODY(net_record_limit, tc)
{

	/*
	 * This expected value is the sum specified by section 5.1.9.3:
	 * a 65,589-byte packet and the 12-byte base header.  It deliberately
	 * does not use sizeof() on bhyve's header or its packet-limit macro.
	 */
	ATF_CHECK_EQ(NETBE_MAX_RECORD_SIZE,
	    VIRTIO14_NET_MAX_BASE_RECORD_SIZE);
}

ATF_TC_WITHOUT_HEAD(compatibility_identities);
ATF_TC_BODY(compatibility_identities, tc)
{

	/*
	 * These values are intentionally sourced from the separate bhyve
	 * compatibility oracle.  They are not VirtIO 1.4 modern identities and
	 * must never become expected values in virtio_1_4_spec.h.
	 */
	ATF_CHECK_EQ(VIRTIO_PCI_COMPAT_VSOCK_DEVICE,
	    BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_DEVICE_ID);
	ATF_CHECK_EQ(VIRTIO_VENDOR,
	    BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_VENDOR);
	ATF_CHECK_EQ(VIRTIO_ID_VSOCK,
	    BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_SUBDEVICE);
	ATF_CHECK_EQ(VIRTIO_VENDOR,
	    BHYVE_COMPAT_VIRTIO_VSOCK_LEGACY_SUBVENDOR);
	ATF_CHECK_EQ(VIRTIO_PCI_MODERN_DEVICE_BASE + VIRTIO_ID_VSOCK,
	    VIRTIO14_PCI_MODERN_DEVICE_BASE + VIRTIO14_DEVICE_VSOCK);
	ATF_CHECK(VIRTIO_PCI_COMPAT_VSOCK_DEVICE !=
	    VIRTIO_PCI_MODERN_DEVICE_BASE + VIRTIO_ID_VSOCK);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pci_identity_constants);
	ATF_TP_ADD_TC(tp, net_record_limit);
	ATF_TP_ADD_TC(tp, compatibility_identities);

	return (atf_no_error());
}
