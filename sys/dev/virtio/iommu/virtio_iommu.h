/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * VirtIO IOMMU (VirtIO device ID 23) guest driver -- wire ABI.
 *
 * These definitions mirror the device contract implemented by the bhyve
 * back end in usr.sbin/bhyve/pci_virtio_iommu.c and the associated
 * virtio_iommu_* protocol/config/queue helpers.  They are the little-endian,
 * over-the-wire structures placed in the request and event virtqueues; the
 * driver always byte-swaps explicitly (htoleNN / leNNtoh) when populating or
 * reading a descriptor buffer, so the layout is independent of the transport
 * config-space accessors.
 */

#ifndef _DEV_VIRTIO_IOMMU_VIRTIO_IOMMU_H_
#define	_DEV_VIRTIO_IOMMU_VIRTIO_IOMMU_H_

/* Feature bit numbers (feature mask is 1ULL << bit). */
#define	VIRTIO_IOMMU_F_INPUT_RANGE	0
#define	VIRTIO_IOMMU_F_DOMAIN_RANGE	1
#define	VIRTIO_IOMMU_F_MAP_UNMAP	2
#define	VIRTIO_IOMMU_F_BYPASS		3	/* legacy; not negotiated */
#define	VIRTIO_IOMMU_F_PROBE		4
#define	VIRTIO_IOMMU_F_MMIO		5
#define	VIRTIO_IOMMU_F_BYPASS_CONFIG	6

/*
 * Device configuration space (40 bytes).  Fields are little-endian on the
 * wire; the driver converts to host order with virtio_htog* on read.  Mirrors
 * BHYVE_VIOMMU_CONFIG_SIZE and the offsets in virtio_iommu_config.c.
 */
struct virtio_iommu_config {
	uint64_t page_size_mask;	/* 0 */
	struct {
		uint64_t start;		/* 8 */
		uint64_t end;		/* 16 */
	} input_range;
	struct {
		uint32_t start;		/* 24 */
		uint32_t end;		/* 28 */
	} domain_range;
	uint32_t probe_size;		/* 32 */
	uint8_t	 bypass;		/* 36 */
	uint8_t	 reserved[3];		/* 37 */
} __packed;

/* Request types. */
#define	VIRTIO_IOMMU_T_ATTACH	1
#define	VIRTIO_IOMMU_T_DETACH	2
#define	VIRTIO_IOMMU_T_MAP	3
#define	VIRTIO_IOMMU_T_UNMAP	4
#define	VIRTIO_IOMMU_T_PROBE	5

/* Request status codes (returned in the request tail). */
#define	VIRTIO_IOMMU_S_OK	0
#define	VIRTIO_IOMMU_S_IOERR	1
#define	VIRTIO_IOMMU_S_UNSUPP	2
#define	VIRTIO_IOMMU_S_DEVERR	3
#define	VIRTIO_IOMMU_S_INVAL	4
#define	VIRTIO_IOMMU_S_RANGE	5
#define	VIRTIO_IOMMU_S_NOENT	6
#define	VIRTIO_IOMMU_S_FAULT	7
#define	VIRTIO_IOMMU_S_NOMEM	8

/* Common request/response framing. */
struct virtio_iommu_req_head {
	uint8_t	type;
	uint8_t	reserved[3];
} __packed;

struct virtio_iommu_req_tail {
	uint8_t	status;
	uint8_t	reserved[3];
} __packed;

/* ATTACH flags. */
#define	VIRTIO_IOMMU_ATTACH_F_BYPASS	(1U << 0)

struct virtio_iommu_req_attach {
	struct virtio_iommu_req_head head;
	uint32_t domain;
	uint32_t endpoint;
	uint32_t flags;
	uint8_t	 reserved[4];
} __packed;

struct virtio_iommu_req_detach {
	struct virtio_iommu_req_head head;
	uint32_t domain;
	uint32_t endpoint;
	uint8_t	 reserved[8];
} __packed;

/* MAP flags. */
#define	VIRTIO_IOMMU_MAP_F_READ		(1U << 0)
#define	VIRTIO_IOMMU_MAP_F_WRITE	(1U << 1)
#define	VIRTIO_IOMMU_MAP_F_MMIO		(1U << 2)
#define	VIRTIO_IOMMU_MAP_F_MASK		(VIRTIO_IOMMU_MAP_F_READ | \
	VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO)

struct virtio_iommu_req_map {
	struct virtio_iommu_req_head head;
	uint32_t domain;
	uint64_t virt_start;
	uint64_t virt_end;
	uint64_t phys_start;
	uint32_t flags;
} __packed;

struct virtio_iommu_req_unmap {
	struct virtio_iommu_req_head head;
	uint32_t domain;
	uint64_t virt_start;
	uint64_t virt_end;
	uint8_t	 reserved[4];
} __packed;

struct virtio_iommu_req_probe {
	struct virtio_iommu_req_head head;
	uint32_t endpoint;
	uint8_t	 reserved[64];
	/* Followed by a device-writable properties[probe_size] region + tail. */
} __packed;

/* PROBE property TLV header. */
#define	VIRTIO_IOMMU_PROBE_T_MASK	0xfff
#define	VIRTIO_IOMMU_PROBE_T_NONE	0
#define	VIRTIO_IOMMU_PROBE_T_RESV_MEM	1

struct virtio_iommu_probe_property {
	uint16_t type;
	uint16_t length;
} __packed;

/* RESV_MEM property subtypes. */
#define	VIRTIO_IOMMU_RESV_MEM_T_RESERVED	0
#define	VIRTIO_IOMMU_RESV_MEM_T_MSI		1

struct virtio_iommu_probe_resv_mem {
	struct virtio_iommu_probe_property head;
	uint8_t	 subtype;
	uint8_t	 reserved[3];
	uint64_t start;
	uint64_t end;
} __packed;

/* Fault event (device-writable, event virtqueue). */
#define	VIRTIO_IOMMU_FAULT_R_UNKNOWN	0
#define	VIRTIO_IOMMU_FAULT_R_DOMAIN	1
#define	VIRTIO_IOMMU_FAULT_R_MAPPING	2

#define	VIRTIO_IOMMU_FAULT_F_READ	(1U << 0)
#define	VIRTIO_IOMMU_FAULT_F_WRITE	(1U << 1)
#define	VIRTIO_IOMMU_FAULT_F_EXEC	(1U << 2)
#define	VIRTIO_IOMMU_FAULT_F_ADDRESS	(1U << 8)

struct virtio_iommu_fault {
	uint8_t	 reason;
	uint8_t	 reserved[3];
	uint32_t flags;
	uint32_t endpoint;
	uint8_t	 reserved2[4];
	uint64_t address;
} __packed;

/*
 * IOMMU-framework provider seam (see the block comment in virtio_iommu.c).
 *
 * FreeBSD's busdma/IOMMU layer discovers a translation unit through the
 * per-platform iommu_find() and drives it via iommu_unit/iommu_domain/
 * iommu_ctx map/unmap ops, with endpoints bound by ACPI (DMAR/IVRS/IORT, and
 * for virtio-iommu the VIOT table).  None of that machinery has a
 * machine-independent "register a new provider" entry point that a loadable
 * virtio child driver may call without editing the framework and platform
 * busdma back ends -- which is out of this driver's file scope.
 *
 * Rather than fake translation, the driver publishes this provider vtable so a
 * future VIOT/busdma_iommu back end can locate the request-queue protocol
 * engine by endpoint RID and drive real MAP/UNMAP/ATTACH/DETACH against the
 * host.  virtio_iommu_provider_lookup() returns the provider that owns a given
 * endpoint RID, or NULL when no virtio-iommu instance claims it.
 */
struct virtio_iommu_provider {
	device_t dev;
	int	(*attach)(device_t, uint32_t domain, uint32_t endpoint,
		    uint32_t flags);
	int	(*detach)(device_t, uint32_t domain, uint32_t endpoint);
	int	(*map)(device_t, uint32_t domain, uint64_t iova_start,
		    uint64_t iova_end, uint64_t phys_start, uint32_t prot);
	int	(*unmap)(device_t, uint32_t domain, uint64_t iova_start,
		    uint64_t iova_end);
	int	(*probe_endpoint)(device_t, uint32_t endpoint);
	LIST_ENTRY(virtio_iommu_provider) link;
};

struct virtio_iommu_provider *virtio_iommu_provider_lookup(uint32_t endpoint);

#endif /* _DEV_VIRTIO_IOMMU_VIRTIO_IOMMU_H_ */
