/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2017 Shunsuke Mie
 * Copyright (c) 2018 Leon Dang
 * Copyright (c) 2020 Chuck Tuffli
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * bhyve PCIe-NVMe device emulation.
 *
 * options:
 *  -s <n>,nvme,devpath,maxq=#,qsz=#,ioslots=#,sectsz=#,ser=A-Z,eui64=#,dsm=<opt>
 *
 *  accepted devpath:
 *    /dev/blockdev
 *    /path/to/image
 *    ram=size_in_MiB
 *
 *  maxq    = max number of queues
 *  qsz     = max elements in each queue
 *  ioslots = max number of concurrent io requests
 *  sectsz  = sector size (defaults to blockif sector size)
 *  ser     = serial number (20-chars max)
 *  eui64   = IEEE Extended Unique Identifier (8 byte value)
 *  dsm     = DataSet Management support. Option is one of auto, enable,disable
 *
 */

/* TODO:
    - create async event for smart and log
    - intr coalesce
 */

#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/crc16.h>
#include <net/ieee_oui.h>

#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <machine/atomic.h>
#include <machine/vmm.h>
#include <vmmapi.h>

#include <dev/nvme/nvme.h>

#include "bhyverun.h"
#include "block_if.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#include "snapshot_identity.h"
#endif
#include "pci_nvme_model.h"


static int nvme_debug = 0;
#define	DPRINTF(fmt, args...) if (nvme_debug) PRINTLN(fmt, ##args)
#define	WPRINTF(fmt, args...) PRINTLN(fmt, ##args)

/* defaults; can be overridden */
#define	NVME_MSIX_BAR		4

#define	NVME_IOSLOTS		8

/* The NVMe spec defines bits 13:4 in BAR0 as reserved */
#define NVME_MMIO_SPACE_MIN	(1 << 14)

#define	NVME_QUEUES		16
#define	NVME_MAX_QENTRIES	2048
/* Memory Page size Minimum reported in CAP register */
#define	NVME_MPSMIN		0
/* MPSMIN converted to bytes */
#define	NVME_MPSMIN_BYTES	(1 << (12 + NVME_MPSMIN))

#define	NVME_PRP2_ITEMS		(PAGE_SIZE/sizeof(uint64_t))
#define	NVME_MDTS		9
/* Note the + 1 allows for the initial descriptor to not be page aligned */
#define	NVME_MAX_IOVEC		((1 << NVME_MDTS) + 1)
#define	NVME_MAX_DATA_SIZE	((1 << NVME_MDTS) * NVME_MPSMIN_BYTES)
#define	NVME_MAX_PENDING_CQES	65536U

/* This is a synthetic status code to indicate there is no status */
#define NVME_NO_STATUS		0xffff
#define NVME_COMPLETION_VALID(c)	((c).status != NVME_NO_STATUS)

/* Reported temperature in Kelvin (i.e. room temperature) */
#define NVME_TEMPERATURE 296

/* helpers */

/* Convert a zero-based value into a one-based value */
#define ONE_BASED(zero)		((zero) + 1)
/* Convert a one-based value into a zero-based value */
#define ZERO_BASED(one)		((one)  - 1)

/* Encode number of SQ's and CQ's for Set/Get Features */
#define NVME_FEATURE_NUM_QUEUES(sc) \
	(ZERO_BASED((sc)->num_squeues) & 0xffff) | \
	(ZERO_BASED((sc)->num_cqueues) & 0xffff) << 16

#define	NVME_DOORBELL_OFFSET	offsetof(struct nvme_registers, doorbell)

enum nvme_controller_register_offsets {
	NVME_CR_CAP_LOW = 0x00,
	NVME_CR_CAP_HI  = 0x04,
	NVME_CR_VS      = 0x08,
	NVME_CR_INTMS   = 0x0c,
	NVME_CR_INTMC   = 0x10,
	NVME_CR_CC      = 0x14,
	NVME_CR_CSTS    = 0x1c,
	NVME_CR_NSSR    = 0x20,
	NVME_CR_AQA     = 0x24,
	NVME_CR_ASQ_LOW = 0x28,
	NVME_CR_ASQ_HI  = 0x2c,
	NVME_CR_ACQ_LOW = 0x30,
	NVME_CR_ACQ_HI  = 0x34,
};

enum nvme_cmd_cdw11 {
	NVME_CMD_CDW11_PC  = 0x0001,
	NVME_CMD_CDW11_IEN = 0x0002,
	NVME_CMD_CDW11_IV  = 0xFFFF0000,
};

enum nvme_copy_dir {
	NVME_COPY_TO_PRP,
	NVME_COPY_FROM_PRP,
};

#define	NVME_CQ_INTEN	0x01
#define	NVME_CQ_INTCOAL	0x02

struct pci_nvme_pending_cqe {
	STAILQ_ENTRY(pci_nvme_pending_cqe) link;
	uint32_t	cdw0;
	uint16_t	sqhd;
	uint16_t	sqid;
	uint16_t	cid;
	uint16_t	status;
};

struct nvme_completion_queue {
	struct nvme_completion *qbase;
	pthread_mutex_t	mtx;
	uint32_t	size;
	uint16_t	tail; /* nvme progress */
	uint16_t	head; /* guest progress */
	uint16_t	intr_vec;
	uint32_t	intr_en;
	bool		phase;
	STAILQ_HEAD(, pci_nvme_pending_cqe) pending;
	uint32_t	pending_count;
};

struct nvme_submission_queue {
	struct nvme_command *qbase;
	pthread_mutex_t	mtx;
	uint32_t	size;
	uint16_t	head; /* nvme progress */
	uint16_t	tail; /* guest progress */
	uint16_t	cqid; /* completion queue id */
	int		qpriority;
	uint32_t	pending_ios;
};

enum nvme_storage_type {
	NVME_STOR_BLOCKIF = 0,
	NVME_STOR_RAM = 1,
};

struct pci_nvme_blockstore {
	enum nvme_storage_type type;
	void		*ctx;
	uint64_t	size;
	uint32_t	sectsz;
	uint32_t	sectsz_bits;
	uint64_t	eui64;
	uint32_t	deallocate:1;
};

/*
 * Calculate the number of additional page descriptors for guest IO requests
 * based on the advertised Max Data Transfer (MDTS) and given the number of
 * default iovec's in a struct blockif_req.
 */
#define MDTS_PAD_SIZE \
	( NVME_MAX_IOVEC > BLOCKIF_IOV_MAX ? \
	  NVME_MAX_IOVEC - BLOCKIF_IOV_MAX : \
	  0 )

struct pci_nvme_ioreq {
	struct pci_nvme_softc *sc;
	STAILQ_ENTRY(pci_nvme_ioreq) link;
	struct nvme_submission_queue *nvme_sq;
	uint16_t	sqid;

	/* command information */
	uint16_t	opc;
	uint16_t	cid;
	uint16_t	sqhd;
	uint32_t	nsid;

	uint64_t	prev_gpaddr;
	size_t		prev_size;
	size_t		bytes;

	struct blockif_req io_req;

	struct iovec	iovpadding[MDTS_PAD_SIZE];
};

enum nvme_dsm_type {
	/* Dataset Management bit in ONCS reflects backing storage capability */
	NVME_DATASET_MANAGEMENT_AUTO,
	/* Unconditionally set Dataset Management bit in ONCS */
	NVME_DATASET_MANAGEMENT_ENABLE,
	/* Unconditionally clear Dataset Management bit in ONCS */
	NVME_DATASET_MANAGEMENT_DISABLE,
};

struct pci_nvme_softc;
struct nvme_feature_obj;

typedef void (*nvme_feature_cb)(struct pci_nvme_softc *,
    struct nvme_feature_obj *,
    struct nvme_command *,
    struct nvme_completion *);

struct nvme_feature_obj {
	uint32_t	cdw11;
	uint32_t	default_cdw11;
	nvme_feature_cb	set;
	nvme_feature_cb	get;
	bool namespace_specific;
};

#define NVME_FID_MAX		(NVME_FEAT_ENDURANCE_GROUP_EVENT_CONFIGURATION + 1)

typedef enum {
	PCI_NVME_AE_TYPE_ERROR = 0,
	PCI_NVME_AE_TYPE_SMART,
	PCI_NVME_AE_TYPE_NOTICE,
	PCI_NVME_AE_TYPE_IO_CMD = 6,
	PCI_NVME_AE_TYPE_VENDOR = 7,
	PCI_NVME_AE_TYPE_MAX		/* Must be last */
} pci_nvme_async_type;

/* Asynchronous Event Requests */
struct pci_nvme_aer {
	STAILQ_ENTRY(pci_nvme_aer) link;
	uint16_t	cid;	/* Command ID of the submitted AER */
	uint16_t	sqhd;	/* Submission queue head at consumption */
};

/** Asynchronous Event Information - Error */
typedef enum {
	PCI_NVME_AEI_ERROR_INVALID_DB,
	PCI_NVME_AEI_ERROR_INVALID_DB_VALUE,
	PCI_NVME_AEI_ERROR_DIAG_FAILURE,
	PCI_NVME_AEI_ERROR_PERSISTANT_ERR,
	PCI_NVME_AEI_ERROR_TRANSIENT_ERR,
	PCI_NVME_AEI_ERROR_FIRMWARE_LOAD_ERR,
	PCI_NVME_AEI_ERROR_MAX,
} pci_nvme_async_event_info_error;

/** Asynchronous Event Information - Notice */
typedef enum {
	PCI_NVME_AEI_NOTICE_NS_ATTR_CHANGED = 0,
	PCI_NVME_AEI_NOTICE_FW_ACTIVATION,
	PCI_NVME_AEI_NOTICE_TELEMETRY_CHANGE,
	PCI_NVME_AEI_NOTICE_ANA_CHANGE,
	PCI_NVME_AEI_NOTICE_PREDICT_LATENCY_CHANGE,
	PCI_NVME_AEI_NOTICE_LBA_STATUS_ALERT,
	PCI_NVME_AEI_NOTICE_ENDURANCE_GROUP_CHANGE,
	PCI_NVME_AEI_NOTICE_MAX,
} pci_nvme_async_event_info_notice;

#define PCI_NVME_AEI_NOTICE_SHIFT		8
#define PCI_NVME_AEI_NOTICE_MASK(event)	(1 << (event + PCI_NVME_AEI_NOTICE_SHIFT))

/* Asynchronous Event Notifications */
struct pci_nvme_aen {
	pci_nvme_async_type atype;
	uint32_t	event_data;
	bool		posted;
};

/*
 * By default, enable all Asynchrnous Event Notifications:
 *     SMART / Health Critical Warnings
 *     Namespace Attribute Notices
 */
#define PCI_NVME_AEN_DEFAULT_MASK	0x11f

typedef enum {
	NVME_CNTRLTYPE_IO = 1,
	NVME_CNTRLTYPE_DISCOVERY = 2,
	NVME_CNTRLTYPE_ADMIN = 3,
} pci_nvme_cntrl_type;

struct pci_nvme_softc {
	struct pci_devinst *nsc_pi;

	pthread_mutex_t	mtx;

	struct nvme_registers regs;

	struct nvme_namespace_data  nsdata;
	struct nvme_controller_data ctrldata;
	struct nvme_error_information_entry err_log;
	struct nvme_health_information_page health_log;
	struct nvme_firmware_page fw_log;
	struct nvme_ns_list ns_log;

	struct pci_nvme_blockstore nvstore;

	uint32_t	max_qentries;	/* max entries per queue */
	uint32_t	max_queues;	/* max number of IO SQ's or CQ's */
	uint32_t	num_cqueues;
	uint32_t	num_squeues;
	bool		num_q_is_set; /* Has host set Number of Queues */

	struct pci_nvme_ioreq *ioreqs;
	STAILQ_HEAD(, pci_nvme_ioreq) ioreqs_free; /* free list of ioreqs */
	uint32_t	pending_ios;
	uint32_t	active_sq_handlers;
	uint32_t	ioslots;
	sem_t		iosemlock;
	bool		reset_pending;

	/*
	 * Memory mapped Submission and Completion queues
	 * Each array includes both Admin and IO queues
	 */
	struct nvme_completion_queue *compl_queues;
	struct nvme_submission_queue *submit_queues;

	struct nvme_feature_obj feat[NVME_FID_MAX];

	enum nvme_dsm_type dataset_management;

	/* Accounting for SMART data */
	__uint128_t	read_data_units;
	__uint128_t	write_data_units;
	__uint128_t	read_commands;
	__uint128_t	write_commands;
	uint32_t	read_dunits_remainder;
	uint32_t	write_dunits_remainder;

	STAILQ_HEAD(, pci_nvme_aer) aer_list;
	pthread_mutex_t	aer_mtx;
	uint32_t	aer_count;
	struct pci_nvme_aen aen[PCI_NVME_AE_TYPE_MAX];
	pthread_t	aen_tid;
	pthread_mutex_t	aen_mtx;
	pthread_cond_t	aen_cond;
#ifdef BHYVE_SNAPSHOT
	/*
	 * Checkpoint pause fence for the AEN worker.  While set, the worker
	 * parks on aen_cond instead of publishing completions, so no thread
	 * of this device can touch guest memory during a snapshot.
	 */
	bool		aen_paused;
#endif
};


static bool pci_nvme_cq_update(struct pci_nvme_softc *sc,
    struct nvme_completion_queue *cq,
    uint32_t cdw0,
    uint16_t cid,
    uint16_t sqid,
    uint16_t sqhd,
    uint16_t status);
static struct pci_nvme_ioreq *pci_nvme_get_ioreq(struct pci_nvme_softc *);
static void pci_nvme_release_ioreq(struct pci_nvme_softc *, struct pci_nvme_ioreq *);
static void pci_nvme_io_done(struct blockif_req *, int);
static int pci_nvme_init_controller(struct pci_nvme_softc *);

/* Controller Configuration utils */
#define	NVME_CC_GET_EN(cc) \
	NVMEV(NVME_CC_REG_EN, cc)
#define	NVME_CC_GET_CSS(cc) \
	NVMEV(NVME_CC_REG_CSS, cc)
#define	NVME_CC_GET_SHN(cc) \
	NVMEV(NVME_CC_REG_SHN, cc)
#define	NVME_CC_GET_IOSQES(cc) \
	NVMEV(NVME_CC_REG_IOSQES, cc)
#define	NVME_CC_GET_IOCQES(cc) \
	NVMEV(NVME_CC_REG_IOCQES, cc)

#define	NVME_CC_WRITE_MASK \
	(NVMEM(NVME_CC_REG_EN) | \
	 NVMEM(NVME_CC_REG_IOSQES) | \
	 NVMEM(NVME_CC_REG_IOCQES))

#define	NVME_CC_NEN_WRITE_MASK \
	(NVMEM(NVME_CC_REG_CSS) | \
	 NVMEM(NVME_CC_REG_MPS) | \
	 NVMEM(NVME_CC_REG_AMS))

/* Controller Status utils */
#define	NVME_CSTS_GET_RDY(sts) \
	NVMEV(NVME_CSTS_REG_RDY, sts)

#define	NVME_CSTS_RDY	(NVMEF(NVME_CSTS_REG_RDY, 1))
#define	NVME_CSTS_CFS	(NVMEF(NVME_CSTS_REG_CFS, 1))

/* Completion Queue status word utils */
#define	NVME_STATUS_P	(NVMEF(NVME_STATUS_P, 1))
#define	NVME_STATUS_MASK \
	(NVMEM(NVME_STATUS_SCT) | \
	 NVMEM(NVME_STATUS_SC))

#define NVME_ONCS_DSM	NVMEM(NVME_CTRLR_DATA_ONCS_DSM)

static void nvme_feature_invalid_cb(struct pci_nvme_softc *,
    struct nvme_feature_obj *,
    struct nvme_command *,
    struct nvme_completion *);
static void nvme_feature_temperature(struct pci_nvme_softc *,
    struct nvme_feature_obj *,
    struct nvme_command *,
    struct nvme_completion *);
static void nvme_feature_num_queues(struct pci_nvme_softc *,
    struct nvme_feature_obj *,
    struct nvme_command *,
    struct nvme_completion *);
static void nvme_feature_iv_config(struct pci_nvme_softc *,
    struct nvme_feature_obj *,
    struct nvme_command *,
    struct nvme_completion *);
static void nvme_feature_async_event(struct pci_nvme_softc *,
    struct nvme_feature_obj *,
    struct nvme_command *,
    struct nvme_completion *);

static void *aen_thr(void *arg);

static __inline void
cpywithpad(char *dst, size_t dst_size, const char *src, char pad)
{
	size_t len;

	len = strnlen(src, dst_size);
	memset(dst, pad, dst_size);
	memcpy(dst, src, len);
}

static __inline void
pci_nvme_status_tc(uint16_t *status, uint16_t type, uint16_t code)
{

	*status &= ~NVME_STATUS_MASK;
	*status |= NVMEF(NVME_STATUS_SCT, type) | NVMEF(NVME_STATUS_SC, code);
}

static __inline void
pci_nvme_status_genc(uint16_t *status, uint16_t code)
{

	pci_nvme_status_tc(status, NVME_SCT_GENERIC, code);
}

/*
 * Initialize the requested number or IO Submission and Completion Queues.
 * Admin queues are allocated implicitly.
 */
static int
pci_nvme_init_queues(struct pci_nvme_softc *sc, uint32_t nsq, uint32_t ncq)
{
	uint32_t i, initialized_cq, initialized_sq;
	int error;

	initialized_cq = 0;
	initialized_sq = 0;

	/*
	 * Allocate and initialize the Submission Queues
	 */
	if (nsq > NVME_QUEUES) {
		WPRINTF("%s: clamping number of SQ from %u to %u",
					__func__, nsq, NVME_QUEUES);
		nsq = NVME_QUEUES;
	}

	sc->num_squeues = nsq;

	sc->submit_queues = calloc(sc->num_squeues + 1,
				sizeof(struct nvme_submission_queue));
	if (sc->submit_queues == NULL) {
		WPRINTF("%s: SQ allocation failed", __func__);
		sc->num_squeues = 0;
		return (ENOMEM);
	} else {
		struct nvme_submission_queue *sq = sc->submit_queues;

		for (i = 0; i < sc->num_squeues + 1; i++) {
			error = pthread_mutex_init(&sq[i].mtx, NULL);
			if (error != 0)
				goto fail;
			initialized_sq++;
		}
	}

	/*
	 * Allocate and initialize the Completion Queues
	 */
	if (ncq > NVME_QUEUES) {
		WPRINTF("%s: clamping number of CQ from %u to %u",
					__func__, ncq, NVME_QUEUES);
		ncq = NVME_QUEUES;
	}

	sc->num_cqueues = ncq;

	sc->compl_queues = calloc(sc->num_cqueues + 1,
				sizeof(struct nvme_completion_queue));
	if (sc->compl_queues == NULL) {
		WPRINTF("%s: CQ allocation failed", __func__);
		sc->num_cqueues = 0;
		error = ENOMEM;
		goto fail;
	} else {
		struct nvme_completion_queue *cq = sc->compl_queues;

		for (i = 0; i < sc->num_cqueues + 1; i++) {
			error = pthread_mutex_init(&cq[i].mtx, NULL);
			if (error != 0)
				goto fail;
			STAILQ_INIT(&cq[i].pending);
			initialized_cq++;
		}
	}
	return (0);

fail:
	while (initialized_cq > 0)
		pthread_mutex_destroy(
		    &sc->compl_queues[--initialized_cq].mtx);
	while (initialized_sq > 0)
		pthread_mutex_destroy(
		    &sc->submit_queues[--initialized_sq].mtx);
	free(sc->compl_queues);
	free(sc->submit_queues);
	sc->compl_queues = NULL;
	sc->submit_queues = NULL;
	sc->num_cqueues = 0;
	sc->num_squeues = 0;
	return (error);
}

static void
pci_nvme_fini_queues(struct pci_nvme_softc *sc)
{
	uint32_t i;

	if (sc->compl_queues != NULL) {
		for (i = 0; i < sc->num_cqueues + 1; i++) {
			struct pci_nvme_pending_cqe *pending;

			while ((pending = STAILQ_FIRST(
			    &sc->compl_queues[i].pending)) != NULL) {
				STAILQ_REMOVE_HEAD(&sc->compl_queues[i].pending, link);
				free(pending);
			}
			pthread_mutex_destroy(&sc->compl_queues[i].mtx);
		}
	}
	if (sc->submit_queues != NULL) {
		for (i = 0; i < sc->num_squeues + 1; i++)
			pthread_mutex_destroy(&sc->submit_queues[i].mtx);
	}
	free(sc->compl_queues);
	free(sc->submit_queues);
	sc->compl_queues = NULL;
	sc->submit_queues = NULL;
	sc->num_cqueues = 0;
	sc->num_squeues = 0;
}

static void
pci_nvme_init_ctrldata(struct pci_nvme_softc *sc)
{
	struct nvme_controller_data *cd = &sc->ctrldata;
	int ret;

	cd->vid = 0xFB5D;
	cd->ssvid = 0x0000;

	cpywithpad((char *)cd->mn, sizeof(cd->mn), "bhyve-NVMe", ' ');
	cpywithpad((char *)cd->fr, sizeof(cd->fr), "1.0", ' ');

	/* Num of submission commands that we can handle at a time (2^rab) */
	cd->rab   = 4;

	/* FreeBSD OUI */
	cd->ieee[0] = 0xfc;
	cd->ieee[1] = 0x9c;
	cd->ieee[2] = 0x58;

	cd->mic = 0;

	cd->mdts = NVME_MDTS;	/* max data transfer size (2^mdts * CAP.MPSMIN) */

	cd->ver = NVME_REV(1,4);

	cd->cntrltype = NVME_CNTRLTYPE_IO;
	cd->oacs = NVMEF(NVME_CTRLR_DATA_OACS_FORMAT, 1);
	cd->oaes = NVMEM(NVME_CTRLR_DATA_OAES_NS_ATTR);
	cd->acl = 2;
	cd->aerl = 4;

	/* Advertise 1, Read-only firmware slot */
	cd->frmw = NVMEM(NVME_CTRLR_DATA_FRMW_SLOT1_RO) |
	    NVMEF(NVME_CTRLR_DATA_FRMW_NUM_SLOTS, 1);
	cd->lpa = 0;	/* TODO: support some simple things like SMART */
	cd->elpe = 0;	/* max error log page entries */
	/*
	 * Report a single power state (zero-based value)
	 * power_state[] values are left as zero to indicate "Not reported"
	 */
	cd->npss = 0;

	/* Warning Composite Temperature Threshold */
	cd->wctemp = 0x0157;
	cd->cctemp = 0x0157;

	/* SANICAP must not be 0 for Revision 1.4 and later NVMe Controllers */
	cd->sanicap = NVMEF(NVME_CTRLR_DATA_SANICAP_NODMMAS,
	    NVME_CTRLR_DATA_SANICAP_NODMMAS_NO);

	cd->sqes = NVMEF(NVME_CTRLR_DATA_SQES_MAX, 6) |
	    NVMEF(NVME_CTRLR_DATA_SQES_MIN, 6);
	cd->cqes = NVMEF(NVME_CTRLR_DATA_CQES_MAX, 4) |
	    NVMEF(NVME_CTRLR_DATA_CQES_MIN, 4);
	cd->nn = 1;	/* number of namespaces */

	cd->oncs = 0;
	switch (sc->dataset_management) {
	case NVME_DATASET_MANAGEMENT_AUTO:
		if (sc->nvstore.deallocate)
			cd->oncs |= NVME_ONCS_DSM;
		break;
	case NVME_DATASET_MANAGEMENT_ENABLE:
		cd->oncs |= NVME_ONCS_DSM;
		break;
	default:
		break;
	}

	cd->fna = NVMEM(NVME_CTRLR_DATA_FNA_FORMAT_ALL);

	cd->vwc = NVMEF(NVME_CTRLR_DATA_VWC_ALL, NVME_CTRLR_DATA_VWC_ALL_NO);

	ret = snprintf(cd->subnqn, sizeof(cd->subnqn),
	    "nqn.2013-12.org.freebsd:bhyve-%s-%u-%u-%u",
	    get_config_value("name"), sc->nsc_pi->pi_bus,
	    sc->nsc_pi->pi_slot, sc->nsc_pi->pi_func);
	if ((ret < 0) || ((unsigned)ret > sizeof(cd->subnqn)))
		EPRINTLN("%s: error setting subnqn (%d)", __func__, ret);
}

static void
pci_nvme_init_nsdata_size(struct pci_nvme_blockstore *nvstore,
    struct nvme_namespace_data *nd)
{

	/* Get capacity and block size information from backing store */
	nd->nsze = nvstore->size / nvstore->sectsz;
	nd->ncap = nd->nsze;
	nd->nuse = nd->nsze;
}

static void
pci_nvme_init_nsdata(struct pci_nvme_softc *sc,
    struct nvme_namespace_data *nd, uint32_t nsid,
    struct pci_nvme_blockstore *nvstore)
{

	pci_nvme_init_nsdata_size(nvstore, nd);

	if (nvstore->type == NVME_STOR_BLOCKIF)
		nvstore->deallocate = blockif_candelete(nvstore->ctx);

	nd->nlbaf = 0; /* NLBAF is a 0's based value (i.e. 1 LBA Format) */
	nd->flbas = 0;

	/* Create an EUI-64 if user did not provide one */
	if (nvstore->eui64 == 0) {
		char *data = NULL;
		uint64_t eui64 = nvstore->eui64;

		asprintf(&data, "%s%u%u%u", get_config_value("name"),
		    sc->nsc_pi->pi_bus, sc->nsc_pi->pi_slot,
		    sc->nsc_pi->pi_func);

		if (data != NULL) {
			eui64 = OUI_FREEBSD_NVME_LOW | crc16(0, data, strlen(data));
			free(data);
		}
		nvstore->eui64 = (eui64 << 16) | (nsid & 0xffff);
	}
	be64enc(nd->eui64, nvstore->eui64);

	/* LBA data-sz = 2^lbads */
	nd->lbaf[0] = NVMEF(NVME_NS_DATA_LBAF_LBADS, nvstore->sectsz_bits);
}

static void
pci_nvme_init_logpages(struct pci_nvme_softc *sc)
{
	__uint128_t power_cycles = 1;

	memset(&sc->err_log, 0, sizeof(sc->err_log));
	memset(&sc->health_log, 0, sizeof(sc->health_log));
	memset(&sc->fw_log, 0, sizeof(sc->fw_log));
	memset(&sc->ns_log, 0, sizeof(sc->ns_log));

	/* Set read/write remainder to round up according to spec */
	sc->read_dunits_remainder = 999;
	sc->write_dunits_remainder = 999;

	/* Set nominal Health values checked by implementations */
	sc->health_log.temperature = NVME_TEMPERATURE;
	sc->health_log.available_spare = 100;
	sc->health_log.available_spare_threshold = 10;

	/* Set Active Firmware Info to slot 1 */
	sc->fw_log.afi = NVMEF(NVME_FIRMWARE_PAGE_AFI_SLOT, 1);
	memcpy(&sc->fw_log.revision[0], sc->ctrldata.fr,
	    sizeof(sc->fw_log.revision[0]));

	memcpy(&sc->health_log.power_cycles, &power_cycles,
	    sizeof(sc->health_log.power_cycles));
}

static void
pci_nvme_init_features(struct pci_nvme_softc *sc)
{
	enum nvme_feature	fid;

	for (fid = 0; fid < NVME_FID_MAX; fid++) {
		switch (fid) {
		case NVME_FEAT_ARBITRATION:
		case NVME_FEAT_POWER_MANAGEMENT:
		case NVME_FEAT_INTERRUPT_COALESCING: //XXX
		case NVME_FEAT_WRITE_ATOMICITY:
			/* Mandatory but no special handling required */
		//XXX hang - case NVME_FEAT_PREDICTABLE_LATENCY_MODE_CONFIG:
		//XXX hang - case NVME_FEAT_HOST_BEHAVIOR_SUPPORT:
		//		  this returns a data buffer
			break;
		case NVME_FEAT_TEMPERATURE_THRESHOLD:
			sc->feat[fid].set = nvme_feature_temperature;
			break;
		case NVME_FEAT_ERROR_RECOVERY:
			sc->feat[fid].namespace_specific = true;
			break;
		case NVME_FEAT_NUMBER_OF_QUEUES:
			sc->feat[fid].set = nvme_feature_num_queues;
			break;
		case NVME_FEAT_INTERRUPT_VECTOR_CONFIGURATION:
			sc->feat[fid].set = nvme_feature_iv_config;
			break;
		case NVME_FEAT_ASYNC_EVENT_CONFIGURATION:
			sc->feat[fid].set = nvme_feature_async_event;
			/* Enable all AENs by default */
			sc->feat[fid].cdw11 = PCI_NVME_AEN_DEFAULT_MASK;
			break;
		default:
			sc->feat[fid].set = nvme_feature_invalid_cb;
			sc->feat[fid].get = nvme_feature_invalid_cb;
		}
		sc->feat[fid].default_cdw11 = sc->feat[fid].cdw11;
	}
}

static void
pci_nvme_aer_reset(struct pci_nvme_softc *sc)
{

	STAILQ_INIT(&sc->aer_list);
	sc->aer_count = 0;
}

static int
pci_nvme_aer_init(struct pci_nvme_softc *sc)
{
	int error;

	error = pthread_mutex_init(&sc->aer_mtx, NULL);
	if (error != 0)
		return (error);
	pci_nvme_aer_reset(sc);
	return (0);
}

static void
pci_nvme_aer_destroy(struct pci_nvme_softc *sc)
{
	struct pci_nvme_aer *aer = NULL;

	pthread_mutex_lock(&sc->aer_mtx);
	while (!STAILQ_EMPTY(&sc->aer_list)) {
		aer = STAILQ_FIRST(&sc->aer_list);
		STAILQ_REMOVE_HEAD(&sc->aer_list, link);
		free(aer);
	}
	pci_nvme_aer_reset(sc);
	pthread_mutex_unlock(&sc->aer_mtx);
}

/*
 * Add an Async Event Request
 *
 * Stores an AER to be returned later if the Controller needs to notify the
 * host of an event.
 * Note that while the NVMe spec doesn't require Controllers to return AER's
 * in order, this implementation does preserve the order.
 */
static int
pci_nvme_aer_add(struct pci_nvme_softc *sc, uint16_t cid, uint16_t sqhd)
{
	struct pci_nvme_aer *aer = NULL;

	aer = calloc(1, sizeof(struct pci_nvme_aer));
	if (aer == NULL)
		return (-1);

	/* Save the Command ID for use in the completion message */
	aer->cid = cid;
	aer->sqhd = sqhd;

	pthread_mutex_lock(&sc->aer_mtx);
	/* AERL is zero based while aer_count is one based. */
	if (sc->aer_count >= sc->ctrldata.aerl + 1U) {
		pthread_mutex_unlock(&sc->aer_mtx);
		free(aer);
		return (EOVERFLOW);
	}
	sc->aer_count++;
	STAILQ_INSERT_TAIL(&sc->aer_list, aer, link);
	pthread_mutex_unlock(&sc->aer_mtx);

	return (0);
}

/*
 * Get an Async Event Request structure
 *
 * Returns a pointer to an AER previously submitted by the host or NULL if
 * no AER's exist. Caller is responsible for freeing the returned struct.
 */
static struct pci_nvme_aer *
pci_nvme_aer_get(struct pci_nvme_softc *sc)
{
	struct pci_nvme_aer *aer = NULL;

	pthread_mutex_lock(&sc->aer_mtx);
	aer = STAILQ_FIRST(&sc->aer_list);
	if (aer != NULL) {
		STAILQ_REMOVE_HEAD(&sc->aer_list, link);
		sc->aer_count--;
	}
	pthread_mutex_unlock(&sc->aer_mtx);

	return (aer);
}

static void
pci_nvme_aen_reset(struct pci_nvme_softc *sc)
{
	uint32_t	atype;

	memset(sc->aen, 0, PCI_NVME_AE_TYPE_MAX * sizeof(struct pci_nvme_aen));

	for (atype = 0; atype < PCI_NVME_AE_TYPE_MAX; atype++) {
		sc->aen[atype].atype = atype;
	}
}

static int
pci_nvme_aen_init(struct pci_nvme_softc *sc)
{
	char nstr[80];
	int error;

	pci_nvme_aen_reset(sc);

	error = pthread_mutex_init(&sc->aen_mtx, NULL);
	if (error != 0)
		return (error);
	error = pthread_cond_init(&sc->aen_cond, NULL);
	if (error != 0) {
		pthread_mutex_destroy(&sc->aen_mtx);
		return (error);
	}
	error = pthread_create(&sc->aen_tid, NULL, aen_thr, sc);
	if (error != 0) {
		pthread_cond_destroy(&sc->aen_cond);
		pthread_mutex_destroy(&sc->aen_mtx);
		return (error);
	}
	snprintf(nstr, sizeof(nstr), "nvme-aen-%d:%d", sc->nsc_pi->pi_slot,
	    sc->nsc_pi->pi_func);
	pthread_set_name_np(sc->aen_tid, nstr);
	return (0);
}

static void
pci_nvme_aen_destroy(struct pci_nvme_softc *sc)
{

	pthread_mutex_lock(&sc->aen_mtx);
	pci_nvme_aen_reset(sc);
	pthread_mutex_unlock(&sc->aen_mtx);
}

/* Notify the AEN thread of pending work */
static void
pci_nvme_aen_notify(struct pci_nvme_softc *sc)
{

	/* Serialize with the predicate check/cond_wait handoff. */
	pthread_mutex_lock(&sc->aen_mtx);
	pthread_cond_signal(&sc->aen_cond);
	pthread_mutex_unlock(&sc->aen_mtx);
}

/*
 * Post an Asynchronous Event Notification
 */
static int32_t
pci_nvme_aen_post(struct pci_nvme_softc *sc, pci_nvme_async_type atype,
		uint32_t event_data)
{
	struct pci_nvme_aen *aen;

	if (atype >= PCI_NVME_AE_TYPE_MAX) {
		return(EINVAL);
	}

	pthread_mutex_lock(&sc->aen_mtx);
	aen = &sc->aen[atype];

	/* Has the controller already posted an event of this type? */
	if (aen->posted) {
		pthread_mutex_unlock(&sc->aen_mtx);
		return(EALREADY);
	}

	aen->event_data = event_data;
	aen->posted = true;
	pthread_mutex_unlock(&sc->aen_mtx);

	pci_nvme_aen_notify(sc);

	return(0);
}

static void
pci_nvme_aen_process(struct pci_nvme_softc *sc)
{
	struct pci_nvme_aer *aer;
	struct pci_nvme_aen *aen;
	pci_nvme_async_type atype;
	uint32_t mask;
	uint16_t status;
	uint8_t lid;
	bool published;

	assert(pthread_mutex_isowned_np(&sc->aen_mtx));
	for (atype = 0; atype < PCI_NVME_AE_TYPE_MAX; atype++) {
		aen = &sc->aen[atype];
		if (!aen->posted) {
			DPRINTF("%s: no AEN posted for atype=%#x", __func__, atype);
			continue;
		}

		status = NVME_SC_SUCCESS;

		/* Is the event masked? */
		mask =
		    sc->feat[NVME_FEAT_ASYNC_EVENT_CONFIGURATION].cdw11;

		DPRINTF("%s: atype=%#x mask=%#x event_data=%#x", __func__, atype, mask, aen->event_data);
		switch (atype) {
		case PCI_NVME_AE_TYPE_ERROR:
			lid = NVME_LOG_ERROR;
			break;
		case PCI_NVME_AE_TYPE_SMART:
			mask &= 0xff;
			if ((mask & aen->event_data) == 0)
				continue;
			lid = NVME_LOG_HEALTH_INFORMATION;
			break;
		case PCI_NVME_AE_TYPE_NOTICE:
			if (aen->event_data >= PCI_NVME_AEI_NOTICE_MAX) {
				EPRINTLN("%s unknown AEN notice type %u",
				    __func__, aen->event_data);
				status = NVME_SC_INTERNAL_DEVICE_ERROR;
				lid = 0;
				break;
			}
			if ((PCI_NVME_AEI_NOTICE_MASK(aen->event_data) & mask) == 0)
				continue;
			switch (aen->event_data) {
			case PCI_NVME_AEI_NOTICE_NS_ATTR_CHANGED:
				lid = NVME_LOG_CHANGED_NAMESPACE;
				break;
			case PCI_NVME_AEI_NOTICE_FW_ACTIVATION:
				lid = NVME_LOG_FIRMWARE_SLOT;
				break;
			case PCI_NVME_AEI_NOTICE_TELEMETRY_CHANGE:
				lid = NVME_LOG_TELEMETRY_CONTROLLER_INITIATED;
				break;
			case PCI_NVME_AEI_NOTICE_ANA_CHANGE:
				lid = NVME_LOG_ASYMMETRIC_NAMESPACE_ACCESS;
				break;
			case PCI_NVME_AEI_NOTICE_PREDICT_LATENCY_CHANGE:
				lid = NVME_LOG_PREDICTABLE_LATENCY_EVENT_AGGREGATE;
				break;
			case PCI_NVME_AEI_NOTICE_LBA_STATUS_ALERT:
				lid = NVME_LOG_LBA_STATUS_INFORMATION;
				break;
			case PCI_NVME_AEI_NOTICE_ENDURANCE_GROUP_CHANGE:
				lid = NVME_LOG_ENDURANCE_GROUP_EVENT_AGGREGATE;
				break;
			default:
				lid = 0;
			}
			break;
		default:
			/* bad type?!? */
			EPRINTLN("%s unknown AEN type %u", __func__, atype);
			status = NVME_SC_INTERNAL_DEVICE_ERROR;
			lid = 0;
			break;
		}

		aer = pci_nvme_aer_get(sc);
		if (aer == NULL) {
			DPRINTF("%s: no AER", __func__);
			break;
		}

		DPRINTF("%s: CID=%#x CDW0=%#x", __func__, aer->cid, (lid << 16) | (aen->event_data << 8) | atype);
		published = pci_nvme_cq_update(sc, &sc->compl_queues[0],
		    (lid << 16) | (aen->event_data << 8) | atype, /* cdw0 */
		    aer->cid,
		    0,		/* SQID */
		    aer->sqhd,
		    status);

		aen->event_data = 0;
		aen->posted = false;

		if (published)
			pci_generate_msix(sc->nsc_pi, 0);
	}
}

static void *
aen_thr(void *arg)
{
	struct pci_nvme_softc *sc;

	sc = arg;

	pthread_mutex_lock(&sc->aen_mtx);
	for (;;) {
#ifdef BHYVE_SNAPSHOT
		/*
		 * pci_nvme_pause() owns aen_mtx while raising this fence, and
		 * pci_nvme_aen_process() runs entirely under aen_mtx, so once
		 * pause returns no AEN completion can reach guest memory
		 * until pci_nvme_resume() clears the fence and signals.
		 */
		if (!sc->aen_paused)
			pci_nvme_aen_process(sc);
#else
		pci_nvme_aen_process(sc);
#endif
		pthread_cond_wait(&sc->aen_cond, &sc->aen_mtx);
	}
	pthread_mutex_unlock(&sc->aen_mtx);

	pthread_exit(NULL);
	return (NULL);
}

static void
pci_nvme_reset_queues_locked(struct pci_nvme_softc *sc)
{
	uint32_t i;

	assert(sc->pending_ios == 0);

	assert(sc->submit_queues != NULL);

	for (i = 0; i < sc->num_squeues + 1; i++) {
		sc->submit_queues[i].qbase = NULL;
		sc->submit_queues[i].size = 0;
		sc->submit_queues[i].cqid = 0;
		sc->submit_queues[i].tail = 0;
		sc->submit_queues[i].head = 0;
		assert(atomic_load_acq_32(
		    &sc->submit_queues[i].pending_ios) == 0);
	}

	assert(sc->compl_queues != NULL);

	for (i = 0; i < sc->num_cqueues + 1; i++) {
		struct pci_nvme_pending_cqe *pending;

		pthread_mutex_lock(&sc->compl_queues[i].mtx);
		while ((pending = STAILQ_FIRST(
		    &sc->compl_queues[i].pending)) != NULL) {
			STAILQ_REMOVE_HEAD(&sc->compl_queues[i].pending, link);
			free(pending);
		}
		sc->compl_queues[i].pending_count = 0;
		sc->compl_queues[i].qbase = NULL;
		sc->compl_queues[i].size = 0;
		sc->compl_queues[i].tail = 0;
		sc->compl_queues[i].head = 0;
		sc->compl_queues[i].phase = true;
		pthread_mutex_unlock(&sc->compl_queues[i].mtx);
	}
	sc->reset_pending = false;
}

static void
pci_nvme_reset_locked(struct pci_nvme_softc *sc)
{

	DPRINTF("%s", __func__);

	/* Stop accepting doorbells before changing any queue state. */
	sc->regs.csts = 0;
	sc->regs.cap_lo = (ZERO_BASED(sc->max_qentries) & NVME_CAP_LO_REG_MQES_MASK) |
	    NVMEF(NVME_CAP_LO_REG_CQR, 1) |
	    NVMEF(NVME_CAP_LO_REG_TO, 60);

	sc->regs.cap_hi = NVMEF(NVME_CAP_HI_REG_CSS_NVM, 1);
	sc->regs.vs = NVME_REV(1,4);	/* NVMe v1.4 */
	sc->regs.cc = 0;

	sc->num_q_is_set = false;

	/*
	 * Block I/O callbacks retain queue pointers until completion, and an
	 * admitted admin handler can still publish an AER after we drop its
	 * private event lock.  Defer the event purge together with queue
	 * invalidation.  Clearing AER/AEN state before this fence would allow a
	 * late old-incarnation handler to repopulate it for the next enable.
	 */
	if (pci_nvme_reset_must_defer(sc->pending_ios,
	    sc->active_sq_handlers)) {
		sc->reset_pending = true;
		return;
	}
	pci_nvme_aer_destroy(sc);
	pci_nvme_aen_destroy(sc);
	pci_nvme_reset_queues_locked(sc);
}

static void
pci_nvme_maybe_finish_reset_locked(struct pci_nvme_softc *sc)
{

	if (sc->pending_ios != 0 || sc->active_sq_handlers != 0)
		return;
	if (sc->reset_pending) {
		/* Commit every old-incarnation controller owner at one edge. */
		pci_nvme_aer_destroy(sc);
		pci_nvme_aen_destroy(sc);
		pci_nvme_reset_queues_locked(sc);
		if (NVME_CC_GET_EN(sc->regs.cc)) {
			if (pci_nvme_init_controller(sc) != 0)
				sc->regs.csts |= NVME_CSTS_CFS;
			else if (!(sc->regs.csts & NVME_CSTS_CFS))
				sc->regs.csts |= NVME_CSTS_RDY;
		}
	} else if (NVME_CC_GET_EN(sc->regs.cc) &&
	    !(NVME_CSTS_GET_RDY(sc->regs.csts)) &&
	    !(sc->regs.csts & NVME_CSTS_CFS)) {
		sc->regs.csts |= NVME_CSTS_RDY;
	}
}

static bool
pci_nvme_sq_handler_enter(struct pci_nvme_softc *sc)
{
	bool entered;

	pthread_mutex_lock(&sc->mtx);
	entered = !sc->reset_pending;
	if (entered)
		sc->active_sq_handlers++;
	pthread_mutex_unlock(&sc->mtx);
	return (entered);
}

static void
pci_nvme_sq_handler_leave(struct pci_nvme_softc *sc)
{

	pthread_mutex_lock(&sc->mtx);
	assert(sc->active_sq_handlers != 0);
	sc->active_sq_handlers--;
	pci_nvme_maybe_finish_reset_locked(sc);
	pthread_mutex_unlock(&sc->mtx);
}

static void
pci_nvme_reset(struct pci_nvme_softc *sc)
{
	pthread_mutex_lock(&sc->mtx);
	pci_nvme_reset_locked(sc);
	pthread_mutex_unlock(&sc->mtx);
}

static int
pci_nvme_init_controller(struct pci_nvme_softc *sc)
{
	uint16_t acqs, asqs;

	DPRINTF("%s", __func__);

	/*
	 * NVMe 2.0 states that "enabling a controller while this field is
	 * cleared to 0h produces undefined results" for both ACQS and
	 * ASQS. If zero, set CFS and do not become ready.
	 */
	asqs = ONE_BASED(NVMEV(NVME_AQA_REG_ASQS, sc->regs.aqa));
	if (asqs < 2) {
		EPRINTLN("%s: illegal ASQS value %#x (aqa=%#x)", __func__,
		    asqs - 1, sc->regs.aqa);
		sc->regs.csts |= NVME_CSTS_CFS;
		return (-1);
	}
	if (!pci_nvme_queue_base_valid(sc->regs.asq, PAGE_SIZE)) {
		EPRINTLN("%s: ASQ address %#lx is not page aligned", __func__,
		    sc->regs.asq);
		sc->regs.csts |= NVME_CSTS_CFS;
		return (-1);
	}
	sc->submit_queues[0].size = asqs;
	sc->submit_queues[0].qbase = vm_map_gpa(sc->nsc_pi->pi_vmctx,
	    sc->regs.asq, sizeof(struct nvme_command) * asqs);
	if (sc->submit_queues[0].qbase == NULL) {
		EPRINTLN("%s: ASQ vm_map_gpa(%lx) failed", __func__,
		    sc->regs.asq);
		sc->regs.csts |= NVME_CSTS_CFS;
		return (-1);
	}

	DPRINTF("%s mapping Admin-SQ guest 0x%lx, host: %p",
	        __func__, sc->regs.asq, sc->submit_queues[0].qbase);

	acqs = ONE_BASED(NVMEV(NVME_AQA_REG_ACQS, sc->regs.aqa));
	if (acqs < 2) {
		EPRINTLN("%s: illegal ACQS value %#x (aqa=%#x)", __func__,
		    acqs - 1, sc->regs.aqa);
		sc->regs.csts |= NVME_CSTS_CFS;
		return (-1);
	}
	if (!pci_nvme_queue_base_valid(sc->regs.acq, PAGE_SIZE)) {
		EPRINTLN("%s: ACQ address %#lx is not page aligned", __func__,
		    sc->regs.acq);
		sc->regs.csts |= NVME_CSTS_CFS;
		return (-1);
	}
	sc->compl_queues[0].size = acqs;
	sc->compl_queues[0].qbase = vm_map_gpa(sc->nsc_pi->pi_vmctx,
	    sc->regs.acq, sizeof(struct nvme_completion) * acqs);
	if (sc->compl_queues[0].qbase == NULL) {
		EPRINTLN("%s: ACQ vm_map_gpa(%lx) failed", __func__,
		    sc->regs.acq);
		sc->regs.csts |= NVME_CSTS_CFS;
		return (-1);
	}
	sc->compl_queues[0].intr_en = NVME_CQ_INTEN;

	DPRINTF("%s mapping Admin-CQ guest 0x%lx, host: %p",
	        __func__, sc->regs.acq, sc->compl_queues[0].qbase);

	return (0);
}

static int
nvme_prp_memcpy(struct pci_nvme_softc *sc, uint64_t prp1, uint64_t prp2,
    uint8_t *b,
	size_t len, enum nvme_copy_dir dir)
{
	struct pci_devinst *pi;
	uint8_t *last, *p, *prp_list;
	uint64_t list_gpa, prp;
	size_t bytes, list_bytes;
	unsigned int list_hops;

	if (!pci_nvme_prp1_valid(prp1))
		return (-1);
	pi = sc->nsc_pi;

	/* Copy from the start of prp1 to the end of the physical page */
	bytes = PAGE_SIZE - (prp1 & PAGE_MASK);
	bytes = MIN(bytes, len);

	p = pci_emul_map_dma(pi, prp1, bytes, dir == NVME_COPY_TO_PRP ?
	    PCI_DMA_DEVICE_WRITE : PCI_DMA_DEVICE_READ);
	if (p == NULL) {
		return (-1);
	}

	if (dir == NVME_COPY_TO_PRP)
		memcpy(p, b, bytes);
	else
		memcpy(b, p, bytes);

	b += bytes;

	len -= bytes;
	if (len == 0) {
		return (0);
	}
	if (!pci_nvme_prp2_valid(prp2, len, PAGE_SIZE))
		return (-1);
	if (len <= PAGE_SIZE) {
		p = pci_emul_map_dma(pi, prp2, len,
		    dir == NVME_COPY_TO_PRP ? PCI_DMA_DEVICE_WRITE :
		    PCI_DMA_DEVICE_READ);
		if (p == NULL)
			return (-1);
		if (dir == NVME_COPY_TO_PRP)
			memcpy(p, b, len);
		else
			memcpy(b, p, len);
		return (0);
	}

	list_gpa = prp2;
	last = NULL;
	prp_list = NULL;
	list_hops = 0;
	while (len != 0) {
		/* The final entry chains to another list when data remains. */
		if (prp_list == NULL ||
		    (prp_list == last && len > PAGE_SIZE)) {
			if (++list_hops > NVME_MAX_IOVEC)
				return (-1);
			if (prp_list != NULL) {
				prp = le64dec(prp_list);
				if ((prp & PAGE_MASK) != 0)
					return (-1);
				list_gpa = prp;
			}
			list_bytes = pci_nvme_prp_list_bytes(list_gpa,
			    PAGE_SIZE);
			if (list_bytes < sizeof(uint64_t))
				return (-1);
			prp_list = pci_emul_map_dma(pi, list_gpa, list_bytes,
			    PCI_DMA_DEVICE_READ);
			if (prp_list == NULL)
				return (-1);
			last = prp_list + list_bytes - sizeof(uint64_t);
		}

		prp = le64dec(prp_list);
		if ((prp & PAGE_MASK) != 0)
			return (-1);
		bytes = MIN(len, PAGE_SIZE);
		p = pci_emul_map_dma(pi, prp, bytes,
		    dir == NVME_COPY_TO_PRP ? PCI_DMA_DEVICE_WRITE :
		    PCI_DMA_DEVICE_READ);
		if (p == NULL)
			return (-1);
		if (dir == NVME_COPY_TO_PRP)
			memcpy(p, b, bytes);
		else
			memcpy(b, p, bytes);
		b += bytes;
		len -= bytes;
		prp_list += sizeof(uint64_t);
	}

	return (0);
}

/*
 * Write a Completion Queue Entry update
 *
 * Write the completion and update the doorbell value
 */
static bool
pci_nvme_cq_full(const struct nvme_completion_queue *cq)
{

	return (pci_nvme_completion_queue_full(
	    atomic_load_acq_short(&cq->head), cq->tail, cq->size));
}

static void
pci_nvme_cq_publish_locked(struct pci_nvme_softc *sc,
    struct nvme_completion_queue *cq,
    const struct pci_nvme_pending_cqe *pending)
{
	struct nvme_completion *cqe;
	bool wrapped;
	uint16_t status;

	assert(pthread_mutex_isowned_np(&cq->mtx));
	assert(cq->qbase != NULL);
	assert(!pci_nvme_cq_full(cq));

	cqe = &cq->qbase[cq->tail];
	status = pci_nvme_status_with_phase(pending->status, cq->phase);
	cqe->cdw0 = htole32(pending->cdw0);
	cqe->sqhd = htole16(pending->sqhd);
	cqe->sqid = htole16(pending->sqid);
	cqe->cid = htole16(pending->cid);
	cqe->status = htole16(status);
	pci_emul_mark_dma_dirty_mapping(sc->nsc_pi, cqe, sizeof(*cqe));

	cq->tail = pci_nvme_ring_advance(cq->tail, cq->size, &wrapped);
	if (wrapped)
		cq->phase = !cq->phase;
}

static bool
pci_nvme_cq_drain_locked(struct pci_nvme_softc *sc,
    struct nvme_completion_queue *cq)
{
	struct pci_nvme_pending_cqe *pending;
	bool published;

	assert(pthread_mutex_isowned_np(&cq->mtx));
	published = false;
	while (!pci_nvme_cq_full(cq) &&
	    (pending = STAILQ_FIRST(&cq->pending)) != NULL) {
		STAILQ_REMOVE_HEAD(&cq->pending, link);
		cq->pending_count--;
		pci_nvme_cq_publish_locked(sc, cq, pending);
		free(pending);
		published = true;
	}
	return (published);
}

static bool
pci_nvme_cq_update(struct pci_nvme_softc *sc,
		struct nvme_completion_queue *cq,
		uint32_t cdw0,
		uint16_t cid,
		uint16_t sqid,
		uint16_t sqhd,
		uint16_t status)
{
	struct pci_nvme_pending_cqe completion, *pending;
	bool published;

	assert(cq->qbase != NULL);
	/*
	 * sqid indexes a completion for an I/O that was admitted when its
	 * submission queue was valid.  Set Features (Number of Queues) can
	 * lower sc->num_squeues below that sqid while the I/O is still in
	 * flight, so bound the check by the immutable array size (max_queues +
	 * 1 slots) rather than the guest-mutable live count.
	 */
	assert(sqid <= sc->max_queues);
	completion.cdw0 = cdw0;
	completion.sqhd = sqhd;
	completion.sqid = sqid;
	completion.cid = cid;
	completion.status = status;

	pthread_mutex_lock(&cq->mtx);
	if (STAILQ_EMPTY(&cq->pending) && !pci_nvme_cq_full(cq)) {
		pci_nvme_cq_publish_locked(sc, cq, &completion);
		published = true;
	} else if (cq->pending_count >= NVME_MAX_PENDING_CQES ||
	    (pending = malloc(sizeof(*pending))) == NULL) {
		/* Fail closed rather than overwrite an unconsumed CQE. */
		atomic_set_32(&sc->regs.csts, NVME_CSTS_CFS);
		published = false;
	} else {
		*pending = completion;
		STAILQ_INSERT_TAIL(&cq->pending, pending, link);
		cq->pending_count++;
		published = false;
	}
	pthread_mutex_unlock(&cq->mtx);
	return (published);
}

static int
nvme_opc_delete_io_sq(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_submission_queue *sq;
	uint16_t qid = le32toh(command->cdw10) & 0xffff;

	DPRINTF("%s DELETE_IO_SQ %u", __func__, qid);
	if (qid == 0 || qid > sc->num_squeues) {
		WPRINTF("%s NOT PERMITTED queue id %u / num_squeues %u",
		        __func__, qid, sc->num_squeues);
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_QUEUE_IDENTIFIER);
		return (1);
	}
	sq = &sc->submit_queues[qid];
	pthread_mutex_lock(&sq->mtx);
	if (sq->qbase == NULL) {
		pthread_mutex_unlock(&sq->mtx);
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_QUEUE_IDENTIFIER);
		return (1);
	}
	if (atomic_load_acq_32(&sq->pending_ios) != 0) {
		pthread_mutex_unlock(&sq->mtx);
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_QUEUE_DELETION);
		return (1);
	}

	sq->qbase = NULL;
	sq->cqid = 0;
	pthread_mutex_unlock(&sq->mtx);
	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);
	return (1);
}

static int
nvme_opc_create_io_sq(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_command *qbase;
	struct nvme_submission_queue *nsq;
	uint64_t prp1;
	uint32_t cdw10, cdw11;
	uint32_t qsize;
	uint16_t cqid, qid;
	uint8_t qpriority;

	cdw10 = le32toh(command->cdw10);
	cdw11 = le32toh(command->cdw11);
	prp1 = le64toh(command->prp1);
	if (cdw11 & NVME_CMD_CDW11_PC) {
		qid = cdw10 & 0xffff;

		if ((qid == 0) || (qid > sc->num_squeues) ||
		    (sc->submit_queues[qid].qbase != NULL)) {
			WPRINTF("%s queue index %u > num_squeues %u",
			        __func__, qid, sc->num_squeues);
			pci_nvme_status_tc(&compl->status,
			    NVME_SCT_COMMAND_SPECIFIC,
			    NVME_SC_INVALID_QUEUE_IDENTIFIER);
			return (1);
		}
		if (!pci_nvme_queue_base_valid(prp1, PAGE_SIZE)) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INVALID_FIELD);
			return (1);
		}

		qsize = ONE_BASED((cdw10 >> 16) & 0xffff);
		DPRINTF("%s size=%u (max=%u)", __func__, qsize,
		    sc->max_qentries);
		if ((qsize < 2) || (qsize > sc->max_qentries)) {
			/*
			 * Queues must specify at least two entries
			 * NOTE: "MAXIMUM QUEUE SIZE EXCEEDED" was renamed to
			 * "INVALID QUEUE SIZE" in the NVM Express 1.3 Spec
			 */
			pci_nvme_status_tc(&compl->status,
			    NVME_SCT_COMMAND_SPECIFIC,
			    NVME_SC_MAXIMUM_QUEUE_SIZE_EXCEEDED);
			return (1);
		}
		cqid = (cdw11 >> 16) & 0xffff;
		if ((cqid == 0) || (cqid > sc->num_cqueues)) {
			pci_nvme_status_tc(&compl->status,
			    NVME_SCT_COMMAND_SPECIFIC,
			    NVME_SC_INVALID_QUEUE_IDENTIFIER);
			return (1);
		}

		if (sc->compl_queues[cqid].qbase == NULL) {
			pci_nvme_status_tc(&compl->status,
			    NVME_SCT_COMMAND_SPECIFIC,
			    NVME_SC_COMPLETION_QUEUE_INVALID);
			return (1);
		}

		qpriority = (cdw11 >> 1) & 0x03;
		qbase = vm_map_gpa(sc->nsc_pi->pi_vmctx, prp1,
		    sizeof(struct nvme_command) * (size_t)qsize);
		if (qbase == NULL) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INVALID_FIELD);
			return (1);
		}

		/* Publish the queue only after every fallible check has passed. */
		nsq = &sc->submit_queues[qid];
		pthread_mutex_lock(&nsq->mtx);
		nsq->size = qsize;
		nsq->head = nsq->tail = 0;
		nsq->cqid = cqid;
		nsq->qpriority = qpriority;
		nsq->qbase = qbase;
		pthread_mutex_unlock(&nsq->mtx);

		DPRINTF("%s sq %u size %u gaddr %p cqid %u", __func__,
		        qid, nsq->size, nsq->qbase, nsq->cqid);

		pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);

		DPRINTF("%s completed creating IOSQ qid %u",
		         __func__, qid);
	} else {
		/*
		 * Guest sent non-cont submission queue request.
		 * This setting is unsupported by this emulation.
		 */
		WPRINTF("%s unsupported non-contig (list-based) "
		         "create i/o submission queue", __func__);

		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
	}
	return (1);
}

static int
nvme_opc_delete_io_cq(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_completion_queue *cq;
	uint16_t qid = le32toh(command->cdw10) & 0xffff;
	uint16_t sqid;

	DPRINTF("%s DELETE_IO_CQ %u", __func__, qid);
	if (qid == 0 || qid > sc->num_cqueues ||
	    (sc->compl_queues[qid].qbase == NULL)) {
		WPRINTF("%s queue index %u / num_cqueues %u",
		        __func__, qid, sc->num_cqueues);
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_QUEUE_IDENTIFIER);
		return (1);
	}
	cq = &sc->compl_queues[qid];

	/* Deleting an Active CQ is an error */
	for (sqid = 1; sqid < sc->num_squeues + 1; sqid++)
		if (sc->submit_queues[sqid].qbase != NULL &&
		    sc->submit_queues[sqid].cqid == qid) {
			pci_nvme_status_tc(&compl->status,
			    NVME_SCT_COMMAND_SPECIFIC,
			    NVME_SC_INVALID_QUEUE_DELETION);
			return (1);
		}
	pthread_mutex_lock(&cq->mtx);
	if (cq->head != cq->tail || !STAILQ_EMPTY(&cq->pending)) {
		pthread_mutex_unlock(&cq->mtx);
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_QUEUE_DELETION);
		return (1);
	}
	cq->qbase = NULL;
	pthread_mutex_unlock(&cq->mtx);

	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);
	return (1);
}

static int
nvme_opc_create_io_cq(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_completion *qbase;
	struct nvme_completion_queue *ncq;
	uint64_t prp1;
	uint32_t cdw10, cdw11;
	uint32_t qsize;
	uint16_t intr_vec, qid;
	uint8_t intr_en;

	cdw10 = le32toh(command->cdw10);
	cdw11 = le32toh(command->cdw11);
	prp1 = le64toh(command->prp1);
	qid = cdw10 & 0xffff;

	/* Only support Physically Contiguous queues */
	if ((cdw11 & NVME_CMD_CDW11_PC) == 0) {
		WPRINTF("%s unsupported non-contig (list-based) "
		         "create i/o completion queue",
		         __func__);

		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	if ((qid == 0) || (qid > sc->num_cqueues) ||
	    (sc->compl_queues[qid].qbase != NULL)) {
		WPRINTF("%s queue index %u > num_cqueues %u",
			__func__, qid, sc->num_cqueues);
		pci_nvme_status_tc(&compl->status,
		    NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_QUEUE_IDENTIFIER);
		return (1);
 	}
	if (!pci_nvme_queue_base_valid(prp1, PAGE_SIZE)) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	intr_en = (cdw11 & NVME_CMD_CDW11_IEN) >> 1;
	intr_vec = (cdw11 >> 16) & 0xffff;
	if (intr_vec > sc->max_queues) {
		pci_nvme_status_tc(&compl->status,
		    NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_INTERRUPT_VECTOR);
		return (1);
	}

	qsize = ONE_BASED((cdw10 >> 16) & 0xffff);
	if ((qsize < 2) || (qsize > sc->max_qentries))  {
		/*
		 * Queues must specify at least two entries
		 * NOTE: "MAXIMUM QUEUE SIZE EXCEEDED" was renamed to
		 * "INVALID QUEUE SIZE" in the NVM Express 1.3 Spec
		 */
		pci_nvme_status_tc(&compl->status,
		    NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_MAXIMUM_QUEUE_SIZE_EXCEEDED);
		return (1);
	}
	qbase = vm_map_gpa(sc->nsc_pi->pi_vmctx, prp1,
	    sizeof(struct nvme_completion) * (size_t)qsize);
	if (qbase == NULL) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	/* Publish the queue only after every fallible check has passed. */
	ncq = &sc->compl_queues[qid];
	pthread_mutex_lock(&ncq->mtx);
	ncq->intr_en = intr_en;
	ncq->intr_vec = intr_vec;
	ncq->size = qsize;
	ncq->head = ncq->tail = 0;
	ncq->phase = true;
	ncq->qbase = qbase;
	pthread_mutex_unlock(&ncq->mtx);

	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);


	return (1);
}

static int
nvme_opc_get_log_page(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_error_information_entry err_log;
	struct nvme_health_information_page health_log;
	struct nvme_ns_list ns_log;
	uint64_t logoff, numd, prp1, prp2, requested;
	uint32_t cdw10, cdw11, cdw12, cdw13;
	size_t logsize;
	uint8_t logpage;

	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);

	/*
	 * Command specifies the number of dwords to return in fields NUMDU
	 * and NUMDL. This is a zero-based value.
	 */
	cdw10 = le32toh(command->cdw10);
	cdw11 = le32toh(command->cdw11);
	cdw12 = le32toh(command->cdw12);
	cdw13 = le32toh(command->cdw13);
	prp1 = le64toh(command->prp1);
	prp2 = le64toh(command->prp2);
	logpage = cdw10 & 0xFF;
	numd = ((uint64_t)(cdw11 & 0xffff) << 16) | (cdw10 >> 16);
	requested = (numd + 1) * sizeof(uint32_t);
	if (requested > NVME_MAX_DATA_SIZE || requested > SIZE_MAX) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}
	logsize = (size_t)requested;
	logoff = ((uint64_t)cdw13 << 32) | cdw12;
	if (!pci_nvme_log_offset_valid(logoff)) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	DPRINTF("%s log page %u offset %lu len %zu", __func__, logpage,
	    logoff, logsize);

	switch (logpage) {
	case NVME_LOG_ERROR:
		if (logoff >= sizeof(sc->err_log)) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INVALID_FIELD);
			break;
		}

		err_log = sc->err_log;
		nvme_error_information_entry_swapbytes(&err_log);
		if (nvme_prp_memcpy(sc, prp1,
		    prp2, (uint8_t *)&err_log + logoff,
		    MIN(logsize, sizeof(err_log) - logoff),
		    NVME_COPY_TO_PRP) != 0)
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		break;
	case NVME_LOG_HEALTH_INFORMATION:
		if (logoff >= sizeof(sc->health_log)) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INVALID_FIELD);
			break;
		}

		pthread_mutex_lock(&sc->mtx);
		health_log = sc->health_log;
		memcpy(&health_log.data_units_read, &sc->read_data_units,
		    sizeof(health_log.data_units_read));
		memcpy(&health_log.data_units_written, &sc->write_data_units,
		    sizeof(health_log.data_units_written));
		memcpy(&health_log.host_read_commands, &sc->read_commands,
		    sizeof(health_log.host_read_commands));
		memcpy(&health_log.host_write_commands, &sc->write_commands,
		    sizeof(health_log.host_write_commands));
		pthread_mutex_unlock(&sc->mtx);
		nvme_health_information_page_swapbytes(&health_log);

		if (nvme_prp_memcpy(sc, prp1,
		    prp2, (uint8_t *)&health_log + logoff,
		    MIN(logsize, sizeof(health_log) - logoff),
		    NVME_COPY_TO_PRP) != 0)
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		break;
	case NVME_LOG_FIRMWARE_SLOT:
		if (logoff >= sizeof(sc->fw_log)) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INVALID_FIELD);
			break;
		}

		if (nvme_prp_memcpy(sc, prp1,
		    prp2, (uint8_t *)&sc->fw_log + logoff,
		    MIN(logsize, sizeof(sc->fw_log) - logoff),
		    NVME_COPY_TO_PRP) != 0)
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		break;
	case NVME_LOG_CHANGED_NAMESPACE:
		if (logoff >= sizeof(sc->ns_log)) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INVALID_FIELD);
			break;
		}

		pthread_mutex_lock(&sc->mtx);
		ns_log = sc->ns_log;
		pthread_mutex_unlock(&sc->mtx);
		nvme_ns_list_swapbytes(&ns_log);
		if (nvme_prp_memcpy(sc, prp1,
		    prp2, (uint8_t *)&ns_log + logoff,
		    MIN(logsize, sizeof(ns_log) - logoff),
		    NVME_COPY_TO_PRP) != 0) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		} else {
			/*
			 * Do not erase a namespace change posted while the snapshot
			 * was being copied to guest memory.
			 */
			nvme_ns_list_swapbytes(&ns_log);
			pthread_mutex_lock(&sc->mtx);
			if (memcmp(&sc->ns_log, &ns_log,
			    sizeof(sc->ns_log)) == 0)
				memset(&sc->ns_log, 0, sizeof(sc->ns_log));
			pthread_mutex_unlock(&sc->mtx);
		}
		break;
	default:
		DPRINTF("%s get log page %x command not supported",
		        __func__, logpage);

		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_LOG_PAGE);
	}

	return (1);
}

static int
nvme_opc_identify(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_controller_data ctrldata;
	struct nvme_namespace_data nsdata;
	uint8_t data[4096];
	uint64_t prp1, prp2;
	uint32_t cdw10, nsid;
	uint16_t status;
	uint8_t cns;

	cdw10 = le32toh(command->cdw10);
	nsid = le32toh(command->nsid);
	prp1 = le64toh(command->prp1);
	prp2 = le64toh(command->prp2);
	cns = cdw10 & 0xff;

	DPRINTF("%s identify 0x%x nsid 0x%x", __func__,
	        cns, nsid);

	status = 0;
	pci_nvme_status_genc(&status, NVME_SC_SUCCESS);

	switch (cns) {
	case 0x00: /* return Identify Namespace data structure */
		if (nsid != 1) {
			pci_nvme_status_genc(&status,
			    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
			break;
		}
		pthread_mutex_lock(&sc->mtx);
		nsdata = sc->nsdata;
		pthread_mutex_unlock(&sc->mtx);
		nvme_namespace_data_swapbytes(&nsdata);
		if (nvme_prp_memcpy(sc, prp1,
		    prp2, (uint8_t *)&nsdata, sizeof(nsdata),
		    NVME_COPY_TO_PRP) != 0)
			pci_nvme_status_genc(&status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		break;
	case 0x01: /* return Identify Controller data structure */
		ctrldata = sc->ctrldata;
		nvme_controller_data_swapbytes(&ctrldata);
		if (nvme_prp_memcpy(sc, prp1,
		    prp2, (uint8_t *)&ctrldata, sizeof(ctrldata),
		    NVME_COPY_TO_PRP) != 0)
			pci_nvme_status_genc(&status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		break;
	case 0x02: /* list of 1024 active NSIDs > CDW1.NSID */
		memset(data, 0, sizeof(data));
		if (nsid < 1)
			le32enc(data, 1);
		if (nvme_prp_memcpy(sc, prp1, prp2,
		    data, sizeof(data), NVME_COPY_TO_PRP) != 0) {
			pci_nvme_status_genc(&status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		}
		break;
	case 0x03: /* list of NSID structures in CDW1.NSID, 4096 bytes */
		if (nsid != 1) {
			pci_nvme_status_genc(&status,
			    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
			break;
		}
		/* All bytes after the descriptor shall be zero */
		memset(data, 0, sizeof(data));

		/* Return NIDT=1 (i.e. EUI64) descriptor */
		data[0] = 1;
		data[1] = sizeof(uint64_t);
		memcpy(data + 4, sc->nsdata.eui64, sizeof(uint64_t));
		if (nvme_prp_memcpy(sc, prp1, prp2,
		    data, sizeof(data), NVME_COPY_TO_PRP) != 0)
			pci_nvme_status_genc(&status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		break;
	case 0x13:
		/*
		 * Controller list is optional but used by UNH tests. Return
		 * a valid but empty list.
		 */
		memset(data, 0, sizeof(data));
		if (nvme_prp_memcpy(sc, prp1, prp2,
		    data, sizeof(data), NVME_COPY_TO_PRP) != 0) {
			pci_nvme_status_genc(&status,
			    NVME_SC_DATA_TRANSFER_ERROR);
		}
		break;
	default:
		DPRINTF("%s unsupported identify command requested 0x%x",
		         __func__, cns);
		pci_nvme_status_genc(&status, NVME_SC_INVALID_FIELD);
		break;
	}

	compl->status = status;
	return (1);
}

static const char *
nvme_fid_to_name(uint8_t fid)
{
	const char *name;

	switch (fid) {
	case NVME_FEAT_ARBITRATION:
		name = "Arbitration";
		break;
	case NVME_FEAT_POWER_MANAGEMENT:
		name = "Power Management";
		break;
	case NVME_FEAT_LBA_RANGE_TYPE:
		name = "LBA Range Type";
		break;
	case NVME_FEAT_TEMPERATURE_THRESHOLD:
		name = "Temperature Threshold";
		break;
	case NVME_FEAT_ERROR_RECOVERY:
		name = "Error Recovery";
		break;
	case NVME_FEAT_VOLATILE_WRITE_CACHE:
		name = "Volatile Write Cache";
		break;
	case NVME_FEAT_NUMBER_OF_QUEUES:
		name = "Number of Queues";
		break;
	case NVME_FEAT_INTERRUPT_COALESCING:
		name = "Interrupt Coalescing";
		break;
	case NVME_FEAT_INTERRUPT_VECTOR_CONFIGURATION:
		name = "Interrupt Vector Configuration";
		break;
	case NVME_FEAT_WRITE_ATOMICITY:
		name = "Write Atomicity Normal";
		break;
	case NVME_FEAT_ASYNC_EVENT_CONFIGURATION:
		name = "Asynchronous Event Configuration";
		break;
	case NVME_FEAT_AUTONOMOUS_POWER_STATE_TRANSITION:
		name = "Autonomous Power State Transition";
		break;
	case NVME_FEAT_HOST_MEMORY_BUFFER:
		name = "Host Memory Buffer";
		break;
	case NVME_FEAT_TIMESTAMP:
		name = "Timestamp";
		break;
	case NVME_FEAT_KEEP_ALIVE_TIMER:
		name = "Keep Alive Timer";
		break;
	case NVME_FEAT_HOST_CONTROLLED_THERMAL_MGMT:
		name = "Host Controlled Thermal Management";
		break;
	case NVME_FEAT_NON_OP_POWER_STATE_CONFIG:
		name = "Non-Operation Power State Config";
		break;
	case NVME_FEAT_READ_RECOVERY_LEVEL_CONFIG:
		name = "Read Recovery Level Config";
		break;
	case NVME_FEAT_PREDICTABLE_LATENCY_MODE_CONFIG:
		name = "Predictable Latency Mode Config";
		break;
	case NVME_FEAT_PREDICTABLE_LATENCY_MODE_WINDOW:
		name = "Predictable Latency Mode Window";
		break;
	case NVME_FEAT_LBA_STATUS_INFORMATION_ATTRIBUTES:
		name = "LBA Status Information Report Interval";
		break;
	case NVME_FEAT_HOST_BEHAVIOR_SUPPORT:
		name = "Host Behavior Support";
		break;
	case NVME_FEAT_SANITIZE_CONFIG:
		name = "Sanitize Config";
		break;
	case NVME_FEAT_ENDURANCE_GROUP_EVENT_CONFIGURATION:
		name = "Endurance Group Event Configuration";
		break;
	case NVME_FEAT_SOFTWARE_PROGRESS_MARKER:
		name = "Software Progress Marker";
		break;
	case NVME_FEAT_HOST_IDENTIFIER:
		name = "Host Identifier";
		break;
	case NVME_FEAT_RESERVATION_NOTIFICATION_MASK:
		name = "Reservation Notification Mask";
		break;
	case NVME_FEAT_RESERVATION_PERSISTENCE:
		name = "Reservation Persistence";
		break;
	case NVME_FEAT_NAMESPACE_WRITE_PROTECTION_CONFIG:
		name = "Namespace Write Protection Config";
		break;
	default:
		name = "Unknown";
		break;
	}

	return (name);
}

static void
nvme_feature_invalid_cb(struct pci_nvme_softc *sc __unused,
    struct nvme_feature_obj *feat __unused,
    struct nvme_command *command __unused,
    struct nvme_completion *compl)
{
	pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
}

static void
nvme_feature_iv_config(struct pci_nvme_softc *sc,
    struct nvme_feature_obj *feat __unused,
    struct nvme_command *command,
    struct nvme_completion *compl)
{
	uint32_t i;
	uint32_t cdw11 = le32toh(command->cdw11);
	uint16_t iv;
	bool cd;

	pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);

	iv = cdw11 & 0xffff;
	cd = cdw11 & (1 << 16);

	if (iv > sc->max_queues) {
		return;
	}

	/* No Interrupt Coalescing (i.e. not Coalescing Disable) for Admin Q */
	if ((iv == 0) && !cd)
		return;

	/* Requested Interrupt Vector must be used by a CQ */
	for (i = 0; i < sc->num_cqueues + 1; i++) {
		if (sc->compl_queues[i].qbase != NULL &&
		    sc->compl_queues[i].intr_vec == iv) {
			pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);
		}
	}
}

#define NVME_ASYNC_EVENT_ENDURANCE_GROUP		(0x4000)
static void
nvme_feature_async_event(struct pci_nvme_softc *sc __unused,
    struct nvme_feature_obj *feat __unused,
    struct nvme_command *command,
    struct nvme_completion *compl)
{
	if (le32toh(command->cdw11) & NVME_ASYNC_EVENT_ENDURANCE_GROUP)
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
}

#define NVME_TEMP_THRESH_OVER	0
#define NVME_TEMP_THRESH_UNDER	1
static void
nvme_feature_temperature(struct pci_nvme_softc *sc,
    struct nvme_feature_obj *feat __unused,
    struct nvme_command *command,
    struct nvme_completion *compl)
{
	uint32_t cdw11;
	uint16_t	tmpth;	/* Temperature Threshold */
	uint8_t		tmpsel; /* Threshold Temperature Select */
	uint8_t		thsel;  /* Threshold Type Select */
	uint8_t		critical_warning;
	bool		set_crit = false;
	bool		report_crit;

	cdw11 = le32toh(command->cdw11);
	tmpth  = cdw11 & 0xffff;
	tmpsel = (cdw11 >> 16) & 0xf;
	thsel  = (cdw11 >> 20) & 0x3;

	DPRINTF("%s: tmpth=%#x tmpsel=%#x thsel=%#x", __func__, tmpth, tmpsel, thsel);

	/* Check for unsupported values */
	if (((tmpsel != 0) && (tmpsel != 0xf)) ||
	    (thsel > NVME_TEMP_THRESH_UNDER)) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return;
	}

	if (((thsel == NVME_TEMP_THRESH_OVER)  && (NVME_TEMPERATURE >= tmpth)) ||
	    ((thsel == NVME_TEMP_THRESH_UNDER) && (NVME_TEMPERATURE <= tmpth)))
		set_crit = true;

	pthread_mutex_lock(&sc->mtx);
	if (set_crit)
		sc->health_log.critical_warning |=
		    NVME_CRIT_WARN_ST_TEMPERATURE;
	else
		sc->health_log.critical_warning &=
		    ~NVME_CRIT_WARN_ST_TEMPERATURE;
	critical_warning = sc->health_log.critical_warning;
	pthread_mutex_unlock(&sc->mtx);

	pthread_mutex_lock(&sc->aen_mtx);
	report_crit =
	    sc->feat[NVME_FEAT_ASYNC_EVENT_CONFIGURATION].cdw11 &
	    NVME_CRIT_WARN_ST_TEMPERATURE;
	pthread_mutex_unlock(&sc->aen_mtx);

	if (set_crit && report_crit)
		pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_SMART,
		    critical_warning);

	DPRINTF("%s: set_crit=%c critical_warning=%#x status=%#x", __func__,
	    set_crit ? 'T':'F', critical_warning, compl->status);
}

static void
nvme_feature_num_queues(struct pci_nvme_softc *sc,
	    struct nvme_feature_obj *feat,
    struct nvme_command *command,
    struct nvme_completion *compl)
{
	uint32_t cdw11, effective;
	uint32_t proposed_cqueues, proposed_squeues;
	uint16_t ncqr, nsqr;	/* Number of Queues Requested */

	if (sc->num_q_is_set) {
		WPRINTF("%s: Number of Queues already set", __func__);
		pci_nvme_status_genc(&compl->status,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		return;
	}

	cdw11 = le32toh(command->cdw11);
	nsqr = cdw11 & 0xFFFF;
	ncqr = (cdw11 >> 16) & 0xFFFF;
	proposed_squeues = MIN((uint32_t)nsqr + 1U, sc->max_queues);
	proposed_cqueues = MIN((uint32_t)ncqr + 1U, sc->max_queues);
	DPRINTF("NSQR=%u NCQR=%u selected SQ=%u CQ=%u", nsqr, ncqr,
	    proposed_squeues, proposed_cqueues);
	sc->num_squeues = proposed_squeues;
	sc->num_cqueues = proposed_cqueues;

	effective = NVME_FEATURE_NUM_QUEUES(sc);
	feat->cdw11 = effective;
	compl->cdw0 = effective;

	sc->num_q_is_set = true;
}

static int
nvme_opc_set_features(struct pci_nvme_softc *sc, struct nvme_command *command,
	struct nvme_completion *compl)
{
	struct nvme_feature_obj *feat;
	uint32_t cdw10, cdw11, nsid;
	uint8_t fid;
	bool sv;

	cdw10 = le32toh(command->cdw10);
	cdw11 = le32toh(command->cdw11);
	nsid = le32toh(command->nsid);
	fid = NVMEV(NVME_FEAT_SET_FID, cdw10);
	sv = NVMEV(NVME_FEAT_SET_SV, cdw10);

	DPRINTF("%s: Feature ID 0x%x (%s)", __func__, fid, nvme_fid_to_name(fid));

	if (fid >= NVME_FID_MAX) {
		DPRINTF("%s invalid feature 0x%x", __func__, fid);
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	if (sv) {
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_FEATURE_NOT_SAVEABLE);
		return (1);
	}

	feat = &sc->feat[fid];

	if (feat->namespace_specific && nsid != 1) {
		pci_nvme_status_genc(&compl->status,
		    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
		return (1);
	}

	if (!feat->namespace_specific &&
	    !((nsid == 0) || (nsid == NVME_GLOBAL_NAMESPACE_TAG))) {
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_FEATURE_NOT_NS_SPECIFIC);
		return (1);
	}

	compl->cdw0 = 0;
	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);

	if (feat->set)
		feat->set(sc, feat, command, compl);
	else {
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_FEATURE_NOT_CHANGEABLE);
		return (1);
	}

	DPRINTF("%s: status=%#x cdw11=%#x", __func__, compl->status,
	    cdw11);
	if (compl->status == NVME_SC_SUCCESS) {
		if (fid != NVME_FEAT_NUMBER_OF_QUEUES) {
			if (fid == NVME_FEAT_ASYNC_EVENT_CONFIGURATION)
				pthread_mutex_lock(&sc->aen_mtx);
			feat->cdw11 = cdw11;
			if (fid == NVME_FEAT_ASYNC_EVENT_CONFIGURATION)
				pthread_mutex_unlock(&sc->aen_mtx);
		}
		if ((fid == NVME_FEAT_ASYNC_EVENT_CONFIGURATION) &&
		    cdw11 != 0)
			pci_nvme_aen_notify(sc);
	}

	return (0);
}

#define NVME_FEATURES_SEL_SUPPORTED	0x3
#define NVME_FEATURES_NS_SPECIFIC	(1 << 1)
#define NVME_FEATURES_CHANGEABLE		(1 << 2)

static int
nvme_opc_get_features(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl)
{
	struct nvme_feature_obj *feat;
	uint32_t cdw10, nsid;
	uint8_t fid, sel;

	cdw10 = le32toh(command->cdw10);
	nsid = le32toh(command->nsid);
	fid = cdw10 & 0xFF;
	sel = (cdw10 >> 8) & 0x7;

	DPRINTF("%s: Feature ID 0x%x (%s)", __func__, fid, nvme_fid_to_name(fid));

	if (fid >= NVME_FID_MAX) {
		DPRINTF("%s invalid feature 0x%x", __func__, fid);
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}
	if (sel > NVME_FEATURES_SEL_SUPPORTED) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	compl->cdw0 = 0;
	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);

	feat = &sc->feat[fid];
	if (feat->namespace_specific && nsid != 1) {
		pci_nvme_status_genc(&compl->status,
		    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
		return (1);
	}
	if (!feat->namespace_specific && nsid != 0 &&
	    nsid != NVME_GLOBAL_NAMESPACE_TAG) {
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_FEATURE_NOT_NS_SPECIFIC);
		return (1);
	}
	if (feat->get) {
		feat->get(sc, feat, command, compl);
	}

	if (compl->status == NVME_SC_SUCCESS) {
		if (sel == NVME_FEATURES_SEL_SUPPORTED) {
			compl->cdw0 = feat->namespace_specific ?
			    NVME_FEATURES_NS_SPECIFIC : 0;
			if (feat->set != NULL)
				compl->cdw0 |= NVME_FEATURES_CHANGEABLE;
		} else if (sel == 1 || sel == 2) {
			compl->cdw0 = feat->default_cdw11;
		} else {
			if (fid == NVME_FEAT_ASYNC_EVENT_CONFIGURATION)
				pthread_mutex_lock(&sc->aen_mtx);
			compl->cdw0 = feat->cdw11;
			if (fid == NVME_FEAT_ASYNC_EVENT_CONFIGURATION)
				pthread_mutex_unlock(&sc->aen_mtx);
		}
	}

	return (0);
}

static int
nvme_opc_format_nvm(struct pci_nvme_softc* sc, struct nvme_command* command,
	struct nvme_completion* compl, uint16_t sqhd)
{
	void *old_ctx, *replacement;
	uint32_t cdw10, nsid;
	uint8_t	ses, lbaf, pi;

	cdw10 = le32toh(command->cdw10);
	nsid = le32toh(command->nsid);
	if (nsid != 1 && nsid != NVME_GLOBAL_NAMESPACE_TAG) {
		pci_nvme_status_genc(&compl->status,
		    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
		return (1);
	}

	/* Only supports Secure Erase Setting - User Data Erase */
	ses = (cdw10 >> 9) & 0x7;
	if (ses > 0x1) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	/* Only supports a single LBA Format */
	lbaf = cdw10 & 0xf;
	if (lbaf != 0) {
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_INVALID_FORMAT);
		return (1);
	}

	/* Doesn't support Protection Information */
	pi = (cdw10 >> 5) & 0x7;
	if (pi != 0) {
		pci_nvme_status_genc(&compl->status, NVME_SC_INVALID_FIELD);
		return (1);
	}

	if (sc->nvstore.type == NVME_STOR_RAM) {
		replacement = calloc(1, sc->nvstore.size);
		if (replacement == NULL) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INTERNAL_DEVICE_ERROR);
			return (1);
		}
		pthread_mutex_lock(&sc->mtx);
		old_ctx = sc->nvstore.ctx;
		sc->nvstore.ctx = replacement;
		pthread_mutex_unlock(&sc->mtx);
		free(old_ctx);
		pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);
	} else {
		struct pci_nvme_ioreq *req;
		int err;

		req = pci_nvme_get_ioreq(sc);
		if (req == NULL) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INTERNAL_DEVICE_ERROR);
			WPRINTF("%s: unable to allocate IO req", __func__);
			return (1);
		}
		req->nvme_sq = &sc->submit_queues[0];
		req->sqid = 0;
		req->opc = command->opc;
		req->cid = le16toh(command->cid);
		req->sqhd = sqhd;
		req->nsid = le32toh(command->nsid);
		atomic_add_32(&req->nvme_sq->pending_ios, 1);

		req->io_req.br_offset = 0;
		req->io_req.br_resid = sc->nvstore.size;
		req->io_req.br_callback = pci_nvme_io_done;

		err = blockif_delete(sc->nvstore.ctx, &req->io_req);
		if (err) {
			pci_nvme_status_genc(&compl->status,
			    NVME_SC_INTERNAL_DEVICE_ERROR);
			pci_nvme_release_ioreq(sc, req);
		} else
			compl->status = NVME_NO_STATUS;
	}

	return (1);
}

static int
nvme_opc_abort(struct pci_nvme_softc *sc __unused, struct nvme_command *command,
	struct nvme_completion *compl)
{
	uint32_t cdw10;

	cdw10 = le32toh(command->cdw10);
	DPRINTF("%s submission queue %u, command ID 0x%x", __func__,
	        cdw10 & 0xFFFF, (cdw10 >> 16) & 0xFFFF);

	/* TODO: search for the command ID and abort it */

	compl->cdw0 = 1;
	pci_nvme_status_genc(&compl->status, NVME_SC_SUCCESS);
	return (1);
}

static int
nvme_opc_async_event_req(struct pci_nvme_softc* sc,
	struct nvme_command* command, struct nvme_completion* compl,
	uint16_t sqhd)
{
	uint32_t aer_count;

	pthread_mutex_lock(&sc->aer_mtx);
	aer_count = sc->aer_count;
	pthread_mutex_unlock(&sc->aer_mtx);
	DPRINTF("%s async event request count=%u aerl=%u cid=%#x", __func__,
	    aer_count, sc->ctrldata.aerl, le16toh(command->cid));

	switch (pci_nvme_aer_add(sc, le16toh(command->cid), sqhd)) {
	case 0:
		break;
	case EOVERFLOW:
		pci_nvme_status_tc(&compl->status, NVME_SCT_COMMAND_SPECIFIC,
		    NVME_SC_ASYNC_EVENT_REQUEST_LIMIT_EXCEEDED);
		return (1);
	default:
		pci_nvme_status_tc(&compl->status, NVME_SCT_GENERIC,
				NVME_SC_INTERNAL_DEVICE_ERROR);
		return (1);
	}

	/*
	 * Raise events when they happen based on the Set Features cmd.
	 * These events happen async, so only set completion successful if
	 * there is an event reflective of the request to get event.
	 */
	compl->status = NVME_NO_STATUS;
	pci_nvme_aen_notify(sc);

	return (0);
}

static void
pci_nvme_handle_admin_cmd(struct pci_nvme_softc* sc, uint64_t value)
{
	struct nvme_completion compl;
	struct nvme_command command;
	struct nvme_command *cmd;
	struct nvme_submission_queue *sq;
	uint16_t sqhead;
	bool missing, published, publish_one;

	DPRINTF("%s index %u", __func__, (uint32_t)value);

	sq = &sc->submit_queues[0];
	published = false;

	pthread_mutex_lock(&sq->mtx);
	missing = sq->qbase == NULL;
	if (missing || !pci_nvme_doorbell_value_valid(sq->size, value)) {
		pthread_mutex_unlock(&sq->mtx);
		pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_ERROR,
		    missing ? PCI_NVME_AEI_ERROR_INVALID_DB :
		    PCI_NVME_AEI_ERROR_INVALID_DB_VALUE);
		return;
	}
	atomic_store_short(&sq->tail, (uint16_t)value);

	sqhead = sq->head;
	DPRINTF("sqhead %u, tail %u", sqhead, sq->tail);

	while (sqhead != atomic_load_acq_short(&sq->tail)) {
		memcpy(&command, &(sq->qbase)[sqhead], sizeof(command));
		cmd = &command;
		sqhead = (sqhead + 1) % sq->size;
		compl.cdw0 = 0;
		compl.status = 0;

		switch (cmd->opc) {
		case NVME_OPC_DELETE_IO_SQ:
			DPRINTF("%s command DELETE_IO_SQ", __func__);
			nvme_opc_delete_io_sq(sc, cmd, &compl);
			break;
		case NVME_OPC_CREATE_IO_SQ:
			DPRINTF("%s command CREATE_IO_SQ", __func__);
			nvme_opc_create_io_sq(sc, cmd, &compl);
			break;
		case NVME_OPC_DELETE_IO_CQ:
			DPRINTF("%s command DELETE_IO_CQ", __func__);
			nvme_opc_delete_io_cq(sc, cmd, &compl);
			break;
		case NVME_OPC_CREATE_IO_CQ:
			DPRINTF("%s command CREATE_IO_CQ", __func__);
			nvme_opc_create_io_cq(sc, cmd, &compl);
			break;
		case NVME_OPC_GET_LOG_PAGE:
			DPRINTF("%s command GET_LOG_PAGE", __func__);
			nvme_opc_get_log_page(sc, cmd, &compl);
			break;
		case NVME_OPC_IDENTIFY:
			DPRINTF("%s command IDENTIFY", __func__);
			nvme_opc_identify(sc, cmd, &compl);
			break;
		case NVME_OPC_ABORT:
			DPRINTF("%s command ABORT", __func__);
			nvme_opc_abort(sc, cmd, &compl);
			break;
		case NVME_OPC_SET_FEATURES:
			DPRINTF("%s command SET_FEATURES", __func__);
			nvme_opc_set_features(sc, cmd, &compl);
			break;
		case NVME_OPC_GET_FEATURES:
			DPRINTF("%s command GET_FEATURES", __func__);
			nvme_opc_get_features(sc, cmd, &compl);
			break;
		case NVME_OPC_FIRMWARE_ACTIVATE:
			DPRINTF("%s command FIRMWARE_ACTIVATE", __func__);
			pci_nvme_status_tc(&compl.status,
			    NVME_SCT_COMMAND_SPECIFIC,
			    NVME_SC_INVALID_FIRMWARE_SLOT);
			break;
		case NVME_OPC_ASYNC_EVENT_REQUEST:
			DPRINTF("%s command ASYNC_EVENT_REQ", __func__);
			nvme_opc_async_event_req(sc, cmd, &compl, sqhead);
			break;
		case NVME_OPC_FORMAT_NVM:
			DPRINTF("%s command FORMAT_NVM", __func__);
			if (NVMEV(NVME_CTRLR_DATA_OACS_FORMAT,
			    sc->ctrldata.oacs) == 0) {
				pci_nvme_status_genc(&compl.status, NVME_SC_INVALID_OPCODE);
				break;
			}
			nvme_opc_format_nvm(sc, cmd, &compl, sqhead);
			break;
		case NVME_OPC_SECURITY_SEND:
		case NVME_OPC_SECURITY_RECEIVE:
		case NVME_OPC_SANITIZE:
		case NVME_OPC_GET_LBA_STATUS:
			DPRINTF("%s command OPC=%#x (unsupported)", __func__,
			    cmd->opc);
			/* Valid but unsupported opcodes */
			pci_nvme_status_genc(&compl.status, NVME_SC_INVALID_FIELD);
			break;
		default:
			DPRINTF("%s command OPC=%#X (not implemented)",
			    __func__,
			    cmd->opc);
			pci_nvme_status_genc(&compl.status, NVME_SC_INVALID_OPCODE);
		}
		if (NVME_COMPLETION_VALID(compl)) {
			publish_one = pci_nvme_cq_update(sc,
			    &sc->compl_queues[0],
			    compl.cdw0,
			    le16toh(cmd->cid),
			    0,		/* SQID */
			    sqhead,
			    compl.status);
			published |= publish_one;
		}
	}

	DPRINTF("setting sqhead %u", sqhead);
	sq->head = sqhead;

	if (published)
		pci_generate_msix(sc->nsc_pi, 0);

	pthread_mutex_unlock(&sq->mtx);
}

/*
 * Update the Write and Read statistics reported in SMART data
 *
 * NVMe defines "data unit" as thousand's of 512 byte blocks and is rounded up.
 * E.g. 1 data unit is 1 - 1,000 512 byte blocks. 3 data units are 2,001 - 3,000
 * 512 byte blocks. Rounding up is achieved by initializing the remainder to 999.
 */
static void
pci_nvme_stats_write_read_update(struct pci_nvme_softc *sc, uint8_t opc,
    size_t bytes, uint16_t status)
{

	pthread_mutex_lock(&sc->mtx);
	switch (opc) {
	case NVME_OPC_WRITE:
		sc->write_commands++;
		if (status != NVME_SC_SUCCESS)
			break;
		sc->write_dunits_remainder += (bytes / 512);
		while (sc->write_dunits_remainder >= 1000) {
			sc->write_data_units++;
			sc->write_dunits_remainder -= 1000;
		}
		break;
	case NVME_OPC_READ:
		sc->read_commands++;
		if (status != NVME_SC_SUCCESS)
			break;
		sc->read_dunits_remainder += (bytes / 512);
		while (sc->read_dunits_remainder >= 1000) {
			sc->read_data_units++;
			sc->read_dunits_remainder -= 1000;
		}
		break;
	default:
		DPRINTF("%s: Invalid OPC 0x%02x for stats", __func__, opc);
		break;
	}
	pthread_mutex_unlock(&sc->mtx);
}

/*
 * Check if the combination of Starting LBA (slba) and number of blocks
 * exceeds the range of the underlying storage.
 *
 * Because NVMe specifies the SLBA in blocks as a uint64_t and blockif stores
 * the capacity in bytes as a uint64_t, care must be taken to avoid integer
 * overflow.
 */
static bool
pci_nvme_out_of_range(struct pci_nvme_blockstore *nvstore, uint64_t slba,
    uint32_t nblocks)
{
	uint64_t offset, bytes;

	/* Overflow check of multiplying Starting LBA by the sector size */
	if (nvstore->sectsz_bits >= 64 ||
	    slba > (UINT64_MAX >> nvstore->sectsz_bits) ||
	    nblocks > (UINT64_MAX >> nvstore->sectsz_bits))
		return (true);

	offset = slba << nvstore->sectsz_bits;
	bytes = (uint64_t)nblocks << nvstore->sectsz_bits;

	/* Overflow check of Number of Logical Blocks */
	if ((nvstore->size <= offset) || ((nvstore->size - offset) < bytes))
		return (true);

	return (false);
}

static int
pci_nvme_append_iov_req(struct pci_nvme_softc *sc,
    struct pci_nvme_ioreq *req, uint64_t gpaddr, size_t size, uint64_t offset,
    bool device_writes)
{
	int iovidx;
	size_t combined_size;
	bool range_is_contiguous;

	if (req == NULL)
		return (-1);

	if (req->io_req.br_iovcnt == NVME_MAX_IOVEC) {
		return (-1);
	}

	/*
	 * Minimize the number of IOVs by concatenating contiguous address
	 * ranges. If the IOV count is zero, there is no previous range to
	 * concatenate.
	 */
	if (req->io_req.br_iovcnt == 0)
		range_is_contiguous = false;
	else if (req->prev_gpaddr > UINT64_MAX - req->prev_size)
		range_is_contiguous = false;
	else
		range_is_contiguous =
		    (req->prev_gpaddr + req->prev_size) == gpaddr;

	if (range_is_contiguous) {
		iovidx = req->io_req.br_iovcnt - 1;
		if (SIZE_MAX - req->prev_size < size)
			return (-1);
		combined_size = req->prev_size + size;

		req->io_req.br_iov[iovidx].iov_base = pci_emul_map_dma(
		    sc->nsc_pi, req->prev_gpaddr, combined_size,
		    device_writes ? PCI_DMA_DEVICE_WRITE : PCI_DMA_DEVICE_READ);
		if (req->io_req.br_iov[iovidx].iov_base == NULL)
			return (-1);

		req->prev_size = combined_size;
		req->io_req.br_resid += size;

		req->io_req.br_iov[iovidx].iov_len = req->prev_size;
	} else {
		iovidx = req->io_req.br_iovcnt;
		if (iovidx == 0) {
			req->io_req.br_offset = offset;
			req->io_req.br_resid = 0;
			req->io_req.br_param = req;
		}

		req->io_req.br_iov[iovidx].iov_base = pci_emul_map_dma(
		    sc->nsc_pi, gpaddr, size, device_writes ?
		    PCI_DMA_DEVICE_WRITE : PCI_DMA_DEVICE_READ);
		if (req->io_req.br_iov[iovidx].iov_base == NULL)
			return (-1);

		req->io_req.br_iov[iovidx].iov_len = size;

		req->prev_gpaddr = gpaddr;
		req->prev_size = size;
		req->io_req.br_resid += size;

		req->io_req.br_iovcnt++;
	}

	return (0);
}

static void
pci_nvme_set_completion(struct pci_nvme_softc *sc,
    struct nvme_submission_queue *sq, int sqid, uint16_t sqhd, uint16_t cid,
    uint16_t status)
{
	struct nvme_completion_queue *cq = &sc->compl_queues[sq->cqid];
	bool published;

	DPRINTF("%s sqid %d cqid %u cid %u status: 0x%x 0x%x",
		 __func__, sqid, sq->cqid, cid, NVME_STATUS_GET_SCT(status),
		 NVME_STATUS_GET_SC(status));

	published = pci_nvme_cq_update(sc, cq, 0, cid, sqid, sqhd, status);

	if (published) {
		if (cq->intr_en & NVME_CQ_INTEN) {
			pci_generate_msix(sc->nsc_pi, cq->intr_vec);
		} else {
			DPRINTF("%s: CQ%u interrupt disabled",
						__func__, sq->cqid);
		}
	}
}

static void
pci_nvme_release_ioreq(struct pci_nvme_softc *sc, struct pci_nvme_ioreq *req)
{
	struct nvme_submission_queue *sq;

	sq = req->nvme_sq;
	assert(sq != NULL);
	assert(atomic_load_acq_32(&sq->pending_ios) != 0);
	atomic_subtract_32(&sq->pending_ios, 1);
	req->sc = NULL;
	req->nvme_sq = NULL;
	req->sqid = 0;
	req->sqhd = 0;

	pthread_mutex_lock(&sc->mtx);

	STAILQ_INSERT_TAIL(&sc->ioreqs_free, req, link);
	sc->pending_ios--;

	pci_nvme_maybe_finish_reset_locked(sc);

	pthread_mutex_unlock(&sc->mtx);

	sem_post(&sc->iosemlock);
}

static struct pci_nvme_ioreq *
pci_nvme_get_ioreq(struct pci_nvme_softc *sc)
{
	struct pci_nvme_ioreq *req = NULL;

	while (sem_wait(&sc->iosemlock) != 0) {
		if (errno == EINTR)
			continue;
		/* A live, initialized semaphore has no other recoverable error. */
		abort();
	}
	pthread_mutex_lock(&sc->mtx);

	req = STAILQ_FIRST(&sc->ioreqs_free);
	assert(req != NULL);
	STAILQ_REMOVE_HEAD(&sc->ioreqs_free, link);

	req->sc = sc;

	sc->pending_ios++;

	pthread_mutex_unlock(&sc->mtx);

	req->io_req.br_iovcnt = 0;
	req->io_req.br_offset = 0;
	req->io_req.br_resid = 0;
	req->io_req.br_param = req;
	req->prev_gpaddr = 0;
	req->prev_size = 0;

	return req;
}

static void
pci_nvme_io_done(struct blockif_req *br, int err)
{
	struct pci_nvme_ioreq *req = br->br_param;
	struct nvme_submission_queue *sq = req->nvme_sq;
	uint16_t code, status;
	int i;

	DPRINTF("%s error %d %s", __func__, err, strerror(err));

	/* TODO return correct error */
	code = err ? NVME_SC_DATA_TRANSFER_ERROR : NVME_SC_SUCCESS;
	status = 0;
	pci_nvme_status_genc(&status, code);
	if (err == 0 && req->opc == NVME_OPC_READ) {
		for (i = 0; i < br->br_iovcnt; i++)
			pci_emul_mark_dma_dirty_mapping(req->sc->nsc_pi,
			    br->br_iov[i].iov_base, br->br_iov[i].iov_len);
	}

	pci_nvme_set_completion(req->sc, sq, req->sqid, req->sqhd, req->cid,
	    status);
	pci_nvme_stats_write_read_update(req->sc, req->opc,
	    req->bytes, status);
	pci_nvme_release_ioreq(req->sc, req);
}

/*
 * Implements the Flush command. The specification states:
 *    If a volatile write cache is not present, Flush commands complete
 *    successfully and have no effect
 * in the description of the Volatile Write Cache (VWC) field of the Identify
 * Controller data. Therefore, set status to Success if the command is
 * not supported (i.e. RAM or as indicated by the blockif).
 */
static bool
nvme_opc_flush(struct pci_nvme_softc *sc __unused,
    struct nvme_command *cmd __unused,
    struct pci_nvme_blockstore *nvstore,
    struct pci_nvme_ioreq *req,
    uint16_t *status)
{
	bool pending = false;

	if (nvstore->type == NVME_STOR_RAM) {
		pci_nvme_status_genc(status, NVME_SC_SUCCESS);
	} else {
		int err;

		req->io_req.br_callback = pci_nvme_io_done;

		err = blockif_flush(nvstore->ctx, &req->io_req);
		switch (err) {
		case 0:
			pending = true;
			break;
		case EOPNOTSUPP:
			pci_nvme_status_genc(status, NVME_SC_SUCCESS);
			break;
		default:
			pci_nvme_status_genc(status, NVME_SC_INTERNAL_DEVICE_ERROR);
		}
	}

	return (pending);
}

static uint16_t
nvme_write_read_ram(struct pci_nvme_softc *sc,
    struct pci_nvme_blockstore *nvstore,
    uint64_t prp1, uint64_t prp2,
    size_t offset, uint64_t bytes,
    bool is_write)
{
	uint8_t *buf;
	enum nvme_copy_dir dir;
	uint16_t status;

	/*
	 * A guest WRITE copies from its PRPs into the namespace; a guest READ
	 * copies namespace data to its PRPs.  Keep this in command direction,
	 * rather than backend-buffer direction, to avoid silently reversing RAM
	 * namespace I/O.
	 */
	if (pci_nvme_command_copies_to_guest(is_write))
		dir = NVME_COPY_TO_PRP;
	else
		dir = NVME_COPY_FROM_PRP;

	status = 0;
	pthread_mutex_lock(&sc->mtx);
	buf = nvstore->ctx;
	if (nvme_prp_memcpy(sc, prp1, prp2,
	    buf + offset, bytes, dir))
		pci_nvme_status_genc(&status,
		    NVME_SC_DATA_TRANSFER_ERROR);
	else
		pci_nvme_status_genc(&status, NVME_SC_SUCCESS);
	pthread_mutex_unlock(&sc->mtx);

	return (status);
}

static uint16_t
nvme_write_read_blockif(struct pci_nvme_softc *sc,
    struct pci_nvme_blockstore *nvstore,
    struct pci_nvme_ioreq *req,
    uint64_t prp1, uint64_t prp2,
    size_t offset, uint64_t bytes,
    bool is_write)
{
	uint64_t size;
	int err;
	uint16_t status = NVME_NO_STATUS;

	size = MIN(PAGE_SIZE - (prp1 % PAGE_SIZE), bytes);
	if (pci_nvme_append_iov_req(sc, req, prp1, size, offset,
	    !is_write)) {
		err = -1;
		goto out;
	}

	offset += size;
	bytes  -= size;

	if (bytes == 0) {
		;
	} else if (bytes <= PAGE_SIZE) {
		size = bytes;
		if (!pci_nvme_prp2_valid(prp2, bytes, PAGE_SIZE)) {
			err = -1;
			goto out;
		}
		if (pci_nvme_append_iov_req(sc, req, prp2, size, offset,
		    !is_write)) {
			err = -1;
			goto out;
		}
	} else {
		uint8_t *last, *prp_list;
		uint64_t list_gpa, prp;
		size_t list_bytes;
		unsigned int list_hops;

		if (!pci_nvme_prp2_valid(prp2, bytes, PAGE_SIZE)) {
			err = -1;
			goto out;
		}
		list_gpa = prp2;
		last = NULL;
		prp_list = NULL;
		list_hops = 0;

		/* PRP2 is pointer to a physical region page list */
		while (bytes) {
			/* Last entry in list points to the next list */
			if (prp_list == NULL ||
			    (prp_list == last && bytes > PAGE_SIZE)) {
				if (++list_hops > NVME_MAX_IOVEC) {
					err = -1;
					goto out;
				}
				if (prp_list != NULL) {
					prp = le64dec(prp_list);
					if ((prp & PAGE_MASK) != 0) {
						err = -1;
						goto out;
					}
					list_gpa = prp;
				}
				list_bytes = pci_nvme_prp_list_bytes(list_gpa,
				    PAGE_SIZE);
				if (list_bytes < sizeof(uint64_t)) {
					err = -1;
					goto out;
				}
				prp_list = pci_emul_map_dma(sc->nsc_pi, list_gpa,
				    list_bytes, PCI_DMA_DEVICE_READ);
				if (prp_list == NULL) {
					err = -1;
					goto out;
				}
				last = prp_list + list_bytes - sizeof(uint64_t);
			}

			size = MIN(bytes, PAGE_SIZE);
			prp = le64dec(prp_list);
			if ((prp & PAGE_MASK) != 0 ||
			    pci_nvme_append_iov_req(sc, req, prp, size,
			    offset, !is_write)) {
				err = -1;
				goto out;
			}

			offset += size;
			bytes  -= size;

			prp_list += sizeof(uint64_t);
		}
	}
	req->io_req.br_callback = pci_nvme_io_done;
	if (is_write)
		err = blockif_write(nvstore->ctx, &req->io_req);
	else
		err = blockif_read(nvstore->ctx, &req->io_req);
out:
	if (err)
		pci_nvme_status_genc(&status, NVME_SC_DATA_TRANSFER_ERROR);

	return (status);
}

static bool
nvme_opc_write_read(struct pci_nvme_softc *sc,
    struct nvme_command *cmd,
    struct pci_nvme_blockstore *nvstore,
    struct pci_nvme_ioreq *req,
    uint16_t *status)
{
	uint64_t lba, nblocks, bytes, prp1, prp2;
	uint32_t cdw10, cdw11, cdw12;
	size_t offset;
	bool is_write = cmd->opc == NVME_OPC_WRITE;
	bool pending = false;

	cdw10 = le32toh(cmd->cdw10);
	cdw11 = le32toh(cmd->cdw11);
	cdw12 = le32toh(cmd->cdw12);
	lba = ((uint64_t)cdw11 << 32) | cdw10;
	nblocks = (cdw12 & 0xFFFF) + 1;
	bytes = nblocks << nvstore->sectsz_bits;
	if (bytes > NVME_MAX_DATA_SIZE) {
		WPRINTF("%s command would exceed MDTS", __func__);
		pci_nvme_status_genc(status, NVME_SC_INVALID_FIELD);
		goto out;
	}

	if (pci_nvme_out_of_range(nvstore, lba, nblocks)) {
		WPRINTF("%s command would exceed LBA range(slba=%#lx nblocks=%#lx)",
		    __func__, lba, nblocks);
		pci_nvme_status_genc(status, NVME_SC_LBA_OUT_OF_RANGE);
		goto out;
	}

	offset = lba << nvstore->sectsz_bits;

	req->bytes = bytes;
	req->io_req.br_offset = lba;

	prp1 = le64toh(cmd->prp1);
	prp2 = le64toh(cmd->prp2);
	if (!pci_nvme_prp1_valid(prp1)) {
		pci_nvme_status_genc(status, NVME_SC_INVALID_FIELD);
		goto out;
	}

	if (nvstore->type == NVME_STOR_RAM) {
		*status = nvme_write_read_ram(sc, nvstore, prp1,
		    prp2, offset, bytes, is_write);
	} else {
		*status = nvme_write_read_blockif(sc, nvstore, req,
		    prp1, prp2, offset, bytes, is_write);

		if (*status == NVME_NO_STATUS)
			pending = true;
	}
out:
	if (!pending)
		pci_nvme_stats_write_read_update(sc, cmd->opc, bytes, *status);

	return (pending);
}

static void
pci_nvme_dealloc_sm(struct blockif_req *br, int err)
{
	struct pci_nvme_ioreq *req = br->br_param;
	struct pci_nvme_softc *sc = req->sc;
	bool done = true;
	uint16_t status;

	status = 0;
	if (err) {
		pci_nvme_status_genc(&status, NVME_SC_INTERNAL_DEVICE_ERROR);
	} else if ((req->prev_gpaddr + 1) == (req->prev_size)) {
		pci_nvme_status_genc(&status, NVME_SC_SUCCESS);
	} else {
		struct iovec *iov = req->io_req.br_iov;

		req->prev_gpaddr++;
		iov += req->prev_gpaddr;

		/* The iov_* values already include the sector size */
		req->io_req.br_offset = (off_t)iov->iov_base;
		req->io_req.br_resid = iov->iov_len;
		if (blockif_delete(sc->nvstore.ctx, &req->io_req)) {
			pci_nvme_status_genc(&status,
			    NVME_SC_INTERNAL_DEVICE_ERROR);
		} else
			done = false;
	}

	if (done) {
		pci_nvme_set_completion(sc, req->nvme_sq, req->sqid, req->sqhd,
		    req->cid, status);
		pci_nvme_release_ioreq(sc, req);
	}
}

static bool
nvme_opc_dataset_mgmt(struct pci_nvme_softc *sc,
    struct nvme_command *cmd,
    struct pci_nvme_blockstore *nvstore,
    struct pci_nvme_ioreq *req,
    uint16_t *status)
{
	struct nvme_dsm_range *range = NULL;
	size_t range_bytes;
	uint64_t prp1, prp2;
	uint32_t attributes, nr, r, non_zero, dr;
	int err;
	bool pending = false;

	if ((sc->ctrldata.oncs & NVME_ONCS_DSM) == 0) {
		pci_nvme_status_genc(status, NVME_SC_INVALID_OPCODE);
		goto out;
	}

	nr = le32toh(cmd->cdw10) & 0xff;
	attributes = le32toh(cmd->cdw11);
	range_bytes = pci_nvme_dsm_range_bytes((uint8_t)nr);
	assert(range_bytes == ((size_t)nr + 1) * sizeof(*range));
	prp1 = le64toh(cmd->prp1);
	prp2 = le64toh(cmd->prp2);

	/* copy locally because a range entry could straddle PRPs */
	range = calloc(1, range_bytes);
	if (range == NULL) {
		pci_nvme_status_genc(status, NVME_SC_INTERNAL_DEVICE_ERROR);
		goto out;
	}
	if (nvme_prp_memcpy(sc, prp1, prp2,
	    (uint8_t *)range, range_bytes,
	    NVME_COPY_FROM_PRP) != 0) {
		pci_nvme_status_genc(status, NVME_SC_DATA_TRANSFER_ERROR);
		goto out;
	}

	/* Check for invalid ranges and the number of non-zero lengths */
	non_zero = 0;
	for (r = 0; r <= nr; r++) {
		range[r].attributes = le32toh(range[r].attributes);
		range[r].length = le32toh(range[r].length);
		range[r].starting_lba = le64toh(range[r].starting_lba);
		if (range[r].length != 0 && pci_nvme_out_of_range(nvstore,
		    range[r].starting_lba, range[r].length)) {
			pci_nvme_status_genc(status, NVME_SC_LBA_OUT_OF_RANGE);
			goto out;
		}
		if (range[r].length != 0)
			non_zero++;
	}

	if (attributes & NVME_DSM_ATTR_DEALLOCATE) {
		size_t offset, bytes;
		int sectsz_bits = sc->nvstore.sectsz_bits;

		/*
		 * DSM calls are advisory only, and compliant controllers
		 * may choose to take no actions (i.e. return Success).
		 */
		if (!nvstore->deallocate) {
			pci_nvme_status_genc(status, NVME_SC_SUCCESS);
			goto out;
		}

		/* If all ranges have a zero length, return Success */
		if (non_zero == 0) {
			pci_nvme_status_genc(status, NVME_SC_SUCCESS);
			goto out;
		}

		if (req == NULL) {
			pci_nvme_status_genc(status, NVME_SC_INTERNAL_DEVICE_ERROR);
			goto out;
		}

		offset = range[0].starting_lba << sectsz_bits;
		bytes = range[0].length << sectsz_bits;

		/*
		 * If the request is for more than a single range, store
		 * the ranges in the br_iov. Optimize for the common case
		 * of a single range.
		 *
		 * Note that NVMe Number of Ranges is a zero based value
		 */
		req->io_req.br_iovcnt = 0;
		req->io_req.br_offset = offset;
		req->io_req.br_resid = bytes;

		if (nr == 0) {
			req->io_req.br_callback = pci_nvme_io_done;
		} else {
			struct iovec *iov = req->io_req.br_iov;
			uint64_t first_offset;
			size_t first_length;

			for (r = 0, dr = 0; r <= nr; r++) {
				offset = range[r].starting_lba << sectsz_bits;
				bytes = range[r].length << sectsz_bits;
				if (bytes == 0)
					continue;

				if ((nvstore->size - offset) < bytes) {
					pci_nvme_status_genc(status,
					    NVME_SC_LBA_OUT_OF_RANGE);
					goto out;
				}
				iov[dr].iov_base = (void *)offset;
				iov[dr].iov_len = bytes;
				dr++;
			}
			/*
			 * The compacted array, rather than range[0], defines the
			 * asynchronous deletion cursor.  In particular, range[0] is
			 * allowed to have zero length while a later range requests real
			 * deallocation.  Submitting the pre-compaction values would issue
			 * a zero-length delete and pci_nvme_dealloc_sm() would then regard
			 * the only compacted entry as already complete.
			 */
			if (dr == 0 || !pci_nvme_dsm_cursor_initialize(dr,
			    (uintptr_t)iov[0].iov_base, iov[0].iov_len,
			    &first_offset, &first_length)) {
				pci_nvme_status_genc(status, NVME_SC_SUCCESS);
				goto out;
			}
			req->io_req.br_offset = (off_t)first_offset;
			req->io_req.br_resid = first_length;
			req->io_req.br_callback = pci_nvme_dealloc_sm;

			/*
			 * Use prev_gpaddr to track the current entry and
			 * prev_size to track the number of entries
			 */
			req->prev_gpaddr = 0;
			req->prev_size = dr;
		}

		err = blockif_delete(nvstore->ctx, &req->io_req);
		if (err)
			pci_nvme_status_genc(status, NVME_SC_INTERNAL_DEVICE_ERROR);
		else
			pending = true;
	}
out:
	free(range);
	return (pending);
}

static void
pci_nvme_handle_io_cmd(struct pci_nvme_softc* sc, uint16_t idx, uint64_t value)
{
	struct nvme_submission_queue *sq;
	uint16_t status;
	uint16_t sqhead;
	bool missing;

	/* handle all submissions up to sq->tail index */
	sq = &sc->submit_queues[idx];

	pthread_mutex_lock(&sq->mtx);
	missing = sq->qbase == NULL;
	if (missing || !pci_nvme_doorbell_value_valid(sq->size, value)) {
		pthread_mutex_unlock(&sq->mtx);
		pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_ERROR,
		    missing ? PCI_NVME_AEI_ERROR_INVALID_DB :
		    PCI_NVME_AEI_ERROR_INVALID_DB_VALUE);
		return;
	}
	atomic_store_short(&sq->tail, (uint16_t)value);

	sqhead = sq->head;
	DPRINTF("nvme_handle_io qid %u head %u tail %u cmdlist %p",
	         idx, sqhead, sq->tail, sq->qbase);

	while (sqhead != atomic_load_acq_short(&sq->tail)) {
		struct nvme_command command;
		struct nvme_command *cmd;
		struct pci_nvme_ioreq *req;
		uint32_t nsid;
		bool pending;

		pending = false;
		req = NULL;
		status = 0;

		memcpy(&command, &sq->qbase[sqhead], sizeof(command));
		cmd = &command;
		sqhead = (sqhead + 1) % sq->size;

		nsid = le32toh(cmd->nsid);
		if ((nsid == 0) || (nsid > sc->ctrldata.nn)) {
			pci_nvme_status_genc(&status,
			    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
			status |= NVMEM(NVME_STATUS_DNR);
			goto complete;
 		}

		req = pci_nvme_get_ioreq(sc);
		if (req == NULL) {
			pci_nvme_status_genc(&status,
			    NVME_SC_INTERNAL_DEVICE_ERROR);
			WPRINTF("%s: unable to allocate IO req", __func__);
			goto complete;
		}
		req->nvme_sq = sq;
		req->sqid = idx;
		req->opc = cmd->opc;
		req->cid = le16toh(cmd->cid);
		req->sqhd = sqhead;
		req->nsid = nsid;
		atomic_add_32(&sq->pending_ios, 1);

		switch (cmd->opc) {
		case NVME_OPC_FLUSH:
			pending = nvme_opc_flush(sc, cmd, &sc->nvstore,
			    req, &status);
 			break;
		case NVME_OPC_WRITE:
		case NVME_OPC_READ:
			pending = nvme_opc_write_read(sc, cmd, &sc->nvstore,
			    req, &status);
			break;
		case NVME_OPC_WRITE_ZEROES:
			/* The controller does not advertise Write Zeroes in ONCS. */
			pci_nvme_status_genc(&status, NVME_SC_INVALID_OPCODE);
			break;
		case NVME_OPC_DATASET_MANAGEMENT:
 			pending = nvme_opc_dataset_mgmt(sc, cmd, &sc->nvstore,
			    req, &status);
			break;
 		default:
 			WPRINTF("%s unhandled io command 0x%x",
			    __func__, cmd->opc);
			pci_nvme_status_genc(&status, NVME_SC_INVALID_OPCODE);
		}
complete:
		if (!pending) {
			pci_nvme_set_completion(sc, sq, idx, sqhead,
			    le16toh(cmd->cid), status);
			if (req != NULL)
				pci_nvme_release_ioreq(sc, req);
		}
	}

	sq->head = sqhead;

	pthread_mutex_unlock(&sq->mtx);
}

static void
pci_nvme_handle_doorbell(struct pci_nvme_softc* sc,
	uint64_t idx, int is_sq, uint64_t value)
{
	struct nvme_completion_queue *cq;
	bool published;

	DPRINTF("nvme doorbell %lu, %s, val 0x%lx",
	        idx, is_sq ? "SQ" : "CQ", value & 0xFFFF);

	if (is_sq) {
		if (idx > sc->num_squeues) {
			WPRINTF("%s queue index %lu overflow from "
			         "guest (max %u)",
			         __func__, idx, sc->num_squeues);
			pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_ERROR,
			    PCI_NVME_AEI_ERROR_INVALID_DB);
			return;
		}
		if (!pci_nvme_sq_handler_enter(sc))
			return;

		if (idx == 0)
			pci_nvme_handle_admin_cmd(sc, value);
		else
			pci_nvme_handle_io_cmd(sc, (uint16_t)idx, value);
		pci_nvme_sq_handler_leave(sc);
	} else {
		if (idx > sc->num_cqueues) {
			WPRINTF("%s queue index %lu overflow from "
			         "guest (max %u)",
			         __func__, idx, sc->num_cqueues);
			pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_ERROR,
			    PCI_NVME_AEI_ERROR_INVALID_DB);
			return;
		}

		cq = &sc->compl_queues[idx];
		pthread_mutex_lock(&cq->mtx);
		if (cq->qbase == NULL) {
			pthread_mutex_unlock(&cq->mtx);
			WPRINTF("%s write to CQ %lu before created", __func__,
			    idx);
			pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_ERROR,
			    PCI_NVME_AEI_ERROR_INVALID_DB);
			return;
		}
		if (!pci_nvme_doorbell_value_valid(cq->size,
		    value)) {
			pthread_mutex_unlock(&cq->mtx);
			EPRINTLN("%s write to CQ %lu of %lu invalid", __func__,
			    idx, value);
			pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_ERROR,
			    PCI_NVME_AEI_ERROR_INVALID_DB_VALUE);
			return;
		}

		atomic_store_short(&cq->head, (uint16_t)value);
		published = pci_nvme_cq_drain_locked(sc, cq);
		pthread_mutex_unlock(&cq->mtx);
		if (published && (cq->intr_en & NVME_CQ_INTEN) != 0)
			pci_generate_msix(sc->nsc_pi, cq->intr_vec);
	}
}

static void
pci_nvme_bar0_reg_dumps(const char *func, uint64_t offset, int iswrite)
{
	const char *s = iswrite ? "WRITE" : "READ";

	switch (offset) {
	case NVME_CR_CAP_LOW:
		DPRINTF("%s %s NVME_CR_CAP_LOW", func, s);
		break;
	case NVME_CR_CAP_HI:
		DPRINTF("%s %s NVME_CR_CAP_HI", func, s);
		break;
	case NVME_CR_VS:
		DPRINTF("%s %s NVME_CR_VS", func, s);
		break;
	case NVME_CR_INTMS:
		DPRINTF("%s %s NVME_CR_INTMS", func, s);
		break;
	case NVME_CR_INTMC:
		DPRINTF("%s %s NVME_CR_INTMC", func, s);
		break;
	case NVME_CR_CC:
		DPRINTF("%s %s NVME_CR_CC", func, s);
		break;
	case NVME_CR_CSTS:
		DPRINTF("%s %s NVME_CR_CSTS", func, s);
		break;
	case NVME_CR_NSSR:
		DPRINTF("%s %s NVME_CR_NSSR", func, s);
		break;
	case NVME_CR_AQA:
		DPRINTF("%s %s NVME_CR_AQA", func, s);
		break;
	case NVME_CR_ASQ_LOW:
		DPRINTF("%s %s NVME_CR_ASQ_LOW", func, s);
		break;
	case NVME_CR_ASQ_HI:
		DPRINTF("%s %s NVME_CR_ASQ_HI", func, s);
		break;
	case NVME_CR_ACQ_LOW:
		DPRINTF("%s %s NVME_CR_ACQ_LOW", func, s);
		break;
	case NVME_CR_ACQ_HI:
		DPRINTF("%s %s NVME_CR_ACQ_HI", func, s);
		break;
	default:
		DPRINTF("unknown nvme bar-0 offset 0x%lx", offset);
	}

}

static void
pci_nvme_write_bar_0(struct pci_nvme_softc *sc, uint64_t offset, int size,
    uint64_t value)
{
	uint32_t ccreg;

	if (offset >= NVME_DOORBELL_OFFSET) {
		uint64_t belloffset = offset - NVME_DOORBELL_OFFSET;
		uint64_t idx = belloffset / 8; /* door bell size = 2*int */
		int is_sq = (belloffset % 8) < 4;

		if (!pci_nvme_doorbell_access_valid(belloffset, size,
		    sc->max_queues)) {
			WPRINTF("guest attempted an invalid doorbell write offset "
			    "0x%lx, size %d, val 0x%lx in %s", offset, size,
			    value, __func__);
			return;
		}

		if ((sc->regs.csts & NVME_CSTS_RDY) == 0) {
			WPRINTF("doorbell write prior to RDY (offset=%#lx)\n",
			    offset);
			return;
		}

		if (is_sq) {
			if (sc->submit_queues[idx].qbase == NULL)
				return;
		} else if (sc->compl_queues[idx].qbase == NULL)
			return;

		pci_nvme_handle_doorbell(sc, idx, is_sq, value);
		return;
	}

	DPRINTF("nvme-write offset 0x%lx, size %d, value 0x%lx",
	        offset, size, value);

	if (size != 4) {
		WPRINTF("guest wrote invalid size %d (offset 0x%lx, "
		         "val 0x%lx) to bar0 in %s",
		         size, offset, value, __func__);
		/* TODO: shutdown device */
		return;
	}

	pci_nvme_bar0_reg_dumps(__func__, offset, 1);

	pthread_mutex_lock(&sc->mtx);

	switch (offset) {
	case NVME_CR_CAP_LOW:
	case NVME_CR_CAP_HI:
		/* readonly */
		break;
	case NVME_CR_VS:
		/* readonly */
		break;
	case NVME_CR_INTMS:
		/* MSI-X, so ignore */
		break;
	case NVME_CR_INTMC:
		/* MSI-X, so ignore */
		break;
	case NVME_CR_CC:
		ccreg = (uint32_t)value;

		DPRINTF("%s NVME_CR_CC en %x css %x shn %x iosqes %u "
		         "iocqes %u",
		        __func__,
			 NVME_CC_GET_EN(ccreg), NVME_CC_GET_CSS(ccreg),
			 NVME_CC_GET_SHN(ccreg), NVME_CC_GET_IOSQES(ccreg),
			 NVME_CC_GET_IOCQES(ccreg));

		if (NVME_CC_GET_SHN(ccreg)) {
			/* perform shutdown - flush out data to backend */
			sc->regs.csts &= ~NVMEM(NVME_CSTS_REG_SHST);
			sc->regs.csts |= NVMEF(NVME_CSTS_REG_SHST,
			    NVME_SHST_COMPLETE);
		}
		if (NVME_CC_GET_EN(ccreg) != NVME_CC_GET_EN(sc->regs.cc)) {
			if (NVME_CC_GET_EN(ccreg) == 0)
				/* transition 1-> causes controller reset */
				pci_nvme_reset_locked(sc);
			else if (!sc->reset_pending)
				pci_nvme_init_controller(sc);
		}

		/* Insert the iocqes, iosqes and en bits from the write */
		sc->regs.cc &= ~NVME_CC_WRITE_MASK;
		sc->regs.cc |= ccreg & NVME_CC_WRITE_MASK;
		if (NVME_CC_GET_EN(ccreg) == 0) {
			/* Insert the ams, mps and css bit fields */
			sc->regs.cc &= ~NVME_CC_NEN_WRITE_MASK;
			sc->regs.cc |= ccreg & NVME_CC_NEN_WRITE_MASK;
			sc->regs.csts &= ~NVME_CSTS_RDY;
		} else if (!sc->reset_pending && (sc->pending_ios == 0) &&
		    !(sc->regs.csts & NVME_CSTS_CFS)) {
			sc->regs.csts |= NVME_CSTS_RDY;
		}
		break;
	case NVME_CR_CSTS:
		break;
	case NVME_CR_NSSR:
		/* ignore writes; don't support subsystem reset */
		break;
	case NVME_CR_AQA:
		sc->regs.aqa = (uint32_t)value;
		break;
	case NVME_CR_ASQ_LOW:
		sc->regs.asq = (sc->regs.asq & (0xFFFFFFFF00000000)) |
		               (0xFFFFF000 & value);
		break;
	case NVME_CR_ASQ_HI:
		sc->regs.asq = (sc->regs.asq & (0x00000000FFFFFFFF)) |
		               (value << 32);
		break;
	case NVME_CR_ACQ_LOW:
		sc->regs.acq = (sc->regs.acq & (0xFFFFFFFF00000000)) |
		               (0xFFFFF000 & value);
		break;
	case NVME_CR_ACQ_HI:
		sc->regs.acq = (sc->regs.acq & (0x00000000FFFFFFFF)) |
		               (value << 32);
		break;
	default:
		DPRINTF("%s unknown offset 0x%lx, value 0x%lx size %d",
		         __func__, offset, value, size);
	}
	pthread_mutex_unlock(&sc->mtx);
}

static void
pci_nvme_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct pci_nvme_softc* sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi)) {
		DPRINTF("nvme-write baridx %d, msix: off 0x%lx, size %d, "
		         " value 0x%lx", baridx, offset, size, value);

		pci_emul_msix_twrite(pi, offset, size, value);
		return;
	}

	switch (baridx) {
	case 0:
		pci_nvme_write_bar_0(sc, offset, size, value);
		break;

	default:
		DPRINTF("%s unknown baridx %d, val 0x%lx",
		         __func__, baridx, value);
	}
}

static uint64_t pci_nvme_read_bar_0(struct pci_nvme_softc* sc,
	uint64_t offset, int size)
{
	uint64_t value;

	pci_nvme_bar0_reg_dumps(__func__, offset, 0);
	value = 0;

	if (pci_nvme_mmio_range_valid(offset, size,
	    NVME_DOORBELL_OFFSET)) {
		void *p = &(sc->regs);
		pthread_mutex_lock(&sc->mtx);
		memcpy(&value, (void *)((uintptr_t)p + offset), size);
		pthread_mutex_unlock(&sc->mtx);
	} else {
		WPRINTF("pci_nvme: read invalid offset %ld size %d", offset,
		    size);
	}

	switch (size) {
	case 1:
		value &= 0xFF;
		break;
	case 2:
		value &= 0xFFFF;
		break;
	case 4:
		value &= 0xFFFFFFFF;
		break;
	}

	DPRINTF("   nvme-read offset 0x%lx, size %d -> value 0x%x",
	         offset, size, (uint32_t)value);

	return (value);
}



static uint64_t
pci_nvme_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct pci_nvme_softc* sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi)) {
		DPRINTF("nvme-read bar: %d, msix: regoff 0x%lx, size %d",
		        baridx, offset, size);

		return pci_emul_msix_tread(pi, offset, size);
	}

	switch (baridx) {
	case 0:
       		return pci_nvme_read_bar_0(sc, offset, size);

	default:
		DPRINTF("unknown bar %d, 0x%lx", baridx, offset);
	}

	return (0);
}

static int
pci_nvme_parse_u32(const char *value, uint32_t minimum, uint32_t maximum,
    uint32_t *result)
{
	char *end;
	unsigned long number;

	if (value == NULL || result == NULL || minimum > maximum)
		return (EINVAL);
	errno = 0;
	end = NULL;
	number = strtoul(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0' ||
	    number < minimum || number > maximum)
		return (EINVAL);
	*result = (uint32_t)number;
	return (0);
}

static int
pci_nvme_parse_u64(const char *value, int base, uint64_t minimum,
    uint64_t maximum, uint64_t *result)
{
	char *end;
	unsigned long long number;

	if (value == NULL || result == NULL || minimum > maximum ||
	    (base != 0 && base != 10))
		return (EINVAL);
	errno = 0;
	end = NULL;
	number = strtoull(value, &end, base);
	if (errno != 0 || end == value || *end != '\0' || value[0] == '-' ||
	    number < minimum || number > maximum)
		return (EINVAL);
	*result = (uint64_t)number;
	return (0);
}

static int
pci_nvme_parse_config(struct pci_nvme_softc *sc, nvlist_t *nvl)
{
	char bident[sizeof("XXX:XXX")];
	const char *value;
	uint64_t parsed64;
	uint32_t sectsz;

	sc->max_queues = NVME_QUEUES;
	sc->max_qentries = NVME_MAX_QENTRIES;
	sc->ioslots = NVME_IOSLOTS;
	sc->num_squeues = sc->max_queues;
	sc->num_cqueues = sc->max_queues;
	sc->dataset_management = NVME_DATASET_MANAGEMENT_AUTO;
	sectsz = 0;
	snprintf(sc->ctrldata.sn, sizeof(sc->ctrldata.sn),
	         "NVME-%d-%d", sc->nsc_pi->pi_slot, sc->nsc_pi->pi_func);

	value = get_config_value_node(nvl, "maxq");
	if (value != NULL && pci_nvme_parse_u32(value, 1, NVME_QUEUES,
	    &sc->max_queues) != 0) {
		EPRINTLN("nvme: Invalid maxq option: %s", value);
		return (-1);
	}
	value = get_config_value_node(nvl, "qsz");
	if (value != NULL && pci_nvme_parse_u32(value, 2,
	    UINT16_MAX + 1U, &sc->max_qentries) != 0) {
		EPRINTLN("nvme: Invalid qsz option: %s", value);
		return (-1);
	}
	value = get_config_value_node(nvl, "ioslots");
	if (value != NULL && pci_nvme_parse_u32(value, 1, UINT16_MAX,
	    &sc->ioslots) != 0) {
		EPRINTLN("nvme: Invalid ioslots option: %s", value);
		return (-1);
	}
	value = get_config_value_node(nvl, "sectsz");
	if (value != NULL && (pci_nvme_parse_u32(value, 512, 8192,
	    &sectsz) != 0 || (sectsz != 512 && sectsz != 4096 &&
	    sectsz != 8192))) {
		EPRINTLN("nvme: Invalid sectsz option: %s", value);
		return (-1);
	}
	value = get_config_value_node(nvl, "ser");
	if (value != NULL) {
		/*
		 * This field indicates the Product Serial Number in
		 * 7-bit ASCII, unused bytes should be space characters.
		 * Ref: NVMe v1.3c.
		 */
		cpywithpad((char *)sc->ctrldata.sn,
		    sizeof(sc->ctrldata.sn), value, ' ');
	}
	value = get_config_value_node(nvl, "eui64");
	if (value != NULL) {
		if (pci_nvme_parse_u64(value, 0, 0, UINT64_MAX,
		    &parsed64) != 0) {
			EPRINTLN("nvme: Invalid eui64 option: %s", value);
			return (-1);
		}
		sc->nvstore.eui64 = htobe64(parsed64);
	}
	value = get_config_value_node(nvl, "dsm");
	if (value != NULL) {
		if (strcmp(value, "auto") == 0)
			sc->dataset_management = NVME_DATASET_MANAGEMENT_AUTO;
		else if (strcmp(value, "enable") == 0)
			sc->dataset_management = NVME_DATASET_MANAGEMENT_ENABLE;
		else if (strcmp(value, "disable") == 0)
			sc->dataset_management = NVME_DATASET_MANAGEMENT_DISABLE;
		else {
			EPRINTLN("nvme: Invalid dsm option: %s", value);
			return (-1);
		}
	}

	value = get_config_value_node(nvl, "bootindex");
	if (value != NULL) {
		if (pci_emul_add_boot_device(sc->nsc_pi, atoi(value))) {
			EPRINTLN("Invalid bootindex %d", atoi(value));
			return (-1);
		}
	}

	value = get_config_value_node(nvl, "ram");
	if (value != NULL) {
		const uint64_t mib = 1024 * 1024;

		if (pci_nvme_parse_u64(value, 10, 1,
		    MIN(UINT64_MAX / mib, SIZE_MAX / mib), &parsed64) != 0) {
			EPRINTLN("nvme: Invalid RAM size: %s", value);
			return (-1);
		}

		sc->nvstore.type = NVME_STOR_RAM;
		sc->nvstore.size = parsed64 * mib;
		sc->nvstore.ctx = calloc(1, sc->nvstore.size);
		sc->nvstore.sectsz = 4096;
		sc->nvstore.sectsz_bits = 12;
		if (sc->nvstore.ctx == NULL) {
			EPRINTLN("nvme: Unable to allocate RAM");
			return (-1);
		}
	} else {
		snprintf(bident, sizeof(bident), "%u:%u",
		    sc->nsc_pi->pi_slot, sc->nsc_pi->pi_func);
		sc->nvstore.ctx = blockif_open(nvl, bident);
		if (sc->nvstore.ctx == NULL) {
			EPRINTLN("nvme: Could not open backing file: %s",
			    strerror(errno));
			return (-1);
		}
		sc->nvstore.type = NVME_STOR_BLOCKIF;
		sc->nvstore.size = blockif_size(sc->nvstore.ctx);
	}

	if (sectsz == 512 || sectsz == 4096 || sectsz == 8192)
		sc->nvstore.sectsz = sectsz;
	else if (sc->nvstore.type != NVME_STOR_RAM)
		sc->nvstore.sectsz = blockif_sectsz(sc->nvstore.ctx);
	for (sc->nvstore.sectsz_bits = 9;
	     (1U << sc->nvstore.sectsz_bits) < sc->nvstore.sectsz;
	     sc->nvstore.sectsz_bits++);

	return (0);
}

static void
pci_nvme_resized(struct blockif_ctxt *bctxt __unused, void *arg,
    off_t new_size)
{
	struct pci_nvme_softc *sc;
	struct pci_nvme_blockstore *nvstore;
	struct nvme_namespace_data *nd;

	sc = arg;
	nvstore = &sc->nvstore;
	nd = &sc->nsdata;

	if (new_size < 0) {
		WPRINTF("ignoring invalid negative namespace size");
		return;
	}
	pthread_mutex_lock(&sc->mtx);
	nvstore->size = new_size;
	pci_nvme_init_nsdata_size(nvstore, nd);

	/* Add changed NSID to list */
	sc->ns_log.ns[0] = 1;
	sc->ns_log.ns[1] = 0;
	pthread_mutex_unlock(&sc->mtx);

	pci_nvme_aen_post(sc, PCI_NVME_AE_TYPE_NOTICE,
	    PCI_NVME_AEI_NOTICE_NS_ATTR_CHANGED);
}

static int
pci_nvme_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_nvme_softc *sc;
	uint32_t pci_membar_sz;
	bool aer_initialized, mutex_initialized, queues_initialized;
	bool semaphore_initialized;
	int error;

	error = 0;
	aer_initialized = false;
	mutex_initialized = false;
	queues_initialized = false;
	semaphore_initialized = false;

	sc = calloc(1, sizeof(struct pci_nvme_softc));
	if (sc == NULL)
		return (ENOMEM);
	pi->pi_arg = sc;
	sc->nsc_pi = pi;

	error = pci_nvme_parse_config(sc, nvl);
	if (error < 0)
		goto done;
	else
		error = 0;

	STAILQ_INIT(&sc->ioreqs_free);
	sc->ioreqs = calloc(sc->ioslots, sizeof(struct pci_nvme_ioreq));
	if (sc->ioreqs == NULL) {
		error = ENOMEM;
		goto done;
	}
	for (uint32_t i = 0; i < sc->ioslots; i++) {
		STAILQ_INSERT_TAIL(&sc->ioreqs_free, &sc->ioreqs[i], link);
	}

	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x0A0A);
	pci_set_cfgdata16(pi, PCIR_VENDOR, 0xFB5D);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_STORAGE);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_STORAGE_NVM);
	pci_set_cfgdata8(pi, PCIR_PROGIF,
	                 PCIP_STORAGE_NVM_ENTERPRISE_NVMHCI_1_0);

	/*
	 * Allocate size of NVMe registers + doorbell space for all queues.
	 *
	 * The specification requires a minimum memory I/O window size of 16K.
	 * The Windows driver will refuse to start a device with a smaller
	 * window.
	 */
	pci_membar_sz = sizeof(struct nvme_registers) +
	    2 * sizeof(uint32_t) * (sc->max_queues + 1);
	pci_membar_sz = MAX(pci_membar_sz, NVME_MMIO_SPACE_MIN);

	DPRINTF("nvme membar size: %u", pci_membar_sz);

	error = pci_emul_alloc_bar(pi, 0, PCIBAR_MEM64, pci_membar_sz);
	if (error) {
		WPRINTF("%s pci alloc mem bar failed", __func__);
		goto done;
	}

	error = pci_emul_add_msixcap(pi, sc->max_queues + 1, NVME_MSIX_BAR);
	if (error) {
		WPRINTF("%s pci add msixcap failed", __func__);
		goto done;
	}

	error = pci_emul_add_pciecap(pi, PCIEM_TYPE_ROOT_INT_EP);
	if (error) {
		WPRINTF("%s pci add Express capability failed", __func__);
		goto done;
	}

	error = pthread_mutex_init(&sc->mtx, NULL);
	if (error != 0)
		goto done;
	mutex_initialized = true;
	if (sem_init(&sc->iosemlock, 0, sc->ioslots) != 0) {
		error = errno;
		goto done;
	}
	semaphore_initialized = true;
	error = pci_nvme_init_queues(sc, sc->max_queues, sc->max_queues);
	if (error != 0)
		goto done;
	queues_initialized = true;
	/*
	 * Controller data depends on Namespace data so initialize Namespace
	 * data first.
	 */
	pci_nvme_init_nsdata(sc, &sc->nsdata, 1, &sc->nvstore);
	pci_nvme_init_ctrldata(sc);
	pci_nvme_init_logpages(sc);
	pci_nvme_init_features(sc);

	error = pci_nvme_aer_init(sc);
	if (error != 0)
		goto done;
	aer_initialized = true;
	error = pci_nvme_aen_init(sc);
	if (error != 0)
		goto done;
	if (sc->nvstore.type == NVME_STOR_BLOCKIF)
		blockif_register_resize_callback(sc->nvstore.ctx,
		    pci_nvme_resized, sc);

	pci_nvme_reset(sc);
done:
	if (error != 0) {
		if (aer_initialized) {
			pci_nvme_aer_destroy(sc);
			pthread_mutex_destroy(&sc->aer_mtx);
		}
		if (queues_initialized)
			pci_nvme_fini_queues(sc);
		if (semaphore_initialized)
			sem_destroy(&sc->iosemlock);
		if (mutex_initialized)
			pthread_mutex_destroy(&sc->mtx);
		free(sc->ioreqs);
		if (sc->nvstore.type == NVME_STOR_BLOCKIF &&
		    sc->nvstore.ctx != NULL)
			(void)blockif_close(sc->nvstore.ctx);
		else if (sc->nvstore.type == NVME_STOR_RAM)
			free(sc->nvstore.ctx);
		pi->pi_arg = NULL;
		free(sc);
	}
	return (error);
}

static int
pci_nvme_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *cp, *ram;

	if (opts == NULL)
		return (0);

	if (strncmp(opts, "ram=", 4) == 0) {
		cp = strchr(opts, ',');
		if (cp == NULL) {
			set_config_value_node(nvl, "ram", opts + 4);
			return (0);
		}
		ram = strndup(opts + 4, cp - opts - 4);
		set_config_value_node(nvl, "ram", ram);
		free(ram);
		return (pci_parse_legacy_config(nvl, cp + 1));
	} else
		return (blockif_legacy_config(nvl, opts));
}

#ifdef BHYVE_SNAPSHOT
/*
 * "NVM1" on disk.  Every field of the record is fixed-width little-endian;
 * the record never contains host pointers, host-endian structures, or
 * in-flight request state.  pci_nvme_pause() drains the backing store and
 * parks the AEN worker before the codec runs, so a truthful record has no
 * outstanding asynchronous work to describe; the codec verifies that
 * instead of serializing it.
 */
#define	NVME_SNAPSHOT_MAGIC	0x314d564eU
#define	NVME_SNAPSHOT_VERSION	1U

/* AQA queue sizes are 12-bit zero-based values, so up to 4096 entries. */
#define	NVME_SNAPSHOT_ADMIN_QMAX	4096U

/* Wire marker for the base address of a queue that is not created. */
#define	NVME_SNAPSHOT_NO_GPA	UINT64_MAX

struct pci_nvme_snapshot_sq {
	bool		present;
	uint32_t	size;
	uint16_t	head;
	uint16_t	tail;
	uint16_t	cqid;
	int		qpriority;
	uint64_t	gpa;
	struct nvme_command *qbase;
};

struct pci_nvme_snapshot_cq {
	bool		present;
	uint32_t	size;
	uint16_t	head;
	uint16_t	tail;
	uint16_t	intr_vec;
	uint32_t	intr_en;
	bool		phase;
	uint64_t	gpa;
	struct nvme_completion *qbase;
	uint32_t	pending_count;
	STAILQ_HEAD(, pci_nvme_pending_cqe) pending;
};

/*
 * Serialize (save) or decode-and-validate (load) the complete device
 * record.  On load, nothing is published to the live softc until every
 * field of the record has been decoded and validated; VM_SNAPSHOT_VALIDATE
 * therefore runs the identical decode path and is guaranteed non-mutating.
 */
static int
pci_nvme_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_nvme_softc *sc;
	struct pci_nvme_snapshot_sq sqs[NVME_QUEUES + 1];
	struct pci_nvme_snapshot_cq cqs[NVME_QUEUES + 1];
	STAILQ_HEAD(, pci_nvme_aer) aers;
	struct pci_nvme_aer *aer;
	struct pci_nvme_pending_cqe *pending;
	uint64_t asq, acq, nvstore_size, eui64;
	uint64_t units_lo, units_hi;
	__uint128_t read_data_units, write_data_units;
	__uint128_t read_commands, write_commands;
	uint32_t magic, version, value32;
	uint32_t cc, csts, nssr, aqa;
	uint32_t num_squeues, num_cqueues;
	uint32_t pending_ios, active_sq_handlers;
	uint32_t feat_cdw11[NVME_FID_MAX];
	uint32_t ns_log[sizeof(((struct nvme_ns_list *)0)->ns) /
	    sizeof(((struct nvme_ns_list *)0)->ns[0])];
	uint32_t read_dunits_remainder, write_dunits_remainder;
	uint32_t aer_count, i, j;
	uint16_t value16;
	uint8_t value8, critical_warning, num_q_is_set, reset_pending;
	uint8_t aen_posted[PCI_NVME_AE_TYPE_MAX];
	uint32_t aen_event_data[PCI_NVME_AE_TYPE_MAX];
	bool loading;
	int ret;

	pi = meta->dev_data;
	sc = pi->pi_arg;
	loading = vm_snapshot_is_loading(meta);

	for (i = 0; i < NVME_QUEUES + 1; i++) {
		memset(&sqs[i], 0, sizeof(sqs[i]));
		memset(&cqs[i], 0, sizeof(cqs[i]));
		STAILQ_INIT(&cqs[i].pending);
	}
	STAILQ_INIT(&aers);

	/*
	 * A RAM-backed namespace lives entirely in host memory: its contents
	 * are not covered by the guest-memory snapshot and are not bounded,
	 * so refuse to cut a checkpoint that would silently lose the disk.
	 */
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    sc->nvstore.type != NVME_STOR_BLOCKIF) {
		ret = EOPNOTSUPP;
		goto done;
	}

	magic = NVME_SNAPSHOT_MAGIC;
	version = NVME_SNAPSHOT_VERSION;
	SNAPSHOT_LE32_OR_LEAVE(magic, meta, ret, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, ret, done);
	if (loading && (magic != NVME_SNAPSHOT_MAGIC ||
	    version != NVME_SNAPSHOT_VERSION)) {
		ret = ENOTSUP;
		goto done;
	}

	/*
	 * Geometry and backend identity.  These are configuration, not guest
	 * state: they are validated against the destination and never
	 * restored, so a mismatched record is rejected before any mutation.
	 */
	value32 = sc->max_queues;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->max_queues) {
		ret = EINVAL;
		goto done;
	}
	value32 = sc->max_qentries;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->max_qentries) {
		ret = EINVAL;
		goto done;
	}
	value32 = sc->ioslots;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->ioslots) {
		ret = EINVAL;
		goto done;
	}
	value32 = (uint32_t)sc->nvstore.type;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && (value32 != (uint32_t)sc->nvstore.type ||
	    value32 != (uint32_t)NVME_STOR_BLOCKIF)) {
		ret = EINVAL;
		goto done;
	}
	value32 = sc->nvstore.sectsz;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->nvstore.sectsz) {
		ret = EINVAL;
		goto done;
	}
	value32 = sc->nvstore.sectsz_bits;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->nvstore.sectsz_bits) {
		ret = EINVAL;
		goto done;
	}
	nvstore_size = sc->nvstore.size;
	SNAPSHOT_LE64_OR_LEAVE(nvstore_size, meta, ret, done);
	if (loading && nvstore_size != sc->nvstore.size) {
		ret = EINVAL;
		goto done;
	}
	eui64 = sc->nvstore.eui64;
	SNAPSHOT_LE64_OR_LEAVE(eui64, meta, ret, done);
	if (loading && eui64 != sc->nvstore.eui64) {
		ret = EINVAL;
		goto done;
	}
	ret = vm_snapshot_identity_string(
	    blockif_checkpoint_identity(sc->nvstore.ctx),
	    BLOCKIF_CHECKPOINT_ID_MAX, meta);
	if (ret != 0)
		goto done;

	/* Table shapes baked into this record version. */
	value32 = NVME_FID_MAX;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != NVME_FID_MAX) {
		ret = EINVAL;
		goto done;
	}
	value32 = PCI_NVME_AE_TYPE_MAX;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != PCI_NVME_AE_TYPE_MAX) {
		ret = EINVAL;
		goto done;
	}

	/*
	 * Controller registers.  CAP and VS are derived from configuration
	 * and validated; the guest-writable registers are decoded to locals.
	 */
	value32 = sc->regs.cap_lo;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->regs.cap_lo) {
		ret = EINVAL;
		goto done;
	}
	value32 = sc->regs.cap_hi;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->regs.cap_hi) {
		ret = EINVAL;
		goto done;
	}
	value32 = sc->regs.vs;
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading && value32 != sc->regs.vs) {
		ret = EINVAL;
		goto done;
	}
	cc = sc->regs.cc;
	SNAPSHOT_LE32_OR_LEAVE(cc, meta, ret, done);
	csts = sc->regs.csts;
	SNAPSHOT_LE32_OR_LEAVE(csts, meta, ret, done);
	nssr = sc->regs.nssr;
	SNAPSHOT_LE32_OR_LEAVE(nssr, meta, ret, done);
	aqa = sc->regs.aqa;
	SNAPSHOT_LE32_OR_LEAVE(aqa, meta, ret, done);
	asq = sc->regs.asq;
	SNAPSHOT_LE64_OR_LEAVE(asq, meta, ret, done);
	acq = sc->regs.acq;
	SNAPSHOT_LE64_OR_LEAVE(acq, meta, ret, done);

	num_q_is_set = sc->num_q_is_set;
	SNAPSHOT_U8_OR_LEAVE(num_q_is_set, meta, ret, done);
	num_squeues = sc->num_squeues;
	SNAPSHOT_LE32_OR_LEAVE(num_squeues, meta, ret, done);
	num_cqueues = sc->num_cqueues;
	SNAPSHOT_LE32_OR_LEAVE(num_cqueues, meta, ret, done);
	if (loading && (num_q_is_set > 1 ||
	    !pci_nvme_snapshot_queue_counts_valid(num_squeues, num_cqueues,
	    sc->max_queues))) {
		ret = EINVAL;
		goto done;
	}

	/*
	 * Quiesce evidence.  pci_nvme_pause() drained the backend with the
	 * vCPUs already fenced, so all three must be zero on save; a record
	 * claiming in-flight work was cut across an un-drained device and
	 * describes requests that were never serialized.
	 */
	pending_ios = sc->pending_ios;
	SNAPSHOT_LE32_OR_LEAVE(pending_ios, meta, ret, done);
	active_sq_handlers = sc->active_sq_handlers;
	SNAPSHOT_LE32_OR_LEAVE(active_sq_handlers, meta, ret, done);
	reset_pending = sc->reset_pending;
	SNAPSHOT_U8_OR_LEAVE(reset_pending, meta, ret, done);
	if (!pci_nvme_snapshot_quiesced_valid(pending_ios,
	    active_sq_handlers, reset_pending != 0) || reset_pending > 1) {
		ret = loading ? EINVAL : EBUSY;
		goto done;
	}

	/* Feature state. */
	for (i = 0; i < NVME_FID_MAX; i++) {
		feat_cdw11[i] = sc->feat[i].cdw11;
		SNAPSHOT_LE32_OR_LEAVE(feat_cdw11[i], meta, ret, done);
	}

	/* SMART / health state. */
	critical_warning = sc->health_log.critical_warning;
	SNAPSHOT_U8_OR_LEAVE(critical_warning, meta, ret, done);
	units_lo = (uint64_t)sc->read_data_units;
	units_hi = (uint64_t)(sc->read_data_units >> 64);
	SNAPSHOT_LE64_OR_LEAVE(units_lo, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(units_hi, meta, ret, done);
	read_data_units = (__uint128_t)units_hi << 64 | units_lo;
	units_lo = (uint64_t)sc->write_data_units;
	units_hi = (uint64_t)(sc->write_data_units >> 64);
	SNAPSHOT_LE64_OR_LEAVE(units_lo, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(units_hi, meta, ret, done);
	write_data_units = (__uint128_t)units_hi << 64 | units_lo;
	units_lo = (uint64_t)sc->read_commands;
	units_hi = (uint64_t)(sc->read_commands >> 64);
	SNAPSHOT_LE64_OR_LEAVE(units_lo, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(units_hi, meta, ret, done);
	read_commands = (__uint128_t)units_hi << 64 | units_lo;
	units_lo = (uint64_t)sc->write_commands;
	units_hi = (uint64_t)(sc->write_commands >> 64);
	SNAPSHOT_LE64_OR_LEAVE(units_lo, meta, ret, done);
	SNAPSHOT_LE64_OR_LEAVE(units_hi, meta, ret, done);
	write_commands = (__uint128_t)units_hi << 64 | units_lo;
	read_dunits_remainder = sc->read_dunits_remainder;
	SNAPSHOT_LE32_OR_LEAVE(read_dunits_remainder, meta, ret, done);
	write_dunits_remainder = sc->write_dunits_remainder;
	SNAPSHOT_LE32_OR_LEAVE(write_dunits_remainder, meta, ret, done);
	if (loading && (read_dunits_remainder > 999 ||
	    write_dunits_remainder > 999)) {
		ret = EINVAL;
		goto done;
	}

	/* Changed Namespace List log. */
	value32 = (uint32_t)(sizeof(ns_log) / sizeof(ns_log[0]));
	SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret, done);
	if (loading &&
	    value32 != (uint32_t)(sizeof(ns_log) / sizeof(ns_log[0]))) {
		ret = EINVAL;
		goto done;
	}
	for (i = 0; i < sizeof(ns_log) / sizeof(ns_log[0]); i++) {
		ns_log[i] = sc->ns_log.ns[i];
		SNAPSHOT_LE32_OR_LEAVE(ns_log[i], meta, ret, done);
	}

	/* Outstanding Asynchronous Event Requests. */
	aer_count = sc->aer_count;
	SNAPSHOT_LE32_OR_LEAVE(aer_count, meta, ret, done);
	if (loading && aer_count > sc->ctrldata.aerl + 1U) {
		ret = EINVAL;
		goto done;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		i = 0;
		STAILQ_FOREACH(aer, &sc->aer_list, link) {
			if (i++ == aer_count) {
				ret = EINVAL;
				goto done;
			}
			value16 = aer->cid;
			SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret, done);
			value16 = aer->sqhd;
			SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret, done);
		}
		if (i != aer_count) {
			ret = EINVAL;
			goto done;
		}
	} else {
		for (i = 0; i < aer_count; i++) {
			aer = calloc(1, sizeof(*aer));
			if (aer == NULL) {
				ret = ENOMEM;
				goto done;
			}
			STAILQ_INSERT_TAIL(&aers, aer, link);
			value16 = 0;
			SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret, done);
			aer->cid = value16;
			value16 = 0;
			SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret, done);
			aer->sqhd = value16;
		}
	}

	/* Posted-but-unprocessed Asynchronous Event Notifications. */
	for (i = 0; i < PCI_NVME_AE_TYPE_MAX; i++) {
		aen_posted[i] = sc->aen[i].posted;
		SNAPSHOT_U8_OR_LEAVE(aen_posted[i], meta, ret, done);
		aen_event_data[i] = sc->aen[i].event_data;
		SNAPSHOT_LE32_OR_LEAVE(aen_event_data[i], meta, ret, done);
		if (loading && aen_posted[i] > 1) {
			ret = EINVAL;
			goto done;
		}
	}

	/* Submission queues (admin plus IO). */
	for (i = 0; i < num_squeues + 1; i++) {
		struct pci_nvme_snapshot_sq *ssq = &sqs[i];
		struct nvme_submission_queue *sq = &sc->submit_queues[i];

		if (meta->op == VM_SNAPSHOT_SAVE &&
		    atomic_load_acq_32(&sq->pending_ios) != 0) {
			ret = EBUSY;
			goto done;
		}
		value8 = sq->qbase != NULL;
		SNAPSHOT_U8_OR_LEAVE(value8, meta, ret, done);
		if (loading && value8 > 1) {
			ret = EINVAL;
			goto done;
		}
		ssq->present = value8 != 0;
		ssq->size = sq->size;
		SNAPSHOT_LE32_OR_LEAVE(ssq->size, meta, ret, done);
		ssq->head = sq->head;
		SNAPSHOT_LE16_OR_LEAVE(ssq->head, meta, ret, done);
		ssq->tail = sq->tail;
		SNAPSHOT_LE16_OR_LEAVE(ssq->tail, meta, ret, done);
		ssq->cqid = sq->cqid;
		SNAPSHOT_LE16_OR_LEAVE(ssq->cqid, meta, ret, done);
		ssq->qpriority = sq->qpriority;
		SNAPSHOT_NONNEGATIVE_INT_OR_LEAVE(ssq->qpriority, meta, ret,
		    done);
		if (meta->op == VM_SNAPSHOT_SAVE) {
			ssq->gpa = NVME_SNAPSHOT_NO_GPA;
			if (sq->qbase != NULL) {
				ssq->gpa = paddr_host2guest(pi->pi_vmctx,
				    sq->qbase);
				if (ssq->gpa == (uint64_t)-1) {
					ret = EFAULT;
					goto done;
				}
			}
		}
		SNAPSHOT_LE64_OR_LEAVE(ssq->gpa, meta, ret, done);
		if (!loading)
			continue;
		if (!pci_nvme_snapshot_queue_shape_valid(ssq->present,
		    ssq->size, ssq->head, ssq->tail, i == 0 ?
		    NVME_SNAPSHOT_ADMIN_QMAX : sc->max_qentries) ||
		    ssq->qpriority > 3) {
			ret = EINVAL;
			goto done;
		}
		if (!ssq->present) {
			if (ssq->gpa != NVME_SNAPSHOT_NO_GPA) {
				ret = EINVAL;
				goto done;
			}
			continue;
		}
		if (i == 0) {
			/* The admin queue is fully described by AQA/ASQ. */
			if (ssq->cqid != 0 || ssq->gpa != asq ||
			    ssq->size != ONE_BASED(NVMEV(NVME_AQA_REG_ASQS,
			    aqa))) {
				ret = EINVAL;
				goto done;
			}
		} else if (ssq->cqid == 0 || ssq->cqid > num_cqueues) {
			ret = EINVAL;
			goto done;
		}
		if (!pci_nvme_queue_base_valid(ssq->gpa, PAGE_SIZE)) {
			ret = EINVAL;
			goto done;
		}
		ssq->qbase = vm_map_gpa(pi->pi_vmctx, ssq->gpa,
		    sizeof(struct nvme_command) * (size_t)ssq->size);
		if (ssq->qbase == NULL) {
			ret = EFAULT;
			goto done;
		}
	}

	/* Completion queues (admin plus IO), with deferred completions. */
	for (i = 0; i < num_cqueues + 1; i++) {
		struct pci_nvme_snapshot_cq *scq = &cqs[i];
		struct nvme_completion_queue *cq = &sc->compl_queues[i];

		value8 = cq->qbase != NULL;
		SNAPSHOT_U8_OR_LEAVE(value8, meta, ret, done);
		if (loading && value8 > 1) {
			ret = EINVAL;
			goto done;
		}
		scq->present = value8 != 0;
		scq->size = cq->size;
		SNAPSHOT_LE32_OR_LEAVE(scq->size, meta, ret, done);
		scq->head = cq->head;
		SNAPSHOT_LE16_OR_LEAVE(scq->head, meta, ret, done);
		scq->tail = cq->tail;
		SNAPSHOT_LE16_OR_LEAVE(scq->tail, meta, ret, done);
		scq->intr_vec = cq->intr_vec;
		SNAPSHOT_LE16_OR_LEAVE(scq->intr_vec, meta, ret, done);
		scq->intr_en = cq->intr_en;
		SNAPSHOT_LE32_OR_LEAVE(scq->intr_en, meta, ret, done);
		value8 = cq->phase;
		SNAPSHOT_U8_OR_LEAVE(value8, meta, ret, done);
		if (loading && value8 > 1) {
			ret = EINVAL;
			goto done;
		}
		scq->phase = value8 != 0;
		if (meta->op == VM_SNAPSHOT_SAVE) {
			scq->gpa = NVME_SNAPSHOT_NO_GPA;
			if (cq->qbase != NULL) {
				scq->gpa = paddr_host2guest(pi->pi_vmctx,
				    cq->qbase);
				if (scq->gpa == (uint64_t)-1) {
					ret = EFAULT;
					goto done;
				}
			}
		}
		SNAPSHOT_LE64_OR_LEAVE(scq->gpa, meta, ret, done);
		scq->pending_count = cq->pending_count;
		SNAPSHOT_LE32_OR_LEAVE(scq->pending_count, meta, ret, done);
		if (loading) {
			if (!pci_nvme_snapshot_queue_shape_valid(scq->present,
			    scq->size, scq->head, scq->tail, i == 0 ?
			    NVME_SNAPSHOT_ADMIN_QMAX : sc->max_qentries) ||
			    !pci_nvme_snapshot_pending_cqes_valid(scq->present,
			    scq->pending_count, NVME_MAX_PENDING_CQES) ||
			    scq->intr_vec > sc->max_queues ||
			    (scq->intr_en &
			    ~(uint32_t)(NVME_CQ_INTEN | NVME_CQ_INTCOAL)) != 0) {
				ret = EINVAL;
				goto done;
			}
			if (scq->present) {
				if (i == 0) {
					if (scq->gpa != acq ||
					    scq->intr_vec != 0 || scq->size !=
					    ONE_BASED(NVMEV(NVME_AQA_REG_ACQS,
					    aqa))) {
						ret = EINVAL;
						goto done;
					}
				}
				if (!pci_nvme_queue_base_valid(scq->gpa,
				    PAGE_SIZE)) {
					ret = EINVAL;
					goto done;
				}
				scq->qbase = vm_map_gpa(pi->pi_vmctx, scq->gpa,
				    sizeof(struct nvme_completion) *
				    (size_t)scq->size);
				if (scq->qbase == NULL) {
					ret = EFAULT;
					goto done;
				}
			} else if (scq->gpa != NVME_SNAPSHOT_NO_GPA) {
				ret = EINVAL;
				goto done;
			}
		}
		if (meta->op == VM_SNAPSHOT_SAVE) {
			j = 0;
			STAILQ_FOREACH(pending, &cq->pending, link) {
				if (j++ == scq->pending_count) {
					ret = EINVAL;
					goto done;
				}
				value32 = pending->cdw0;
				SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret,
				    done);
				value16 = pending->sqhd;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				value16 = pending->sqid;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				value16 = pending->cid;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				value16 = pending->status;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
			}
			if (j != scq->pending_count) {
				ret = EINVAL;
				goto done;
			}
		} else {
			for (j = 0; j < scq->pending_count; j++) {
				pending = calloc(1, sizeof(*pending));
				if (pending == NULL) {
					ret = ENOMEM;
					goto done;
				}
				STAILQ_INSERT_TAIL(&scq->pending, pending,
				    link);
				value32 = 0;
				SNAPSHOT_LE32_OR_LEAVE(value32, meta, ret,
				    done);
				pending->cdw0 = value32;
				value16 = 0;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				pending->sqhd = value16;
				value16 = 0;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				if (value16 > num_squeues) {
					ret = EINVAL;
					goto done;
				}
				pending->sqid = value16;
				value16 = 0;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				pending->cid = value16;
				value16 = 0;
				SNAPSHOT_LE16_OR_LEAVE(value16, meta, ret,
				    done);
				pending->status = value16;
			}
		}
	}

	if (loading) {
		/* Cross-queue invariants, checked before any mutation. */
		if (NVME_CSTS_GET_RDY(csts) != 0 &&
		    (NVME_CC_GET_EN(cc) == 0 || !sqs[0].present ||
		    !cqs[0].present)) {
			ret = EINVAL;
			goto done;
		}
		for (i = 1; i < num_squeues + 1; i++) {
			if (sqs[i].present && !cqs[sqs[i].cqid].present) {
				ret = EINVAL;
				goto done;
			}
		}
	}

	if (vm_snapshot_is_restoring(meta)) {
		/*
		 * Publication.  Every step below is infallible: the record
		 * has been fully validated, the device is paused, and the
		 * vCPUs are fenced, so no partial state can ever be
		 * observed.
		 */
		sc->regs.cc = cc;
		sc->regs.csts = csts;
		sc->regs.nssr = nssr;
		sc->regs.aqa = aqa;
		sc->regs.asq = asq;
		sc->regs.acq = acq;
		sc->num_q_is_set = num_q_is_set != 0;
		sc->num_squeues = num_squeues;
		sc->num_cqueues = num_cqueues;
		for (i = 0; i < NVME_FID_MAX; i++)
			sc->feat[i].cdw11 = feat_cdw11[i];
		sc->health_log.critical_warning = critical_warning;
		sc->read_data_units = read_data_units;
		sc->write_data_units = write_data_units;
		sc->read_commands = read_commands;
		sc->write_commands = write_commands;
		sc->read_dunits_remainder = read_dunits_remainder;
		sc->write_dunits_remainder = write_dunits_remainder;
		for (i = 0; i < sizeof(ns_log) / sizeof(ns_log[0]); i++)
			sc->ns_log.ns[i] = ns_log[i];
		pci_nvme_aer_destroy(sc);
		STAILQ_CONCAT(&sc->aer_list, &aers);
		sc->aer_count = aer_count;
		for (i = 0; i < PCI_NVME_AE_TYPE_MAX; i++) {
			sc->aen[i].posted = aen_posted[i] != 0;
			sc->aen[i].event_data = aen_event_data[i];
		}
		for (i = 0; i < num_squeues + 1; i++) {
			struct nvme_submission_queue *sq =
			    &sc->submit_queues[i];

			sq->qbase = sqs[i].qbase;
			sq->size = sqs[i].size;
			sq->head = sqs[i].head;
			sq->tail = sqs[i].tail;
			sq->cqid = sqs[i].cqid;
			sq->qpriority = sqs[i].qpriority;
		}
		for (i = 0; i < num_cqueues + 1; i++) {
			struct nvme_completion_queue *cq =
			    &sc->compl_queues[i];

			cq->qbase = cqs[i].qbase;
			cq->size = cqs[i].size;
			cq->head = cqs[i].head;
			cq->tail = cqs[i].tail;
			cq->intr_vec = cqs[i].intr_vec;
			cq->intr_en = cqs[i].intr_en;
			cq->phase = cqs[i].phase;
			STAILQ_CONCAT(&cq->pending, &cqs[i].pending);
			cq->pending_count = cqs[i].pending_count;
		}
	}
	ret = 0;

done:
	/*
	 * Publication empties the staging lists, so this frees exactly the
	 * entries that were not (or could not be) published.
	 */
	while ((aer = STAILQ_FIRST(&aers)) != NULL) {
		STAILQ_REMOVE_HEAD(&aers, link);
		free(aer);
	}
	for (i = 0; i < NVME_QUEUES + 1; i++) {
		while ((pending = STAILQ_FIRST(&cqs[i].pending)) != NULL) {
			STAILQ_REMOVE_HEAD(&cqs[i].pending, link);
			free(pending);
		}
	}
	return (ret);
}

static int
pci_nvme_snapshot_validate(struct vm_snapshot_meta *meta)
{

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	/*
	 * The codec publishes only under VM_SNAPSHOT_RESTORE, so running it
	 * with the VALIDATE op consumes and checks the complete record
	 * without mutating live device state or touching guest memory.
	 */
	return (pci_nvme_snapshot(meta));
}

static int
pci_nvme_pause(struct pci_devinst *pi)
{
	struct pci_nvme_softc *sc;
	int error;

	sc = pi->pi_arg;

	/*
	 * Park the AEN worker first.  pci_nvme_aen_process() runs entirely
	 * under aen_mtx, so once this fence is published under that lock the
	 * worker can no longer write completions into guest memory.
	 */
	pthread_mutex_lock(&sc->aen_mtx);
	sc->aen_paused = true;
	pthread_mutex_unlock(&sc->aen_mtx);

	/*
	 * Drain in-flight backend I/O.  blockif_suspend() waits on a bounded
	 * CLOCK_MONOTONIC deadline and resumes the backend itself on
	 * timeout, so a wedged backend fails the pause instead of leaving a
	 * stale completion free to touch guest memory later.
	 */
	if (sc->nvstore.type == NVME_STOR_BLOCKIF) {
		error = blockif_suspend(sc->nvstore.ctx);
		if (error != 0)
			goto fail;
	}

	/*
	 * The vCPUs are fenced and the backend is drained, so every ioreq
	 * completion has run and no doorbell handler can be active.  Verify
	 * rather than serialize: a violation means the device is not
	 * quiescent and the checkpoint must not be cut.
	 */
	pthread_mutex_lock(&sc->mtx);
	if (!pci_nvme_snapshot_quiesced_valid(sc->pending_ios,
	    sc->active_sq_handlers, sc->reset_pending)) {
		pthread_mutex_unlock(&sc->mtx);
		if (sc->nvstore.type == NVME_STOR_BLOCKIF)
			blockif_resume(sc->nvstore.ctx);
		error = EBUSY;
		goto fail;
	}
	pthread_mutex_unlock(&sc->mtx);

	return (0);

fail:
	/* Fail closed but leave the device fully usable. */
	pthread_mutex_lock(&sc->aen_mtx);
	sc->aen_paused = false;
	pthread_cond_signal(&sc->aen_cond);
	pthread_mutex_unlock(&sc->aen_mtx);
	return (error);
}

static int
pci_nvme_resume(struct pci_devinst *pi)
{
	struct pci_nvme_softc *sc;

	sc = pi->pi_arg;

	if (sc->nvstore.type == NVME_STOR_BLOCKIF)
		blockif_resume(sc->nvstore.ctx);

	pthread_mutex_lock(&sc->aen_mtx);
	sc->aen_paused = false;
	pthread_cond_signal(&sc->aen_cond);
	pthread_mutex_unlock(&sc->aen_mtx);

	return (0);
}
#endif	/* BHYVE_SNAPSHOT */

static const struct pci_devemu pci_de_nvme = {
	.pe_emu =	"nvme",
	.pe_init =	pci_nvme_init,
	.pe_legacy_config = pci_nvme_legacy_config,
	.pe_barwrite =	pci_nvme_write,
	.pe_barread =	pci_nvme_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	pci_nvme_snapshot,
	.pe_snapshot_validate = pci_nvme_snapshot_validate,
	.pe_pause =	pci_nvme_pause,
	.pe_resume =	pci_nvme_resume,
	.pe_migration_flags = PCI_MIGRATION_F_STATE_CODEC |
	    PCI_MIGRATION_F_COMPAT_FIXED | PCI_MIGRATION_F_DMA_TRACKED |
	    PCI_MIGRATION_F_QUIESCE_CALLBACK,
#endif
};
PCI_EMUL_SET(pci_de_nvme);
