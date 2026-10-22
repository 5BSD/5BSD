/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Vincenzo Maffione <vmaffione@FreeBSD.org>
 * Copyright (c) 2022 Domagoj Stolfa <ds815@cam.ac.uk>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file implements multiple network backends (tap, netmap, ...),
 * to be used by network frontends such as virtio-net and e1000.
 * The API to access the backend (e.g. send/receive packets, negotiate
 * features) is exported by net_backends.h.
 */

#include <sys/types.h>
#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/_mbufid.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_tap.h>

#include <assert.h>
#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#ifdef WITH_DTRACE
#include <sys/sdt.h>
extern int __dtraceenabled_netbe___tap__recv(void);
extern int __dtraceenabled_netbe___tap__send(void);
extern int __dtraceenabled_netbe___tap__recv__v2(void);
extern int __dtraceenabled_netbe___tap__send__v2(void);
#define NETBE_TAP_RECV_ENABLED() __dtraceenabled_netbe___tap__recv()
#define NETBE_TAP_SEND_ENABLED() __dtraceenabled_netbe___tap__send()
#define NETBE_TAP_RECV_V2_ENABLED() __dtraceenabled_netbe___tap__recv__v2()
#define NETBE_TAP_SEND_V2_ENABLED() __dtraceenabled_netbe___tap__send__v2()
#else
#define DTRACE_PROBE2(...) ((void)0)
#define NETBE_TAP_RECV_ENABLED() 0
#define NETBE_TAP_SEND_ENABLED() 0
#define NETBE_TAP_RECV_V2_ENABLED() 0
#define NETBE_TAP_SEND_V2_ENABLED() 0
#endif

#include "config.h"
#include "debug.h"
#include "globals.h"
#include "iov.h"
#include "mevent.h"
#include "net_backends.h"
#include "net_backends_priv.h"

static int
netbe_make_checkpoint_identity(char *identity, size_t identity_size,
    const char *configured, const char *type, const char *backend)
{
	size_t configured_length;
	int length;

	if (identity == NULL || identity_size == 0 || type == NULL ||
	    backend == NULL)
		return (EINVAL);
	if (configured != NULL) {
		configured_length = strlen(configured);
		if (configured_length == 0 ||
		    configured_length >= identity_size)
			return (EINVAL);
		memcpy(identity, configured, configured_length + 1);
		return (0);
	}
	length = snprintf(identity, identity_size, "local:%s:%s", type,
	    backend);
	if (length < 0 || (size_t)length >= identity_size)
		return (E2BIG);
	return (0);
}
#include "pci_emul.h"

#define	NET_BE_SIZE(be)		(sizeof(*be) + (be)->priv_size)

void
tap_cleanup(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);

	if (priv->mevp) {
		(void)mevent_delete_close_sync(priv->mevp);
		priv->mevp = NULL;
		be->fd = -1;
	}
	if (be->fd != -1) {
		close(be->fd);
		be->fd = -1;
	}
	be->tagging_enabled = 0;
	be->tagging_v2_enabled = 0;
}

static int
tap_init(struct net_backend *be, const char *devname,
    nvlist_t *nvl __unused, net_be_rxeof_t cb, void *param)
{
	struct tap_priv *priv = NET_BE_PRIV(be);
	char tbuf[80];
	int opt = 1, up = IFF_UP;

#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t ioctls[] = { TAPSTAGGING, TAPSBINDVM, TAPSTAGGINGV2,
	    TAPSV2RXFREEZE, TAPGV2RXQUEUED };
	size_t nioctls = nitems(ioctls);
#endif

	if (cb == NULL) {
		EPRINTLN("TAP backend requires non-NULL callback");
		return (-1);
	}

	if (snprintf(tbuf, sizeof(tbuf), "/dev/%s", devname) >=
	    (int)sizeof(tbuf)) {
		EPRINTLN("tap device name is too long");
		return (ENAMETOOLONG);
	}

	be->fd = open(tbuf, O_RDWR);
	if (be->fd == -1) {
		EPRINTLN("open of tap device %s failed", tbuf);
		goto error;
	}

	/*
	 * Set non-blocking and register for read
	 * notifications with the event loop
	 */
	if (ioctl(be->fd, FIONBIO, &opt) < 0) {
		EPRINTLN("tap device O_NONBLOCK failed");
		goto error;
	}

	if (strncmp("ngd", be->prefix, 3) &&
	    ioctl(be->fd, VMIO_SIOCSIFFLAGS, up)) {
		EPRINTLN("tap device link up failed");
		goto error;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE, CAP_IOCTL);
	if (caph_rights_limit(be->fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");

	if (cap_ioctls_limit(be->fd, ioctls, nioctls) == -1)
		errx(EX_OSERR, "Unable to apply ioctl limits for sandbox");
#endif

	memset(priv->bbuf, 0, sizeof(priv->bbuf));
	priv->bbuflen = 0;

	priv->mevp = mevent_add_disabled(be->fd, EVF_READ, cb, param);
	if (priv->mevp == NULL) {
		EPRINTLN("Could not register event");
		goto error;
	}

	return (0);

error:
	tap_cleanup(be);
	return (-1);
}

/* Copy only a complete identifier from the bytes actually in this record. */
static int
tap_probe_id_bytes(const struct iovec *iov, int iovcnt, size_t valid,
    size_t prefix, void *id, size_t idlen)
{
	size_t available, copylen, length, offset, skip;
	int i;

	if (iov == NULL || iovcnt <= 0 || id == NULL || idlen == 0 ||
	    prefix > valid || idlen > valid - prefix)
		return (0);
	available = valid;
	skip = prefix;
	offset = 0;
	for (i = 0; i < iovcnt && available != 0; i++) {
		length = MIN(iov[i].iov_len, available);
		available -= length;
		if (skip >= length) {
			skip -= length;
			continue;
		}
		if (iov[i].iov_base == NULL)
			return (0);
		copylen = MIN(length - skip, idlen - offset);
		memcpy((uint8_t *)id + offset,
		    (const uint8_t *)iov[i].iov_base + skip, copylen);
		offset += copylen;
		skip = 0;
		if (offset == idlen)
			return (1);
	}
	return (0);
}

static int
tap_probe_mbufid(const struct iovec *iov, int iovcnt, size_t valid,
    size_t prefix, mbufid_t *mid)
{

	return (tap_probe_id_bytes(iov, iovcnt, valid, prefix, mid,
	    sizeof(*mid)));
}

static int
tap_probe_mbufid_v2(const struct iovec *iov, int iovcnt, size_t valid,
    size_t prefix, mbufid_v2_t *mid)
{

	return (tap_probe_id_bytes(iov, iovcnt, valid, prefix, mid,
	    sizeof(*mid)));
}

/*
 * Called to send a buffer chain out to the tap device
 */
ssize_t
tap_send(struct net_backend *be, const struct iovec *iov, int iovcnt)
{
	mbufid_t mid;
	mbufid_v2_t midv2;
	size_t valid;

	if (be->tagging_enabled && iov != NULL && iovcnt > 0 &&
	    (NETBE_TAP_SEND_ENABLED() ||
	    (be->tagging_v2_enabled && NETBE_TAP_SEND_V2_ENABLED()))) {
		valid = count_iov(iov, iovcnt);
		if (NETBE_TAP_SEND_ENABLED() &&
		    tap_probe_mbufid(iov, iovcnt, valid,
		    be->be_vnet_hdr_len, &mid))
			DTRACE_PROBE2(netbe, tap__send, g_vmname, &mid);
		if (be->tagging_v2_enabled && NETBE_TAP_SEND_V2_ENABLED() &&
		    tap_probe_mbufid_v2(iov, iovcnt,
		    valid, be->be_vnet_hdr_len, &midv2))
			DTRACE_PROBE2(netbe, tap__send__v2, g_vmname, &midv2);
	}

	return (writev(be->fd, iov, iovcnt));
}

ssize_t
tap_peek_recvlen(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);
	ssize_t ret;

	if (priv->bbuflen > 0) {
		/*
		 * We already have a packet in the bounce buffer.
		 * Just return its length.
		 */
		return priv->bbuflen;
	}

	/*
	 * Read the next packet (if any) into the bounce buffer, so
	 * that we get to know its length and we can return that
	 * to the caller.
	 */
	ret = read(be->fd, priv->bbuf, sizeof(priv->bbuf));
	if (ret < 0 && errno == EWOULDBLOCK) {
		return (0);
	}

	if (ret > 0)
		priv->bbuflen = ret;

	return (ret);
}

static int
tap_checkpoint_rx_quiescent(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);
	int queued;

	if (priv->bbuflen != 0)
		return (EBUSY);
	queued = 0;
	if (ioctl(be->fd, TAPGV2RXQUEUED, &queued) < 0)
		return (errno);
	if (queued < 0)
		return (EIO);
	return (queued == 0 ? 0 : EBUSY);
}

static int
tap_checkpoint_rx_freeze(struct net_backend *be, bool freeze)
{
	int value;

	if (be->fd < 0)
		return (EBADF);
	value = freeze ? 1 : 0;
	if (ioctl(be->fd, TAPSV2RXFREEZE, &value) < 0)
		return (errno);
	return (0);
}

ssize_t
tap_recv(struct net_backend *be, const struct iovec *iov, int iovcnt)
{
	struct tap_priv *priv = NET_BE_PRIV(be);
	struct iovec record;
	ssize_t ret;
	mbufid_t mid;
	mbufid_v2_t midv2;

	if (priv->bbuflen > 0) {
		record = (struct iovec){
		    .iov_base = priv->bbuf,
		    .iov_len = priv->bbuflen,
		};
		/*
		 * A packet is available in the bounce buffer, so
		 * we read it from there.
		 */
		ret = buf_to_iov(priv->bbuf, priv->bbuflen,
		    iov, iovcnt);
		if (be->tagging_enabled && NETBE_TAP_RECV_ENABLED() &&
		    tap_probe_mbufid(&record, 1,
		    (size_t)ret, be->be_vnet_hdr_len, &mid))
			DTRACE_PROBE2(netbe, tap__recv, g_vmname, &mid);
		if (be->tagging_v2_enabled && NETBE_TAP_RECV_V2_ENABLED() &&
		    tap_probe_mbufid_v2(&record, 1,
		    (size_t)ret, be->be_vnet_hdr_len, &midv2))
			DTRACE_PROBE2(netbe, tap__recv__v2, g_vmname, &midv2);

		/* Mark the bounce buffer as empty. */
		priv->bbuflen = 0;

		return (ret);
	}

	ret = readv(be->fd, iov, iovcnt);
	if (ret < 0 && errno == EWOULDBLOCK) {
		return (0);
	}

	if (ret > 0 && be->tagging_enabled && NETBE_TAP_RECV_ENABLED() &&
	    tap_probe_mbufid(iov,
	    iovcnt, (size_t)ret, be->be_vnet_hdr_len, &mid))
		DTRACE_PROBE2(netbe, tap__recv, g_vmname, &mid);
	if (ret > 0 && be->tagging_v2_enabled &&
	    NETBE_TAP_RECV_V2_ENABLED() && tap_probe_mbufid_v2(iov,
	    iovcnt, (size_t)ret, be->be_vnet_hdr_len, &midv2))
		DTRACE_PROBE2(netbe, tap__recv__v2, g_vmname, &midv2);

	return (ret);
}

void
tap_recv_enable(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);

	mevent_enable(priv->mevp);
}

void
tap_recv_disable(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);

	mevent_disable(priv->mevp);
}

uint64_t
tap_get_cap(struct net_backend *be __unused)
{

	return (0); /* no capabilities for now */
}

int
tap_set_cap(struct net_backend *be __unused, uint64_t features,
    unsigned vnet_hdr_len)
{

	return ((features || vnet_hdr_len) ? -1 : 0);
}

static int
tap_tagging_supported(struct net_backend *be __unused)
{
#ifdef TAPSTAGGING
	return (1);
#else
	return (0);
#endif
}

static int
tap_tagging_bind_vm(struct net_backend *be, int vmfd)
{

	return (ioctl(be->fd, TAPSBINDVM, &vmfd));
}

static int
tap_tagging_enable(struct net_backend *be)
{
	int flag = 1;

#ifdef TAPSTAGGING
	struct tap_priv *priv = NET_BE_PRIV(be);
	/* A previously peeked record lacks the prefix of the new format. */
	if (priv->bbuflen != 0) {
		errno = EBUSY;
		return (-1);
	}
	if (ioctl(be->fd, TAPSTAGGING, &flag) != 0)
		return (-1);
	be->tagging_enabled = 1;
	return (0);
#else
	be->tagging_enabled = 0;
	return (0);
#endif
}

static int
tap_tagging_enable_v2(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);
	int flag = 1;

	if (priv->bbuflen != 0) {
		errno = EBUSY;
		return (-1);
	}
	if (ioctl(be->fd, TAPSTAGGINGV2, &flag) != 0)
		return (-1);
	be->tagging_enabled = 1;
	be->tagging_v2_enabled = 1;
	return (0);
}

static int
tap_tagging_disable(struct net_backend *be)
{
	struct tap_priv *priv = NET_BE_PRIV(be);
	int flag = 0;

	if (!be->tagging_enabled)
		return (0);
#ifdef TAPSTAGGING
	if (ioctl(be->fd, be->tagging_v2_enabled ? TAPSTAGGINGV2 :
	    TAPSTAGGING, &flag) != 0)
		return (-1);
#endif
	/* A peeked record still carries the old tagged framing. */
	priv->bbuflen = 0;
	be->tagging_enabled = 0;
	be->tagging_v2_enabled = 0;
	return (0);
}

static struct net_backend tap_backend = {
	.prefix = "tap",
	.priv_size = sizeof(struct tap_priv),
	.init = tap_init,
	.cleanup = tap_cleanup,
	.send = tap_send,
	.peek_recvlen = tap_peek_recvlen,
	.checkpoint_rx_quiescent = tap_checkpoint_rx_quiescent,
	.checkpoint_rx_freeze = tap_checkpoint_rx_freeze,
	.recv = tap_recv,
	.recv_enable = tap_recv_enable,
	.recv_disable = tap_recv_disable,
	.get_cap = tap_get_cap,
	.set_cap = tap_set_cap,
	.tagging_supported = tap_tagging_supported,
	.tagging_bind_vm = tap_tagging_bind_vm,
	.tagging_enable = tap_tagging_enable,
	.tagging_enable_v2 = tap_tagging_enable_v2,
	.tagging_disable = tap_tagging_disable,
};

/* A clone of the tap backend, with a different prefix. */
static struct net_backend vmnet_backend = {
	.prefix = "vmnet",
	.priv_size = sizeof(struct tap_priv),
	.init = tap_init,
	.cleanup = tap_cleanup,
	.send = tap_send,
	.peek_recvlen = tap_peek_recvlen,
	.checkpoint_rx_quiescent = tap_checkpoint_rx_quiescent,
	.checkpoint_rx_freeze = tap_checkpoint_rx_freeze,
	.recv = tap_recv,
	.recv_enable = tap_recv_enable,
	.recv_disable = tap_recv_disable,
	.get_cap = tap_get_cap,
	.set_cap = tap_set_cap,
	.tagging_supported = tap_tagging_supported,
	.tagging_bind_vm = tap_tagging_bind_vm,
	.tagging_enable = tap_tagging_enable,
	.tagging_enable_v2 = tap_tagging_enable_v2,
	.tagging_disable = tap_tagging_disable,
};

/* A clone of the tap backend, with a different prefix. */
static struct net_backend ngd_backend = {
	.prefix = "ngd",
	.priv_size = sizeof(struct tap_priv),
	.init = tap_init,
	.cleanup = tap_cleanup,
	.send = tap_send,
	.peek_recvlen = tap_peek_recvlen,
	.checkpoint_rx_quiescent = tap_checkpoint_rx_quiescent,
	.checkpoint_rx_freeze = tap_checkpoint_rx_freeze,
	.recv = tap_recv,
	.recv_enable = tap_recv_enable,
	.recv_disable = tap_recv_disable,
	.get_cap = tap_get_cap,
	.set_cap = tap_set_cap,
};

DATA_SET(net_backend_set, tap_backend);
DATA_SET(net_backend_set, vmnet_backend);
DATA_SET(net_backend_set, ngd_backend);

int
netbe_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *backend, *cp;

	if (opts == NULL)
		return (0);

	cp = strchr(opts, ',');
	if (cp == NULL) {
		set_config_value_node(nvl, "backend", opts);
		return (0);
	}
	backend = strndup(opts, cp - opts);
	if (backend == NULL)
		return (ENOMEM);
	set_config_value_node(nvl, "backend", backend);
	free(backend);
	return (pci_parse_legacy_config(nvl, cp + 1));
}

/*
 * Initialize a backend and attach to the frontend.
 * This is called during frontend initialization.
 *  @ret is a pointer to the backend to be initialized
 *  @devname is the backend-name as supplied on the command line,
 * 	e.g. -s 2:0,frontend-name,backend-name[,other-args]
 *  @cb is the receive callback supplied by the frontend,
 *	and it is invoked in the event loop when a receive
 *	event is generated in the hypervisor,
 *  @param is a pointer to the frontend, and normally used as
 *	the argument for the callback.
 */
int
netbe_init(struct net_backend **ret, nvlist_t *nvl, net_be_rxeof_t cb,
    void *param)
{
	struct net_backend **pbe, *nbe, *tbe = NULL;
	const char *checkpoint_identity, *value, *type;
	char *devname;
	int err;

	value = get_config_value_node(nvl, "backend");
	if (value == NULL) {
		return (-1);
	}
	devname = strdup(value);
	if (devname == NULL)
		return (ENOMEM);

	/*
	 * Use the type given by configuration if exists; otherwise
	 * use the prefix of the backend as the type.
	 */
	type = get_config_value_node(nvl, "type");
	if (type == NULL)
		type = devname;

	/*
	 * Find the network backend that matches the user-provided
	 * device name. net_backend_set is built using a linker set.
	 */
	SET_FOREACH(pbe, net_backend_set) {
		if (strncmp(type, (*pbe)->prefix,
		    strlen((*pbe)->prefix)) == 0) {
			tbe = *pbe;
			assert(tbe->init != NULL);
			assert(tbe->cleanup != NULL);
			assert(tbe->send != NULL);
			assert(tbe->recv != NULL);
			assert(tbe->get_cap != NULL);
			assert(tbe->set_cap != NULL);
			break;
		}
	}

	*ret = NULL;
	if (tbe == NULL) {
		free(devname);
		return (EINVAL);
	}

	nbe = calloc(1, NET_BE_SIZE(tbe));
	if (nbe == NULL) {
		free(devname);
		return (ENOMEM);
	}
	*nbe = *tbe;	/* copy the template */
	nbe->fd = -1;
	nbe->sc = param;
	nbe->be_vnet_hdr_len = 0;
	nbe->fe_vnet_hdr_len = 0;
	nbe->fe_features = 0;
	checkpoint_identity = get_config_value_node(nvl,
	    "checkpoint_identity");
	err = netbe_make_checkpoint_identity(nbe->checkpoint_identity,
	    sizeof(nbe->checkpoint_identity), checkpoint_identity,
	    tbe->prefix, value);
	if (err != 0) {
		free(devname);
		free(nbe);
		return (err);
	}

	/* Initialize the backend. */
	err = nbe->init(nbe, devname, nvl, cb, param);
	if (err) {
		free(devname);
		free(nbe);
		return (err);
	}

	*ret = nbe;
	free(devname);

	return (0);
}

void
netbe_cleanup(struct net_backend *be)
{

	if (be != NULL) {
		be->cleanup(be);
		free(be);
	}
}

uint64_t
netbe_get_cap(struct net_backend *be)
{

	assert(be != NULL);
	return (be->get_cap(be));
}

int
netbe_set_cap(struct net_backend *be, uint64_t features,
	      unsigned vnet_hdr_len)
{
	uint64_t old_features;
	unsigned int old_vnet_hdr_len;
	int ret;

	assert(be != NULL);

	/* There are only three valid lengths, i.e., 0, 10 and 12. */
	if (vnet_hdr_len && vnet_hdr_len != VNET_HDR_LEN
		&& vnet_hdr_len != (VNET_HDR_LEN - sizeof(uint16_t)))
		return (-1);

	old_features = be->fe_features;
	old_vnet_hdr_len = be->fe_vnet_hdr_len;
	ret = be->set_cap(be, features, vnet_hdr_len);
	if (ret != 0)
		return (ret);
	if (be->be_vnet_hdr_len != vnet_hdr_len) {
		EPRINTLN("network backend installed header length %u, expected %u",
		    be->be_vnet_hdr_len, vnet_hdr_len);
		/*
		 * A successful backend callback with the wrong framing is not a
		 * partially acceptable result.  Restore the previous contract so
		 * feature negotiation and snapshot restore remain transactional.
		 */
		if (be->set_cap(be, old_features, old_vnet_hdr_len) != 0 ||
		    be->be_vnet_hdr_len != old_vnet_hdr_len)
			return (EIO);
		return (EPROTO);
	}
	be->fe_features = features;
	be->fe_vnet_hdr_len = vnet_hdr_len;
	return (0);
}

ssize_t
netbe_send(struct net_backend *be, const struct iovec *iov, int iovcnt)
{

	return (be->send(be, iov, iovcnt));
}

ssize_t
netbe_peek_recvlen(struct net_backend *be)
{

	return (be->peek_recvlen(be));
}

int
netbe_checkpoint_rx_quiescent(struct net_backend *be)
{

	/* A backend without a checkpoint cut cannot promise a safe V2 cut. */
	if (be == NULL || be->checkpoint_rx_quiescent == NULL)
		return (EOPNOTSUPP);
	return (be->checkpoint_rx_quiescent(be));
}

int
netbe_checkpoint_rx_freeze(struct net_backend *be, bool freeze)
{

	if (be == NULL || be->checkpoint_rx_freeze == NULL)
		return (EOPNOTSUPP);
	return (be->checkpoint_rx_freeze(be, freeze));
}

int
netbe_tagging_enabled(struct net_backend *be)
{

	return (be->tagging_enabled);
}

int
netbe_tagging_supported(struct net_backend *be)
{

	return (be->tagging_supported != NULL && be->tagging_supported(be));
}

int
netbe_tagging_bind_vm(struct net_backend *be, int vmfd)
{

	if (be->tagging_bind_vm == NULL) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	return (be->tagging_bind_vm(be, vmfd));
}

int
netbe_tagging_enable(struct net_backend *be)
{

	if (be->tagging_enable == NULL)
		return (EOPNOTSUPP);
	return (be->tagging_enable(be));
}

int
netbe_tagging_v2_supported(struct net_backend *be)
{

	/* V2 identities must have a stable receive cut for checkpointing. */
	return (be != NULL && be->tagging_enable_v2 != NULL &&
	    be->checkpoint_rx_freeze != NULL &&
	    be->checkpoint_rx_quiescent != NULL);
}

int
netbe_tagging_enable_v2(struct net_backend *be)
{

	if (!netbe_tagging_v2_supported(be)) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	return (be->tagging_enable_v2(be));
}

int
netbe_tagging_v2_enabled(struct net_backend *be)
{

	return (be->tagging_v2_enabled);
}

int
netbe_tagging_disable(struct net_backend *be)
{

	if (!be->tagging_enabled)
		return (0);
	if (be->tagging_disable == NULL)
		return (EOPNOTSUPP);
	return (be->tagging_disable(be));
}

/*
 * Try to read a packet from the backend, without blocking.
 * If no packets are available, return 0. In case of success, return
 * the length of the packet just read. Return -1 in case of errors.
 */
ssize_t
netbe_recv(struct net_backend *be, const struct iovec *iov, int iovcnt)
{

	return (be->recv(be, iov, iovcnt));
}

/*
 * Read a packet from the backend and discard it.
 * Returns the size of the discarded packet or zero if no packet was available.
 * A negative error code is returned in case of read error.
 */
ssize_t
netbe_rx_discard(struct net_backend *be)
{
	/*
	 * MP note: the dummybuf is only used to discard frames,
	 * so there is no need for it to be per-vtnet or locked.
	 * VirtIO 1.4 section 5.1.9.3 defines the largest packet as
	 * 65,589 bytes and the base virtio-net header as 12 bytes.
	 * Keep enough room for the complete backend record and V2 provenance so
	 * discarding it never relies on backend-specific truncation behavior.
	 */
	static uint8_t dummybuf[NETBE_MAX_RECORD_SIZE + sizeof(mbufid_v2_t)];
	struct iovec iov;

	iov.iov_base = dummybuf;
	iov.iov_len = sizeof(dummybuf);

	return netbe_recv(be, &iov, 1);
}

void
netbe_rx_disable(struct net_backend *be)
{

	return be->recv_disable(be);
}

void
netbe_rx_enable(struct net_backend *be)
{

	return be->recv_enable(be);
}

size_t
netbe_get_vnet_hdr_len(struct net_backend *be)
{

	return (be->be_vnet_hdr_len);
}

const char *
netbe_checkpoint_identity(struct net_backend *be)
{

	return (be == NULL ? NULL : be->checkpoint_identity);
}
