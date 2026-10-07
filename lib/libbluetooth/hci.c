/*
 * hci.c
 */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009 Maksim Yevmenkin <m_evmenkin@yahoo.com>
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <assert.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int    bt_devany_cb(int s, struct bt_devinfo const *di, void *xdevname);
static char * bt_dev2node (char const *devname, char *nodename, int nnlen);
static time_t bt_get_default_hci_command_timeout(void);
static ssize_t bt_devrecv_until(int, void *, size_t,
    const struct timespec *, int);

/* A single monotonic budget survives signals and unrelated HCI events. */
static int
bt_deadline(time_t seconds, struct timespec *end)
{

	if (clock_gettime(CLOCK_MONOTONIC, end) < 0)
		return (-1);
	if (__builtin_add_overflow(end->tv_sec, seconds, &end->tv_sec)) {
		errno = EOVERFLOW;
		return (-1);
	}
	return (0);
}

static int
bt_devwait(int s, short events, const struct timespec *end, int poll_once)
{
	struct pollfd pfd = { .fd = s, .events = events };
	struct timespec now, remaining, *timeout;
	int n;

	if (s < 0) {
		errno = EBADF;
		return (-1);
	}
	for (;;) {
		timeout = NULL;
		if (end != NULL) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
				return (-1);
			timespecsub(end, &now, &remaining);
			if (remaining.tv_sec < 0) {
				if (!poll_once) {
					errno = ETIMEDOUT;
					return (-1);
				}
				timespecclear(&remaining);
			}
			timeout = &remaining;
		}
		poll_once = 0;
		n = ppoll(&pfd, 1, timeout, NULL);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return (-1);
		}
		if (n == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if (pfd.revents & POLLNVAL) {
			errno = EBADF;
			return (-1);
		}
		return (0);
	}
}

int
bt_devopen(char const *devname)
{
	struct sockaddr_hci	ha;
	bdaddr_t		ba;
	int			s;

	if (devname == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&ha, 0, sizeof(ha));
	ha.hci_len = sizeof(ha);
	ha.hci_family = AF_BLUETOOTH;

	if (bt_aton(devname, &ba)) {
		if (!bt_devname(ha.hci_node, &ba))
			return (-1);
	} else if (bt_dev2node(devname, ha.hci_node,
					sizeof(ha.hci_node)) == NULL) {
		errno = ENXIO;
		return (-1);
	}

	s = socket(PF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI);
	if (s < 0)
		return (-1);

	/* HCI names are not paths; 5BSD's *at socket calls work in capmode. */
	if (bindat(s, s, (struct sockaddr *) &ha, sizeof(ha)) < 0 ||
	    connectat(s, s, (struct sockaddr *) &ha, sizeof(ha)) < 0) {
		close(s);
		return (-1);
	}

	return (s);
}

int
bt_devclose(int s)
{
	return (close(s));
}

int
bt_devsend(int s, uint16_t opcode, void *param, size_t plen)
{
	ng_hci_cmd_pkt_t	h;
	struct iovec		iv[2];
	int			ivn;
	ssize_t			n;

	if ((plen == 0 && param != NULL) ||
	    (plen > 0 && param == NULL) ||
	    plen > UINT8_MAX) { 
		errno = EINVAL;
		return (-1);
	}

	iv[0].iov_base = &h;
	iv[0].iov_len = sizeof(h);
	ivn = 1;

	h.type = NG_HCI_CMD_PKT;
	h.opcode = htole16(opcode);
	if (plen > 0) {
		h.length = plen;

		iv[1].iov_base = param;
		iv[1].iov_len = plen;
		ivn = 2;
	} else
		h.length = 0;

	while ((n = writev(s, iv, ivn)) < 0) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN && bt_devwait(s, POLLOUT, NULL, 0) == 0)
			continue;

		return (-1);
	}
	/* Commands are records: never accept or retry a partially sent record. */
	if ((size_t)n != sizeof(h) + plen) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

ssize_t
bt_devrecv(int s, void *buf, size_t size, time_t to)
{
	struct timespec end;

	if (to >= 0 && bt_deadline(to, &end) < 0)
		return (-1);
	return (bt_devrecv_until(s, buf, size, to >= 0 ? &end : NULL, 1));
}

static ssize_t
bt_devrecv_until(int s, void *buf, size_t size, const struct timespec *end,
    int poll_once)
{
	ssize_t n;

	if (buf == NULL || size == 0) {
		errno = EINVAL;
		return (-1);
	}

	for (;;) {
		if (bt_devwait(s, POLLIN, end, poll_once) < 0)
			return (-1);
		poll_once = 0;
		n = read(s, buf, size);
		if (n >= 0)
			break;
		if (errno == EAGAIN || errno == EINTR)
			continue;

		return (-1);
	}
	if (n == 0) {
		errno = ECONNRESET;
		return (-1);
	}

	switch (*((uint8_t *) buf)) {
	case NG_HCI_CMD_PKT: {
		ng_hci_cmd_pkt_t	*h = (ng_hci_cmd_pkt_t *) buf;

		if (n >= sizeof(*h) && n == (sizeof(*h) + h->length))
			return (n);
		} break;

	case NG_HCI_ACL_DATA_PKT: {
		ng_hci_acldata_pkt_t	*h = (ng_hci_acldata_pkt_t *) buf;

		if (n >= sizeof(*h) && n == (sizeof(*h) + le16toh(h->length)))
			return (n);
		} break;

	case NG_HCI_SCO_DATA_PKT: {
		ng_hci_scodata_pkt_t	*h = (ng_hci_scodata_pkt_t *) buf;

		if (n >= sizeof(*h) && n == (sizeof(*h) + h->length))
			return (n);
		} break;

	case NG_HCI_EVENT_PKT: {
		ng_hci_event_pkt_t	*h = (ng_hci_event_pkt_t *) buf;

		if (n >= sizeof(*h) && n == (sizeof(*h) + h->length))
			return (n);
		} break;
	}

	errno = EIO;
	return (-1);
}

int
bt_devreq(int s, struct bt_devreq *r, time_t to)
{

	return (bt_devreq_events(s, r, to, NULL));
}

/* The event callback must copy the packet and must not reenter this socket. */
int
bt_devreq_events(int s, struct bt_devreq *r, time_t to,
    void (*event_cb)(int, const void *, size_t))
{
	uint8_t				buf[320]; /* more than enough */
	ng_hci_event_pkt_t		*e = (ng_hci_event_pkt_t *) buf;
	ng_hci_command_compl_ep		*cc = (ng_hci_command_compl_ep *)(e+1);
	ng_hci_command_status_ep	*cs = (ng_hci_command_status_ep*)(e+1);
	struct bt_devfilter		old, new;
	struct timespec			end;
	uint16_t			opcode;
	ssize_t				n;
	int				error, poll_once;

	if (s < 0 || r == NULL || to < 0) {
		errno = EINVAL;
		return (-1);
	}

	if ((r->rlen == 0 && r->rparam != NULL) ||
	    (r->rlen > 0 && r->rparam == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Finding H-H3: zero-fill the caller's return-parameter buffer up front.
	 * A short or empty Command Complete (or a Command Status mapped success)
	 * copies fewer than r->rlen octets — historically leaving the tail as
	 * caller stack garbage while still returning 0.  Pre-zeroing means an
	 * absent/truncated response yields deterministic zeros (status field
	 * included) rather than uninitialized memory, protecting every
	 * libbluetooth consumer.
	 */
	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);

	/* Keep subscribed events queued if they arrive just after completion. */
	if (bt_devfilter(s, NULL, &old) < 0)
		return (-1);
	memset(&new, 0, sizeof(new));
	memcpy(new.event_mask, old.event_mask, sizeof(new.event_mask));
	bt_devfilter_pkt_set(&new, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&new, NG_HCI_EVENT_COMMAND_COMPL);
	bt_devfilter_evt_set(&new, NG_HCI_EVENT_COMMAND_STATUS);
	if (r->event != 0)
		bt_devfilter_evt_set(&new, r->event);

	if (bt_devfilter(s, &new, NULL) < 0)
		return (-1);

	error = 0;

	n = bt_devsend(s, r->opcode, r->cparam, r->clen);
	if (n < 0) {
		error = errno;
		goto out;	
	}

	opcode = htole16(r->opcode);
	if (bt_deadline(to, &end) < 0) {
		error = errno;
		goto out;
	}
	poll_once = 1;

	do {
		n = bt_devrecv_until(s, buf, sizeof(buf), &end, poll_once);
		poll_once = 0;
		if (n < 0) {
			error = errno;
			goto out;
		}

		if (e->type != NG_HCI_EVENT_PKT) {
			error = EIO;
			goto out;
		}

		n -= sizeof(*e);

		switch (e->event) {
		case NG_HCI_EVENT_COMMAND_COMPL:
			if (n < (ssize_t)sizeof(*cc)) {
				error = EIO;
				goto out;
			}
			if (cc->opcode == opcode) {
				n -= sizeof(*cc);

				/*
				 * C3-M3: copy min(rlen, n) rather than skipping
				 * the copy entirely when the controller returns
				 * MORE bytes than the caller's buffer.  The old
				 * `if (rlen >= n)` guard failed on an oversize
				 * response, leaving rlen unchanged and (with the
				 * H-H3 zero-fill) the caller reading an all-zero
				 * buffer as a status==0 success.  Copying what
				 * fits keeps the status byte + available fields
				 * real; a short/absent response reduces rlen to
				 * the actual length, so it stays distinguishable.
				 */
				if (n < 0)
					n = 0;
				if ((ssize_t)r->rlen > n)
					r->rlen = n;
				if (r->rlen > 0)
					memcpy(r->rparam, cc + 1, r->rlen);

				goto out;
			}
			break;

		case NG_HCI_EVENT_COMMAND_STATUS:
			if (n < (ssize_t)sizeof(*cs)) {
				error = EIO;
				goto out;
			}
			if (cs->opcode == opcode) {
				if (r->event != NG_HCI_EVENT_COMMAND_STATUS) {
					if (cs->status != 0) {
						error = EIO;
						goto out;
					}
				} else {
					/* C3-M3: copy min(rlen, n). */
					if (n < 0)
						n = 0;
					if ((ssize_t)r->rlen > n)
						r->rlen = n;
					if (r->rlen > 0)
						memcpy(r->rparam, cs, r->rlen);

					goto out;
				}
			}
			break;

		default:
			if (e->event == r->event) {
				/* C3-M3: copy min(rlen, n). */
				if (n < 0)
					n = 0;
				if ((ssize_t)r->rlen > n)
					r->rlen = n;
				if (r->rlen > 0)
					memcpy(r->rparam, e + 1, r->rlen);

				goto out;
			}
			if (event_cb != NULL)
				event_cb(s, buf, (size_t)n + sizeof(*e));
			break;
		}
	} while (to > 0);

	error = ETIMEDOUT;
out:
	if (bt_devfilter(s, &old, NULL) < 0 && error == 0)
		error = errno;

	if (error != 0) {
		errno = error;
		return (-1);
	}

	return (0);
}

int
bt_devfilter(int s, struct bt_devfilter const *new, struct bt_devfilter *old)
{
	struct ng_btsocket_hci_raw_filter	f;
	socklen_t				len;

	if (new == NULL && old == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (old != NULL) {
		len = sizeof(f);
		if (getsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER, &f, &len) < 0)
			return (-1);

		memset(old, 0, sizeof(*old));
		memcpy(old->packet_mask, &f.packet_mask,
			MIN(sizeof(old->packet_mask), sizeof(f.packet_mask)));
		memcpy(old->event_mask, &f.event_mask,
			MIN(sizeof(old->event_mask), sizeof(f.event_mask)));
	}

	if (new != NULL) {
		memset(&f, 0, sizeof(f));
		memcpy(&f.packet_mask, new->packet_mask,
			MIN(sizeof(f.packet_mask), sizeof(new->packet_mask)));
		memcpy(&f.event_mask, new->event_mask,
			MIN(sizeof(f.event_mask), sizeof(new->event_mask)));

		len = sizeof(f);
		if (setsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER, &f, len) < 0)
			return (-1);
	}

	return (0);
}

void
bt_devfilter_pkt_set(struct bt_devfilter *filter, uint8_t type)
{
	bit_set(filter->packet_mask, type - 1);
}

void
bt_devfilter_pkt_clr(struct bt_devfilter *filter, uint8_t type)
{
	bit_clear(filter->packet_mask, type - 1);
}

int
bt_devfilter_pkt_tst(struct bt_devfilter const *filter, uint8_t type)
{
	return (bit_test(filter->packet_mask, type - 1));
}

void
bt_devfilter_evt_set(struct bt_devfilter *filter, uint8_t event)
{
	bit_set(filter->event_mask, event - 1);
}

void
bt_devfilter_evt_clr(struct bt_devfilter *filter, uint8_t event)
{
	bit_clear(filter->event_mask, event - 1);
}

int
bt_devfilter_evt_tst(struct bt_devfilter const *filter, uint8_t event)
{
	return (bit_test(filter->event_mask, event - 1));
}

int
bt_devinquiry(char const *devname, time_t length, int num_rsp,
		struct bt_devinquiry **ii)
{
	uint8_t				buf[320];
	char				_devname[HCI_DEVNAME_SIZE];
	struct bt_devfilter		f;
	ng_hci_inquiry_cp		*cp = (ng_hci_inquiry_cp *) buf;
	ng_hci_event_pkt_t		*e = (ng_hci_event_pkt_t *) buf;
	ng_hci_inquiry_result_ep	*ep = (ng_hci_inquiry_result_ep *)(e+1);
	ng_hci_inquiry_response		*ir;
	struct bt_devinquiry		*i;
	int				s, n;

	if (ii == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (devname == NULL) {
		memset(_devname, 0, sizeof(_devname));
		devname = _devname;

		n = bt_devenum(bt_devany_cb, _devname);
		if (n <= 0) {
			if (n == 0)
				*ii = NULL;

			return (n);
		}
	}

	s = bt_devopen(devname);
	if (s < 0)
		return (-1);

	if (bt_devfilter(s, NULL, &f) < 0) {
		bt_devclose(s);
		return (-1);
	}

	bt_devfilter_evt_set(&f, NG_HCI_EVENT_INQUIRY_COMPL);
	bt_devfilter_evt_set(&f, NG_HCI_EVENT_INQUIRY_RESULT);

	if (bt_devfilter(s, &f, NULL) < 0) {
		bt_devclose(s);
		return (-1);
	}

	/* Always use GIAC LAP */
	cp->lap[0] = 0x33;
	cp->lap[1] = 0x8b;
	cp->lap[2] = 0x9e;

	/*
	 * Calculate inquire length in 1.28 second units
	 * v2.x specification says that 1.28 -> 61.44 seconds
	 * range is acceptable
	 */

	if (length <= 0)
		length = 5;
	else if (length == 1)
		length = 2;
	else if (length > 62)
		length = 62;

	cp->inquiry_length = (uint8_t)((length * 100) / 128);

	if (num_rsp <= 0 || num_rsp > 255)
		num_rsp = 8;
	cp->num_responses = (uint8_t) num_rsp;

	i = *ii = calloc(num_rsp, sizeof(struct bt_devinquiry));
	if (i == NULL) {
		bt_devclose(s);
		errno = ENOMEM;
		return (-1);
	}

	if (bt_devsend(s,
		NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL, NG_HCI_OCF_INQUIRY),
			cp, sizeof(*cp)) < 0) {
		free(*ii);
		*ii = NULL;
		bt_devclose(s);
		return (-1);
	}

wait_for_more:

	n = bt_devrecv(s, buf, sizeof(buf), length);
	if (n < 0) {
		/*
		 * Free the allocation BASE, not i: i is advanced past *ii for
		 * every response copied out of an INQUIRY_RESULT, so free(i)
		 * on a later error would pass an interior pointer to free()
		 * (undefined behavior) and leak the real block.
		 */
		free(*ii);
		*ii = NULL;
		bt_devclose(s);
		return (-1);
	}

	if (n < sizeof(ng_hci_event_pkt_t)) {
		free(*ii);
		*ii = NULL;
		bt_devclose(s);
		errno = EIO;
		return (-1);
	}

	switch (e->event) {
	case NG_HCI_EVENT_INQUIRY_COMPL:
		break;

	case NG_HCI_EVENT_INQUIRY_RESULT: {
		/*
		 * Core Spec 6.3 Vol 4 Part E §7.7.2 Inquiry Result: bound the
		 * per-event response count to the bytes actually received.  Use
		 * SIGNED arithmetic so a short INQUIRY_RESULT event (bt_devrecv
		 * only guarantees n >= sizeof(*e)) cannot underflow the size_t
		 * expression into a huge max_ir and drive an over-read.
		 */
		int avail = (int)n - (int)sizeof(*e) - (int)sizeof(*ep);
		int max_ir = (avail > 0) ? avail / (int)sizeof(*ir) : 0;
		int count = ep->num_responses;
		if (count > max_ir)
			count = max_ir;

		ir = (ng_hci_inquiry_response *)(ep + 1);

		for (n = 0; n < MIN(count, num_rsp); n ++) {
			bdaddr_copy(&i->bdaddr, &ir->bdaddr);
			i->pscan_rep_mode = ir->page_scan_rep_mode;
			i->pscan_period_mode = ir->page_scan_period_mode;
			memcpy(i->dev_class, ir->uclass, sizeof(i->dev_class));
			i->clock_offset = le16toh(ir->clock_offset);

			ir ++;
			i ++;
		}
		/*
		 * Decrement the remaining response budget AFTER the loop:
		 * num_rsp must not be part of the loop bound while also being
		 * mutated inside it, or index and bound converge twice as fast
		 * and half of a multi-response INQUIRY_RESULT is dropped.
		 */
		num_rsp -= n;
		} /* FALLTHROUGH */

	default:
		goto wait_for_more;
		/* NOT REACHED */
	}

	bt_devclose(s);
		
	return (i - *ii);
}

char *
bt_devremote_name(char const *devname, const bdaddr_t *remote, time_t to,
    uint16_t clk_off, uint8_t ps_rep_mode, uint8_t ps_mode)
{
	char				 _devname[HCI_DEVNAME_SIZE];
	struct bt_devreq		 r;
	ng_hci_remote_name_req_cp	 cp;
	ng_hci_remote_name_req_compl_ep	 ep;
	int				 s;
	char				*remote_name = NULL;

	if (remote == NULL || to < 0) {
		errno = EINVAL;
		goto out;
	}

	if (to == 0) {
		to = bt_get_default_hci_command_timeout();
		if (to < 0)
			goto out;
	}
	to++;

	if (devname == NULL) {
		memset(_devname, 0, sizeof(_devname));
		devname = _devname;
		if (bt_devenum(bt_devany_cb, _devname) <= 0)
			goto out;
        }

	memset(&r, 0, sizeof(r));
	memset(&cp, 0, sizeof(cp));
	memset(&ep, 0, sizeof(ep));
	cp.clock_offset = htole16(clk_off);
	cp.page_scan_rep_mode = ps_rep_mode;
	cp.page_scan_mode = ps_mode;
	bdaddr_copy(&cp.bdaddr, remote);
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
				 NG_HCI_OCF_REMOTE_NAME_REQ);
	r.event = NG_HCI_EVENT_REMOTE_NAME_REQ_COMPL;
	r.cparam = &cp;
	r.clen = sizeof(cp);
	r.rparam = &ep;
	r.rlen = sizeof(ep);

	s = bt_devopen(devname);
	if (s < 0)
		goto out;

	/*
	 * Core Spec 6.3 Vol 4 Part E §7.7.7: the Remote Name is valid only
	 * when the request succeeded AND the Remote Name Request Complete
	 * Status == 0x00.  Use && -- ep is memset(0) above, so a || would
	 * report a bogus empty name whenever bt_devreq() failed/timed out
	 * (ep.status still 0) or completed with a non-zero status.
	 */
	if (bt_devreq(s, &r, to) == 0 && ep.status == 0x00)
		remote_name = strndup((const char *)&ep.name, sizeof(ep.name));

	bt_devclose(s);
out:
	return (remote_name);
}

int
bt_devinfo(struct bt_devinfo *di)
{
	union {
		struct ng_btsocket_hci_raw_node_state		r0;
		struct ng_btsocket_hci_raw_node_bdaddr		r1;
		struct ng_btsocket_hci_raw_node_features	r2;
		struct ng_btsocket_hci_raw_node_buffer		r3;
		struct ng_btsocket_hci_raw_node_stat		r4;
		struct ng_btsocket_hci_raw_node_link_policy_mask r5;
		struct ng_btsocket_hci_raw_node_packet_mask	r6;
		struct ng_btsocket_hci_raw_node_role_switch	r7;
		struct ng_btsocket_hci_raw_node_debug		r8;
	}						rp;
	struct sockaddr_hci				ha;
	socklen_t					halen;
	int						s, rval;

	if (di == NULL) {
		errno = EINVAL;
		return (-1);
	}

	s = bt_devopen(di->devname);
	if (s < 0)
		return (-1);

	rval = -1;

	halen = sizeof(ha);
	if (getsockname(s, (struct sockaddr *) &ha, &halen) < 0)
		goto bad;
	strlcpy(di->devname, ha.hci_node, sizeof(di->devname));

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_STATE, &rp.r0, sizeof(rp.r0)) < 0)
		goto bad;
	di->state = rp.r0.state;

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_BDADDR, &rp.r1, sizeof(rp.r1)) < 0)
		goto bad;
	bdaddr_copy(&di->bdaddr, &rp.r1.bdaddr);
	
	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_FEATURES, &rp.r2, sizeof(rp.r2)) < 0)
		goto bad;
	memcpy(di->features, rp.r2.features, sizeof(di->features));

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_BUFFER, &rp.r3, sizeof(rp.r3)) < 0)
		goto bad;
	di->cmd_free = rp.r3.buffer.cmd_free;
	di->sco_size = rp.r3.buffer.sco_size;
	di->sco_pkts = rp.r3.buffer.sco_pkts;
	di->sco_free = rp.r3.buffer.sco_free;
	di->acl_size = rp.r3.buffer.acl_size;
	di->acl_pkts = rp.r3.buffer.acl_pkts;
	di->acl_free = rp.r3.buffer.acl_free;

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_STAT, &rp.r4, sizeof(rp.r4)) < 0)
		goto bad;
	di->cmd_sent = rp.r4.stat.cmd_sent;
	di->evnt_recv = rp.r4.stat.evnt_recv;
	di->acl_recv = rp.r4.stat.acl_recv;
	di->acl_sent = rp.r4.stat.acl_sent;
	di->sco_recv = rp.r4.stat.sco_recv;
	di->sco_sent = rp.r4.stat.sco_sent;
	di->bytes_recv = rp.r4.stat.bytes_recv;
	di->bytes_sent = rp.r4.stat.bytes_sent;

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_LINK_POLICY_MASK,
			&rp.r5, sizeof(rp.r5)) < 0)
		goto bad;
	di->link_policy_info = rp.r5.policy_mask;

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_PACKET_MASK,
			&rp.r6, sizeof(rp.r6)) < 0)
		goto bad;
	di->packet_type_info = rp.r6.packet_mask;

	 if (ioctl(s, SIOC_HCI_RAW_NODE_GET_ROLE_SWITCH,
			&rp.r7, sizeof(rp.r7)) < 0)
		goto bad;
	di->role_switch_info = rp.r7.role_switch;

	if (ioctl(s, SIOC_HCI_RAW_NODE_GET_DEBUG, &rp.r8, sizeof(rp.r8)) < 0)
		goto bad;
	di->debug = rp.r8.debug;

	rval = 0;
bad:
	bt_devclose(s);

	return (rval);
}

int
bt_devenum(bt_devenum_cb_t cb, void *arg)
{
	struct ng_btsocket_hci_raw_node_list_names	rp;
	struct bt_devinfo				di;
	struct sockaddr_hci				ha;
	int						s, i, count;

	rp.num_names = HCI_DEVMAX;
	rp.names = (struct nodeinfo *) calloc(rp.num_names,
						sizeof(struct nodeinfo));
	if (rp.names == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	memset(&ha, 0, sizeof(ha));
	ha.hci_len = sizeof(ha);
	ha.hci_family = AF_BLUETOOTH;
	ha.hci_node[0] = 'x';

	s = socket(PF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI);
	if (s < 0) {
		free(rp.names);

		return (-1);
	}

	if (bindat(s, s, (struct sockaddr *) &ha, sizeof(ha)) < 0 ||
	    connectat(s, s, (struct sockaddr *) &ha, sizeof(ha)) < 0 ||
	    ioctl(s, SIOC_HCI_RAW_NODE_LIST_NAMES, &rp, sizeof(rp)) < 0) {
		close(s);
		free(rp.names);

		return (-1);
	}

	for (count = 0, i = 0; i < rp.num_names; i ++) {
		strlcpy(di.devname, rp.names[i].name, sizeof(di.devname));
		if (bt_devinfo(&di) < 0)
			continue;

		count ++;

		if (cb == NULL)
			continue;

		strlcpy(ha.hci_node, rp.names[i].name, sizeof(ha.hci_node));
		if (bindat(s, s, (struct sockaddr *) &ha, sizeof(ha)) < 0 ||
		    connectat(s, s, (struct sockaddr *) &ha, sizeof(ha)) < 0)
			continue;

		if ((*cb)(s, &di, arg) > 0)
			break;
	}

	close (s);
	free(rp.names);

	return (count);
}

static int
bt_devany_cb(int s, struct bt_devinfo const *di, void *xdevname)
{
	strlcpy((char *) xdevname, di->devname, HCI_DEVNAME_SIZE);
	return (1);
}

static char *
bt_dev2node(char const *devname, char *nodename, int nnlen)
{
	static char const *	 bt_dev_prefix[] = {
		"ubt",		/* Bluetooth USB devices */
		"vhci",		/* Virtual HCI controllers (ng_hci_virt) */
		NULL		/* should be last */
	};

	static char		_nodename[HCI_DEVNAME_SIZE];
	char const		**p;
	char			*ep;
	int			plen, unit;

	if (nodename == NULL) {
		nodename = _nodename;
		nnlen = HCI_DEVNAME_SIZE;
	}

	for (p = bt_dev_prefix; *p != NULL; p ++) {
		plen = strlen(*p);
		if (strncmp(devname, *p, plen) != 0)
			continue;

		unit = strtoul(devname + plen, &ep, 10);
		if (*ep != '\0' &&
		    strcmp(ep, "hci") != 0 &&
		    strcmp(ep, "l2cap") != 0)
			return (NULL);	/* can't make sense of device name */

		snprintf(nodename, nnlen, "%s%uhci", *p, unit);

		return (nodename);
	}

	return (NULL);
}

static time_t
bt_get_default_hci_command_timeout(void)
{
	int	to;
	size_t	to_size = sizeof(to);

	if (sysctlbyname("net.bluetooth.hci.command_timeout",
			 &to, &to_size, NULL, 0) < 0)
		return (-1);

	/* Should not happen */
	if (to <= 0) {
		errno = ERANGE;
		return (-1);
	}

	return ((time_t)to);
}
