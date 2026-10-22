/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Scripted stand-in for dtraced, used only by coverage-cli.py.
 *
 * usage: cli-fake-dtraced SOCKET SCRIPT LOG
 *
 * The real dtrace(1) reaches this server through the preload shim's
 * connect() redirection.  It speaks the dtraced consumer protocol: server
 * hello, client hello, framed requests answered with one byte, and the
 * server-initiated messages of the ELFWRITE subscription.  Wire encoding
 * uses the shared dtraced_wire.h codecs; the test oracles are the CLI's
 * observable results (exit status, output, and the replies logged here).
 *
 * Script lines (executed in order by the current ELFWRITE connection; a
 * "close" hands the remaining steps to the next ELFWRITE connection):
 *   reg-ack N               ACK byte for the program registration (default 1)
 *   wait-elf N              wait until N ELF frames have been received
 *   send-elf SRC k=v...     send an ELF message (see send_elf())
 *   expect-ack              read and log one consumer ACK
 *   drain k=v... / stop k=v...   send a quiescence challenge, log the reply
 *   header TYPE [len]       send a bare header of any type
 *   short N                 send N bytes of a header, then close
 *   sleep MS
 *   close                   close this ELFWRITE connection
 *   hold                    keep the connection open until the peer closes
 * Policy lines (any position):
 *   frame-ack TYPE N VALUE  byte answering the Nth READDATA frame of TYPE
 *                           (0 means every frame); VALUE "close" closes
 *   info k=v...             reply for INFO subscriptions
 *   refuse-elfwrite N       close the Nth ELFWRITE connection after hello
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>

#include "dtraced.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"

#define	MAXSTEP	128
#define	MAXELF	32
#define	MAXPOL	32

static FILE *logfp;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static char *steps[MAXSTEP];
static int nsteps, step;
static struct {
	unsigned char *data;
	size_t len;
	char location[DTRACED_LOCSIZE];
} elfs[MAXELF];
static int nelfs;
static struct {
	uint64_t type;
	int nth;
	int value;		/* -1: close */
	int seen;
} pol[MAXPOL];
static int npol;
static uint8_t session[16];	/* consumer session from the ELFWRITE hello */
static uint8_t digest[32];	/* registered compiled-program digest */
static int registered;
static int reg_ack = 1;
static int reg_nack_nth;	/* refuse only the Nth registration */
static int refuse_elfwrite, nelfwrite;
static int drop_conn[8], ndrop;
static char info_spec[512];
static char dump_dir[256];
static int accepted;		/* connections accepted so far */
static int ack_delay_ms;	/* delay ACKs of outbound ELF frames */	/* every received ELF frame is written here */

static void
logf_(const char *fmt, ...)
{
	va_list ap;

	pthread_mutex_lock(&mtx);
	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);
	fputc('\n', logfp);
	fflush(logfp);
	pthread_mutex_unlock(&mtx);
}

static int64_t
deadline(void)
{
	return (dtraced_io_deadline_after(15000));
}

static int
xfer(int fd, void *p, size_t n, bool wr)
{
	size_t done;

	return (dtraced_io_transfer(fd, p, n, wr, deadline(), &done));
}

static void
hex16(const char *s, uint8_t out[16])
{
	memset(out, 0, 16);
	for (int i = 0; i < 16 && s[2 * i] && s[2 * i + 1]; i++) {
		char h[3] = { s[2 * i], s[2 * i + 1], 0 };
		out[i] = strtoul(h, NULL, 16);
	}
}

static void
hexdump(char *out, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", p[i]);
}

static const char *
kv(const char *line, const char *key, char *buf, size_t cap)
{
	size_t kl = strlen(key);
	const char *p = line;

	while ((p = strstr(p, key)) != NULL) {
		if ((p == line || p[-1] == ' ') && p[kl] == '=') {
			size_t n = strcspn(p + kl + 1, " \n");

			if (n >= cap)
				n = cap - 1;
			memcpy(buf, p + kl + 1, n);
			buf[n] = '\0';
			return (buf);
		}
		p += kl;
	}
	return (NULL);
}

static uint64_t
kvnum(const char *line, const char *key, uint64_t def)
{
	char buf[64];

	return (kv(line, key, buf, sizeof (buf)) ? strtoull(buf, NULL, 0) : def);
}

/* Fill a 16-byte identity: "zero", "session", hex, or derived from seed. */
static void
ident(const char *line, const char *key, uint8_t out[16], unsigned seed)
{
	char buf[64];

	if (kv(line, key, buf, sizeof (buf)) == NULL) {
		for (int i = 0; i < 16; i++)
			out[i] = (uint8_t)(seed * 31 + i + 1);
	} else if (strcmp(buf, "zero") == 0)
		memset(out, 0, 16);
	else if (strcmp(buf, "session") == 0)
		memcpy(out, session, 16);
	else
		hex16(buf, out);
}

static int
send_header(int fd, const dtraced_hdr_t *h)
{
	unsigned char wire[DTRACED_MSGHDRSIZE];

	dtraced_wire_encode_header(wire, h);
	return (xfer(fd, wire, sizeof (wire), true));
}

/*
 * send-elf SRC [vmid=] [epoch=] [delivery=] [name=] [program=] [source=]
 *     [installed=match|mismatch|none] [isession=session|zero|HEX]
 *     [envelope=yes|no|bad] [len=N]
 * SRC: base (first base ELF received), derived (last outbound ELF received,
 * target prefix removed), elf#N, or garbage.
 */
static int
send_elf(int fd, const char *line)
{
	char src[512], name[64], buf[64];
	const unsigned char *elf = NULL;
	unsigned char *payload, garbage[64];
	size_t elflen = 0, prefix = 0, namelen, total;
	struct hypertrace_vm_envelope env = { 0 };
	dtraced_hdr_t h = { 0 };
	uint16_t vmid = kvnum(line, "vmid", 0);
	uint64_t epoch = kvnum(line, "epoch", vmid ? 1 : 0);
	int i, rc;

	sscanf(line, "send-elf %511s", src);
	pthread_mutex_lock(&mtx);
	if (strcmp(src, "base") == 0) {
		for (i = 0; i < nelfs; i++)
			if (strcmp(elfs[i].location, "base") == 0)
				break;
	} else if (strcmp(src, "derived") == 0) {
		for (i = nelfs - 1; i >= 0; i--)
			if (strcmp(elfs[i].location, "outbound") == 0)
				break;
	} else if (strncmp(src, "elf#", 4) == 0)
		i = atoi(src + 4);
	else
		i = -1;
	if (i >= 0 && i < nelfs) {
		elf = elfs[i].data;
		elflen = elfs[i].len;
		if (elflen >= HYPERTRACE_VM_ENVELOPE_WIRE_SIZE &&
		    memcmp(elf, "\177ELF", 4) != 0) {
			elf += HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
			elflen -= HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
		}
	}
	pthread_mutex_unlock(&mtx);
	if (strncmp(src, "file:", 5) == 0) {
		FILE *fp = fopen(src + 5, "r");
		static unsigned char fbuf[4 * 1024 * 1024];

		if (fp != NULL) {
			elflen = fread(fbuf, 1, sizeof (fbuf), fp);
			fclose(fp);
			elf = fbuf;
		}
	}
	if (strcmp(src, "garbage") == 0) {
		memset(garbage, 0x5a, sizeof (garbage));
		memcpy(garbage, "\177ELF", 4);
		elf = garbage;
		elflen = sizeof (garbage);
	}
	if (elf == NULL) {
		logf_("ERROR no ELF source %s", src);
		return (-1);
	}
	if (kv(line, "name", name, sizeof (name)) == NULL)
		strlcpy(name, "vm0", sizeof (name));
	namelen = strlen(name);
	if (kv(line, "envelope", buf, sizeof (buf)) == NULL)
		strlcpy(buf, vmid ? "yes" : "no", sizeof (buf));
	if (strcmp(buf, "no") != 0)
		prefix = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + namelen;
	total = prefix + elflen;
	payload = malloc(total);
	if (prefix != 0) {
		env.magic = strcmp(buf, "bad") == 0 ? 0x1234 :
		    HYPERTRACE_ENVELOPE_MAGIC;
		env.version = kvnum(line, "env_version",
		    HYPERTRACE_ENVELOPE_VERSION);
		env.vmid = kvnum(line, "env_vmid", vmid);
		env.epoch = kvnum(line, "env_epoch", epoch);
		env.name_length = kvnum(line, "env_namelen", namelen);
		hypertrace_envelope_encode(payload, &env);
		memcpy(payload + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, name,
		    namelen);
		if (kvnum(line, "name_nul", 0))
			payload[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE] = '\0';
	}
	memcpy(payload + prefix, elf, elflen);
	if (kvnum(line, "elf_bad", 0))
		payload[prefix] = 'X';
	if (kvnum(line, "truncate", 0) != 0)
		total = kvnum(line, "truncate", 0);
	h.msg_type = DTRACED_MSG_ELF;
	h.elf.len = kvnum(line, "len", total);
	h.elf.delivery_id = kvnum(line, "delivery", 0);
	if (h.elf.delivery_id == 0) {
		/* An unidentified frame may still carry stray identity. */
		h.elf.vmid = kvnum(line, "hvmid", 0);
		h.elf.epoch = kvnum(line, "hepoch", 0);
	} else {
		h.elf.vmid = kvnum(line, "hvmid", vmid);
		h.elf.epoch = kvnum(line, "hepoch", epoch);
		ident(line, "program", h.elf.program_id,
		    (unsigned)h.elf.delivery_id);
		ident(line, "source", h.elf.source_id,
		    (unsigned)h.elf.delivery_id + 100);
	}
	if (kv(line, "installed", buf, sizeof (buf)) == NULL)
		strlcpy(buf, h.elf.delivery_id ? "match" : "none",
		    sizeof (buf));
	if (strcmp(buf, "none") != 0) {
		h.installed.delivery_id = h.elf.delivery_id +
		    (strcmp(buf, "mismatch") == 0);
		h.installed.vmid = h.elf.vmid + (strcmp(buf, "vmid") == 0);
		h.installed.epoch = h.elf.epoch + (strcmp(buf, "epoch") == 0);
		memcpy(h.installed.program_id, h.elf.program_id, 16);
		memcpy(h.installed.source_id, h.elf.source_id, 16);
		if (strcmp(buf, "program") == 0)
			h.installed.program_id[0] ^= 1;
		if (strcmp(buf, "source") == 0)
			h.installed.source_id[0] ^= 1;
		ident(line, "isession", (uint8_t *)h.installed.name, 0);
		if (kv(line, "isession", buf, sizeof (buf)) == NULL)
			memcpy(h.installed.name, session, 16);
	}
	rc = send_header(fd, &h);
	if (rc == 0 && !kvnum(line, "headeronly", 0))
		rc = xfer(fd, payload, total < h.elf.len ? total : h.elf.len,
		    true);
	logf_("SENT-ELF %s delivery=%ju vmid=%u epoch=%ju bytes=%zu rc=%d", src,
	    (uintmax_t)h.elf.delivery_id, vmid, (uintmax_t)epoch, total, rc);
	free(payload);
	return (rc);
}

static int
expect_ack(int fd)
{
	unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];

	if (xfer(fd, wire, sizeof (wire), false) != 0) {
		logf_("ACK-READ-FAILED errno=%d", errno);
		return (-1);
	}
	logf_("ACK delivery=%ju vmid=%u epoch=%ju outcome=%u",
	    (uintmax_t)dtraced_wire_get_u64(wire),
	    dtraced_wire_get_u16(wire + 40),
	    (uintmax_t)dtraced_wire_get_u64(wire + 48), wire[42]);
	return (0);
}

/* drain|stop [token=HEX] [vmid=] [epoch=] [csession=session|HEX]
 *     [digest=match|zero|bad] [len=N] [noreply=1] */
static int
challenge(int fd, const char *line, int stop)
{
	dtraced_consumer_drain_t c = { 0 }, r;
	unsigned char wire[DTRACED_CONSUMER_STOP_WIRE_SIZE];
	unsigned char reply[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE];
	dtraced_hdr_t h = { 0 };
	char buf[80];
	size_t n;

	if (kv(line, "token", buf, sizeof (buf)) != NULL)
		hex16(buf, c.token);
	else
		memset(c.token, 0x77, 16);
	memset(c.source_session, 0x55, 16);
	if (kv(line, "csession", buf, sizeof (buf)) == NULL ||
	    strcmp(buf, "session") == 0)
		memcpy(c.consumer_session, session, 16);
	else
		hex16(buf, c.consumer_session);
	if (kv(line, "digest", buf, sizeof (buf)) == NULL ||
	    strcmp(buf, "match") == 0)
		memcpy(c.program_digest, digest, 32);
	else
		memset(c.program_digest, 0xee, 32);
	c.vmid = kvnum(line, "vmid", 3);
	c.epoch = kvnum(line, "epoch", 9);
	if (stop) {
		dtraced_wire_encode_consumer_stop(wire, &c);
		n = DTRACED_CONSUMER_STOP_WIRE_SIZE;
		if (kvnum(line, "badmagic", 0))
			wire[0] = 'X';
	} else {
		dtraced_wire_encode_consumer_drain(wire, &c);
		n = DTRACED_CONSUMER_DRAIN_WIRE_SIZE;
		if (kvnum(line, "zerotoken", 0))
			memset(wire, 0, 16);
	}
	h.msg_type = stop ? DTRACED_MSG_CONSUMER_STOP :
	    DTRACED_MSG_CONSUMER_DRAIN;
	h.elf.len = n;
	if (send_header(fd, &h) != 0 ||
	    xfer(fd, wire, kvnum(line, "len", n), true) != 0) {
		logf_("%s-SEND-FAILED errno=%d", stop ? "STOP" : "DRAIN", errno);
		return (-1);
	}
	if (kvnum(line, "noreply", 0))
		return (0);
	n = stop ? DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE :
	    DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE;
	if (xfer(fd, reply, n, false) != 0) {
		logf_("%s-REPLY-FAILED errno=%d", stop ? "STOP" : "DRAIN",
		    errno);
		return (-1);
	}
	if ((stop ? dtraced_wire_decode_consumer_stop_ack(&r, reply) :
	    dtraced_wire_decode_consumer_drain_ack(&r, reply)) != 0) {
		logf_("%s-REPLY-MALFORMED", stop ? "STOP" : "DRAIN");
		return (-1);
	}
	logf_("%s-REPLY result=%u echo=%d", stop ? "STOP" : "DRAIN", r.result,
	    memcmp(r.token, c.token, 16) == 0 && r.vmid == c.vmid &&
	    r.epoch == c.epoch);
	return (0);
}

static int
policy(uint64_t type)
{
	int i, value = 1;

	pthread_mutex_lock(&mtx);
	for (i = 0; i < npol; i++) {
		if (pol[i].type != type)
			continue;
		pol[i].seen++;
		if (pol[i].nth == 0 || pol[i].nth == pol[i].seen)
			value = pol[i].value;
	}
	pthread_mutex_unlock(&mtx);
	return (value);
}

/* READDATA: framed requests, each answered with one byte. */
static void
readdata(int fd, int conn)
{
	for (;;) {
		unsigned char hw[DTRACED_MSGHDRSIZE], answer;
		dtraced_hdr_t h;
		size_t size, done, body;
		unsigned char *data = NULL;
		int value;

		if (dtraced_io_read_size(fd, &size, deadline(), &done) != 0)
			break;
		if (size < DTRACED_MSGHDRSIZE || size > 64U * 1024 * 1024 ||
		    xfer(fd, hw, sizeof (hw), false) != 0) {
			logf_("FRAME-BAD conn=%d size=%zu", conn, size);
			break;
		}
		if (dtraced_wire_decode_header(&h, hw) != 0) {
			logf_("FRAME-HEADER-INVALID conn=%d type=%ju", conn,
			    (uintmax_t)dtraced_wire_get_u64(hw));
			break;
		}
		body = size - DTRACED_MSGHDRSIZE;
		if (body != 0) {
			data = malloc(body);
			if (xfer(fd, data, body, false) != 0) {
				free(data);
				break;
			}
		}
		if (h.msg_type == DTRACED_MSG_ELF && dump_dir[0] != '\0') {
			char path[400], tmp[410];
			FILE *fp;

			pthread_mutex_lock(&mtx);
			snprintf(path, sizeof (path), "%s/elf-%d-%s.bin", dump_dir,
			    nelfs, h.elf.location);
			snprintf(tmp, sizeof (tmp), "%s.tmp", path);
			if ((fp = fopen(tmp, "w")) != NULL) {
				fwrite(data, 1, body, fp);
				fclose(fp);
				rename(tmp, path);
			}
			pthread_mutex_unlock(&mtx);
		}
		if (h.msg_type == DTRACED_MSG_ELF) {
			pthread_mutex_lock(&mtx);
			if (nelfs < MAXELF) {
				elfs[nelfs].data = data;
				elfs[nelfs].len = body;
				strlcpy(elfs[nelfs].location, h.elf.location,
				    DTRACED_LOCSIZE);
				nelfs++;
				data = NULL;
			}
			pthread_cond_broadcast(&cv);
			pthread_mutex_unlock(&mtx);
			logf_("ELF conn=%d location=%s bytes=%zu ident=%d "
			    "delivery=%ju ivmid=%u", conn, h.elf.location, body,
			    h.elf.ident_present,
			    (uintmax_t)h.installed.delivery_id,
			    h.installed.vmid);
		} else if (h.msg_type == DTRACED_MSG_CONSUMER_EXECUTION &&
		    body == DTRACED_CONSUMER_EXECUTION_WIRE_SIZE) {
			dtraced_consumer_ack_t x;
			char s[33];

			if (dtraced_wire_decode_consumer_execution(&x,
			    data) != 0)
				logf_("EXEC-MALFORMED conn=%d", conn);
			else {
				hexdump(s, x.ingress_session, 16);
				logf_("EXEC conn=%d delivery=%ju vmid=%u "
				    "outcome=%u session_ok=%d", conn,
				    (uintmax_t)x.delivery_id, x.vmid,
				    x.outcome, memcmp(x.ingress_session,
				    session, 16) == 0);
			}
		} else if (h.msg_type == DTRACED_MSG_CONSUMER_STOP_COMMIT) {
			dtraced_consumer_stop_t st;

			logf_("COMMIT conn=%d valid=%d result=%u", conn,
			    body == DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE &&
			    dtraced_wire_decode_consumer_stop_ack(&st,
			    data) == 0, body ==
			    DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE ? st.result :
			    255);
		} else if (h.msg_type == DTRACED_MSG_KILL) {
			logf_("KILL conn=%d pid=%d vmid=%u epoch=%ju", conn,
			    h.kill.pid, h.kill.vmid,
			    (uintmax_t)h.kill.epoch);
		} else {
			logf_("FRAME conn=%d type=%ju bytes=%zu", conn,
			    (uintmax_t)h.msg_type, body);
		}
		free(data);
		if (h.msg_type == DTRACED_MSG_ELF && ack_delay_ms > 0 &&
		    strcmp(elfs[nelfs > 0 ? nelfs - 1 : 0].location,
		    "outbound") == 0)
			usleep(ack_delay_ms * 1000);
		value = policy(h.msg_type);
		if (value < 0) {
			logf_("FRAME-CLOSE conn=%d type=%ju", conn,
			    (uintmax_t)h.msg_type);
			break;
		}
		answer = (unsigned char)value;
		if (xfer(fd, &answer, 1, true) != 0)
			break;
	}
}

static void
info(int fd)
{
	dtraced_hdr_t h = { 0 };
	unsigned char wire[DTRACED_INFO_WIRE_SIZE];
	char buf[256], *names, *tok, *save = NULL;
	uint64_t count;
	int unterminated = (int)kvnum(info_spec, "unterminated", 0);

	if (kv(info_spec, "names", buf, sizeof (buf)) == NULL)
		buf[0] = '\0';
	names = strdup(buf);
	count = 0;
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",",
	    &save))
		count++;
	if (kvnum(info_spec, "short", 0)) {
		(void) xfer(fd, wire, 10, true);
		free(names);
		return;
	}
	h.msg_type = kvnum(info_spec, "type", DTRACED_MSG_INFO);
	h.info.count = kvnum(info_spec, "count", count);
	if (kvnum(info_spec, "badvm", 0))
		h.elf.vmid = 0xffff;
	if (send_header(fd, &h) != 0)
		goto out;
	save = NULL;
	for (tok = strtok_r(names, ",", &save); tok; tok = strtok_r(NULL, ",",
	    &save)) {
		dtraced_infomsg_t m = { 0 };
		char *colon = strchr(tok, ':');

		m.client_kind = colon ? atoi(colon + 1) :
		    DTRACED_KIND_FORWARDER;
		if (colon)
			*colon = '\0';
		strlcpy(m.client_name, tok, sizeof (m.client_name));
		if (unterminated)
			memset(m.client_name, 'z', sizeof (m.client_name));
		dtraced_wire_encode_info(wire, &m);
		if (kvnum(info_spec, "badentry", 0))
			wire[0] = 0x7f;
		if (xfer(fd, wire, sizeof (wire), true) != 0)
			break;
	}
out:
	free(names);
}

static int
next_step(char *line, size_t cap)
{
	int ok = 0;

	pthread_mutex_lock(&mtx);
	if (step < nsteps) {
		strlcpy(line, steps[step++], cap);
		ok = 1;
	}
	pthread_mutex_unlock(&mtx);
	return (ok);
}

static void
elfwrite(int fd, int conn)
{
	unsigned char hw[DTRACED_MSGHDRSIZE], body[64], answer;
	dtraced_hdr_t h;
	size_t size, done;
	char line[512];
	int n;

	pthread_mutex_lock(&mtx);
	n = ++nelfwrite;
	pthread_mutex_unlock(&mtx);
	if (n == refuse_elfwrite) {
		logf_("ELFWRITE-REFUSED conn=%d", conn);
		return;
	}
	/* Registration: HPI2 (64 bytes) program binding. */
	if (dtraced_io_read_size(fd, &size, deadline(), &done) != 0 ||
	    size != DTRACED_MSGHDRSIZE + 64 || xfer(fd, hw, sizeof (hw),
	    false) != 0 || dtraced_wire_decode_header(&h, hw) != 0 ||
	    h.msg_type != DTRACED_MSG_CONSUMER_PROGRAM ||
	    xfer(fd, body, 64, false) != 0) {
		logf_("REGISTRATION-BAD conn=%d", conn);
		return;
	}
	pthread_mutex_lock(&mtx);
	memcpy(digest, body + 8, 32);
	registered++;
	pthread_mutex_unlock(&mtx);
	logf_("REGISTERED conn=%d magic=%.4s", conn, body);
	answer = (unsigned char)reg_ack;
	pthread_mutex_lock(&mtx);
	if (registered == reg_nack_nth)
		answer = 0;
	pthread_mutex_unlock(&mtx);
	if (xfer(fd, &answer, 1, true) != 0 || answer != 1)
		return;
	for (;;) {
		char probe;

		/* A connection the consumer has closed takes no more steps;
		 * they belong to its reconnection. */
		if (recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
			logf_("PEER-CLOSED conn=%d", conn);
			return;
		}
		if (!next_step(line, sizeof (line)))
			break;
		logf_("STEP %s conn=%d", line, conn);
		if (strncmp(line, "repeat ", 7) == 0) {
			/* repeat N send-elf ...: N sends without waiting. */
			int n = atoi(line + 7);
			char *rest = strchr(line + 7, ' ');

			for (int i = 0; rest != NULL && i < n; i++)
				if (send_elf(fd, rest + 1) != 0)
					return;
			continue;
		}
		if (strncmp(line, "wait-elf", 8) == 0) {
			int want = atoi(line + 9);

			pthread_mutex_lock(&mtx);
			while (nelfs < want)
				pthread_cond_wait(&cv, &mtx);
			pthread_mutex_unlock(&mtx);
		} else if (strncmp(line, "send-elf", 8) == 0) {
			if (send_elf(fd, line) != 0)
				return;
		} else if (strcmp(line, "expect-ack") == 0) {
			if (expect_ack(fd) != 0)
				return;
		}
		else if (strncmp(line, "drain", 5) == 0) {
			/* A failed exchange ends this connection; the
			 * remaining steps go to the consumer's reconnection. */
			if (challenge(fd, line, 0) != 0)
				return;
		} else if (strncmp(line, "stop", 4) == 0) {
			if (challenge(fd, line, 1) != 0)
				return;
		}
		else if (strncmp(line, "header", 6) == 0) {
			dtraced_hdr_t x = { 0 };

			x.msg_type = strtoull(line + 7, NULL, 0);
			x.elf.len = kvnum(line, "len", 0);
			(void) send_header(fd, &x);
		} else if (strncmp(line, "short", 5) == 0) {
			memset(hw, 0, sizeof (hw));
			(void) xfer(fd, hw, atoi(line + 6), true);
			return;
		} else if (strncmp(line, "save-elf", 8) == 0) {
			/* save-elf derived|base|N PATH: ELF bytes without the
			 * target prefix, for an external guest run. */
			char which[32], path[256];
			int i = -1;

			if (sscanf(line, "save-elf %31s %255s", which, path) == 2) {
				pthread_mutex_lock(&mtx);
				for (int k = nelfs - 1; k >= 0 && i < 0; k--)
					if (strcmp(elfs[k].location, which) == 0 ||
					    (strcmp(which, "derived") == 0 &&
					    strcmp(elfs[k].location, "outbound") == 0))
						i = k;
				if (i < 0 && which[0] >= '0' && which[0] <= '9')
					i = atoi(which);
				if (i >= 0 && i < nelfs) {
					unsigned char *e = elfs[i].data;
					size_t n = elfs[i].len;
					char tmp[300];
					FILE *fp;

					if (n >= HYPERTRACE_VM_ENVELOPE_WIRE_SIZE &&
					    memcmp(e, "\177ELF", 4) != 0) {
						e += HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
						n -= HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
					}
					snprintf(tmp, sizeof (tmp), "%s.tmp", path);
					fp = fopen(tmp, "w");
					fwrite(e, 1, n, fp);
					fclose(fp);
					rename(tmp, path);
				}
				pthread_mutex_unlock(&mtx);
				logf_("SAVED %s index=%d", path, i);
			}
		} else if (strncmp(line, "wait-log", 8) == 0) {
			/* wait-log PATH TEXT: until the shim log has TEXT. */
			char path[256], *text = NULL;
			int found = 0;

			if (sscanf(line, "wait-log %255s", path) == 1)
				text = strchr(line + 9, ' ');
			while (text != NULL && !found) {
				FILE *fp = fopen(path, "r");
				char buf[512];

				while (fp != NULL && fgets(buf, sizeof (buf), fp))
					if (strstr(buf, text + 1) != NULL)
						found = 1;
				if (fp != NULL)
					fclose(fp);
				if (!found)
					usleep(10000);
			}
		} else if (strncmp(line, "wait-conn", 9) == 0) {
			/* wait-conn N: until N connections have been accepted. */
			int want = atoi(line + 10);

			while (__atomic_load_n(&accepted, __ATOMIC_SEQ_CST) < want)
				usleep(10000);
		} else if (strncmp(line, "wait-file", 9) == 0) {
			struct stat st;

			while (stat(line + 10, &st) != 0)
				usleep(10000);
		} else if (strncmp(line, "sleep", 5) == 0)
			usleep(atoi(line + 6) * 1000);
		else if (strcmp(line, "close") == 0)
			return;
		else if (strcmp(line, "hold") == 0) {
			while (read(fd, hw, sizeof (hw)) > 0)
				continue;
			return;
		} else
			logf_("ERROR unknown step %s", line);
	}
	/* Script exhausted: wait for the consumer to go away. */
	while (read(fd, hw, sizeof (hw)) > 0)
		continue;
}

struct conn {
	int fd, id;
};

static void *
serve(void *arg)
{
	struct conn *c = arg;
	dtd_initmsg_t hello = { 0 }, peer;
	size_t done;
	char s[33];

	for (int i = 0; i < ndrop; i++) {
		if (drop_conn[i] == c->id) {
			logf_("DROP conn=%d", c->id);
			goto out;
		}
	}
	hello.kind = DTRACED_KIND_DTRACED;
	hello.protocol_version = DTRACED_PROTOCOL_VERSION;
	if (dtraced_wire_write_init(c->fd, &hello, deadline(), &done) != 0 ||
	    dtraced_wire_read_init(c->fd, &peer, deadline(), &done) != 0) {
		logf_("HELLO-FAILED conn=%d", c->id);
		goto out;
	}
	hexdump(s, peer.session_id, 16);
	logf_("CONN %d kind=%d subs=%ju version=%u ident_prefix=%.7s "
	    "session=%s", c->id, peer.kind, (uintmax_t)peer.subs,
	    peer.protocol_version, peer.ident, s);
	if (peer.subs == DTD_SUB_INFO)
		info(c->fd);
	else if (peer.subs == DTD_SUB_READDATA)
		readdata(c->fd, c->id);
	else if (peer.subs == DTD_SUB_ELFWRITE) {
		pthread_mutex_lock(&mtx);
		memcpy(session, peer.session_id, 16);
		pthread_mutex_unlock(&mtx);
		elfwrite(c->fd, c->id);
	}
out:
	logf_("CLOSE %d", c->id);
	close(c->fd);
	free(c);
	return (NULL);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	char line[512];
	FILE *script;
	int lfd, id = 0;

	if (argc != 4)
		return (2);
	signal(SIGPIPE, SIG_IGN);
	logfp = fopen(argv[3], "w");
	script = fopen(argv[2], "r");
	if (logfp == NULL || script == NULL)
		return (2);
	while (fgets(line, sizeof (line), script) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0' || line[0] == '#')
			continue;
		if (strncmp(line, "frame-ack ", 10) == 0 && npol < MAXPOL) {
			char v[16];

			sscanf(line + 10, "%ju %d %15s",
			    (uintmax_t *)&pol[npol].type, &pol[npol].nth, v);
			pol[npol].value = strcmp(v, "close") == 0 ? -1 : atoi(v);
			npol++;
		} else if (strncmp(line, "info ", 5) == 0)
			strlcpy(info_spec, line, sizeof (info_spec));
		else if (strncmp(line, "reg-nack ", 9) == 0)
			reg_nack_nth = atoi(line + 9);
		else if (strncmp(line, "reg-ack ", 8) == 0)
			reg_ack = atoi(line + 8);
		else if (strncmp(line, "ack-delay ", 10) == 0)
			ack_delay_ms = atoi(line + 10);
		else if (strncmp(line, "dump-dir ", 9) == 0)
			strlcpy(dump_dir, line + 9, sizeof (dump_dir));
		else if (strncmp(line, "drop-conn ", 10) == 0 && ndrop < 8)
			drop_conn[ndrop++] = atoi(line + 10);
		else if (strncmp(line, "refuse-elfwrite ", 16) == 0)
			refuse_elfwrite = atoi(line + 16);
		else if (nsteps < MAXSTEP)
			steps[nsteps++] = strdup(line);
	}
	fclose(script);
	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	strlcpy(sun.sun_path, argv[1], sizeof (sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	unlink(argv[1]);
	if (lfd < 0 || bind(lfd, (void *)&sun, sun.sun_len) != 0 ||
	    listen(lfd, 16) != 0)
		return (3);
	logf_("LISTENING");
	for (;;) {
		struct conn *c = calloc(1, sizeof (*c));
		pthread_t t;

		c->fd = accept(lfd, NULL, NULL);
		if (c->fd < 0) {
			free(c);
			continue;
		}
		c->id = ++id;
		__atomic_store_n(&accepted, id, __ATOMIC_SEQ_CST);
		pthread_create(&t, NULL, serve, c);
		pthread_detach(t);
	}
}
