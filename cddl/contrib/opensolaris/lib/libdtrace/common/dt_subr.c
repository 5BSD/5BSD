/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Use is subject to license terms.
 */

#ifdef illumos
#include <sys/sysmacros.h>
#endif
#include <sys/isa_defs.h>
#include <sys/socket.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#ifdef illumos
#include <alloca.h>
#else
#include <sys/sysctl.h>
#include <libproc_compat.h>
#endif
#include <assert.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <unistd.h>

#include <dt_impl.h>
#include <dtraced.h>
#include <sys/hypertrace_wire.h>
#include "dtraced_io.h"
#include "dtraced_wire.h"
#include "dtraced_derived.h"
#include <dt_hypertrace.h>
#include <dt_oformat.h>

static const struct {
	size_t dtps_offset;
	size_t dtps_len;
} dtrace_probespecs[] = {
	{ offsetof(dtrace_probedesc_t, dtpd_target),	DTRACE_TARGETNAMELEN },
	{ offsetof(dtrace_probedesc_t, dtpd_provider),	DTRACE_PROVNAMELEN },
	{ offsetof(dtrace_probedesc_t, dtpd_mod),	DTRACE_MODNAMELEN },
	{ offsetof(dtrace_probedesc_t, dtpd_func),	DTRACE_FUNCNAMELEN },
	{ offsetof(dtrace_probedesc_t, dtpd_name),	DTRACE_NAMELEN }
};

int
dtrace_xstr2desc(dtrace_hdl_t *dtp, dtrace_probespec_t spec,
    const char *s, int argc, char *const argv[], dtrace_probedesc_t *pdp)
{
	size_t off, len, vlen, wlen;
	const char *p, *q, *v, *w;

	char buf[32]; /* for id_t as %d (see below) */

	if (spec < DTRACE_PROBESPEC_NONE || spec > DTRACE_PROBESPEC_NAME)
		return (dt_set_errno(dtp, EINVAL));

	bzero(pdp, sizeof (dtrace_probedesc_t));
	p = s + strlen(s) - 1;

	do {
		for (len = 0; p >= s && *p != ':'; len++)
			p--; /* move backward until we find a delimiter */

		q = p + 1;
		vlen = 0;
		w = NULL;
		wlen = 0;

		if ((v = strchr(q, '$')) != NULL && v < q + len) {
			/*
			 * Set vlen to the length of the variable name and then
			 * reset len to the length of the text prior to '$'. If
			 * the name begins with a digit, interpret it using the
			 * the argv[] array.  Otherwise we look in dt_macros.
			 * For the moment, all dt_macros variables are of type
			 * id_t (see dtrace_update() for more details on that).
			 */
			vlen = (size_t)(q + len - v);
			len = (size_t)(v - q);

			/*
			 * If the variable string begins with $$, skip past the
			 * leading dollar sign since $ and $$ are equivalent
			 * macro reference operators in a probe description.
			 */
			if (vlen > 2 && v[1] == '$') {
				vlen--;
				v++;
			}

			if (isdigit(v[1])) {
				long i;

				/*
				 * A digit string is never negative, and an
				 * overflow yields LONG_MAX, which exceeds any
				 * int argc.
				 */
				i = strtol(v + 1, (char **)&w, 10);

				wlen = vlen - (w - v);

				if (i >= argc)
					return (dt_set_errno(dtp, EDT_BADSPCV));

				v = argv[i];
				vlen = strlen(v);

				if (yypcb != NULL && yypcb->pcb_sargv == argv)
					yypcb->pcb_sflagv[i] |= DT_IDFLG_REF;

			} else if (vlen > 1) {
				char *vstr = alloca(vlen);
				dt_ident_t *idp;

				(void) strncpy(vstr, v + 1, vlen - 1);
				vstr[vlen - 1] = '\0';
				idp = dt_idhash_lookup(dtp->dt_macros, vstr);

				if (idp == NULL)
					return (dt_set_errno(dtp, EDT_BADSPCV));

				v = buf;
				vlen = snprintf(buf, 32, "%d", idp->di_id);

			} else
				return (dt_set_errno(dtp, EDT_BADSPCV));
		}

		if (spec == DTRACE_PROBESPEC_NONE)
			return (dt_set_errno(dtp, EDT_BADSPEC));

		if (len + vlen >= dtrace_probespecs[spec].dtps_len)
			return (dt_set_errno(dtp, ENAMETOOLONG));

		off = dtrace_probespecs[spec--].dtps_offset;
		bcopy(q, (char *)pdp + off, len);
		bcopy(v, (char *)pdp + off + len, vlen);
		bcopy(w, (char *)pdp + off + len + vlen, wlen);
	} while (--p >= s);

	pdp->dtpd_id = DTRACE_IDNONE;
	return (0);
}

int
dtrace_str2desc(dtrace_hdl_t *dtp, dtrace_probespec_t spec,
    const char *s, dtrace_probedesc_t *pdp)
{
	return (dtrace_xstr2desc(dtp, spec, s, 0, NULL, pdp));
}

int
dtrace_id2desc(dtrace_hdl_t *dtp, dtrace_id_t id, dtrace_probedesc_t *pdp)
{
	bzero(pdp, sizeof (dtrace_probedesc_t));
	pdp->dtpd_id = id;
	/*
	 * NOTE: We only support id2desc for host probes.
	 */
	pdp->dtpd_vmid = 0;

	if (dt_ioctl(dtp, DTRACEIOC_PROBES, pdp) == -1 ||
	    pdp->dtpd_id != id)
		return (dt_set_errno(dtp, EDT_BADID));

	return (0);
}

char *
dtrace_desc2str(const dtrace_probedesc_t *pdp, char *buf, size_t len)
{
	if (pdp->dtpd_id == 0) {
		(void) snprintf(buf, len, "%s:%s:%s:%s", pdp->dtpd_provider,
		    pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);
	} else
		(void) snprintf(buf, len, "%u", pdp->dtpd_id);

	return (buf);
}

char *
dtrace_attr2str(dtrace_attribute_t attr, char *buf, size_t len)
{
	const char *name = dtrace_stability_name(attr.dtat_name);
	const char *data = dtrace_stability_name(attr.dtat_data);
	const char *class = dtrace_class_name(attr.dtat_class);

	if (name == NULL || data == NULL || class == NULL)
		return (NULL); /* one or more invalid attributes */

	(void) snprintf(buf, len, "%s/%s/%s", name, data, class);
	return (buf);
}

static char *
dt_getstrattr(char *p, char **qp)
{
	char *q;

	if (*p == '\0')
		return (NULL);

	if ((q = strchr(p, '/')) == NULL)
		q = p + strlen(p);
	else
		*q++ = '\0';

	*qp = q;
	return (p);
}

int
dtrace_str2attr(const char *str, dtrace_attribute_t *attr)
{
	dtrace_stability_t s;
	dtrace_class_t c;
	char *p, *q;

	if (str == NULL || attr == NULL)
		return (-1); /* invalid function arguments */

	*attr = _dtrace_maxattr;
	p = alloca(strlen(str) + 1);
	(void) strcpy(p, str);

	if ((p = dt_getstrattr(p, &q)) == NULL)
		return (0);

	for (s = 0; s <= DTRACE_STABILITY_MAX; s++) {
		if (strcasecmp(p, dtrace_stability_name(s)) == 0) {
			attr->dtat_name = s;
			break;
		}
	}

	if (s > DTRACE_STABILITY_MAX)
		return (-1);

	if ((p = dt_getstrattr(q, &q)) == NULL)
		return (0);

	for (s = 0; s <= DTRACE_STABILITY_MAX; s++) {
		if (strcasecmp(p, dtrace_stability_name(s)) == 0) {
			attr->dtat_data = s;
			break;
		}
	}

	if (s > DTRACE_STABILITY_MAX)
		return (-1);

	if ((p = dt_getstrattr(q, &q)) == NULL)
		return (0);

	for (c = 0; c <= DTRACE_CLASS_MAX; c++) {
		if (strcasecmp(p, dtrace_class_name(c)) == 0) {
			attr->dtat_class = c;
			break;
		}
	}

	if (c > DTRACE_CLASS_MAX || (p = dt_getstrattr(q, &q)) != NULL)
		return (-1);

	return (0);
}

const char *
dtrace_stability_name(dtrace_stability_t s)
{
	switch (s) {
	case DTRACE_STABILITY_INTERNAL:	return ("Internal");
	case DTRACE_STABILITY_PRIVATE:	return ("Private");
	case DTRACE_STABILITY_OBSOLETE:	return ("Obsolete");
	case DTRACE_STABILITY_EXTERNAL:	return ("External");
	case DTRACE_STABILITY_UNSTABLE:	return ("Unstable");
	case DTRACE_STABILITY_EVOLVING:	return ("Evolving");
	case DTRACE_STABILITY_STABLE:	return ("Stable");
	case DTRACE_STABILITY_STANDARD:	return ("Standard");
	default:			return (NULL);
	}
}

const char *
dtrace_class_name(dtrace_class_t c)
{
	switch (c) {
	case DTRACE_CLASS_UNKNOWN:	return ("Unknown");
	case DTRACE_CLASS_CPU:		return ("CPU");
	case DTRACE_CLASS_PLATFORM:	return ("Platform");
	case DTRACE_CLASS_GROUP:	return ("Group");
	case DTRACE_CLASS_ISA:		return ("ISA");
	case DTRACE_CLASS_COMMON:	return ("Common");
	default:			return (NULL);
	}
}

dtrace_attribute_t
dt_attr_min(dtrace_attribute_t a1, dtrace_attribute_t a2)
{
	dtrace_attribute_t am;

	am.dtat_name = MIN(a1.dtat_name, a2.dtat_name);
	am.dtat_data = MIN(a1.dtat_data, a2.dtat_data);
	am.dtat_class = MIN(a1.dtat_class, a2.dtat_class);

	return (am);
}

dtrace_attribute_t
dt_attr_max(dtrace_attribute_t a1, dtrace_attribute_t a2)
{
	dtrace_attribute_t am;

	am.dtat_name = MAX(a1.dtat_name, a2.dtat_name);
	am.dtat_data = MAX(a1.dtat_data, a2.dtat_data);
	am.dtat_class = MAX(a1.dtat_class, a2.dtat_class);

	return (am);
}

/*
 * Compare two attributes and return an integer value in the following ranges:
 *
 * <0 if any of a1's attributes are less than a2's attributes
 * =0 if all of a1's attributes are equal to a2's attributes
 * >0 if all of a1's attributes are greater than or equal to a2's attributes
 *
 * To implement this function efficiently, we subtract a2's attributes from
 * a1's to obtain a negative result if an a1 attribute is less than its a2
 * counterpart.  We then OR the intermediate results together, relying on the
 * twos-complement property that if any result is negative, the bitwise union
 * will also be negative since the highest bit will be set in the result.
 */
int
dt_attr_cmp(dtrace_attribute_t a1, dtrace_attribute_t a2)
{
	return (((int)a1.dtat_name - a2.dtat_name) |
	    ((int)a1.dtat_data - a2.dtat_data) |
	    ((int)a1.dtat_class - a2.dtat_class));
}

char *
dt_attr_str(dtrace_attribute_t a, char *buf, size_t len)
{
	static const char stability[] = "ipoxuesS";
	static const char class[] = "uCpgIc";

	/* The letter tables are strings: exclude their terminating NUL. */
	if (a.dtat_name < sizeof (stability) - 1 &&
	    a.dtat_data < sizeof (stability) - 1 &&
	    a.dtat_class < sizeof (class) - 1) {
		(void) snprintf(buf, len, "[%c/%c/%c]", stability[a.dtat_name],
		    stability[a.dtat_data], class[a.dtat_class]);
	} else {
		(void) snprintf(buf, len, "[%u/%u/%u]",
		    a.dtat_name, a.dtat_data, a.dtat_class);
	}

	return (buf);
}

char *
dt_version_num2str(dt_version_t v, char *buf, size_t len)
{
	uint_t M = DT_VERSION_MAJOR(v);
	uint_t m = DT_VERSION_MINOR(v);
	uint_t u = DT_VERSION_MICRO(v);

	if (u == 0)
		(void) snprintf(buf, len, "%u.%u", M, m);
	else
		(void) snprintf(buf, len, "%u.%u.%u", M, m, u);

	return (buf);
}

int
dt_version_str2num(const char *s, dt_version_t *vp)
{
	int i = 0, n[3] = { 0, 0, 0 };
	char c;

	while ((c = *s++) != '\0') {
		if (isdigit(c)) {
			/* Every component is below 2^12: refuse before overflow. */
			if (n[i] > DT_VERSION_MINMAX)
				return (-1);
			n[i] = n[i] * 10 + c - '0';
		} else if (c != '.' || i++ >= sizeof (n) / sizeof (n[0]) - 1)
			return (-1);
	}

	if (n[0] > DT_VERSION_MAJMAX ||
	    n[1] > DT_VERSION_MINMAX ||
	    n[2] > DT_VERSION_MICMAX)
		return (-1);

	if (vp != NULL)
		*vp = DT_VERSION_NUMBER(n[0], n[1], n[2]);

	return (0);
}

int
dt_version_defined(dt_version_t v)
{
	int i;

	for (i = 0; _dtrace_versions[i] != 0; i++) {
		if (_dtrace_versions[i] == v)
			return (1);
	}

	return (0);
}

char *
dt_cpp_add_arg(dtrace_hdl_t *dtp, const char *str)
{
	char *arg;

	if (dtp->dt_cpp_argc == dtp->dt_cpp_args) {
		int olds = dtp->dt_cpp_args;
		int news = olds * 2;
		char **argv = realloc(dtp->dt_cpp_argv, sizeof (char *) * news);

		if (argv == NULL)
			return (NULL);

		bzero(&argv[olds], sizeof (char *) * olds);
		dtp->dt_cpp_argv = argv;
		dtp->dt_cpp_args = news;
	}

	if ((arg = strdup(str)) == NULL)
		return (NULL);

	assert(dtp->dt_cpp_argc < dtp->dt_cpp_args);
	dtp->dt_cpp_argv[dtp->dt_cpp_argc++] = arg;
	return (arg);
}

char *
dt_cpp_pop_arg(dtrace_hdl_t *dtp)
{
	char *arg;

	if (dtp->dt_cpp_argc <= 1)
		return (NULL); /* dt_cpp_argv[0] cannot be popped */

	arg = dtp->dt_cpp_argv[--dtp->dt_cpp_argc];
	dtp->dt_cpp_argv[dtp->dt_cpp_argc] = NULL;

	return (arg);
}

int
dt_cpu_maxid(dtrace_hdl_t *dtp)
{
	size_t len;
	u_int count;
	int error;

	len = sizeof(count);
	error = sysctlbyname("kern.smp.maxid", &count, &len, NULL, 0);
	if (error != 0)
		return (dt_set_errno(dtp, errno));
	return (count);
}

/*PRINTFLIKE1*/
void
dt_dprintf(const char *format, ...)
{
	if (_dtrace_debug) {
		va_list alist;

		va_start(alist, format);
		(void) fputs("libdtrace DEBUG: ", stderr);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}

int
#ifdef illumos
dt_ioctl(dtrace_hdl_t *dtp, int val, void *arg)
#else
dt_ioctl(dtrace_hdl_t *dtp, u_long val, void *arg)
#endif
{
	const dtrace_vector_t *v = dtp->dt_vector;

#ifndef illumos
	/* Avoid sign extension. */
	val &= 0xffffffff;
#endif

	if (v != NULL)
		return (v->dtv_ioctl(dtp->dt_varg, val, arg));

	if (dtp->dt_fd >= 0)
		return (ioctl(dtp->dt_fd, val, arg));

	errno = EBADF;
	return (-1);
}

int
dt_status(dtrace_hdl_t *dtp, processorid_t cpu)
{
	const dtrace_vector_t *v = dtp->dt_vector;

	if (v == NULL) {
#ifdef illumos
		return (p_online(cpu, P_STATUS));
#else
		int maxid = 0;
		size_t len = sizeof(maxid);
		if (sysctlbyname("kern.smp.maxid", &maxid, &len, NULL, 0) != 0)
			return (cpu == 0 ? 1 : -1);
		else
			return (cpu <= maxid ? 1 : -1);
#endif
	}

	return (v->dtv_status(dtp->dt_varg, cpu));
}

long
dt_sysconf(dtrace_hdl_t *dtp, int name)
{
	const dtrace_vector_t *v = dtp->dt_vector;

	if (v == NULL)
		return (sysconf(name));

	return (v->dtv_sysconf(dtp->dt_varg, name));
}

/*
 * Wrapper around write(2) to handle partial writes.  For maximum safety of
 * output files and proper error reporting, we continuing writing in the
 * face of partial writes until write(2) fails or 'buf' is completely written.
 * We also record any errno in the specified dtrace_hdl_t as well as 'errno'.
 */
ssize_t
dt_write(dtrace_hdl_t *dtp, int fd, const void *buf, size_t n)
{
	ssize_t resid = n;
	ssize_t len;

	while (resid != 0) {
		if ((len = write(fd, buf, resid)) <= 0)
			break;

		resid -= len;
		buf = (char *)buf + len;
	}

	if (resid == n && n != 0)
		return (dt_set_errno(dtp, errno));

	return (n - resid);
}

/*
 * This function handles all output from libdtrace, as well as the
 * dtrace_sprintf() case.  If we're here due to dtrace_sprintf(), then
 * dt_sprintf_buflen will be non-zero; in this case, we sprintf into the
 * specified buffer and return.  Otherwise, if output is buffered (denoted by
 * a NULL fp), we sprintf the desired output into the buffered buffer
 * (expanding the buffer if required).  If we don't satisfy either of these
 * conditions (that is, if we are to actually generate output), then we call
 * fprintf with the specified fp.  In this case, we need to deal with one of
 * the more annoying peculiarities of libc's printf routines:  any failed
 * write persistently sets an error flag inside the FILE causing every
 * subsequent write to fail, but only the caller that initiated the error gets
 * the errno.  Since libdtrace clients often intercept SIGINT, this case is
 * particularly frustrating since we don't want the EINTR on one attempt to
 * write to the output file to preclude later attempts to write.  This
 * function therefore does a clearerr() if any error occurred, and saves the
 * errno for the caller inside the specified dtrace_hdl_t.
 */
/*PRINTFLIKE3*/
int
dt_printf(dtrace_hdl_t *dtp, FILE *fp, const char *format, ...)
{
	va_list ap;
	va_list ap2;
	int n;

	if (dtp->dt_output_discarded)
		return (dt_set_errno(dtp, ESHUTDOWN));
#ifndef illumos
	/*
	 * On FreeBSD, check if output is currently being re-directed
	 * to another file. If so, output to that file instead of the
	 * one the caller has specified.
	 */
	if (dtp->dt_freopen_fp != NULL)
		fp = dtp->dt_freopen_fp;
#endif

	va_start(ap, format);

	if (dtp->dt_sprintf_buflen != 0) {
		int len;
		char *buf;

		assert(dtp->dt_sprintf_buf != NULL);

		buf = &dtp->dt_sprintf_buf[len = strlen(dtp->dt_sprintf_buf)];
		len = dtp->dt_sprintf_buflen - len;
		assert(len >= 0);

		va_copy(ap2, ap);
		if ((n = vsnprintf(buf, len, format, ap2)) < 0)
			n = dt_set_errno(dtp, errno);

		va_end(ap2);
		va_end(ap);
		
		return (n);
	}

	if (fp == NULL) {
		int needed, rval;
		size_t avail;

		/*
		 * Using buffered output is not allowed if a handler has
		 * not been installed.
		 */
		if (dtp->dt_bufhdlr == NULL) {
			va_end(ap);
			return (dt_set_errno(dtp, EDT_NOBUFFERED));
		}

		if (dtp->dt_buffered_buf == NULL) {
			assert(dtp->dt_buffered_size == 0);
			dtp->dt_buffered_size = 1;
			dtp->dt_buffered_buf = malloc(dtp->dt_buffered_size);

			if (dtp->dt_buffered_buf == NULL) {
				va_end(ap);
				return (dt_set_errno(dtp, EDT_NOMEM));
			}

			dtp->dt_buffered_offs = 0;
			dtp->dt_buffered_buf[0] = '\0';
		}

		va_copy(ap2, ap);
		if ((needed = vsnprintf(NULL, 0, format, ap2)) < 0) {
			rval = dt_set_errno(dtp, errno);
			va_end(ap2);
			va_end(ap);
			return (rval);
		}
		va_end(ap2);

		if (needed == 0) {
			va_end(ap);
			return (0);
		}

		for (;;) {
			char *newbuf;

			assert(dtp->dt_buffered_offs < dtp->dt_buffered_size);
			avail = dtp->dt_buffered_size - dtp->dt_buffered_offs;

			if (needed + 1 < avail)
				break;

			if ((newbuf = realloc(dtp->dt_buffered_buf,
			    dtp->dt_buffered_size << 1)) == NULL) {
				va_end(ap);
				return (dt_set_errno(dtp, EDT_NOMEM));
			}

			dtp->dt_buffered_buf = newbuf;
			dtp->dt_buffered_size <<= 1;
		}

		va_copy(ap2, ap);
		if (vsnprintf(&dtp->dt_buffered_buf[dtp->dt_buffered_offs],
		    avail, format, ap2) < 0) {
			rval = dt_set_errno(dtp, errno);
			va_end(ap2);
			va_end(ap);
			return (rval);
		}
		va_end(ap2);

		dtp->dt_buffered_offs += needed;
		assert(dtp->dt_buffered_buf[dtp->dt_buffered_offs] == '\0');
		va_end(ap);
		return (0);
	}

	va_copy(ap2, ap);
	n = vfprintf(fp, format, ap2);
	va_end(ap2);
	va_end(ap);

	if (n < 0) {
		clearerr(fp);
		return (dt_set_errno(dtp, errno));
	}

	return (n);
}

int
dt_buffered_flush(dtrace_hdl_t *dtp, dtrace_probedata_t *pdata,
    const dtrace_recdesc_t *rec, const dtrace_aggdata_t *agg, uint32_t flags)
{
	dtrace_bufdata_t data;

	if (dtp->dt_buffered_offs == 0)
		return (0);

	data.dtbda_handle = dtp;
	data.dtbda_buffered = dtp->dt_buffered_buf;
	data.dtbda_probe = pdata;
	data.dtbda_recdesc = rec;
	data.dtbda_aggdata = agg;
	data.dtbda_flags = flags;

	if ((*dtp->dt_bufhdlr)(&data, dtp->dt_bufarg) == DTRACE_HANDLE_ABORT)
		return (dt_set_errno(dtp, EDT_DIRABORT));

	dtp->dt_buffered_offs = 0;
	dtp->dt_buffered_buf[0] = '\0';

	return (0);
}

void
dt_buffered_destroy(dtrace_hdl_t *dtp)
{
	free(dtp->dt_buffered_buf);
	dtp->dt_buffered_buf = NULL;
	dtp->dt_buffered_offs = 0;
	dtp->dt_buffered_size = 0;
}

void *
dt_zalloc(dtrace_hdl_t *dtp, size_t size)
{
	void *data;

	if ((data = malloc(size)) == NULL)
		(void) dt_set_errno(dtp, EDT_NOMEM);
	else
		bzero(data, size);

	return (data);
}

void *
dt_alloc(dtrace_hdl_t *dtp, size_t size)
{
	void *data;

	if ((data = malloc(size)) == NULL)
		(void) dt_set_errno(dtp, EDT_NOMEM);

	return (data);
}

void
dt_free(dtrace_hdl_t *dtp, void *data)
{
	assert(dtp != NULL); /* ensure sane use of this interface */
	free(data);
}

void
dt_difo_free(dtrace_hdl_t *dtp, dtrace_difo_t *dp)
{
	if (dp == NULL)
		return; /* simplify caller code */

	dt_free(dtp, dp->dtdo_buf);
	dt_free(dtp, dp->dtdo_inttab);
	dt_free(dtp, dp->dtdo_strtab);
	dt_free(dtp, dp->dtdo_symtab);
	dt_free(dtp, dp->dtdo_vartab);
	dt_free(dtp, dp->dtdo_kreltab);
	dt_free(dtp, dp->dtdo_ureltab);
	dt_free(dtp, dp->dtdo_xlmtab);
	/* The HyperTrace type checker's per-instruction type names. */
	if (dp->dtdo_types != NULL) {
		for (uint_t i = 0; i < dp->dtdo_len; i++)
			free(dp->dtdo_types[i]);
		dt_free(dtp, dp->dtdo_types);
	}

	dt_free(dtp, dp);
}

dtrace_difo_t *
dt_difo_dup(dtrace_hdl_t *dtp, dtrace_difo_t *dp, int *alloc_fail)
{
	dtrace_difo_t *ndp;

	*alloc_fail = 0;

	if (dp == NULL)
		return (NULL);

	ndp = dt_zalloc(dtp, sizeof(dtrace_difo_t));
	if (ndp == NULL) {
		*alloc_fail = 1;
		goto cleanup;
	}

	memcpy(ndp, dp, sizeof(dtrace_difo_t));
	ndp->dtdo_buf = NULL;
	ndp->dtdo_inttab = NULL;
	ndp->dtdo_strtab = NULL;
	ndp->dtdo_symtab = NULL;
	ndp->dtdo_vartab = NULL;
	ndp->dtdo_kreltab = NULL;
	ndp->dtdo_ureltab = NULL;
	ndp->dtdo_xlmtab = NULL;
	ndp->dtdo_types = NULL;	/* not copied: they describe dp's link */

	if (dp->dtdo_len == 0)
		goto cleanup;

	ndp->dtdo_buf = dt_alloc(dtp, dp->dtdo_len * sizeof(dif_instr_t));
	if (ndp->dtdo_buf == NULL) {
		*alloc_fail = 1;
		goto cleanup;
	}

	if (dp->dtdo_intlen > 0) {
		ndp->dtdo_inttab = dt_alloc(dtp,
		    dp->dtdo_intlen * sizeof(uint64_t));
		if (ndp->dtdo_inttab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	if (dp->dtdo_strlen > 0) {
		ndp->dtdo_strtab = dt_alloc(dtp, dp->dtdo_strlen);
		if (ndp->dtdo_strtab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	if (dp->dtdo_symlen > 0) {
		ndp->dtdo_symtab = dt_alloc(dtp, dp->dtdo_symlen);
		if (ndp->dtdo_symtab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	if (dp->dtdo_varlen > 0) {
		ndp->dtdo_vartab = dt_alloc(dtp,
		    dp->dtdo_varlen * sizeof(dtrace_difv_t));
		if (ndp->dtdo_vartab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	if (dp->dtdo_krelen > 0) {
		ndp->dtdo_kreltab = dt_alloc(dtp,
		    dp->dtdo_krelen * sizeof(dof_relodesc_t));
		if (ndp->dtdo_kreltab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	if (dp->dtdo_urelen > 0) {
		ndp->dtdo_ureltab = dt_alloc(dtp,
		    dp->dtdo_urelen * sizeof(dof_relodesc_t));
		if (ndp->dtdo_ureltab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	if (dp->dtdo_xlmlen > 0) {
		ndp->dtdo_xlmtab = dt_alloc(dtp,
		    dp->dtdo_xlmlen * sizeof(struct dt_node *));
		if (ndp->dtdo_xlmtab == NULL) {
			*alloc_fail = 1;
			goto cleanup;
		}
	}

	memcpy(ndp->dtdo_buf, dp->dtdo_buf, dp->dtdo_len * sizeof(dif_instr_t));
	if (dp->dtdo_intlen > 0)
		memcpy(ndp->dtdo_inttab, dp->dtdo_inttab,
		    dp->dtdo_intlen * sizeof(uint64_t));
	if (dp->dtdo_strlen > 0)
		memcpy(ndp->dtdo_strtab, dp->dtdo_strtab, dp->dtdo_strlen);
	if (dp->dtdo_symlen > 0)
		memcpy(ndp->dtdo_symtab, dp->dtdo_symtab, dp->dtdo_symlen);

	if (dp->dtdo_varlen > 0)
		memcpy(ndp->dtdo_vartab, dp->dtdo_vartab,
		    dp->dtdo_varlen * sizeof(dtrace_difv_t));
	if (dp->dtdo_krelen > 0)
		memcpy(ndp->dtdo_kreltab, dp->dtdo_kreltab,
		    dp->dtdo_krelen * sizeof(dof_relodesc_t));
	if (dp->dtdo_urelen > 0)
		memcpy(ndp->dtdo_ureltab, dp->dtdo_ureltab,
		    dp->dtdo_urelen * sizeof(dof_relodesc_t));
	if (dp->dtdo_xlmlen > 0)
		memcpy(ndp->dtdo_xlmtab, dp->dtdo_xlmtab,
		    dp->dtdo_xlmlen * sizeof(struct dt_node *));

	return (ndp);

cleanup:
	dt_difo_free(dtp, ndp);

	return (NULL);
}

/*
 * dt_gmatch() is similar to gmatch(3GEN) and dtrace(7D) globbing, but also
 * implements the behavior that an empty pattern matches any string.
 */
int
dt_gmatch(const char *s, const char *p)
{
	return (p == NULL || *p == '\0' || gmatch(s, p));
}

char *
dt_basename(char *str)
{
	char *last = strrchr(str, '/');

	if (last == NULL)
		return (str);

	return (last + 1);
}

/*
 * dt_popc() is a fast implementation of population count.  The algorithm is
 * from "Hacker's Delight" by Henry Warren, Jr with a 64-bit equivalent added.
 */
ulong_t
dt_popc(ulong_t x)
{
#if defined(_ILP32)
	x = x - ((x >> 1) & 0x55555555UL);
	x = (x & 0x33333333UL) + ((x >> 2) & 0x33333333UL);
	x = (x + (x >> 4)) & 0x0F0F0F0FUL;
	x = x + (x >> 8);
	x = x + (x >> 16);
	return (x & 0x3F);
#elif defined(_LP64)
	x = x - ((x >> 1) & 0x5555555555555555ULL);
	x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
	x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
	x = x + (x >> 8);
	x = x + (x >> 16);
	x = x + (x >> 32);
	return (x & 0x7F);
#else
/* This should be a #warning but for now ignore error. Err: "need td_popc() implementation" */
#endif
}

/*
 * dt_popcb() is a bitmap-based version of population count that returns the
 * number of one bits in the specified bitmap 'bp' at bit positions below 'n'.
 */
ulong_t
dt_popcb(const ulong_t *bp, ulong_t n)
{
	ulong_t maxb = n & BT_ULMASK;
	ulong_t maxw = n >> BT_ULSHIFT;
	ulong_t w, popc = 0;

	if (n == 0)
		return (0);

	for (w = 0; w < maxw; w++)
		popc += dt_popc(bp[w]);

	return (popc + dt_popc(bp[maxw] & ((1UL << maxb) - 1)));
}

#ifdef illumos
struct _rwlock;
struct _lwp_mutex;

int
dt_rw_read_held(pthread_rwlock_t *lock)
{
	extern int _rw_read_held(struct _rwlock *);
	return (_rw_read_held((struct _rwlock *)lock));
}

int
dt_rw_write_held(pthread_rwlock_t *lock)
{
	extern int _rw_write_held(struct _rwlock *);
	return (_rw_write_held((struct _rwlock *)lock));
}
#endif

int
dt_mutex_held(pthread_mutex_t *lock)
{
#ifdef illumos
	extern int _mutex_held(struct _lwp_mutex *);
	return (_mutex_held((struct _lwp_mutex *)lock));
#else
	return (1);
#endif
}

static int
dt_string2str(char *s, char *str, int nbytes)
{
	int len = strlen(s);

	if (nbytes == 0) {
		/*
		 * Like snprintf(3C), we don't check the value of str if the
		 * number of bytes is 0.
		 */
		return (len);
	}

	if (nbytes <= len) {
		(void) strncpy(str, s, nbytes - 1);
		/*
		 * Like snprintf(3C) (and unlike strncpy(3C)), we guarantee
		 * that the string is null-terminated.
		 */
		str[nbytes - 1] = '\0';
	} else {
		(void) strcpy(str, s);
	}

	return (len);
}

int
dtrace_addr2str(dtrace_hdl_t *dtp, uint64_t addr, char *str, int nbytes)
{
	dtrace_syminfo_t dts;
	GElf_Sym sym;

	size_t n = 20; /* for 0x%llx\0 */
	char *s;
	int err, modonly = 0;

	if ((err = dtrace_lookup_by_addr(dtp, addr, &sym, &dts)) == 0) {
		n += strlen(dts.dts_object) + strlen(dts.dts_name) + 2; /* +` */
	} else if (dtrace_lookup_by_addr(dtp, addr, NULL, &dts) == 0) {
		/*
		 * No symbol: repeat the lookup with a NULL GElf_Sym, asking
		 * only for the containing module, and size for "mod`0x...".
		 */
		modonly = 1;
		n += strlen(dts.dts_object) + 1;
	}

	s = alloca(n);

	if (err == 0 && addr != sym.st_value) {
		(void) snprintf(s, n, "%s`%s+0x%llx", dts.dts_object,
		    dts.dts_name, (u_longlong_t)addr - sym.st_value);
	} else if (err == 0) {
		(void) snprintf(s, n, "%s`%s",
		    dts.dts_object, dts.dts_name);
	} else if (modonly) {
		(void) snprintf(s, n, "%s`0x%llx", dts.dts_object,
		    (u_longlong_t)addr);
	} else {
		(void) snprintf(s, n, "0x%llx", (u_longlong_t)addr);
	}

	return (dt_string2str(s, str, nbytes));
}

int
dtrace_uaddr2str(dtrace_hdl_t *dtp, pid_t pid,
    uint64_t addr, char *str, int nbytes)
{
	char name[PATH_MAX], objname[PATH_MAX], c[PATH_MAX * 2];
	struct ps_prochandle *P = NULL;
	GElf_Sym sym;
	char *obj;

	if (pid != 0)
		P = dt_proc_grab(dtp, pid, PGRAB_RDONLY | PGRAB_FORCE, 0);

	if (P == NULL) {
	  (void) snprintf(c, sizeof (c), "0x%jx", (uintmax_t)addr);
		return (dt_string2str(c, str, nbytes));
	}

	dt_proc_lock(dtp, P);

	if (Plookup_by_addr(P, addr, name, sizeof (name), &sym) == 0) {
		(void) Pobjname(P, addr, objname, sizeof (objname));

		obj = dt_basename(objname);

		if (addr > sym.st_value) {
			(void) snprintf(c, sizeof (c), "%s`%s+0x%llx", obj,
			    name, (u_longlong_t)(addr - sym.st_value));
		} else {
			(void) snprintf(c, sizeof (c), "%s`%s", obj, name);
		}
	} else if (Pobjname(P, addr, objname, sizeof (objname)) != 0) {
		(void) snprintf(c, sizeof (c), "%s`0x%jx",
				dt_basename(objname), (uintmax_t)addr);
	} else {
	  (void) snprintf(c, sizeof (c), "0x%jx", (uintmax_t)addr);
	}

	dt_proc_unlock(dtp, P);
	dt_proc_release(dtp, P);

	return (dt_string2str(c, str, nbytes));
}

/* A process descriptor naming the caller.  pdself(2) is capability-mode
 * only and fails with ENOTCAPABLE for an ambient process such as dtrace(1)
 * started from a shell, so an ambient caller names itself with pdopenpid(2),
 * as libservice does.  Neither call changes the caller's mode.  A kernel
 * without Capsicum (ENOSYS) is ambient.  open_dtraced_session() connects by
 * path, which capability mode refuses before this runs; the pdself(2) branch
 * is for a future caller that connects with connectat(2). */
static int
dtraced_self_procdesc(int *fdp)
{
	u_int mode = 0;

	if (cap_getmode(&mode) != 0 && errno != ENOSYS)
		return (-1);
	if (mode != 0)
		return (pdself(fdp, PD_DAEMON | PD_CLOEXEC));
	*fdp = pdopenpid(getpid(), PD_DAEMON | PD_CLOEXEC);
	return (*fdp < 0 ? -1 : 0);
}

/* The incarnation is the kernel monotonic process birth, queried afresh so
 * a forked child cannot inherit its parent's identity. No PID-only fallback. */
static int
dtraced_birth_ident(char ident[DTRACED_FDIDENTLEN])
{
	static const char hex[] = "0123456789abcdef";
	uint8_t nonce[16];
	uint32_t pid;
	int error, prefix, fd;
	struct pd_birth_identity birth = {0};

	if (dtraced_self_procdesc(&fd) != 0)
		return (-1);
	error = ioctl(fd, PDIOC_GET_BIRTH_IDENTITY, &birth) != 0 ? errno : 0;
	if (close(fd) != 0 && error == 0)
		error = errno;
	pid = (uint32_t)getpid();
	if (error == 0 && (birth.pid != (pid_t)pid || birth.reserved != 0 ||
	    birth.start_usec >= 1000000 ||
	    (birth.start_sec == 0 && birth.start_usec == 0)))
		error = EPROTO;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	for (unsigned i = 0; i < 8; i++) {
		nonce[i] = (uint8_t)(birth.start_sec >> (8 * i));
		nonce[8 + i] = (uint8_t)(birth.start_usec >> (8 * i));
	}
	/* "dtrace-<uint32>-" plus 32 hex digits and NUL always fit. */
	_Static_assert(sizeof("dtrace-4294967295-") - 1 + 32 <
	    DTRACED_FDIDENTLEN, "birth identity does not fit");
	memset(ident, 0, DTRACED_FDIDENTLEN);
	prefix = snprintf(ident, DTRACED_FDIDENTLEN, "dtrace-%u-", pid);
	for (unsigned i = 0; i < sizeof(nonce); i++) {
		ident[prefix + 2 * i] = hex[nonce[i] >> 4];
		ident[prefix + 2 * i + 1] = hex[nonce[i] & 15];
	}
	ident[prefix + 32] = '\0';
	return (0);
}

int
open_dtraced_session(uint64_t subs, uint8_t session_id[16])
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	dtd_initmsg_t initmsg = { 0 };
	const uint8_t zero_session[16] = { 0 };
	int fd, error;
	size_t transferred;
	int64_t deadline;

	if (session_id == NULL) {
		errno = EINVAL;
		return (-1);
	}
	/* A caller that reconnects retains this identity across attempts. */
	if (memcmp(session_id, zero_session, sizeof(zero_session)) == 0) {
		do {
			arc4random_buf(session_id, 16);
		} while (memcmp(session_id, zero_session,
		    sizeof(zero_session)) == 0);
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return (-1);
	_Static_assert(sizeof(DTRACED_SOCKPATH) <= sizeof(addr.sun_path),
	    "daemon socket path does not fit");
	(void) strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	addr.sun_len = SUN_LEN(&addr);
	if (connect(fd, (struct sockaddr *)&addr, addr.sun_len) != 0)
		goto fail;
	deadline = dtraced_io_milliseconds() + 2000;
	if (dtraced_wire_read_init(fd, &initmsg, deadline,
	    &transferred) != 0)
		goto fail;
	if (!dtraced_wire_valid_server_init(&initmsg)) {
		errno = EPROTO;
		goto fail;
	}
	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.protocol_version = DTRACED_PROTOCOL_VERSION;
	initmsg.kind = DTRACED_KIND_CONSUMER;
	initmsg.subs = subs;
	memcpy(initmsg.session_id, session_id, sizeof(initmsg.session_id));
	if (dtraced_birth_ident(initmsg.ident) != 0)
		goto fail;
	if (dtraced_wire_write_init(fd, &initmsg, deadline,
	    &transferred) != 0)
		goto fail;
	return (fd);
fail:
	error = errno;
	close(fd);
	errno = error;
	return (-1);
}

int
open_dtraced(uint64_t subs)
{
	uint8_t session_id[16] = { 0 };

	return (open_dtraced_session(subs, session_id));
}

/* Serialize complete frames and their replies, including async and KILL. */
static pthread_mutex_t dt_transport_mtx = PTHREAD_MUTEX_INITIALIZER;

int
dtrace_send_message(int fd, const dtraced_hdr_t *header,
    const void *payload, size_t payload_len)
{
	unsigned char ack;
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	size_t transferred;
	size_t length;
	int error = 0;
	int64_t deadline;

	if (fd < 0 || header == NULL ||
	    (payload_len != 0 && payload == NULL) ||
	    payload_len > 64U * 1024U * 1024U - DTRACED_MSGHDRSIZE) {
		errno = EINVAL;
		return (-1);
	}
	length = DTRACED_MSGHDRSIZE + payload_len;
	dtraced_wire_encode_header(header_wire, header);
	pthread_mutex_lock(&dt_transport_mtx);
	deadline = dtraced_io_milliseconds() + 10000;
	if (dtraced_io_write_size(fd, length, deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(fd, header_wire, sizeof(header_wire), true,
	    deadline, &transferred) != 0 ||
	    (payload_len != 0 &&
	    dtraced_io_transfer(fd, (void *)payload, payload_len, true,
	    deadline, &transferred) != 0) ||
	    dtraced_io_transfer(fd, &ack, sizeof(ack), false, deadline,
	    &transferred) != 0)
		error = errno;
	else if (ack != 1)
		error = EPROTO;
	if (error != 0)
		(void)shutdown(fd, SHUT_RDWR);
	pthread_mutex_unlock(&dt_transport_mtx);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

typedef struct {
	dt_list_t list;
	char ident[DT_PROG_IDENTLEN];
	char srcident[DT_PROG_IDENTLEN];
	uint16_t vmid;
	uint64_t epoch;
	int fromfd;
	int tofd;
	char *location;
	int send_ident;
	int has_program;
	char *filepath;
} dtrace_elfqueue_t;

static pthread_mutex_t _elf_async_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _elf_async_cv = PTHREAD_COND_INITIALIZER;
static dt_list_t _elf_async_queue;
static pthread_t _elf_async_tid;
static int _elf_async_initialized;
static int _elf_async_closing;
static int _elf_async_discarded;
static int _elf_async_done = 1;
static dtrace_elfqueue_t *_elf_async_active;
static size_t _elf_async_count;
static atomic_int _elf_async_shutdown;

static void
_dtrace_elfqueue_free(dtrace_elfqueue_t *entry)
{
	unlink(entry->filepath);
	free(entry->filepath);
	free(entry->location);
	close(entry->fromfd);
	close(entry->tofd);
	free(entry);
}

static void *
_dtrace_send_elf_async(void *arg __unused)
{
	dtrace_elfqueue_t *entry;
	dtrace_prog_t program;

	pthread_mutex_lock(&_elf_async_mtx);
	for (;;) {
		while (dt_list_next(&_elf_async_queue) == NULL &&
		    !atomic_load(&_elf_async_shutdown))
			pthread_cond_wait(&_elf_async_cv, &_elf_async_mtx);
		if (atomic_load(&_elf_async_shutdown))
			break;
		entry = dt_list_next(&_elf_async_queue);
		dt_list_delete(&_elf_async_queue, entry);
		_elf_async_count--;
		_elf_async_active = entry;
		pthread_mutex_unlock(&_elf_async_mtx);
		memset(&program, 0, sizeof(program));
		memcpy(program.dp_ident, entry->ident, sizeof(entry->ident));
		memcpy(program.dp_srcident, entry->srcident,
		    sizeof(entry->srcident));
		program.dp_vmid = entry->vmid;
		program.dp_vmepoch = entry->epoch;
		if (dtrace_send_elf(entry->has_program ? &program : NULL,
		    entry->fromfd, entry->tofd,
		    entry->location, entry->send_ident) != 0 &&
		    !atomic_load(&_elf_async_shutdown))
			fprintf(stderr, "dtrace: asynchronous ELF send failed: %s\n",
			    strerror(errno));
		pthread_mutex_lock(&_elf_async_mtx);
		_elf_async_active = NULL;
		_dtrace_elfqueue_free(entry);
	}
	while ((entry = dt_list_next(&_elf_async_queue)) != NULL) {
		dt_list_delete(&_elf_async_queue, entry);
		_dtrace_elfqueue_free(entry);
	}
	_elf_async_count = 0;
	_elf_async_done = 1;
	pthread_cond_broadcast(&_elf_async_cv);
	pthread_mutex_unlock(&_elf_async_mtx);
	return (NULL);
}

/* Terminal, process-wide admission fence. Never wait here: the collector's
 * existing stop deadline governs repeated calls. Keep the active descriptor
 * owned by the worker; shutdown interrupts I/O without descriptor reuse races. */
int
dtrace_async_discard_step(void)
{
	int error = pthread_mutex_trylock(&_elf_async_mtx);
	if (error == EBUSY)
		return (0);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	_elf_async_discarded = 1;
	atomic_store(&_elf_async_shutdown, 1);
	if (_elf_async_active != NULL)
		(void)shutdown(_elf_async_active->tofd, SHUT_RDWR);
	pthread_cond_broadcast(&_elf_async_cv);
	int done = _elf_async_done && _elf_async_active == NULL &&
	    dt_list_next(&_elf_async_queue) == NULL;
	pthread_mutex_unlock(&_elf_async_mtx);
	return (done);
}

void
dtrace_async_teardown(void)
{
	dtrace_elfqueue_t *entry;

	pthread_mutex_lock(&_elf_async_mtx);
	if (!_elf_async_initialized || _elf_async_closing) {
		pthread_mutex_unlock(&_elf_async_mtx);
		return;
	}
	_elf_async_closing = 1;
	atomic_store(&_elf_async_shutdown, 1);
	pthread_cond_broadcast(&_elf_async_cv);
	pthread_mutex_unlock(&_elf_async_mtx);
	pthread_join(_elf_async_tid, NULL);
	pthread_mutex_lock(&_elf_async_mtx);
	while ((entry = dt_list_next(&_elf_async_queue)) != NULL) {
		dt_list_delete(&_elf_async_queue, entry);
		_dtrace_elfqueue_free(entry);
	}
	_elf_async_count = 0;
	_elf_async_initialized = _elf_async_closing = 0;
	pthread_mutex_unlock(&_elf_async_mtx);
}

int
dtrace_send_elf_async(dtrace_prog_t *pgp, int fromfd, int tofd,
    char *filepath, const char *location, int send_ident)
{
	dtrace_elfqueue_t *entry;
	int error;

	if (fromfd < 0 || tofd < 0 || filepath == NULL || location == NULL ||
	    (send_ident != 0 && send_ident != 1) || (send_ident && pgp == NULL))
		return (EINVAL);
	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return (EDT_NOMEM);
	entry->tofd = fcntl(tofd, F_DUPFD_CLOEXEC, 0);
	error = entry->tofd < 0 ? errno : 0;
	entry->location = strdup(location);
	entry->filepath = strdup(filepath);
	entry->send_ident = send_ident;
	entry->has_program = pgp != NULL;
	entry->fromfd = fromfd;
	if (pgp != NULL) {
		entry->vmid = pgp->dp_vmid;
		entry->epoch = pgp->dp_vmepoch;
		memcpy(entry->srcident, pgp->dp_srcident,
		    sizeof(entry->srcident));
	}
	if (pgp != NULL)
		memcpy(entry->ident, pgp->dp_ident, sizeof(entry->ident));
	if (entry->tofd < 0 || entry->location == NULL || entry->filepath == NULL) {
		error = entry->tofd < 0 ? error : EDT_NOMEM;
		goto fail;
	}
	pthread_mutex_lock(&_elf_async_mtx);
	if (_elf_async_discarded || _elf_async_closing || _elf_async_count >= 64) {
		error = _elf_async_discarded ? ESHUTDOWN :
		    _elf_async_closing ? EBUSY : ENOBUFS;
		goto unlock_fail;
	}
	if (!_elf_async_initialized) {
		atomic_store(&_elf_async_shutdown, 0);
		error = pthread_create(&_elf_async_tid, NULL,
		    _dtrace_send_elf_async, NULL);
		if (error != 0)
			goto unlock_fail;
		_elf_async_initialized = 1;
		_elf_async_done = 0;
	}
	dt_list_append(&_elf_async_queue, entry);
	_elf_async_count++;
	pthread_cond_signal(&_elf_async_cv);
	pthread_mutex_unlock(&_elf_async_mtx);
	/* Success transfers ownership of fromfd and its temporary pathname. */
	return (0);
unlock_fail:
	pthread_mutex_unlock(&_elf_async_mtx);
fail:
	if (entry->tofd >= 0)
		close(entry->tofd);
	free(entry->location);
	free(entry->filepath);
	free(entry);
	return (error);
}

int
dtrace_oformat_configure(dtrace_hdl_t *dtp)
{

	dtp->dt_oformat = xo_get_style(NULL) == XO_STYLE_TEXT ?
	    DTRACE_OFORMAT_TEXT :
	    DTRACE_OFORMAT_STRUCTURED;
	xo_set_flags(NULL, XOF_DTRT);
	return (0);
}

int
dtrace_program_source_id(const dtrace_prog_t *pgp, uint8_t id[16])
{
	const char *ident;
	const char zero[DT_PROG_IDENTLEN] = { 0 };
	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (pgp == NULL || id == NULL) {
		errno = EINVAL;
		return (-1);
	}
	ident = memcmp(pgp->dp_srcident, zero, sizeof(zero)) == 0 ?
	    pgp->dp_ident : pgp->dp_srcident;
	if (memcmp(ident, zero, sizeof(zero)) == 0 ||
	    SHA256((const unsigned char *)ident, DT_PROG_IDENTLEN,
	    digest) == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(id, digest, 16);
	explicit_bzero(digest, sizeof(digest));
	return (0);
}

/* A compiled-program identity for a supervised consumer. The ELF wrapper
 * carries random dp_ident/dp_srcident values. Stripped DOF excludes those,
 * but each action still has a process-local uarg used to route userland
 * callbacks. Clear only that non-execution field in our disposable DOF
 * image before hashing; the generated program itself is unchanged. */
int
dtrace_program_compiled_digest(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    uint8_t id[32])
{
	dof_hdr_t *dof;
	dof_sec_t *sections;
	unsigned char bound[4 + SHA256_DIGEST_LENGTH];
	size_t length;
	int error = 0;

	if (id == NULL || dtp == NULL || pgp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(id, 0, 32);
	/* The compiled program, before it is forwarded to be linked. */
	dof = dt_dof_create(dtp, pgp, DTRACE_D_STRIP);
	if (dof == NULL)
		return (-1);
	if (dof->dofh_filesz < sizeof(*dof) ||
	    dof->dofh_filesz > 64U * 1024U * 1024U ||
	    dof->dofh_hdrsize != sizeof(*dof) ||
	    dof->dofh_secsize != sizeof(dof_sec_t) ||
	    dof->dofh_loadsz > dof->dofh_filesz ||
	    dof->dofh_secoff < sizeof(*dof) ||
	    dof->dofh_secoff > dof->dofh_filesz ||
	    dof->dofh_secnum > (dof->dofh_filesz - dof->dofh_secoff) /
	    sizeof(dof_sec_t)) {
		error = EPROTO;
		goto done;
	}
	length = (size_t)dof->dofh_filesz;
	sections = (dof_sec_t *)((uint8_t *)dof + dof->dofh_secoff);
	for (uint32_t i = 0; i < dof->dofh_secnum; i++) {
		dof_sec_t *sec = &sections[i];
		if (sec->dofs_offset > length ||
		    sec->dofs_size > length - sec->dofs_offset) {
			error = EPROTO;
			goto done;
		}
		if (sec->dofs_type != DOF_SECT_ACTDESC)
			continue;
		if (sec->dofs_entsize != sizeof(dof_actdesc_t) ||
		    sec->dofs_size % sizeof(dof_actdesc_t) != 0 ||
		    sec->dofs_offset < dof->dofh_secoff +
		    (uint64_t)dof->dofh_secnum * sizeof(dof_sec_t) ||
		    sec->dofs_offset % _Alignof(dof_actdesc_t) != 0) {
			error = EPROTO;
			goto done;
		}
		dof_actdesc_t *actions = (dof_actdesc_t *)
		    ((uint8_t *)dof + sec->dofs_offset);
		for (size_t j = 0; j < sec->dofs_size /
		    sizeof(dof_actdesc_t); j++)
			actions[j].dofa_uarg = 0;
	}
	memcpy(bound, "HPI1", 4);
	if (SHA256((const unsigned char *)dof, length, bound + 4) == NULL ||
	    SHA256(bound, sizeof(bound), id) == NULL)
		error = EIO;
done:
	dtrace_dof_destroy(dtp, dof);
	explicit_bzero(bound, sizeof(bound));
	if (error != 0) {
		memset(id, 0, 32);
		errno = error;
		return (-1);
	}
	return (0);
}

static int
dtrace_send_elf_impl(dtrace_prog_t *pgp, int fromfd, int tofd,
    const char *location, int send_ident,
    const dtraced_derived_parent_t *parent)
{
	unsigned char *buf;
	size_t payload, offset, prefix = 0;
	struct hypertrace_vm_envelope target = { 0 };
	struct stat sb;
	dtraced_hdr_t header = { 0 };
	ssize_t n;
	int error, result;

	if (fromfd < 0 || tofd < 0 || location == NULL ||
	    (send_ident != 0 && send_ident != 1) || (send_ident && pgp == NULL) ||
	    /* With a parent, the only caller sends "outbound" without ident. */
	    (parent != NULL && (pgp == NULL ||
	    !dtraced_derived_parent_valid(parent)))) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * A derived program continues its parent's source lineage.  Its own
	 * srcident names the guest's linked program (hypertrace_link() gives
	 * that a new identity), which dtraced knows by no source.
	 */
	if (parent != NULL)
		memcpy(header.elf.source_id, parent->source_id,
		    sizeof(header.elf.source_id));
	else if (pgp != NULL &&
	    dtrace_program_source_id(pgp, header.elf.source_id) != 0)
		return (-1);
	if (pgp != NULL && pgp->dp_vmid != 0 && strcmp(location, "outbound") == 0) {
		if (pgp->dp_vmid >= HYPERTRACE_MAX_VMS || pgp->dp_vmepoch == 0) {
			errno = ESTALE;
			return (-1);
		}
		prefix = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE;
		target.magic = HYPERTRACE_TARGET_MAGIC;
		target.version = HYPERTRACE_ENVELOPE_VERSION;
		target.vmid = pgp->dp_vmid;
		target.epoch = pgp->dp_vmepoch;
	}
	if (fstat(fromfd, &sb) != 0)
		return (-1);
	if (!S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    (uint64_t)sb.st_size > 64U * 1024U * 1024U -
	    DTRACED_MSGHDRSIZE - prefix) {
		errno = EMSGSIZE;
		return (-1);
	}
	if (strlcpy(header.elf.location, location, sizeof(header.elf.location)) >=
	    sizeof(header.elf.location)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	payload = (size_t)sb.st_size;
	buf = malloc(prefix + payload);
	if (buf == NULL)
		return (-1);
	for (offset = 0; offset < payload; offset += n) {
		n = pread(fromfd, buf + prefix + offset,
		    payload - offset, offset);
		if (n < 0 && errno == EINTR) {
			n = 0;
			continue;
		}
		if (n <= 0) {
			error = n == 0 ? EIO : errno;
			free(buf);
			errno = error;
			return (-1);
		}
	}
	header.msg_type = DTRACED_MSG_ELF;
	header.elf.len = prefix + payload;
	if (prefix != 0)
		hypertrace_envelope_encode(buf, &target);
	if (parent != NULL &&
	    (dtraced_derived_parent_to_header(&header, parent) != 0 ||
	    dtraced_derived_program_id(parent, buf,
	    prefix + payload, header.elf.program_id) != 0)) {
		error = errno;
		free(buf);
		errno = error;
		return (-1);
	}
	DTRACED_MSG_IDENT_PRESENT(header) = send_ident;
	if (send_ident)
		memcpy(DTRACED_MSG_IDENT(header), pgp->dp_ident, DT_PROG_IDENTLEN);
	result = dtrace_send_message(tofd, &header, buf, prefix + payload);
	error = errno;
	free(buf);
	errno = error;
	return (result);
}

int
dtrace_send_elf(dtrace_prog_t *pgp, int fromfd, int tofd,
    const char *location, int send_ident)
{
	return (dtrace_send_elf_impl(pgp, fromfd, tofd, location,
	    send_ident, NULL));
}

int
dtrace_send_elf_derived(dtrace_prog_t *pgp, int fromfd, int tofd,
    const dtraced_derived_parent_t *parent)
{
	return (dtrace_send_elf_impl(pgp, fromfd, tofd, "outbound", 0,
	    parent));
}

void
dtrace_enable_hypertrace(dtrace_hdl_t *dtp)
{

	(void) dtrace_setopt(dtp, "hypertrace", "yes");
	dtp->dt_hypertrace = 1;
	log_hypertrace_elf = getenv("_HYPERTRACE_LOG_ELF") != NULL;
	log_hypertrace_linker = getenv("_HYPERTRACE_LOG_LINKER") != NULL;
	log_hypertrace_typing = getenv("_HYPERTRACE_LOG_TYPING") != NULL;
}

void
dtrace_set_failmsg_needed(dtrace_hdl_t *dtp)
{

	dtp->dt_failmsg_needed = 1;
}

int
dtrace_hypertrace_enabled(dtrace_hdl_t *dtp)
{

	return (dtp->dt_hypertrace);
}

int
dtrace_hypertrace_options_update(dtrace_hdl_t *dtp)
{

	/*
	 * For now, all we neeed to do is reload the kernel options.
	 */
	return (dt_options_load(dtp));
}

const char *
dtrace_hypertrace_errstr(int err)
{
	switch (err) {
	case E_HYPERTRACE_NONE:
		return ("No error");
	case E_HYPERTRACE_SYS:
		return ("System error");
	case E_HYPERTRACE_ELFCREATE:
		return ("ELF Creation failed");
	case E_HYPERTRACE_ELFPARSE:
		return ("ELF Parsing failed");
	case E_HYPERTRACE_LIBDTRACE:
		return ("Internal libdtrace error");
	case E_HYPERTRACE_CHECKSUM:
		return ("Checksum error");
	case E_HYPERTRACE_AGAIN:
		return ("Call the subroutine again");
	case E_HYPERTRACE_PROPAGATED:
		return ("Propagated error");
	case E_HYPERTRACE_IDENT_NOTFOUND:
		return ("Identifier not found");
	case E_HYPERTRACE_LINKING:
		return ("Linking error");
	}
	return ("Unknown error");
}

int
dtrace_oformat(dtrace_hdl_t *dtp)
{

	return (dtp->dt_oformat != DTRACE_OFORMAT_TEXT);
}

void
dtrace_set_outfp(const FILE *ofp)
{

	xo_set_file((FILE *)ofp);
}

void
dtrace_oformat_setup(dtrace_hdl_t *dtp)
{

	xo_open_container("dtrace");
	xo_open_list("probes");
}

/* Fresh-session shutdown discards formatter state on its owning thread.
 * xo_destroy normally flushes, so replace every output callback first. Switch
 * away from encoder style as its flush callback bypasses the normal writer. */
static xo_ssize_t
dt_oformat_discard_write(void *unused, const char *data)
{
	(void)unused;
	return ((xo_ssize_t)strlen(data));
}

void
dtrace_oformat_discard(dtrace_hdl_t *dtp)
{
	(void)dtp;
	xo_set_style(NULL, XO_STYLE_TEXT);
	xo_set_writer(NULL, NULL, dt_oformat_discard_write, NULL, NULL);
	xo_destroy(NULL);
}

int
dtrace_output_discard(dtrace_hdl_t *dtp, FILE *fp)
{
	int error = 0;

	if (dtp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	/* Keep the fence set on failure: retry may purge, but cannot resume output. */
	dtp->dt_output_discarded = 1;
	if (fp != NULL && fpurge(fp) != 0)
		error = errno;
#ifndef illumos
	if (dtp->dt_freopen_fp != NULL && dtp->dt_freopen_fp != fp &&
	    fpurge(dtp->dt_freopen_fp) != 0 && error == 0)
		error = errno;
#endif
	dt_buffered_destroy(dtp);
	dtrace_oformat_discard(dtp);
	if (error != 0) {
		errno = error;
		return (dt_set_errno(dtp, error));
	}
	return (0);
}

void
dtrace_oformat_teardown(dtrace_hdl_t *dtp)
{

	xo_close_list("probes");
	xo_close_container("dtrace");
}
