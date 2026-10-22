/* SPDX-License-Identifier: BSD-2-Clause */
/* Shared between consume-records.c and consume-records-internal.c. */
#ifndef CONSUME_RECORDS_H
#define	CONSUME_RECORDS_H

#include <stddef.h>

struct dtrace_hdl;

int cr_buf_cases(struct dtrace_hdl *, char *, size_t);
int cr_buf_fault_cases(struct dtrace_hdl *, void (*)(long), char *, size_t);
int cr_sleep_cases(struct dtrace_hdl *, char *, size_t);

/* libdtrace error numbers (dt_errtags.h is private). */
extern const int cr_EDT_BRICKED;
extern const int cr_EDT_DIRABORT;
extern const int cr_EDT_BADRVAL;
extern const int cr_EDT_NOMEM;
extern const int cr_EDT_BADNORMAL;
extern const int cr_EDT_BADTRUNC;
extern const int cr_EDT_BADSETOPT;
extern const int cr_EDT_BADSTACKPC;
extern const int cr_EDT_DMISMATCH;
extern const int cr_EDT_BADAGG;
extern const int cr_EDT_ERRABORT;
extern const int cr_EDT_NOBUFFERED;
extern const int cr_EDT_DROPABORT;
extern const int cr_DT_ACT_CLEAR;
extern const int cr_DT_ACT_TRUNC;
#ifndef CR_INTERNAL
#define	EDT_BRICKED	cr_EDT_BRICKED
#define	EDT_DIRABORT	cr_EDT_DIRABORT
#define	EDT_BADRVAL	cr_EDT_BADRVAL
#define	EDT_NOMEM	cr_EDT_NOMEM
#define	EDT_BADNORMAL	cr_EDT_BADNORMAL
#define	EDT_BADTRUNC	cr_EDT_BADTRUNC
#define	EDT_BADSETOPT	cr_EDT_BADSETOPT
#define	EDT_BADSTACKPC	cr_EDT_BADSTACKPC
#define	EDT_DMISMATCH	cr_EDT_DMISMATCH
#define	EDT_BADAGG	cr_EDT_BADAGG
#define	EDT_ERRABORT	cr_EDT_ERRABORT
#define	EDT_NOBUFFERED	cr_EDT_NOBUFFERED
#define	EDT_DROPABORT	cr_EDT_DROPABORT
#define	DT_ACT_CLEAR	cr_DT_ACT_CLEAR
#define	DT_ACT_TRUNC	cr_DT_ACT_TRUNC
#endif

#endif
