/* SPDX-License-Identifier: BSD-2-Clause */
/* Capture SDT arguments in production-function fixtures, without DTrace. */
#ifndef MMC_SDT_TEST_H
#define MMC_SDT_TEST_H
#include <assert.h>
#include <stdint.h>
#include <string.h>
struct sdt_test_event {
	const char *provider, *name;
	uintptr_t args[6];
};
static _Thread_local struct sdt_test_event sdt_events[8192];
static _Thread_local unsigned sdt_count;
static inline void
sdt_record(const char *provider, const char *name, uintptr_t a, uintptr_t b,
    uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f)
{
	assert(sdt_count < sizeof(sdt_events) / sizeof(sdt_events[0]));
	sdt_events[sdt_count++] = (struct sdt_test_event){provider, name,
	    {a, b, c, d, e, f}};
}
#define SDT_PROBE1(p,m,f,n,a) SDT_PROBE6(p,m,f,n,a,0,0,0,0,0)
#define SDT_PROBE2(p,m,f,n,a,b) SDT_PROBE6(p,m,f,n,a,b,0,0,0,0)
#define SDT_PROBE3(p,m,f,n,a,b,c) SDT_PROBE6(p,m,f,n,a,b,c,0,0,0)
#define SDT_PROBE4(p,m,f,n,a,b,c,d) SDT_PROBE6(p,m,f,n,a,b,c,d,0,0)
#define SDT_PROBE5(p,m,f,n,a,b,c,d,e) SDT_PROBE6(p,m,f,n,a,b,c,d,e,0)
#define SDT_PROBE6(p,m,f,n,a,b,c,d,e,g) \
	sdt_record(#p, #n, (uintptr_t)a, (uintptr_t)b, (uintptr_t)c, \
	    (uintptr_t)d, (uintptr_t)e, (uintptr_t)g)
#endif
