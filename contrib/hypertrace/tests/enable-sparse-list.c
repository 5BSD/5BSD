/* Build the current kernel dtrace_enabling_list() body in this fixture. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DTRACE_PROVNAMELEN 16
#define DTRACE_MODNAMELEN 16
#define DTRACE_FUNCNAMELEN 16
#define DTRACE_NAMELEN 16
#define KM_NOSLEEP 0
#define ASSERT(expr) assert(expr)
#define ASSERT3S(a, op, b) assert((a) op (b))
#define MUTEX_HELD(lock) (*(lock) == 1)

typedef uint16_t dtrace_vmid_t;
typedef struct { const char *dtpv_name; } dtrace_provider_t;
typedef struct {
	uint32_t dtpr_id;
	dtrace_vmid_t dtpr_vmid;
	void *dtpr_provider;
	const char *dtpr_vprovider;
	const char *dtpr_mod;
	const char *dtpr_func;
	const char *dtpr_name;
} dtrace_probe_t;
typedef struct {
	uint32_t dtpd_id;
	dtrace_vmid_t dtpd_vmid;
	char dtpd_provider[DTRACE_PROVNAMELEN];
	char dtpd_mod[DTRACE_MODNAMELEN];
	char dtpd_func[DTRACE_FUNCNAMELEN];
	char dtpd_name[DTRACE_NAMELEN];
} dtrace_probedesc_t;
typedef struct {
	int dten_probelistsize;
	dtrace_probe_t **dten_probelist;
} dtrace_enabling_t;

static int dtrace_lock = 1;
static size_t allocated_bytes, freed_desc_bytes, freed_list_bytes;
static int fail_alloc;

static void *
kmem_zalloc(size_t size, int flags)
{
	assert(flags == KM_NOSLEEP);
	allocated_bytes = size;
	return (fail_alloc ? NULL : calloc(1, size));
}

static void
kmem_free(void *ptr, size_t size)
{
	assert(ptr != NULL);
	if (size == allocated_bytes)
		freed_desc_bytes += size;
	else
		freed_list_bytes += size;
	free(ptr);
}

#include "enable-sparse-list-impl.inc"

static dtrace_probe_t **
new_slots(int count)
{
	dtrace_probe_t **slots = calloc((size_t)count, sizeof(*slots));
	assert(slots != NULL);
	return (slots);
}

int
main(void)
{
	dtrace_provider_t provider = { .dtpv_name = "hostprov" };
	dtrace_probe_t host = { .dtpr_id = 2, .dtpr_provider = &provider,
	    .dtpr_mod = "mod", .dtpr_func = "func", .dtpr_name = "enter" };
	dtrace_probe_t guest = { .dtpr_id = 90000, .dtpr_vmid = 7,
	    .dtpr_vprovider = "guestprov", .dtpr_mod = "vm",
	    .dtpr_func = "func", .dtpr_name = "return" };
	dtrace_probe_t malformed = { .dtpr_id = 1,
	    .dtpr_provider = &provider, .dtpr_mod = "module-name-too-long",
	    .dtpr_func = "func", .dtpr_name = "enter" };
	dtrace_enabling_t enab = { .dten_probelistsize = 100000,
	    .dten_probelist = new_slots(100000) };
	dtrace_probedesc_t *list;
	size_t bytes = 0;
	int count = -1;

	enab.dten_probelist[1] = &host;
	enab.dten_probelist[89999] = &guest;
	list = dtrace_enabling_list(&enab, &count, &bytes);
	assert(list != NULL && count == 2);
	assert(bytes == 2 * sizeof(*list) && allocated_bytes == bytes);
	assert(freed_list_bytes == 100000 * sizeof(dtrace_probe_t *));
	assert(enab.dten_probelist == NULL && enab.dten_probelistsize == 0);
	assert(list[0].dtpd_id == 2 &&
	    strcmp(list[0].dtpd_provider, "hostprov") == 0);
	assert(list[1].dtpd_vmid == 7 &&
	    strcmp(list[1].dtpd_provider, "guestprov") == 0);
	kmem_free(list, bytes);
	assert(freed_desc_bytes == bytes);

	enab.dten_probelistsize = 4;
	enab.dten_probelist = new_slots(4);
	enab.dten_probelist[0] = &malformed;
	allocated_bytes = 0;
	bytes = 0;
	assert(dtrace_enabling_list(&enab, &count, &bytes) == NULL);
	assert(freed_desc_bytes == 2 * sizeof(*list) + sizeof(*list));
	assert(enab.dten_probelist != NULL);
	free(enab.dten_probelist);

	enab.dten_probelist = new_slots(4);
	enab.dten_probelist[0] = &host;
	fail_alloc = 1;
	bytes = 0;
	assert(dtrace_enabling_list(&enab, &count, &bytes) == NULL);
	assert(bytes == 0 && enab.dten_probelist != NULL);
	fail_alloc = 0;
	free(enab.dten_probelist);

	enab.dten_probelist = new_slots(4);
	bytes = 9;
	assert(dtrace_enabling_list(&enab, &count, &bytes) == NULL);
	assert(bytes == 0 && enab.dten_probelist != NULL);
	free(enab.dten_probelist);
	puts("enable sparse list: pass");
	return (0);
}
