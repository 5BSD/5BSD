/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unwind.h>

static _Unwind_Reason_Code (*walk)(_Unwind_Trace_Fn, void *);
static uintptr_t (*get_ip)(struct _Unwind_Context *);
static volatile unsigned completed;
struct trace {
	unsigned frames;
	unsigned next;
	int stop;
};

static _Unwind_Reason_Code
visit(struct _Unwind_Context *context, void *argument)
{
	struct trace *trace = argument;
	const char *names[] = { "unwind_leaf", "unwind_middle", "unwind_outer" };
	Dl_info info;
	uintptr_t ip = get_ip(context);

	assert(++trace->frames < 256);
	if (trace->stop)
		return (_URC_NORMAL_STOP);
	/* The return PC can be at the next symbol's boundary. */
	if (ip != 0 && dladdr((void *)(uintptr_t)(ip - 1), &info) != 0 &&
	    info.dli_sname != NULL && trace->next < 3 &&
	    strcmp(info.dli_sname, names[trace->next]) == 0)
		trace->next++;
	return (_URC_NO_REASON);
}

__attribute__((noinline)) _Unwind_Reason_Code
unwind_leaf(struct trace *trace)
{
	_Unwind_Reason_Code result = walk(visit, trace);
	completed++;
	return (result);
}

__attribute__((noinline)) _Unwind_Reason_Code
unwind_middle(struct trace *trace)
{
	_Unwind_Reason_Code result = unwind_leaf(trace);
	completed++;
	return (result);
}

__attribute__((noinline)) _Unwind_Reason_Code
unwind_outer(struct trace *trace)
{
	_Unwind_Reason_Code result = unwind_middle(trace);
	completed++;
	return (result);
}

static void *
checked_symbol(void *handle, const char *name, const struct stat *expected)
{
	void *symbol = dlsym(handle, name);
	Dl_info info;
	struct stat actual;

	assert(symbol != NULL);
	assert(dladdr(symbol, &info) != 0 && info.dli_fname != NULL);
	assert(stat(info.dli_fname, &actual) == 0);
	assert(actual.st_dev == expected->st_dev && actual.st_ino == expected->st_ino);
	return (symbol);
}

int
main(int argc, char **argv)
{
	struct trace trace = {0};
	struct stat expected;
	void *handle;

	assert(argc == 2 && stat(argv[1], &expected) == 0);
	handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		return (1);
	}
	walk = (_Unwind_Reason_Code (*)(_Unwind_Trace_Fn, void *))
	    checked_symbol(handle, "_Unwind_Backtrace", &expected);
	get_ip = (uintptr_t (*)(struct _Unwind_Context *))
	    checked_symbol(handle, "_Unwind_GetIP", &expected);
	assert(unwind_outer(&trace) == _URC_END_OF_STACK);
	assert(trace.next == 3 && completed == 3);
	trace = (struct trace){ .stop = 1 };
	assert(unwind_outer(&trace) == _URC_NORMAL_STOP);
	assert(trace.frames == 1 && completed == 6);
	assert(dlclose(handle) == 0);
	puts("native libgcc_s: ordered caller frames and callback stop passed");
	return (0);
}
