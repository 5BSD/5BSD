/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); abort(); } } while (0)
#define HYPERTRACE_MAX_VMS 1024
#define HYPERTRACE_HOSTID 0
#define panic(...) abort()
#define dtrace_membar_consumer() ((void)0)
typedef uint32_t dtrace_id_t;
typedef bool dtrace_icookie_t;
typedef struct { int marker; } dtrace_probe_t;
static dtrace_probe_t **dtrace_vprobes[HYPERTRACE_MAX_VMS];
static int dtrace_nvprobes[HYPERTRACE_MAX_VMS];
static dtrace_id_t dtrace_probeid_error = 7;
static struct { uint8_t t_dtrace_inprobe; const void *t_hypertrace_vmhdl; } thread;
#define curthread (&thread)
static bool interrupts = true;
static dtrace_icookie_t dtrace_interrupt_disable(void)
{
    bool prior = interrupts; interrupts = false; return (prior);
}
static void dtrace_interrupt_enable(dtrace_icookie_t prior) { interrupts = prior; }
#include "entry.inc"
int main(void)
{
    dtrace_probe_t probe = { 1 }, *table[] = { &probe };
    dtrace_vprobes[1] = table; dtrace_nvprobes[1] = 1;
    CHECK(dtrace_probe_lookup_firing(1, 0) == NULL);
    CHECK(dtrace_probe_lookup_firing(1, 1) == &probe);
    CHECK(dtrace_probe_lookup_firing(1, 2) == NULL);
    CHECK(dtrace_probe_lookup_firing(UINT16_MAX, 1) == NULL);
    CHECK(dtrace_probe_lookup_firing(2, 1) == NULL);
    thread.t_hypertrace_vmhdl = &probe;
    CHECK(dtrace_probe_vmhdl(dtrace_probeid_error) == &probe);
    struct dtrace_probe_cookie outer = dtrace_probe_enter(1, 1);
    CHECK(!interrupts && thread.t_dtrace_inprobe == 1);
    CHECK(dtrace_probe_vmhdl(1) == &probe);
    CHECK(dtrace_probe_vmhdl(dtrace_probeid_error) == NULL);
    struct dtrace_probe_cookie inner = dtrace_probe_enter(0, dtrace_probeid_error);
    dtrace_probe_exit(inner);
    CHECK(!interrupts && thread.t_dtrace_inprobe == 1);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        /* A guest ID equal to the host ERROR ID is not an exception. */
        (void)dtrace_probe_enter(1, dtrace_probeid_error);
        _exit(1);
    }
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    dtrace_probe_exit(outer);
    CHECK(interrupts && thread.t_dtrace_inprobe == 0);
    puts("PASS: probe lookup bounds, host ERROR namespace, nested in-probe/interrupt restoration");
    return (0);
}
