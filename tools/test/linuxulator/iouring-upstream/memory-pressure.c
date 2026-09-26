/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable-VM helper: hold and repeatedly touch 512 MiB until SIGTERM. */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
int main(void)
{
 const size_t len = 512UL * 1024 * 1024;
 volatile unsigned char *p = malloc(len);
 size_t i;
 if (p == NULL) return 1;
 signal(SIGTERM, stop);
 for (i = 0; i < len; i += 4096) p[i] = 1;
 puts("PRESSURE_READY 536870912");
 fflush(stdout);
 while (!stopping) {
  for (i = 0; i < len; i += 4096) p[i]++;
  sleep(1);
 }
 free((void *)p);
 return 0;
}
