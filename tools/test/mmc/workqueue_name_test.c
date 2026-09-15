/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#define MAXCOMLEN 19
struct workqueue_struct { int unused; };
static struct workqueue_struct queue;
static char saved[MAXCOMLEN+1];
static struct workqueue_struct *linux_create_workqueue_common(const char *name,int cpus) {
 assert(cpus==1);snprintf(saved,sizeof(saved),"%s",name);return &queue;
}
#include "power_functions.h"
int main(void) {
 assert(linux_alloc_ordered_workqueue("brcmf_wq/%s","sdio0")==&queue);
 assert(strcmp(saved,"brcmf_wq/sdio0")==0);
 linux_alloc_ordered_workqueue("%s","name%with%signs");
 assert(strcmp(saved,"name%with%signs")==0);
 linux_alloc_ordered_workqueue("ib_mad%d",2);assert(strcmp(saved,"ib_mad2")==0);
 linux_alloc_ordered_workqueue("%s","1234567890123456789012345");
 assert(strlen(saved)==MAXCOMLEN);
 return 0;
}
