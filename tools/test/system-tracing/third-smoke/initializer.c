/* SPDX-License-Identifier: BSD-2-Clause */
#include <dlfcn.h>
#include <assert.h>
int initialized;
static void init(void) __attribute__((constructor));
static void init(void) {
 void *p=dlopen("libm.so.5",RTLD_NOW); assert(p); assert(dlclose(p)==0); initialized=7;
}
