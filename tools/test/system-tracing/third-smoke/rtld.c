/* SPDX-License-Identifier: BSD-2-Clause */
#include <dlfcn.h>
#include <assert.h>
int main(int argc,char **argv) {
 assert(argc==2);
 void *p=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); assert(p);
 int *initialized=dlsym(p,"initialized"); assert(initialized && *initialized==7);
 assert(dlclose(p)==0);
 assert(dlopen("/no-such-trace-library.so",RTLD_NOW)==0); assert(dlerror());
 return 0;
}
