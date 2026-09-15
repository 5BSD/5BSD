/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define GFP_KERNEL 0
#define CLK_SET_ROUND_EXACT 1
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((intptr_t)(p)<0)
struct device_node { int bsd_node; };
struct device { struct device_node *of_node; void *bsddev; };
struct native_clk { bool held,enabled; uint64_t rate; };
struct linux_clk { struct native_clk *native; };
static struct native_clk native;
static unsigned allocated,gets,sets,enables,disables,releases,index_expected;
static bool has_clocks,alloc_fail;
static int names_count,get_error,read_error,set_error,enable_error,action_error;
static const char *names[]={"bus","lpo"};
static void (*cleanup)(void *);
static void *cleanup_arg;
static void *kzalloc(size_t n,int flags) { (void)flags;if(alloc_fail)return NULL;allocated++;return calloc(1,n); }
static void kfree(void *p) { assert(allocated && p);allocated--;free(p); }
static bool of_property_read_bool(struct device_node *n,const char *p) { assert(n && !strcmp(p,"clocks"));return has_clocks; }
static int of_property_count_strings(struct device_node *n,const char *p) { assert(n && !strcmp(p,"clock-names"));return names_count; }
static int of_property_read_string_index(struct device_node *n,const char *p,int i,const char **s) { (void)n;(void)p;assert(i>=0 && i<2);*s=names[i];return 0; }
static int clk_get_by_ofw_index(void *d,int node,int i,struct native_clk **out) {
 (void)d;assert(node==12 && (unsigned)i==index_expected);gets++;
 if(get_error)return get_error;
 assert(!native.held);native.held=true;*out=&native;return 0;
}
static int clk_get_freq(struct native_clk *c,uint64_t *rate) { assert(c->held);if(read_error)return read_error;*rate=c->rate;return 0; }
static int clk_set_freq(struct native_clk *c,unsigned long rate,int flags) { assert(c->held && !c->enabled && flags==CLK_SET_ROUND_EXACT);sets++;if(set_error)return set_error;c->rate=rate;return 0; }
static int clk_enable(struct native_clk *c) { assert(c->held && !c->enabled);if(enable_error)return enable_error;c->enabled=true;enables++;return 0; }
static void clk_disable(struct native_clk *c) { assert(c->held && c->enabled);c->enabled=false;disables++; }
static void clk_release(struct native_clk *c) { assert(c->held && !c->enabled);c->held=false;releases++; }
static int devm_add_action_or_reset(struct device *d,void (*fn)(void *),void *p) {
 (void)d;if(action_error){fn(p);return action_error;}assert(!cleanup);cleanup=fn;cleanup_arg=p;return 0;
}
#include "power_functions.h"
static void setup(void) {
 assert(!allocated && !native.held && !native.enabled && !cleanup);
 native.rate=32768;has_clocks=true;alloc_fail=false;names_count=2;index_expected=1;
 get_error=read_error=set_error=enable_error=action_error=0;
 gets=sets=enables=disables=releases=0;
}
static void release_managed(void) { assert(cleanup);cleanup(cleanup_arg);cleanup=NULL;assert(!allocated && !native.held && enables==disables); }
int main(void) {
 struct device_node node={.bsd_node=12};struct device dev={.of_node=&node};struct linux_clk *clk;
 /* NULL IDs select the first clock, even without clock-names. */
 setup();names_count=-EINVAL;index_expected=0;
 clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,NULL,32768);
 assert(clk && !IS_ERR(clk) && gets==1 && enables==1);release_managed();
 setup();has_clocks=false;assert(linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",32768)==NULL && !gets);
 setup();assert(linux_devm_clk_get_optional_enabled_with_rate(&dev,"missing",32768)==NULL && !gets);
 setup();clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",32768);
 assert(clk && !IS_ERR(clk) && !sets && enables==1);release_managed();
 setup();native.rate=1000;clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",32768);
 assert(clk && !IS_ERR(clk) && sets==1 && native.rate==32768);release_managed();
 /* Rate zero is still a request; it must not silently retain another rate. */
 setup();clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",0);
 assert(clk && !IS_ERR(clk) && sets==1 && native.rate==0);release_managed();
 /* Reading an unset provider rate can fail; setting it can still succeed. */
 setup();read_error=EIO;clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",32768);
 assert(clk && !IS_ERR(clk) && sets==1);release_managed();
 for(unsigned failure=0;failure<5;failure++) {
  setup();native.rate=1000;
  switch(failure) { case 0:alloc_fail=true;break;case 1:get_error=ENXIO;break;
   case 2:set_error=ERANGE;break;case 3:enable_error=EIO;break;case 4:action_error=-ENOMEM;break; }
  clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",32768);
  const int expected[]={-ENOMEM,-ENXIO,-ERANGE,-EIO,-ENOMEM};assert(PTR_ERR(clk)==expected[failure]);
  assert(!allocated && !native.held && !native.enabled && !cleanup && enables==disables);
 }
 setup();names_count=-EILSEQ;clk=linux_devm_clk_get_optional_enabled_with_rate(&dev,"lpo",32768);
 assert(PTR_ERR(clk)==-EILSEQ && !gets && !allocated);
 puts("PASS: named/default clocks, rate changes, missing clocks and allocation/provider/enable/devres rollback");
 return 0;
}
