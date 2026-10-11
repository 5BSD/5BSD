#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test actual MAC dispatch macros with synthetic policies, without a live kernel."""
import argparse,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--src',type=Path,default=Path('/usr/src'));p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
s=(a.src/'sys/security/mac/mac_internal.h').read_text();macros=[]
for m in re.finditer(r'^#define\s+(?:MAC_POLICY_|MAC_HOOK_)\w+\(',s,re.M):
 if m[0].startswith('#define\tMAC_POLICY_CHECK_PROBE') or 'MAC_POLICY_CHECK_PROBE(' in m[0]:continue
 lines=[]
 for line in s[m.start():].splitlines():
  lines.append(line)
  if not line.endswith('\\'):break
 macros.append('\n'.join(lines))
c=r'''
#include <sys/types.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#define __XSTRING_INNER(x) #x
#ifndef __XSTRING
#define __XSTRING(x) __XSTRING_INNER(x)
#endif
#ifndef __unused
#define __unused __attribute__((unused))
#endif
static int starts, ends, calls, locks, returned, snapshots, absent, skipped;
static int args_enabled=1, capture=0;
static int observed_int, zero_calls, eight_calls;
static uint64_t observed_wide;
static void snapshot(const char *hook, unsigned n, const uint64_t *v) {
 snapshots++;
 if (!strcmp(hook,"file_check_ioctl")) {
  assert(n==4 && v[0]==0 && v[1]==0);
  assert((int)v[2]==observed_int && v[3]==observed_wide);
 } else if (!strcmp(hook,"vnode_check_setutimes")) {
  assert(n==5);
  const struct timespec *at=(const void *)(uintptr_t)v[3];
  const struct timespec *mt=(const void *)(uintptr_t)v[4];
  assert(at->tv_sec==-7 && at->tv_nsec==123);
  assert(mt->tv_sec==13 && mt->tv_nsec==987);
 } else if (!strcmp(hook,"cred_setcred_enter")) assert(n==0);
 else if (!strcmp(hook,"vnode_create_extattr")) {
  assert(n==8); for (unsigned i=0;i<n;i++) assert(v[i]==0);
 } else { assert(n==1); capture=(int)v[0]; }
}
static void probe_hook__done(const char *h, const char *p, int v, int kind) {
 (void)h;(void)p;(void)kind;ends++;returned=v;
}
static void probe_hook__args(const char *h,const char *p,unsigned n,const uint64_t *v) {
 (void)p;snapshot(h,n,v);
}
#define enabled_hook__done 1
#define enabled_hook__args args_enabled
#ifdef HOOKS
#define SDT_PROBE2(p,m,f,n,a,b) do { starts++; } while (0)
#define SDT_PROBE3(p,m,f,n,a,b,c) do { if ((c)==1) absent++; else if ((c)==2) skipped++; else assert(0); } while (0)
#define SDT_PROBE4(p,m,f,n,a,b,c,d) do { if (enabled_ ## n) probe_ ## n(a,b,c,d); } while (0)
#else
#define SDT_PROBE2(...) do { } while (0)
#define SDT_PROBE3(...) do { } while (0)
#define SDT_PROBE4(...) do { } while (0)
#endif
struct rm_priotracker { int unused; };
static void mac_policy_slock_sleep(void) { locks++; }
static void mac_policy_sunlock_sleep(void) { locks--; }
static void mac_policy_slock_nosleep(struct rm_priotracker *p) { (void)p;locks++; }
static void mac_policy_sunlock_nosleep(struct rm_priotracker *p) { (void)p;locks--; }
static int mac_error_select(int a,int b) { return a?a:b; }
struct ucred; struct file; struct vnode; struct label; struct mount; struct componentname;
struct ops {
 int (*mpo_check)(int); void (*mpo_perform)(int);
 int (*mpo_file_check_ioctl)(struct ucred *,struct file *,int,u_long);
 int (*mpo_vnode_check_setutimes)(struct ucred *,struct vnode *,struct label *,struct timespec,struct timespec);
 void (*mpo_cred_setcred_enter)(void);
 int (*mpo_vnode_create_extattr)(struct ucred *,struct mount *,struct label *,struct vnode *,struct label *,struct vnode *,struct label *,struct componentname *);
};
struct mac_policy_conf { struct ops *mpc_ops; const char *mpc_name; LIST_ENTRY(mac_policy_conf) mpc_list; };
LIST_HEAD(head,mac_policy_conf);
static struct head mac_static_policy_list=LIST_HEAD_INITIALIZER(mac_static_policy_list);
static struct head mac_policy_list=LIST_HEAD_INITIALIZER(mac_policy_list);
static int check(int v) {
 assert(locks==calls%2);calls++;
#ifdef HOOKS
 if(args_enabled) assert(capture==v);
#endif
 return v;
}
static void perform(int v) { assert(locks==calls%2);calls+=v; }
static int ioctl_hook(struct ucred *c,struct file *f,int fd,u_long cmd) {
 assert(!c && !f && fd==observed_int && cmd==observed_wide);return EACCES;
}
static int times_hook(struct ucred *c,struct vnode *v,struct label *l,struct timespec at,struct timespec mt) {
 assert(!c && !v && !l && at.tv_sec==-7 && mt.tv_nsec==987);return 0;
}
static void zero_hook(void) { zero_calls++; }
static int eight_hook(struct ucred *c,struct mount *m,struct label *l,struct vnode *v,struct label *l2,struct vnode *v2,struct label *l3,struct componentname *n) {
 assert(!c && !m && !l && !v && !l2 && !v2 && !l3 && !n);eight_calls++;return 0;
}
'''+(a.src/'sys/security/mac/mac_trace_args.h').read_text()+'\n'+'\n'.join(macros)+r'''
#undef MAC_POLICY_CHECK_PROBE
#define MAC_POLICY_CHECK_PROBE(...) do { } while (0)
#define MAC_HOOK_ARGS_check(p,a) SDT_PROBE4(mac_framework,,,hook__args,"check",(p)->mpc_name,1,((const uint64_t[]){(uint64_t)(a)}))
#define MAC_HOOK_ARGS_perform(p,a) SDT_PROBE4(mac_framework,,,hook__args,"perform",(p)->mpc_name,1,((const uint64_t[]){(uint64_t)(a)}))
int main(void) {
 struct ops ops={.mpo_check=check,.mpo_perform=perform,.mpo_file_check_ioctl=ioctl_hook,.mpo_vnode_check_setutimes=times_hook,.mpo_cred_setcred_enter=zero_hook,.mpo_vnode_create_extattr=eight_hook},empty={0};
 struct mac_policy_conf one={.mpc_ops=&ops,.mpc_name="one"},two={.mpc_ops=&ops,.mpc_name="two"},missing={.mpc_ops=&empty,.mpc_name="absent"};
 int error,result,v=0;
 LIST_INSERT_HEAD(&mac_static_policy_list,&one,mpc_list);
 LIST_INSERT_HEAD(&mac_policy_list,&two,mpc_list);
 MAC_POLICY_CHECK(check,++v);assert(calls==2 && v==2 && error==2);
 MAC_POLICY_CHECK_NOSLEEP(check,0);assert(calls==4 && error==0);
 MAC_POLICY_GRANT_NOSLEEP(check,0);assert(calls==6 && error==0);
 result=0;MAC_POLICY_BOOLEAN(check,&&,++v);assert(calls==6 && result==0 && v==2);
 result=1;MAC_POLICY_BOOLEAN_NOSLEEP(check,||,++v);assert(calls==6 && result==1 && v==2);
 result=0;MAC_POLICY_BOOLEAN(check,|,1);assert(calls==8 && result==1);
 result=0;MAC_POLICY_BOOLEAN_NOSLEEP(check,|,1);assert(calls==10 && result==1);
 MAC_POLICY_PERFORM(perform,1);MAC_POLICY_PERFORM_NOSLEEP(perform,1);
 assert(calls==14 && locks==0);
#ifdef HOOKS
 assert(starts==14 && ends==14 && returned==0 && snapshots==14 && skipped==4);
#endif
 LIST_INSERT_HEAD(&mac_static_policy_list,&missing,mpc_list);
 MAC_POLICY_CHECK(check,++v);assert(v==4 && calls==16);
 MAC_POLICY_PERFORM_NOSLEEP(perform,1);assert(calls==18);
#ifdef HOOKS
 assert(absent==2);
#endif
 LIST_REMOVE(&missing,mpc_list);
 args_enabled=0;int previous=snapshots;
 MAC_POLICY_CHECK_NOSLEEP(check,++v);assert(v==6 && calls==20 && snapshots==previous);
 args_enabled=1;
 observed_int=-19;observed_wide=0xfedcba9876543210UL;
 error=MAC_POLICY_CALL_INT(file_check_ioctl,&one,NULL,NULL,observed_int,observed_wide);assert(error==EACCES);
 struct timespec at={-7,123},mt={13,987};
 error=MAC_POLICY_CALL_INT(vnode_check_setutimes,&one,NULL,NULL,NULL,at,mt);assert(error==0);
 MAC_POLICY_PERFORM_NOSLEEP(cred_setcred_enter);assert(zero_calls==2);
 MAC_POLICY_CHECK(vnode_create_extattr,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);assert(eight_calls==2 && error==0);
#ifndef HOOKS
 assert(starts==0 && ends==0 && snapshots==0 && absent==0 && skipped==0);
#endif
 assert(locks==0);return 0;
}
'''
source=a.output/'mac-dispatch.c';source.write_text(c);results=[]
for mode in ('hooks','nohooks'):
 exe=a.output/('mac-dispatch-'+mode);cmd=['cc','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable',str(source),'-o',str(exe)]+(['-DHOOKS'] if mode=='hooks' else [])
 subprocess.run(cmd,check=True);subprocess.run([str(exe)],check=True);results.append(dict(name=mode,status=0));print(mode,'PASS')
(a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
