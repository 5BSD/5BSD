#!/usr/bin/env python3
"""Exercise the actual kernel-buffer helper and statistics handlers natively.

No host sysctl, firewall changes, or vendor counter mutation is performed.
The kernel/VNET counter backend still requires guest runtime qualification.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


class StatsContract(unittest.TestCase):
    def test_readonly_copy_and_handler_lifetime(self):
        header = (ROOT / 'sys/netpfil/openbsd-pf/openbsd_compat.h').read_text()
        helper = re.search(r'static __inline int\nobsd_sysctl_rdstruct\(.*?\n\}',
                           header, re.S).group(0)
        source = (ROOT / 'sys/netpfil/openbsd-pf/pf_sysctl.c').read_text()
        source = re.sub(r'^#include.*\n', '', source, flags=re.M)
        mock = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define SYSCTL_DECL(...)
#define SYSCTL_NODE(...) int unused_node_##__LINE__ __attribute__((unused))
#define SYSCTL_PROC(...)
#define SI_SUB_PROTO_FIREWALL 1
#define SI_ORDER_LAST 4
#define SYSINIT(n, s, o, f, a) _Static_assert(o == SI_ORDER_LAST, "late publication")
#define atomic_store_rel_int(p,v) (*(p) = (v))
#define atomic_load_acq_int(p) (*(p))
struct pfsyncstats { uint64_t count[4]; };
struct pflowstats { uint64_t count[3]; };
struct req { void *newptr; unsigned char out[64]; size_t len; };
#define SYSCTL_HANDLER_ARGS struct req *req
#define SYSCTL_OUT(r,p,l) output(r,p,l)
#define NET_PFLOW_STATS 1
static int vendor_calls, vendor_error, output_error;
static int output(struct req *r, void *p, size_t l) {
 if (output_error) return output_error;
 assert(l <= sizeof(r->out)); memcpy(r->out,p,l); r->len=l; return 0;
}
int pflow_sysctl(int *, unsigned, void *, size_t *, void *, size_t);
'''
        driver = r'''
int pfsync_sysctl_pfsyncstat(void *p, size_t *l, void *n) {
 struct pfsyncstats s={{1,2,3,4}}; vendor_calls++;
 if(vendor_error) return vendor_error;
 return obsd_sysctl_rdstruct(p,l,n,&s,sizeof(s));
}
int pflow_sysctl(int *m, unsigned count, void *p, size_t *l, void *n, size_t nl) {
 struct pflowstats s={{7,8,9}}; vendor_calls++;
 assert(count==1 && m[0]==NET_PFLOW_STATS && nl==0);
 if(vendor_error) return vendor_error;
 return obsd_sysctl_rdstruct(p,l,n,&s,sizeof(s));
}
int main(void) {
 unsigned char buf[16], original[16], value[4]={1,2,3,4}; size_t len;
 struct req r={0};
 memset(buf,0xa5,sizeof(buf)); memcpy(original,buf,sizeof(buf));
 len=0; assert(obsd_sysctl_rdstruct(NULL,&len,NULL,value,4)==0 && len==4);
 len=3; assert(obsd_sysctl_rdstruct(buf+4,&len,NULL,value,4)==ENOMEM);
 assert(len==3 && memcmp(buf,original,16)==0);
 len=4; assert(obsd_sysctl_rdstruct(buf+4,&len,buf,value,4)==EPERM);
 assert(memcmp(buf,original,16)==0);
 assert(obsd_sysctl_rdstruct(buf+4,&len,NULL,value,4)==0 && len==4);
 assert(memcmp(buf+4,value,4)==0 && memcmp(buf,original,4)==0 &&
     memcmp(buf+8,original+8,8)==0);
 assert(pf_sysctl_pfsync_stats(&r)==EAGAIN);
 assert(pf_sysctl_pflow_stats(&r)==EAGAIN && vendor_calls==0);
 r.newptr=buf; assert(pf_sysctl_pfsync_stats(&r)==EPERM);
 assert(pf_sysctl_pflow_stats(&r)==EPERM && vendor_calls==0); r.newptr=NULL;
 pf_stats_init(NULL);
 assert(pf_sysctl_pfsync_stats(&r)==0 && r.len==sizeof(struct pfsyncstats));
 struct pfsyncstats sync; memcpy(&sync,r.out,sizeof(sync)); assert(sync.count[3]==4);
 assert(pf_sysctl_pflow_stats(&r)==0 && r.len==sizeof(struct pflowstats));
 struct pflowstats flow; memcpy(&flow,r.out,sizeof(flow)); assert(flow.count[2]==9);
 vendor_error=EIO; r.len=0; memset(r.out,0xa5,sizeof(r.out));
 assert(pf_sysctl_pfsync_stats(&r)==EIO && r.len==0 && r.out[0]==0xa5);
 assert(pf_sysctl_pflow_stats(&r)==EIO && r.len==0); vendor_error=0;
 output_error=ENOMEM; assert(pf_sysctl_pfsync_stats(&r)==ENOMEM);
 assert(pf_sysctl_pflow_stats(&r)==ENOMEM); output_error=0;
 int calls=vendor_calls; r.newptr=buf;
 assert(pf_sysctl_pfsync_stats(&r)==EPERM && pf_sysctl_pflow_stats(&r)==EPERM);
 assert(vendor_calls==calls);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / 'test.c').write_text(mock + helper + source + driver)
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
                           ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
