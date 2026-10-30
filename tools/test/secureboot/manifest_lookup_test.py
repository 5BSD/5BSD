# SPDX-License-Identifier: BSD-2-Clause
"""Actual manifest lookup must not match truncated names or overrun a path."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class ManifestLookup(unittest.TestCase):
    def test_path_bounds_and_exact_names(self):
        s=(ROOT/'lib/libsecureboot/veopen.c').read_text()
        declarations=s[s.index('struct fingerprint_info {'):s.index('\n/**')]
        a=s.index('static char *\nmaybe_skip(')
        legacy='#ifdef MANIFEST_SKIP_MAYBE\n'+s[a:s.index('\n}\n',a)+3]+'\n#endif\n'
        functions=[legacy]
        for signature in ('int\nfingerprint_info_add(', 'char *\nfingerprint_info_lookup('):
            a=s.index(signature);functions.append(s[a:s.index('\n}\n',a)+3])
        before=r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <unistd.h>
#define MAXPATHLEN 64
#define MIN(a,b) ((a)<(b)?(a):(b))
#define DEBUG_PRINTF(level,args) ((void)0)
'''
        main=r'''
static void clear(void) {
 struct fingerprint_info *p;
 while((p=LIST_FIRST(&fi_list))!=NULL) {
  LIST_REMOVE(p,entries); free(p->fi_prefix); free(p->fi_skip); free(p);
 }
}
int main(void) {
 struct stat st={0};
 assert(fingerprint_info_add(NULL,"/boot",NULL,"kernel sha256=good\nxkernel sha256=bad\n",&st)==0);
 assert(!strcmp(fingerprint_info_lookup(-1,"/boot/kernel"),"sha256=good\nxkernel sha256=bad\n"));
 assert(fingerprint_info_lookup(-1,"/boot/ker")==NULL);
 assert(fingerprint_info_lookup(-1,"/boot/kernel-extra")==NULL);
 assert(fingerprint_info_lookup(-1,"")==NULL);
 assert(fingerprint_info_lookup(-1,"/")==NULL);
 clear();
 char skip[61], manifest[96], combined[96];
 memset(skip,'s',60); skip[60]='\0';
 snprintf(combined,sizeof(combined),"%s/kernel",skip);
 memcpy(manifest,combined,MAXPATHLEN);
 strcpy(manifest+MAXPATHLEN," sha256=wrong\n");
 assert(fingerprint_info_add(NULL,"/boot",skip,manifest,&st)==0);
 assert(fingerprint_info_lookup(-1,"/boot/kernel")==NULL);
 clear();
 /* An exact-fit combined name must remain valid. */
 skip[57]='\0'; snprintf(manifest,sizeof(manifest),"%s/kernel sha256=fit\n",skip);
 assert(fingerprint_info_add(NULL,"/boot",skip,manifest,&st)==0);
 assert(!strcmp(fingerprint_info_lookup(-1,"/boot/kernel"),"sha256=fit\n"));
 clear();
 char longprefix[8192]; memset(longprefix,'p',sizeof(longprefix)-1);
 longprefix[0]='/'; longprefix[sizeof(longprefix)-1]='\0';
 assert(fingerprint_info_add(NULL,"/",NULL,"kernel sha256=root\n",&st)==0);
 assert(fingerprint_info_lookup(-1,"")==NULL);
 assert(fingerprint_info_lookup(-1,"/")==NULL);
 assert(fingerprint_info_add(NULL,longprefix,NULL,"unrelated sha256=none\n",&st)==0);
 assert(!strcmp(fingerprint_info_lookup(-1,"/kernel"),"sha256=root\n"));
 assert(!strcmp(fingerprint_info_lookup(-1,"kernel"),"sha256=root\n"));
 char longpath[66]; memset(longpath,'x',sizeof(longpath)-1);longpath[65]='\0';
 assert(fingerprint_info_lookup(-1,longpath)==NULL);
 clear();
#ifdef MANIFEST_SKIP_MAYBE
 assert(fingerprint_info_add(NULL,"/boot",NULL,"x/kernel sha256=bad\nboot/kernel sha256=legacy\n",&st)==0);
 assert(!strcmp(fingerprint_info_lookup(-1,"/boot/kernel"),"sha256=legacy\n"));
 clear();
#endif
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'probe.c').write_text(before+declarations+'\n'.join(functions)+main)
            for flags in ([], ['-DMANIFEST_SKIP_MAYBE="boot"']):
                subprocess.run(['cc','-Wall','-Wextra','-Werror',*flags,str(p/'probe.c'),'-o',str(p/'probe')],check=True)
                subprocess.run([str(p/'probe')],check=True)

if __name__=='__main__': unittest.main()
