# SPDX-License-Identifier: BSD-2-Clause
"""Actual uefisign digest routine against independent byte-range SHA256 vectors."""
from pathlib import Path
import hashlib,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "uefisign.h"
static size_t certificate_size;
size_t signature_size(const struct executable *x){(void)x;return certificate_size;}
void range_check(const struct executable *x,off_t offset,size_t length,const char *name) {
 (void)name;assert(offset>=0 && (uintmax_t)offset<=x->x_len && length<=x->x_len-offset);
}
'''
MAIN=r'''
int main(int argc,char **argv) {
 assert(argc==2);int mode=atoi(argv[1]);
 unsigned char bytes[160];for(size_t i=0;i<sizeof(bytes);i++)bytes[i]=i;
 struct executable x={.x_buf=(char *)bytes,.x_len=sizeof(bytes),.x_headers_len=64,
  .x_checksum_off=8,.x_checksum_len=4,.x_certificate_entry_off=20,.x_certificate_entry_len=8,
  .x_nsections=2,.x_section_off={64,96},.x_section_len={32,32}};
 if(mode==1 || mode==3){x.x_section_off[0]=96;x.x_section_off[1]=64;}
 if(mode>=2){x.x_nsections=3;x.x_section_off[2]=99999;x.x_section_len[2]=0;}
 if(mode==3)certificate_size=16;
 if(mode==4)certificate_size=sizeof(bytes);
 digest(&x);
 for(unsigned i=0;i<x.x_digest_len;i++)printf("%02x",x.x_digest[i]);
 puts("");return 0;
}
'''
class Digest(unittest.TestCase):
    def test_section_order_empty_sections_and_certificate_exclusion(self):
        source=(ROOT/'usr.sbin/uefisign/child.c').read_text();parts=[]
        for signature in ('static void\ndigest_range(', 'static void\ndigest('):
            start=source.index(signature);parts.append(source[start:source.index('\n}\n',start)+3])
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'probe.c';binary=Path(directory)/'probe'
            c.write_text(PRE+'\n'.join(parts)+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'usr.sbin/uefisign'),str(c),'-lcrypto','-o',str(binary)],check=True)
            data=bytes(range(160))
            for mode in range(4):
                with self.subTest(mode=mode):
                    output=subprocess.run([str(binary),str(mode)],capture_output=True,text=True,check=True)
                    expected=hashlib.sha256(data[:8]+data[12:20]+data[28:64]+data[64:96]+data[96:128]+data[128:144 if mode==3 else 160]).hexdigest()
                    self.assertEqual(output.stdout,expected+'\n')
            result=subprocess.run([str(binary),'4'],capture_output=True,text=True)
            self.assertEqual(result.returncode,1)
            self.assertIn('certificate size exceeds remaining file data',result.stderr)

if __name__=='__main__':unittest.main()
