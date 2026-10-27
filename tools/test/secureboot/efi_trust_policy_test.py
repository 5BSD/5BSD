# SPDX-License-Identifier: BSD-2-Clause
"""Actual EFI trust initialization with firmware/store seams; not cryptographic verification."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

class TrustPolicy(unittest.TestCase):
    def test_restricted_policy_query(self):
        source=(ROOT/'lib/libsecureboot/verify_file.c').read_text()
        start=source.index('int\nverify_manifest_trust_restricted(')
        function=source[start:source.index('\n}\n',start)+3]
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test'
            for restricted in (0,1):
                c.write_text('#include <assert.h>\n'+function+
                    'int main(void) {assert(verify_manifest_trust_restricted()=='+str(restricted)+');return 0;}')
                subprocess.run(['cc','-Wall','-Wextra','-Werror']+
                    (['-DVE_EFI_COMPILED_TRUST_ONLY'] if restricted else [])+
                    [str(c),'-o',str(binary)],check=True)
                subprocess.run([str(binary)],check=True)

    def test_trust_sources_and_revocations(self):
        source = (ROOT / 'lib/libsecureboot/efi/efi_init.c').read_text()
        function = source[source.index('void\nve_efi_init(void)'):]
        harness = r"""
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
typedef int br_x509_certificate;
typedef int hash_data;
static int enabled, anchors, db, dbx, hashes, required, imported, revoked;
static int cert, digest;
static jmp_buf failed;
static const char *panic_text;
#define panic(s) do { panic_text=(s); longjmp(failed,1); } while(0)
static int efi_secure_boot_enabled(void) { return enabled; }
static void verify_require(void) { required++; }
static int ve_trust_init(void) { return anchors; }
static br_x509_certificate *efi_get_trusted_certs(size_t *n) { db++; *n=1; return &cert; }
static br_x509_certificate *efi_get_forbidden_certs(size_t *n) { dbx++; *n=1; return &cert; }
static hash_data *efi_get_forbidden_digests(size_t *n) { hashes++; *n=1; return &digest; }
static size_t ve_trust_anchors_add(br_x509_certificate *p,size_t n) { assert(p==&cert); imported++; return n; }
static size_t ve_forbidden_anchors_add(br_x509_certificate *p,size_t n) { assert(p==&cert); revoked++; return n; }
static void ve_forbidden_digest_add(hash_data *p,size_t n) { assert(p==&digest && n==1); }
static void free_certificates(br_x509_certificate *p,size_t n) { assert(p==&cert && n==1); }
#define xfree(p) ((void)(p))
"""
        cases = r"""
int main(int argc,char **argv) {
 assert(argc==3); enabled=atoi(argv[1]); anchors=atoi(argv[2]);
 if (setjmp(failed)) {
  assert(enabled<0 || (enabled==1 && anchors==0));
  if (enabled<0) assert(strstr(panic_text,"firmware policy"));
  else assert(strstr(panic_text,"compiled manifest trust"));
  assert(db==0 && imported==0); return 0;
 }
 ve_efi_init();
 if (enabled<0) abort();
 if (!enabled) { assert(required==0 && db==0 && dbx==0); return 0; }
 assert(required==1 && dbx==1 && hashes==1 && revoked==1);
#ifdef VE_EFI_COMPILED_TRUST_ONLY
 assert(anchors>0 && db==0 && imported==0);
#else
 assert(db==1 && imported==1);
#endif
 ve_efi_init(); assert(required==1 && dbx==1 && hashes==1);
 return 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            c = base / 'test.c'; c.write_text(harness + function + cases)
            for restricted in (False, True):
                binary = base / 'test'
                flags = ['-DVE_EFI_COMPILED_TRUST_ONLY'] if restricted else []
                subprocess.run(['cc', *flags, str(c), '-o', str(binary)], check=True)
                for enabled, anchors in ((-1,1),(0,0),(1,0),(1,1)):
                    with self.subTest(restricted=restricted, enabled=enabled, anchors=anchors):
                        subprocess.run([str(binary), str(enabled), str(anchors)], check=True, cwd=base)

if __name__ == '__main__':
    unittest.main()
