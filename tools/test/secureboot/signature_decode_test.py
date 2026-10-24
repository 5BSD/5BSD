# SPDX-License-Identifier: BSD-2-Clause
"""Production detached-signature ownership and dispatch with crypto/I/O seams."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
class Decode(unittest.TestCase):
    def test_rsa_and_ec_cleanup(self):
        source=(ROOT/'lib/libsecureboot/vets.c').read_text()
        bodies=[]
        for signature in ('static pem_object *\nread_signature(', 'static unsigned char *\nverify_ec(', 'static unsigned char *\nverify_rsa('):
            start=source.index(signature);end=source.index('\n}\n',start)+3
            bodies.append(source[start:end])
        harness=r'''
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
static int live, scenario, crypto_pass, crypto_calls;
static void *allocate(size_t n) { void *p=calloc(1,n); assert(p); live++; return p; }
static void release(void *p) { if(p) { assert(live>0); live--; free(p); } }
#define free release
typedef struct { char *name; unsigned char *data; size_t data_len; } pem_object;
static unsigned char *read_file(const char *path,size_t *len) {
 if((scenario==5 && !strcmp(path,"sig")) || (scenario==6 && !strcmp(path,"file"))) return NULL;
 *len=1; return allocate(1);
}
static pem_object *decode_pem(const void *data,size_t len,size_t *count) {
 (void)data; (void)len;
 if(scenario==4) return NULL;
 *count=scenario==1 ? 0 : scenario==2 ? 2 : 1;
 pem_object *p=allocate((*count+1)*sizeof(*p));
 for(size_t i=0;i<*count;i++) { p[i].name=allocate(10); strcpy(p[i].name,"SIGNATURE"); p[i].data=allocate(1); p[i].data_len=scenario==3 ? 0 : 1; }
 return p;
}
static void free_pem_object_contents(pem_object *p) { free(p->name); free(p->data); }
#define br_sha512_SIZE 64
#define br_sha256_SIZE 32
#define BR_HASH_OID_SHA256 ((const unsigned char *)"oid")
typedef struct { struct { int rsa,ec; } key; } br_x509_pkey;
typedef int br_sha256_context;
static void br_sha256_init(br_sha256_context *c) { *c=0; }
static void br_sha256_update(br_sha256_context *c,const void *p,size_t n) { (void)c;(void)p;(void)n; }
static void br_sha256_out(br_sha256_context *c,void *p) { (void)c;memset(p,0,32); }
typedef int br_ec_impl;
typedef int (*br_ecdsa_vrfy)(const br_ec_impl *,const void *,size_t,const int *,const void *,size_t);
static int ec_verify(const br_ec_impl *e,const void *h,size_t n,const int *k,const void *d,size_t l) { (void)e;(void)h;(void)n;(void)k;(void)d;(void)l;crypto_calls++;return crypto_pass; }
static const br_ec_impl *br_ec_get_default(void) { static int e;return &e; }
static br_ecdsa_vrfy br_ecdsa_vrfy_asn1_get_default(void) { return ec_verify; }
typedef struct hash br_hash_class;
struct hash { void (*init)(const br_hash_class **);void (*update)(const br_hash_class **,const void *,size_t);void (*out)(const br_hash_class **,void *); };
typedef struct { const br_hash_class *vtable; } br_hash_compat_context;
static void init(const br_hash_class **c) { (void)c; }
static void update(const br_hash_class **c,const void *p,size_t n) { (void)c;(void)p;(void)n; }
static void out(const br_hash_class **c,void *p) { (void)c;memset(p,0,32); }
static const br_hash_class br_sha256_vtable={init,update,out};
static int verify_rsa_digest(int *k,const unsigned char *oid,unsigned char *h,size_t n,unsigned char *d,size_t l) { (void)k;(void)oid;(void)h;(void)n;(void)d;(void)l;crypto_calls++;return crypto_pass; }
'''
        cases=r'''
int main(void) {
 br_x509_pkey key={0};
 for(int ec=0;ec<=1;ec++) for(scenario=0;scenario<7;scenario++) for(crypto_pass=0;crypto_pass<=1;crypto_pass++) {
  crypto_calls=0; assert(live==0);
  unsigned char *p=ec ? verify_ec(&key,"file","sig") : verify_rsa(&key,"file","sig");
  assert((p!=NULL)==(scenario==0 && crypto_pass));
  assert(crypto_calls==(scenario==0));
  free(p); assert(live==0);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c=Path(tmp)/'test.c';c.write_text(harness+'\n'.join(bodies)+cases)
            binary=Path(tmp)/'test'
            subprocess.run(['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,cwd=tmp)
if __name__=='__main__':unittest.main()
