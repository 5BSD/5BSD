# SPDX-License-Identifier: BSD-2-Clause
"""Provider lifecycle/control-flow tests with injected kernel operations.

Executes actual provider methods and constructor, not a live GEOM graph.
Injected open-time event processing checks constructor lifetime ordering.
This does not claim live kernel race qualification.
"""
from pathlib import Path
import subprocess
import resource
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <geom/verity/g_verity_io.h>
struct g_class { int dummy; };
struct g_geom { void *softc; struct g_class *class; };
struct g_provider { struct g_geom *geom; int acr, acw, ace; };
struct g_consumer { struct g_geom *geom; };
struct bio { int bio_cmd, bio_flags; off_t bio_offset, bio_length, bio_completed;
 void *bio_data; struct g_provider *bio_to; struct bio *next; };
struct bio_queue_head { struct bio *head, *tail; };
struct mtx { int locked; };
#define BIO_READ 1
#define BIO_WRITE 2
#define BIO_DELETE 3
#define BIO_GETATTR 4
#define BIO_UNMAPPED 1
#define BIO_VLIST 2
#define M_VERITY 0
#define M_WAITOK 0
#define PRIBIO 0
#define EV_CANCEL 1
#define KASSERT(test,msg) assert(test)
#define g_topology_assert() assert(!in_worker)
#define free(ptr,type) free(ptr)
static unsigned maxphys=131072;
static int in_worker, delivered, verified, withered, closed, verify_error;
static int errors[8];
static jmp_buf exited;
static void (*event_fn)(void *, int);
static void *event_arg;
static void mtx_lock(struct mtx *m) { assert(!m->locked);m->locked=1; }
static void mtx_unlock(struct mtx *m) { assert(m->locked);m->locked=0; }
static void mtx_destroy(struct mtx *m) { assert(!m->locked); }
static void msleep(void *a,struct mtx *m,int p,const char *w,int t) {
 (void)a;(void)m;(void)p;(void)w;(void)t;assert(!"unexpected wait");
}
static void wakeup(void *p) { (void)p; }
static void wakeup_one(void *p) { (void)p; }
static struct bio *bioq_takefirst(struct bio_queue_head *q) {
 struct bio *b=q->head;if(b) { q->head=b->next;if(!q->head) q->tail=NULL; }return b;
}
static void bioq_insert_tail(struct bio_queue_head *q,struct bio *b) {
 b->next=NULL;if(q->tail) q->tail->next=b;else q->head=b;q->tail=b;
}
static void g_io_deliver(struct bio *,int);
static void g_wither_geom_close(struct g_geom *,int);
static void g_wither_provider(struct g_provider *p,int e) {
 assert(p && e==ENXIO);withered++;
}
static void g_post_event(void (*fn)(void *,int),void *arg,int f,void *end) {
 (void)f;assert(end==NULL && event_fn==NULL);event_fn=fn;event_arg=arg;
}
static void kproc_exit(int e) { assert(e==0);longjmp(exited,1); }
'''
POST = r'''
int g_verity_window_init(struct g_verity_read_window *w,
 struct g_verity_backing *b,uint64_t o,size_t l,void *buf,size_t cap) {
 (void)w;(void)b;(void)o;(void)l;(void)buf;(void)cap;return 0;
}
int g_verity_window_read(void *a,int t,uint64_t o,void *b,size_t l) {
 (void)a;(void)t;(void)o;(void)b;(void)l;assert(!"unused injected callback");return EIO;
}
static struct verity_softc *active;
int g_verity_cached_read_range(struct g_verity_cache *c,uint64_t off,size_t len,
 g_verity_read_t *reader,void *arg,void *data,void *hashes,void *out) {
 (void)c;(void)off;(void)reader;(void)arg;(void)data;(void)hashes;
 assert(in_worker && !active->lock.locked);verified++;
 memset(out,0x61,len);
 /* Inject shutdown during an in-flight verification, after queue unlock. */
 active->stopping=true;
 return verify_error;
}
static void g_io_deliver(struct bio *b,int e) {
 assert(!active->lock.locked);assert(delivered<8);errors[delivered++]=e;
 if(e) assert(b->bio_completed==0);
}
static void g_wither_geom_close(struct g_geom *g,int e) {
 assert(g && e==ENXIO);closed++;
}
static struct verity_softc *setup(struct g_geom *g,struct g_provider *p) {
 struct verity_softc *s=calloc(1,sizeof(*s));assert(s);
 s->geom=g;s->provider=p;s->allocated=1;s->running=2;
 s->backing.data_bytes=8192;s->window_size=4096;
 s->workers=calloc(1,sizeof(*s->workers));assert(s->workers);
 s->workers[0].sc=s;s->workers[0].allocation=malloc(4096);
 assert(s->workers[0].allocation);
 g->softc=s;g->class=&g_verity_class;p->geom=g;
 active=s;delivered=verified=withered=closed=0;event_fn=NULL;event_arg=NULL;
 verity_constructor_done(s);assert(s->running==1 && !event_fn);
 return s;
}
static void run_worker(struct verity_softc *s) {
 in_worker=1;if(setjmp(exited)==0) verity_worker(&s->workers[0]);in_worker=0;
 assert(s->running==0 && !s->lock.locked && event_fn==verity_drained);
}
static void drain_event(void) {
 assert(event_fn);void (*fn)(void *,int)=event_fn;event_fn=NULL;fn(event_arg,0);
}
int main(void) {
 /* Test both provider disappearance orderings and success/error in-flight. */
 for(int early=0;early<2;early++) for(int fault=0;fault<2;fault++) {
  struct g_geom g={0};struct g_provider p={0};
  struct verity_softc *s=setup(&g,&p);
  char first[512],second[512];memset(first,0x51,sizeof(first));memset(second,0x51,sizeof(second));
  struct bio a={.bio_cmd=BIO_READ,.bio_length=512,.bio_data=first,.bio_to=&p};
  struct bio b={.bio_cmd=BIO_READ,.bio_offset=512,.bio_length=512,.bio_data=second,.bio_to=&p};
  verity_start(&a);verity_start(&b);assert(!delivered && s->queue.head==&a);
  verify_error=fault?EAUTH:0;run_worker(s);
  assert(verified==1 && delivered==2 && errors[0]==verify_error && errors[1]==ENXIO);
  assert(a.bio_completed==(fault?0:512) && b.bio_completed==0);
  for(unsigned i=0;i<512;i++) { assert(first[i]==(fault?0:0x61));assert(second[i]==0); }
  if(early) { verity_providergone(&p);assert(g.softc==s); }
  drain_event();assert(closed==1);
  if(!early) { assert(g.softc==s);verity_providergone(&p); }
  assert(g.softc==NULL);
 }
 /* Larger upstream reads do not require larger private worker buffers. */
 {
  struct g_geom lg={0};struct g_provider lp={0};static char large[262144];
  struct verity_softc *ls=setup(&lg,&lp);ls->backing.data_bytes=sizeof(large);
  assert(sizeof(large)>maxphys);
  struct bio big={.bio_cmd=BIO_READ,.bio_length=sizeof(large),.bio_data=large,.bio_to=&lp};
  verify_error=0;verity_start(&big);
  assert(!delivered && ls->queue.head==&big);
  run_worker(ls);
  assert(delivered==1 && errors[0]==0 && big.bio_completed==sizeof(large));
  for(unsigned i=0;i<sizeof(large);i++) assert(large[i]==0x61);
  drain_event();verity_providergone(&lp);assert(!lg.softc);
 }
 /* Control admission and explicit destroy refusal while a reader holds it. */
 struct g_geom g={0};struct g_provider p={0};struct verity_softc *s=setup(&g,&p);
 char out[512];struct bio b={.bio_cmd=BIO_WRITE,.bio_length=512,.bio_data=out,.bio_to=&p};
 verity_start(&b);assert(errors[0]==EROFS && !s->queue.head);
 b.bio_cmd=BIO_DELETE;verity_start(&b);assert(errors[1]==EROFS);
 b.bio_cmd=BIO_GETATTR;verity_start(&b);assert(errors[2]==EOPNOTSUPP);
 b.bio_cmd=BIO_READ;b.bio_offset=-1;verity_start(&b);assert(errors[3]==EINVAL);
 b.bio_offset=8192;verity_start(&b);assert(errors[4]==EINVAL);
 b.bio_offset=0;b.bio_flags=BIO_UNMAPPED;verity_start(&b);assert(errors[5]==EINVAL);
 assert(verity_access(&p,0,1,0)==EROFS);
 p.acr=1;assert(g_verity_provider_destroy(&g)==EBUSY && !s->stopping);p.acr=0;
 assert(g_verity_provider_destroy(&g)==0 && s->stopping && withered==1);
 assert(verity_access(&p,1,0,0)==ENXIO && verity_access(&p,-1,0,0)==0);
 assert(g_verity_provider_destroy(&g)==0 && withered==1);
 run_worker(s);drain_event();verity_providergone(&p);assert(!g.softc);
 /* Both backing removal and resize use the same terminal transition. */
 for(int resize=0;resize<2;resize++) {
  struct g_geom g2={0};struct g_provider p2={0};struct g_consumer cp={.geom=&g2};
  s=setup(&g2,&p2);if(resize) verity_resize(&cp);else verity_orphan(&cp);
  assert(s->stopping && withered==1);run_worker(s);drain_event();verity_providergone(&p2);
 }
 return 0;
}
'''

CONSTRUCTOR_PRE = r'''
#define MAXCPU 64
#define M_ZERO 2
#define MTX_DEF 0
static int constructor_mode, fail_attach, fail_access, fail_bind, orphan_open;
static int fail_thread, thread_calls, spawned, published, duplicate_name;
static int allocations;
static void *owned[128], *worker_args[64];
static struct g_geom constructed_geom;
static struct g_consumer constructed_consumer;
static struct g_provider constructed_provider;
static void verity_orphan(struct g_consumer *);
static void drain_event(void);
static void *kernel_alloc(size_t n) {
 void *p=calloc(1,n);assert(p);
 for(unsigned i=0;i<128;i++) if(!owned[i]) {owned[i]=p;allocations++;return p;}
 assert(!"allocation registry full");return NULL;
}
static void kernel_free(void *p) {
 for(unsigned i=0;i<128;i++) if(p && owned[i]==p) {owned[i]=NULL;allocations--;break;}
 free(p);
}
static void mtx_init(struct mtx *m,const char *s,void *p,int flags) {
 (void)s;(void)p;(void)flags;m->locked=0;
}
static void bioq_init(struct bio_queue_head *q) { memset(q,0,sizeof(*q)); }
static struct g_provider *g_provider_by_name(const char *n) {
 (void)n;return duplicate_name?&constructed_provider:NULL;
}
static struct g_geom *g_new_geomf(struct g_class *c,const char *fmt,const char *n) {
 (void)fmt;(void)n;memset(&constructed_geom,0,sizeof(constructed_geom));
 constructed_geom.class=c;return &constructed_geom;
}
static struct g_consumer *g_new_consumer(struct g_geom *g) {
 memset(&constructed_consumer,0,sizeof(constructed_consumer));
 constructed_consumer.geom=g;return &constructed_consumer;
}
static int g_attach(struct g_consumer *c,struct g_provider *p) {
 if(fail_attach) return ENXIO;
 c->provider=p;return 0;
}
static int g_access(struct g_consumer *c,int r,int w,int e) {
 if(fail_access) return EBUSY;
 c->acr+=r;c->acw+=w;c->ace+=e;
 if(orphan_open) {
  verity_orphan(c);
  /* Model event processing while the backing open has dropped topology. */
  if(event_fn) drain_event();
  assert(c->geom->softc != NULL);
  assert(!event_fn);
 }
 return 0;
}
static int kproc_create(void (*fn)(void *),void *arg,void *p,int f,int pages,
 const char *fmt,unsigned i) {
 (void)fn;(void)p;(void)f;(void)pages;(void)fmt;(void)i;
 thread_calls++;if(thread_calls==fail_thread) return EAGAIN;
 worker_args[spawned++]=arg;return 0;
}
static struct g_provider *g_new_providerf(struct g_geom *g,const char *fmt,const char *n) {
 (void)fmt;(void)n;published++;memset(&constructed_provider,0,sizeof(constructed_provider));
 constructed_provider.geom=g;return &constructed_provider;
}
static void g_error_provider(struct g_provider *p,int e) {assert(p && e==0);}
#define malloc(n,type,flags) kernel_alloc(n)
#define mallocarray(n,size,type,flags) kernel_alloc((n)*(size))
#define free(p,type) kernel_free(p)
'''
CONSTRUCTOR_POST = r'''
int g_verity_cache_init(struct g_verity_cache *c,const struct g_verity_root *r,
 uint64_t *tags,void *blocks,size_t entries) {
 if(r->layout.block_size!=4096) return EINVAL;
 memset(c,0,sizeof(*c));c->root=*r;c->tags=tags;c->blocks=blocks;c->entries=entries;
 return 0;
}
int g_verity_backing_bind(struct g_verity_backing *b,struct g_consumer *c,
 uint64_t bytes,uint32_t block) {
 assert(c->acr==1 && c->ace==1 && c->acw==0);
 if(fail_bind) return EINVAL;
 b->consumer=c;b->data_bytes=bytes;b->block_size=block;return 0;
}
static void reset_constructor(void) {
 assert(allocations==0);
 constructor_mode=1;fail_attach=fail_access=fail_bind=orphan_open=0;
 fail_thread=thread_calls=spawned=published=duplicate_name=0;
 event_fn=NULL;event_arg=NULL;closed=withered=0;
 memset(&constructed_consumer,0,sizeof(constructed_consumer));
 memset(&constructed_geom,0,sizeof(constructed_geom));
}
static void finish_constructor(void) {
 /* Scheduling after construction returns tests bookkeeping, not races. */
 for(int i=0;i<spawned;i++) {
  in_worker=1;
  if(setjmp(exited)==0) verity_worker(worker_args[i]);
  in_worker=0;
 }
 assert(event_fn==verity_drained);
 drain_event();
 assert(closed==1 && allocations==0 && !constructed_geom.softc);
 assert(!constructed_consumer.acr && !constructed_consumer.ace);
}
int main(void) {
 assert(lifecycle_main()==0);
 struct g_provider backing={.sectorsize=512}, sentinel={0},*out;
 struct g_verity_root root={.layout={.block_size=4096,.data_bytes=8192}};
 /* Preflight exact allocation boundary and reject impossible requests. */
 reset_constructor();size_t per_worker=0;
 assert(g_verity_provider_resources(&root,3,8,4096,1024*1024,&per_worker)==0);
 size_t exact=sizeof(struct verity_softc)+3*(per_worker+sizeof(struct verity_worker));
 assert(g_verity_provider_resources(&root,3,8,4096,exact,&per_worker)==0);
 size_t saved_size=per_worker;
 assert(g_verity_provider_resources(&root,3,8,4096,exact-1,&per_worker)==ENOMEM);
 assert(per_worker==saved_size && !allocations && !published);
 assert(g_verity_provider_resources(&root,MAXCPU+1,8,4096,SIZE_MAX,&per_worker)==EINVAL);
 assert(g_verity_provider_resources(&root,1,UINT64_MAX,4096,SIZE_MAX,&per_worker)!=0);
 assert(g_verity_provider_resources(&root,1,0,4095,SIZE_MAX,&per_worker)==EINVAL);
 assert(g_verity_provider_resources(&root,1,0,4097,SIZE_MAX,&per_worker)==EINVAL);
 assert(g_verity_provider_resources(&root,1,0,maxphys+4096,SIZE_MAX,&per_worker)==EINVAL);
 assert(g_verity_provider_resources(NULL,1,0,4096,SIZE_MAX,&per_worker)==EINVAL);
 assert(g_verity_provider_resources(&root,1,0,4096,SIZE_MAX,NULL)==EINVAL);
 assert(per_worker==saved_size && !allocations && !published);
 /* Fail attach, open, binding, open-time orphan, and each thread start. */
 for(int failure=0;failure<7;failure++) {
  reset_constructor();out=&sentinel;
  if(failure==0) fail_attach=1;
  if(failure==1) fail_access=1;
  if(failure==2) fail_bind=1;
  if(failure==3) orphan_open=1;
  if(failure>=4) fail_thread=failure-3;
  int e=g_verity_provider_create(&backing,"test",&root,3,8,4096,1024*1024,&out);
  assert(e==(failure==1?EBUSY:failure==2?EINVAL:failure>=4?EAGAIN:ENXIO));
  assert(out==&sentinel && !published);
  if(orphan_open) assert(thread_calls==0);
  if(spawned) assert(!event_fn && constructed_consumer.acr==1);
  finish_constructor();
 }
 for(int invalid=0;invalid<5;invalid++) {
  reset_constructor();out=&sentinel;
  duplicate_name=invalid==4;
  int e=g_verity_provider_create(&backing,"test",&root,invalid==0?0:3,
      invalid==1?SIZE_MAX:8,invalid==2?4095:4096,invalid==3?1:1024*1024,&out);
  assert(e==(invalid==3?ENOMEM:invalid==4?EEXIST:EINVAL));
  assert(out==&sentinel && !allocations && !event_fn && !thread_calls && !published);
 }
 reset_constructor();out=&sentinel;
 assert(g_verity_provider_create(&backing,"test",&root,3,8,4096,1024*1024,&out)==0);
 assert(out==&constructed_provider && published==1 && spawned==3);
 assert(out->mediasize==8192 && out->sectorsize==512);
 struct g_verity_root observed,unchanged;
 memset(&unchanged,0xa7,sizeof(unchanged));observed=unchanged;
 assert(g_verity_provider_root(NULL,&observed)==EINVAL);
 assert(!memcmp(&observed,&unchanged,sizeof(observed)));
 assert(g_verity_provider_root(out,NULL)==EINVAL);
 struct g_class other_class={0};
 struct g_geom other_geom={.class=&other_class,.softc=constructed_geom.softc};
 struct g_provider alias={.geom=&other_geom};
 assert(g_verity_provider_root(&alias,&observed)==EINVAL);
 alias.geom=&constructed_geom;
 assert(g_verity_provider_root(&alias,&observed)==ENXIO);
 assert(!memcmp(&observed,&unchanged,sizeof(observed)));
 assert(g_verity_provider_root(out,&observed)==0);
 assert(!memcmp(&observed,&root,sizeof(root)));
 /* Caller mutations cannot alter the provider identity returned later. */
 observed.root_hash[0]^=1;
 assert(g_verity_provider_root(out,&observed)==0);
 assert(!memcmp(&observed,&root,sizeof(root)));
 assert(g_verity_provider_destroy(&constructed_geom)==0);
 observed=unchanged;
 assert(g_verity_provider_root(out,&observed)==ENXIO);
 assert(!memcmp(&observed,&unchanged,sizeof(observed)));
 finish_constructor();
 return 0;
}
'''

class Provider(unittest.TestCase):
    def test_constructor_failures_and_cleanup(self):
        source=(ROOT/'sys/geom/verity/g_verity_provider.c').read_text()
        start=source.index('struct verity_softc;')
        end=source.index('\nstatic struct g_class g_verity_class =')
        pre=PRE.replace('struct g_provider { struct g_geom *geom; int acr, acw, ace; };',
            'struct g_provider { struct g_geom *geom; int acr, acw, ace; off_t mediasize; unsigned sectorsize; };')
        pre=pre.replace('struct g_consumer { struct g_geom *geom; };',
            'struct g_consumer { struct g_geom *geom; struct g_provider *provider; int acr, acw, ace; };')
        pre=pre.replace('#define free(ptr,type) free(ptr)', '')
        post=POST.replace('int main(void)', 'static int lifecycle_main(void)')
        old='assert(g && e==ENXIO);closed++;'
        new=old+'''
 if(constructor_mode) {
  constructed_consumer.acr=constructed_consumer.ace=0;
  if(g->softc) {
   struct verity_softc *sc=g->softc;
   assert(sc->drained && !sc->running);
   verity_providergone(&constructed_provider);
  }
 }
'''
        assert old in post
        post=post.replace(old,new)
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'constructor.c';binary=Path(directory)/'constructor'
            c.write_text(pre+CONSTRUCTOR_PRE+source[start:end]+
                         '\n#undef malloc\n#undef free\n'+post+CONSTRUCTOR_POST)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                            str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)
            # The open-time orphan regression must detect removal of the guard.
            guard = '\tif (sc->stopping) {\n\t\terror = ENXIO;\n\t\tgoto fail;\n\t}\n'
            assert source[start:end].count(guard) == 1
            c.write_text(pre+CONSTRUCTOR_PRE+source[start:end].replace(guard, '')+
                         '\n#undef malloc\n#undef free\n'+post+CONSTRUCTOR_POST)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                            str(c),'-o',str(binary)],check=True)
            def no_core():
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            rejected = subprocess.run([str(binary)], capture_output=True, text=True,
                                      preexec_fn=no_core)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('e==(failure==1?', rejected.stderr)
            # Removing only the constructor reference must expose cleanup while
            # the backing open still owns the constructor's local pointers.
            body = source[start:end]
            constructor = body.index('int\ng_verity_provider_create(')
            mutated = body[:constructor] + body[constructor:].replace(
                'sc->running = 1;', 'sc->running = 0;').replace(
                '\tverity_constructor_done(sc);\n', '')
            c.write_text(pre+CONSTRUCTOR_PRE+mutated+
                         '\n#undef malloc\n#undef free\n'+post+CONSTRUCTOR_POST)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                            str(c),'-o',str(binary)],check=True)
            rejected = subprocess.run([str(binary)], capture_output=True, text=True,
                                      preexec_fn=no_core)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('c->geom->softc != NULL', rejected.stderr)


    def test_lifecycle_and_read_admission(self):
        source=(ROOT/'sys/geom/verity/g_verity_provider.c').read_text()
        start=source.index('struct verity_softc;')
        end=source.index('\nint\ng_verity_provider_resources(')
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'provider.c';binary=Path(directory)/'provider'
            c.write_text(PRE+source[start:end]+POST)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),
                            str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

if __name__=='__main__': unittest.main()
