#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/bhyve/migration_session.c').read_text()
parts=[]
for signature in ('static bool\nmigration_max_rounds_valid(', 'static int\nprod_local_hello(', 'static nvlist_t *\nvm_do_migrate(', 'static const unsigned migration_repair_delay_ms[]', 'static nvlist_t *\nvm_do_migrate_repair('):
 a=s.index(signature); b=s.index('\n}',a)+2; parts.append(s[a:b])
fixture=r'''
#define BHYVE_SNAPSHOT 1
#include <assert.h>
#include <err.h>
#include <sys/capsicum.h>
#include <sys/wait.h>
#include <sys/nv.h>
#include "migration_credentials_nv.h"
#include "migration_source_storage.h"
#include "migration_fresh_preflight.h"
struct vmctx { int unused; };
#include <sys/param.h>
#include <time.h>
struct migration_prod_source {
 struct vmctx *ctx; int recovery_dirfd; bool retirement_started, quiesced;
 bool retired, intent_pending;
 struct migration_recovery_record recovery;
};
static struct migration_prod_source migration_ipc_source;
static struct migration_source_storage migration_source_storage;
struct migration_channel { bool secure; };
static int mode, connects, runs, cleanups, quarantines, wedges, unwedges;
static int resume_calls, resume_failures;
static bool wedged;
static void ipc_quarantine_vm(void) { quarantines++; wedged = false; }
static void ipc_wedge_vm(void) { assert(quarantines == 0); wedges++; wedged = true; }
static int ipc_unwedge_vm(void) { if (!wedged) return EPERM; unwedges++; wedged = false; return 0; }
static bool retiring_cpus;
static bool fbsdrun_cpus_retiring(void) { return retiring_cpus; }
/* The idempotent production rollback is tested separately; model its result. */
static int prod_resume(void *arg) {
 struct migration_prod_source *src = arg; resume_calls++;
 if (src->retirement_started) return ECANCELED;
 if (resume_failures > 0) { resume_failures--; return EIO; }
 src->quiesced = false; return 0;
}
static __attribute__((unused)) const char *get_config_value(const char *key) {
 assert(strcmp(key,"gdb.port")==0); return mode==7?"1234":NULL;
}
static bool hypertrace_initialized(void) { return true; }
int migration_prod_fill_hello(struct vmctx *ctx, struct migration_hello *hello) {
 (void)ctx; memset(hello,0,sizeof(*hello)); hello->capability_flags=MIGRATION_CAP_PRECOPY; return 0;
}
static int migration_channel_init(struct migration_channel *channel,
 struct migration_transport *xp, int fd, bool server,
 const struct migration_tls_credentials *credentials, int timeout) {
 (void)xp; assert(fd>=0 && !server && credentials && timeout==30000);
 connects++; channel->secure=true; return mode==3?EACCES:0;
}
/* The fixture always supplies credentials; plaintext is never requested. */
static int migration_channel_policy(int fd, bool credentials, bool plaintext) {
 (void)fd; assert(credentials && !plaintext); return 0;
}
static int migration_channel_binding(struct migration_channel *channel, bool source,
 uint8_t src[32],uint8_t dst[32]) {
 assert(channel->secure && source); memset(src,3,32); memset(dst,4,32);
 return mode==4?EIO:0;
}
static void migration_channel_cleanup(struct migration_channel *channel) { (void)channel; cleanups++; }
#ifdef BHYVE_GDB
/* Debug-server ownership: mode 7 models an attached debugger. */
static int fences, unfences;
static bool fenced;
static int gdb_migration_fence(const char **reason) {
 assert(!fenced && connects == 1);
 if (mode == 7) { *reason = "a GDB client is attached"; return EBUSY; }
 *reason = NULL; fences++; fenced = true; return 0;
}
static void gdb_migration_unfence(void) { if (fenced) unfences++; fenced = false; }
#define GDB_REFUSES 1
#else
#define GDB_REFUSES 0
#endif
'''+parts[0]+'\n'+parts[1]+'\n'+parts[3]+r'''
static const struct migration_source_ops migration_prod_source_ops={.so_local_hello=prod_local_hello};
int migration_source_run(const struct migration_transport *xp,
 const struct migration_source_ops *ops, void *arg,
 const struct migration_session_config *config,struct migration_source_result *result) {
 (void)xp; assert(config->max_rounds==8); runs++;
 struct migration_hello hello;
 assert(ops->so_local_hello(arg,&hello)==0);
 assert(hello.capability_flags&MIGRATION_CAP_HYPERTRACE_FRESH);
 struct migration_prod_source *src=arg;
 src->retirement_started=mode==6;
 src->quiesced=mode==6||mode==8||mode==9;
 /* Mode 8: every repair attempt fails; mode 9: the second succeeds. */
 resume_failures=mode==8?100:mode==9?1:0;
 result->phase=MIGRATION_PHASE_FAILED; result->reason=MIGRATION_REASON_STATE;
 result->source_runnable=mode!=6 && mode!=8 && mode!=9;
 return EIO;
}
'''+parts[2]+'\n'+parts[4]+r'''
int main(void) {
 char canonical[]="root.XXXXXX",other[]="other.XXXXXX";
 assert(mkdtemp(canonical) && mkdtemp(other));
 int rootfd=open(canonical,O_RDONLY|O_DIRECTORY), otherfd=open(other,O_RDONLY|O_DIRECTORY);
 FILE *pem=tmpfile(); assert(rootfd>=0 && otherfd>=0 && pem);
 for (mode=0;mode<10;mode++) {
  nvlist_t *request=nvlist_create(0); assert(request);
  nvlist_add_descriptor(request,"fd",fileno(pem));
  nvlist_add_descriptor(request,"recovery_fddir",mode==2?otherfd:rootfd);
  if (mode!=0) {
   nvlist_add_descriptor(request,"tls_certificate_fd",fileno(pem));
   nvlist_add_descriptor(request,"tls_private_key_fd",fileno(pem));
   nvlist_add_descriptor(request,"tls_trust_fd",fileno(pem));
   nvlist_add_string(request,"tls_peer_sha256","0404040404040404040404040404040404040404040404040404040404040404");
  }
  pid_t child=fork(); assert(child>=0);
  if (child==0) {
   migration_source_storage=(struct migration_source_storage){.directory=dup(rootfd),.prepared=true,.error=mode==1?ENOENT:0};
   assert(migration_source_storage.directory>=0);
   assert(cap_enter()==0);
   struct vmctx ctx={0}; nvlist_t *reply=vm_do_migrate(&ctx,request);
   assert(nvlist_exists_string(reply,"error"));
   assert(nvlist_get_bool(reply,"source_runnable")== (mode!=6 && mode!=8));
   /* Automatic repair runs only for a wedged source whose retirement never
    * began: none after INTENT (mode 6), bounded failure (8), success (9). */
   assert(nvlist_exists_bool(reply,"repaired")==(mode==8||mode==9));
   if (mode==8) assert(!nvlist_get_bool(reply,"repaired") &&
    nvlist_get_number(reply,"repair_attempts")==3 && resume_calls==3);
   if (mode==9) assert(nvlist_get_bool(reply,"repaired") &&
    nvlist_get_number(reply,"repair_attempts")==2 && resume_calls==2);
   if (mode==6) assert(resume_calls==0);
   assert(wedges==(mode==8?1:0));
   /* Without a debug server build a configured port refuses before any
    * transport; with one, the debugger fence refuses after transport setup
    * but before migration (and quiesce) runs. */
   assert(connects==(mode>=2 && (mode!=7 || GDB_REFUSES)?1:0));
   assert(runs==(mode>=5 && mode!=7?1:0));
   assert(cleanups==((mode==2||(mode>=4 && (mode!=7 || GDB_REFUSES)))?1:0));
#ifdef BHYVE_GDB
   assert(fences==(mode>=5 && mode!=7?1:0));
   assert(unfences==(mode==5||mode==9?1:0));
   assert(fenced==(mode==6||mode==8));
   if (mode==7) assert(strstr(nvlist_get_string(reply,"error"),"GDB client is attached")!=NULL);
#endif
   assert(quarantines==(mode==6?1:0));
   if (mode==6 || mode==8) {
    struct vmctx *retained=migration_ipc_source.ctx;
    nvlist_t *again=vm_do_migrate(&ctx,request);
    assert(!nvlist_get_bool(again,"source_runnable"));
    assert(connects==1 && runs==1 && cleanups==1);
    assert(migration_ipc_source.ctx==retained && quarantines==(mode==6?1:0));
    assert(migration_ipc_source.quiesced);
    nvlist_destroy(again);
    /* Operator repair: refused after retirement began (no resume at all);
     * a wedged source is repaired once its resume succeeds. */
    int before=resume_calls;
    if (mode==8) resume_failures=0;
    nvlist_t *repair=vm_do_migrate_repair(NULL,NULL);
    assert(nvlist_get_bool(repair,"repaired")==(mode==8));
    assert(nvlist_get_bool(repair,"source_runnable")==(mode==8));
    if (mode==6) assert(nvlist_get_number(repair,"error_code")==EPERM && resume_calls==before);
    else assert(resume_calls==before+1 && unwedges==1 && !wedged);
#ifdef BHYVE_GDB
    assert(fenced==(mode==6));
#endif
    nvlist_destroy(repair);
    repair=vm_do_migrate_repair(NULL,NULL);
    assert(!nvlist_get_bool(repair,"repaired"));
    assert(nvlist_get_number(repair,"error_code")==(mode==6?EPERM:EALREADY));
    nvlist_destroy(repair);
   }
   nvlist_destroy(reply); nvlist_destroy(request); _exit(0);
  }
  int status; assert(waitpid(child,&status,0)==child);
  assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
  nvlist_destroy(request);
 }
 close(rootfd); close(otherfd); fclose(pem);
 return 0;
}
'''
(out/'admission.c').write_text(fixture)
for variant, defines in (('admission', []), ('admission-gdb', ['-DBHYVE_GDB'])):
 subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined']+defines+['-I'+str(root/'sys'),'-I'+str(root/'usr.sbin/bhyve'),str(out/'admission.c'),'-lnv','-lmd','-o',str(out/variant)],check=True)
 subprocess.run([str(out/variant)],cwd=out,check=True,timeout=30)
print('PASS: full source IPC under actual Capsicum enforces TLS, pinned journal, binding, debugger fence and persistent retirement quarantine; VM/TLS boundaries mocked')
