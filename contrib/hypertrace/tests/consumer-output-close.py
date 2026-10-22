#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test terminal output and close against a rebuilt libdtrace, in NODEV mode."""
from pathlib import Path
import subprocess,sys,os,shlex,json
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve();lib=Path(sys.argv[2]).resolve()
if not out.is_relative_to('/usr/obj') or not lib.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
fixture=r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dt_impl.h>
#include <dt_oformat.h>
struct discard_arg { dtrace_hdl_t *handle; FILE *output; };
static void *discard_thread(void *arg) {
 struct discard_arg *a=arg;
 assert(dtrace_output_discard(a->handle,a->output)==0);
 return NULL;
}
int main(void) {
 for(int discard=0;discard<2;discard++) {
  int error=0;
  dtrace_hdl_t *dtp=dtrace_open(DTRACE_VERSION,DTRACE_O_NODEV,&error);
  if(!dtp){fprintf(stderr,"NODEV open failed: %s\n",dtrace_errmsg(NULL,error));return 1;}
  FILE *caller=tmpfile(),*redirect=tmpfile();assert(caller && redirect);
  assert(setvbuf(caller,NULL,_IOFBF,4096)==0 && setvbuf(redirect,NULL,_IOFBF,4096)==0);
  int retained=dup(fileno(redirect));assert(retained>=0);
  dtp->dt_freopen_fp=redirect;
  assert(dt_printf(dtp,caller,"old redirected output")>=0);
  xo_set_style(NULL,XO_STYLE_JSON);xo_set_file(caller);
  xo_clear_flags(NULL,XOF_FLUSH|XOF_FLUSH_LINE);
  xo_open_container("dtrace");xo_emit("{:value/%s}","old formatter output");
  if(discard) {
   pthread_t thread;struct discard_arg arg={dtp,caller};
   assert(pthread_create(&thread,NULL,discard_thread,&arg)==0);
   assert(pthread_join(thread,NULL)==0);
   assert(dtp->dt_output_discarded);
   assert(dt_printf(dtp,caller,"late output")==-1 && dtrace_errno(dtp)==ESHUTDOWN);
   assert(dtrace_work_consumer(dtp,caller,NULL,NULL)==DTRACE_WORKSTATUS_ERROR);
   assert(dtrace_errno(dtp)==ESHUTDOWN);
   for(int retry=0;retry<2;retry++) {
    assert(dtrace_sprintf(dtp,caller,NULL,NULL,0,NULL,0)==-1);
    assert(dtrace_system(dtp,caller,NULL,NULL,NULL,0,NULL,0)==-1);
    assert(dtrace_freopen(dtp,caller,NULL,NULL,NULL,0,NULL,0)==-1);
    assert(dtrace_errno(dtp)==ESHUTDOWN);
   }
  }
  dtrace_close(dtp);
  assert(fflush(caller)==0);
  struct stat a,b;assert(fstat(fileno(caller),&a)==0 && fstat(retained,&b)==0);
  if(discard) assert(a.st_size==0 && b.st_size==0);
  else assert(a.st_size>0 && b.st_size>0);
  assert(close(retained)==0 && fclose(caller)==0);
  xo_destroy(NULL);
 }
 return 0;
}
'''
(out/'close.c').write_text(fixture)
env=dict(os.environ,MAKEOBJDIR=str(lib))
flags=shlex.split(subprocess.check_output(['make','-V','CFLAGS'],cwd=root/'cddl/lib/libdtrace',env=env,text=True))
cmd=['cc']+flags+['-UNDEBUG','-fsanitize=address,undefined','-pthread',str(out/'close.c'),'-L'+str(lib),'-Wl,-rpath,'+str(lib),'-ldtrace','-lxo','-o',str(out/'close')]
(out/'command.json').write_text(json.dumps(cmd,indent=2))
subprocess.run(cmd,check=True)
runtime=dict(os.environ)
if len(sys.argv)>3:
 runtime['LD_LIBRARY_PATH']=':'.join([str(lib)]+[str(Path(x).resolve()) for x in sys.argv[3:]])
 (out/'runtime-libraries.json').write_text(json.dumps(runtime['LD_LIBRARY_PATH']))
subprocess.run([str(out/'close')],env=runtime,check=True,timeout=60)
print('PASS: rebuilt libdtrace NODEV, redirected output, cross-thread formatter close, terminal write/work refusal, and ordinary close flushing')
