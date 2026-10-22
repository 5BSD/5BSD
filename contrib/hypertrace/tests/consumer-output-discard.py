#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the actual libdtrace discard function against libxo, without tracing."""
from pathlib import Path
import subprocess,sys,json
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'cddl/contrib/opensolaris/lib/libdtrace/common/dt_subr.c').read_text()
a=s.index('static xo_ssize_t\ndt_oformat_discard_write(')
b=s.index('void\ndtrace_oformat_teardown(',a)
fixture=r'''
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libxo/xo.h>
typedef struct {
 int dt_output_discarded,dt_errno;
 FILE *dt_freopen_fp;
 char *dt_buffered_buf;
 size_t dt_buffered_offs,dt_buffered_size;
} dtrace_hdl_t;
static int dt_set_errno(dtrace_hdl_t *dtp,int error) { dtp->dt_errno=error;return -1; }
static void dt_buffered_destroy(dtrace_hdl_t *dtp) {
 free(dtp->dt_buffered_buf);dtp->dt_buffered_buf=NULL;
 dtp->dt_buffered_offs=dtp->dt_buffered_size=0;
}
static FILE *fail_purge;
static int test_fpurge(FILE *fp) {
 if(fp==fail_purge){errno=EIO;return -1;}
 return fpurge(fp);
}
#define fpurge test_fpurge
'''+s[a:b]+r'''
#undef fpurge
static unsigned writes,flushes,closes;
static xo_ssize_t output(void *opaque,const char *data) {
 writes++; return fprintf((FILE *)opaque,"%s",data);
}
static int flush(void *opaque) { flushes++;return fflush((FILE *)opaque); }
static void close_output(void *opaque) { closes++;assert(fclose((FILE *)opaque)==0); }
int main(void) {
 xo_style_t styles[]={XO_STYLE_TEXT,XO_STYLE_XML,XO_STYLE_JSON,XO_STYLE_HTML,XO_STYLE_SDPARAMS};
 for(unsigned i=0;i<sizeof(styles)/sizeof(styles[0]);i++) {
  FILE *fp=tmpfile();assert(fp);
  xo_set_style(NULL,styles[i]);
  xo_clear_flags(NULL,XOF_FLUSH|XOF_FLUSH_LINE);
  xo_set_flags(NULL,XOF_CLOSE_FP);
  xo_set_writer(NULL,fp,output,close_output,flush);
  writes=flushes=closes=0;
  xo_open_container("dtrace");xo_open_list("probes");
  xo_open_instance("probes");xo_emit("{:value/%s}","old-session");
  assert(writes==0 && flushes==0 && closes==0);
  dtrace_oformat_discard(NULL);
  assert(writes==0 && flushes==0 && closes==0);
  assert(fflush(fp)==0);
  struct stat st;assert(fstat(fileno(fp),&st)==0 && st.st_size==0);
  assert(fclose(fp)==0);
  assert(xo_get_style(NULL)==XO_STYLE_TEXT);
  xo_destroy(NULL);
 }
 for(unsigned mode=0;mode<4;mode++) {
  FILE *caller=tmpfile(),*redirect=tmpfile();assert(caller && redirect);
  assert(setvbuf(caller,NULL,_IOFBF,4096)==0 && setvbuf(redirect,NULL,_IOFBF,4096)==0);
  assert(fputs("old caller",caller)>=0 && fputs("old redirect",redirect)>=0);
  dtrace_hdl_t handle={0};handle.dt_freopen_fp=redirect;
  handle.dt_buffered_buf=strdup("old callback output");assert(handle.dt_buffered_buf);
  handle.dt_buffered_size=20;handle.dt_buffered_offs=19;
  fail_purge=mode==1?caller:mode==2?redirect:NULL;
  assert(dtrace_output_discard(&handle,mode==3?redirect:caller)==(fail_purge?-1:0));
  assert(handle.dt_output_discarded && !handle.dt_buffered_buf && handle.dt_buffered_offs==0);
  if(fail_purge)assert(handle.dt_errno==EIO && errno==EIO);
  fail_purge=NULL;
  assert(dtrace_output_discard(&handle,caller)==0);
  assert(fflush(caller)==0 && fflush(redirect)==0);
  struct stat st;
  assert(fstat(fileno(caller),&st)==0 && st.st_size==0);
  assert(fstat(fileno(redirect),&st)==0 && st.st_size==0);
  assert(fclose(caller)==0 && fclose(redirect)==0);
 }
 assert(dtrace_output_discard(NULL,NULL)==-1 && errno==EINVAL);
 return 0;
}
'''
(out/'discard.c').write_text(fixture)
lib=[sys.argv[2]] if len(sys.argv)>2 else ['-lxo']
command=['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(out/'discard.c')]+lib+['-lutil','-o',str(out/'discard')]
(out/'command.json').write_text(json.dumps(command,indent=2))
subprocess.run(command,check=True)
subprocess.run([str(out/'discard')],check=True,timeout=30)
print('PASS: actual formatter discard across five styles, with no writer/flush/close callback or file output')
