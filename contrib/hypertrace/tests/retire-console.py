#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual console gates and input dispatch with a callback in flight."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/bhyve/console.c').read_text()
parts=[]
for name in ('console_input_pause','console_input_resume','console_input_retire','console_key_event','console_ptr_event'):
 a=s.index('void\n'+name+'(');parts.append(s[a:s.index('\n}',a)+2])
fixture=r'''
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include "console.h"
static pthread_rwlock_t console_lock=PTHREAD_RWLOCK_INITIALIZER;
static bool console_input_paused, console_input_retired;
static struct {
 kbd_event_func_t kbd_event_cb; void *kbd_arg;
 ptr_event_func_t ptr_event_cb; void *ptr_arg;
} console;
static atomic_bool entered, released, pause_started, paused;
static int keys,pointers;
'''+'\n'.join(parts)+r'''
static void key(int down,uint32_t sym,uint32_t code,void *arg) {
 (void)down;(void)sym;(void)code;assert(arg==(void *)1); keys++;
 atomic_store(&entered,true);
 while (!atomic_load(&released)) usleep(100);
}
static void pointer(uint8_t button,int x,int y,void *arg) {
 (void)button;(void)x;(void)y;assert(arg==(void *)2);pointers++;
}
static void *input(void *unused) {
 (void)unused;console_key_event(1,2,3);return NULL;
}
static void *pause_input(void *unused) {
 (void)unused;atomic_store(&pause_started,true);console_input_pause();
 atomic_store(&paused,true);return NULL;
}
int main(void) {
 console.kbd_event_cb=key;console.kbd_arg=(void *)1;
 console.ptr_event_cb=pointer;console.ptr_arg=(void *)2;
 pthread_t cb, pauser;
 assert(pthread_create(&cb,NULL,input,NULL)==0);
 while (!atomic_load(&entered)) usleep(100);
 assert(pthread_create(&pauser,NULL,pause_input,NULL)==0);
 while (!atomic_load(&pause_started)) usleep(100);
 usleep(10000);assert(!atomic_load(&paused));
 atomic_store(&released,true);
 assert(pthread_join(cb,NULL)==0 && pthread_join(pauser,NULL)==0);
 console_key_event(1,2,3);console_ptr_event(1,2,3);
 assert(keys==1 && pointers==0);
 console_input_resume(); console_key_event(1,2,3);console_ptr_event(1,2,3);
 assert(keys==2 && pointers==1);
 console_input_pause();console_input_retire();console_input_resume();
 console.kbd_arg=NULL;console.ptr_arg=NULL;
 console_key_event(1,2,3);console_ptr_event(1,2,3);
 assert(keys==2 && pointers==1);
 console_input_retire();console_input_resume();console_key_event(1,2,3);
 assert(keys==2);
 return 0;
}
'''
(out/'console.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined','-I'+str(root/'usr.sbin/bhyve'),str(out/'console.c'),'-o',str(out/'console')],check=True)
subprocess.run([str(out/'console')],check=True,timeout=30)
print('PASS: input pause drains callbacks, rollback reopens admission, and retirement cannot reopen')
