#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/dtraced/dtraced_process.cc').read_text();a=s.index('int\ncollector_process_pin(');b=s.index('durable_delivery\nguest_delivery_record',a)
fixture=r'''
#include <cassert>
#include <cerrno>
#include <sys/procdesc.h>
#include <poll.h>
static int mode,opens,closes,queries,polls;
static pd_birth_identity birth{42,0,100,200};
static int mock_pdopenpid(pid_t pid,int flags){
 assert(pid==42 && flags==(PD_DAEMON|PD_CLOEXEC));opens++;
 if(mode==1){errno=ESRCH;return -1;}return 123;
}
static int mock_ioctl(int fd,unsigned long command,pd_birth_identity *out){
 assert(fd==123 && command==PDIOC_GET_BIRTH_IDENTITY);queries++;
 if(mode==2 || mode==3){errno=mode==2?ENOTTY:ESRCH;return -1;}
 *out=birth;
 if(mode==4)out->pid++;
 if(mode==5)out->start_sec++;
 if(mode==6)out->start_usec++;
 if(mode==7)out->reserved=1;
 return 0;
}
static int reaper_mode;
static unsigned reaper_flags;
static int mock_ioctl(int fd,unsigned long command,pd_reaper_exit *out){
 assert(fd==123 && command==PDIOC_GET_REAPER_EXIT);
 if(reaper_mode==1){errno=ENOTTY;return -1;}
 out->flags=reaper_flags;out->reserved=reaper_mode==2?1:0;
 return 0;
}
static int mock_close(int fd){assert(fd==123);closes++;errno=EIO;return -1;}
static int mock_poll(pollfd *event,nfds_t count,int timeout){
 assert(event->fd==123 && event->events==POLLIN && count==1 && timeout==0);polls++;
 if(mode==2){errno=EINTR;return -1;}
 event->revents=mode==1?POLLHUP:mode==3?POLLNVAL:mode==4?POLLERR:mode==5?POLLIN:mode==6?(POLLHUP|POLLERR):0;
 return mode==0?0:1;
}
#define pdopenpid mock_pdopenpid
#define ioctl mock_ioctl
#define close mock_close
#define poll mock_poll
'''+s[a:b]+r'''
int main(){
 for(mode=0;mode<8;mode++){
  opens=closes=queries=0;int fd=-55;
  assert(collector_process_pin(42,birth,&fd)==(mode==0?0:-1));
  assert(fd==(mode==0?123:-55));
  assert(opens==1 && queries==(mode!=1) && closes==(mode>=2));
  if(mode)assert(errno==(mode==1||mode==3?ESRCH:mode==2?ENOTTY:ESTALE));
 }
 opens=0;
 for(unsigned i=0;i<5;i++){
  auto invalid=birth;
  if(i==0)invalid.pid++;
  if(i==1)invalid.reserved=1;
  if(i==2)invalid.start_usec=1000000;
  if(i==3)invalid.start_sec=invalid.start_usec=0;
  int fd=-55;
  assert(collector_process_pin(42,invalid,i==4?nullptr:&fd)==-1 && errno==EINVAL && fd==-55);
 }
 assert(opens==0);
 for(mode=0;mode<=7;mode++){
  int result=collector_process_exited(123);
  assert(result==(mode==0?0:mode==1?1:-1));
  if(mode>=2)assert(errno==(mode==2?EINTR:mode==3?EBADF:mode==4||mode==6?EIO:EPROTO));
 }
 for(reaper_flags=0;reaper_flags<16;reaper_flags++){
  int expected=reaper_flags==7?1:(reaper_flags==0||reaper_flags==1||reaper_flags==3)?0:-1;
  assert(collector_process_reaper_empty(123)==expected);
  if(expected==-1)assert(errno==EPROTO);
 }
 reaper_flags=7;
 reaper_mode=1;assert(collector_process_reaper_empty(123)==-1 && errno==ENOTTY);
 reaper_mode=2;assert(collector_process_reaper_empty(123)==-1 && errno==EPROTO);
 assert(collector_process_reaper_empty(-1)==-1 && errno==EINVAL);
 int before=polls;
 assert(collector_process_exited(-1)==-1 && errno==EINVAL && polls==before);
 return 0;
}
'''
(out/'process.cc').write_text(fixture)
subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(root/'sys'),str(out/'process.cc'),'-o',str(out/'process')],check=True)
subprocess.run([str(out/'process')],check=True,timeout=30)
print('PASS: exact process birth, non-killing descriptor ownership, explicit exit only, PID reuse/error refusal')
