#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/dtraced/dtraced_process.cc').read_text();a=s.index('int\ncollector_handle_retired(');b=s.index('/* Never infer process death',a)
fixture=r'''
#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/hypertrace.h>
#include "dtraced_wire.h"
static int mode,opened,closed,queried;
static int mock_open(const char *path,int flags) {
 assert(strcmp(path,"/dev/dtrace/hypertrace")==0);
 assert(flags==(O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));opened++;
 if(mode==2){errno=ENOENT;return -1;}return 123;
}
static int mock_ioctl(int fd,unsigned long cmd,dtrace_handle_lifetime_t *q) {
 assert(fd==123 && cmd==HYPERTRACE_IOC_HANDLE_QUERY);queried++;
 assert(q->generation[0]==1 && q->generation[1]==2 && q->serial==3 && q->retired==0 && q->reserved==0);
 if(mode>=3 && mode<=5){errno=mode==3?ENOTTY:mode==4?ESTALE:EIO;return -1;}
 q->retired=mode==1;
 if(mode==6)q->generation[0]++;
 if(mode==7)q->serial++;
 if(mode==8)q->reserved=1;
 if(mode==9)q->retired=2;
 return 0;
}
static int mock_close(int fd){assert(fd==123);closed++;if(mode==10){errno=EIO;return -1;}return 0;}
#define open mock_open
#define ioctl mock_ioctl
#define close mock_close
'''+s[a:b]+r'''
int main(){
 std::array<uint8_t,24> identity{};
 dtraced_wire_put_u64(identity.data(),1);dtraced_wire_put_u64(identity.data()+8,2);dtraced_wire_put_u64(identity.data()+16,3);
 for(mode=0;mode<=10;mode++){
  opened=closed=queried=0;
  int r=collector_handle_retired(identity);
  assert(r==(mode==0?0:mode==1?1:-1));
  if(mode>1)assert(errno==(mode==2?ENOENT:mode==3?ENOTTY:mode==4?ESTALE:mode==5||mode==10?EIO:EPROTO));
  assert(opened==1 && closed==(mode!=2) && queried==(mode!=2));
 }
 opened=0;identity.fill(0);assert(collector_handle_retired(identity)==-1 && errno==EINVAL && opened==0);
 return 0;
}
'''
(out/'query.cc').write_text(fixture)
subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(root/'sys'),'-I'+str(root/'usr.sbin/dtraced'),str(out/'query.cc'),'-o',str(out/'query')],check=True)
subprocess.run([str(out/'query')],check=True,timeout=30)
print('PASS: exact control-device query, live/retired distinction, unavailable/stale/malformed refusal')
