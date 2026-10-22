#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
fixture=r'''
#include <cassert>
#include <cstdlib>
#include "dtraced_collector_owner.h"
static int original=-1, retained=-1, checks, mode;
static bool fail_alloc;
extern "C" void *__real__Znwm(size_t);
extern "C" void *__wrap__Znwm(size_t size) {
 if(fail_alloc)throw std::bad_alloc();return __real__Znwm(size);
}
namespace dtraced {
int collector_process_reaper_empty(int fd) {
 assert(fd != original && fcntl(fd,F_GETFD)>=0);
 if(mode==2){errno=EIO;return -1;}
 return mode;
}
int collector_process_exited(int fd) {
 assert(fd != original && fcntl(fd,F_GETFD)>=0);
 assert(fcntl(fd,F_GETFD)&FD_CLOEXEC);
 retained=fd;checks++;
 if(mode==2){errno=EIO;return -1;}
 return mode;
}
}
int main(){
 using namespace dtraced;
 std::array<uint8_t,16> session{},birth{};std::array<uint8_t,32> program{};std::array<uint8_t,24> handle{};
 session[0]=1;birth[0]=2;program[0]=3;handle[0]=4;
 auto key=collector_owner_identity(session,birth,100,200,program,handle);
 original=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(original>=0);
 {
  collector_owner_registry owners;
  assert(owners.exited(key)==-1 && errno==EAGAIN && checks==0);
  assert(owners.reaper_empty(key)==-1 && errno==EAGAIN);
  assert(owners.retain(key,-1)==-1 && errno==EBADF);
  fail_alloc=true;assert(owners.retain(key,original)==-1 && errno==ENOMEM);fail_alloc=false;
  assert(owners.exited(key)==-1 && errno==EAGAIN);
  assert(owners.retain(key,original)==0);
  assert(owners.exited(key)==0 && retained!=original);
  int first=retained;
  fail_alloc=true;assert(owners.retain(key,original)==0);fail_alloc=false;
  assert(close(original)==0); // Socket-side owner can release its descriptor.
  assert(owners.exited(key)==0 && retained==first);
  for(unsigned offset : {0U,16U,32U,36U,40U,72U}){
   auto other=key;other[offset]^=1;int before=checks;
   assert(owners.exited(other)==-1 && errno==EAGAIN && checks==before);
  }
  assert(owners.reaper_empty(key)==0);
  mode=1;assert(owners.reaper_empty(key)==1);
  mode=1;assert(owners.exited(key)==1);
  mode=2;assert(owners.reaper_empty(key)==-1 && errno==EIO);
  mode=2;assert(owners.exited(key)==-1 && errno==EIO);
  assert(owners.retained(key));
  assert(owners.release_after_durable_exit(key)==0);
  assert(!owners.retained(key));
  assert(fcntl(retained,F_GETFD)==-1 && errno==EBADF);
  assert(owners.release_after_durable_exit(key)==0);
  int before=checks;
  assert(owners.exited(key)==-1 && errno==EAGAIN && checks==before);
 }
 assert(fcntl(retained,F_GETFD)==-1 && errno==EBADF);
 original=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(original>=0);
 {
  collector_owner_registry owners;collector_owner_key cursor{};
  std::array<collector_owner_key,32> batch{};
  assert(owners.batch_after(cursor,batch)==0);
  for(unsigned i=1;i<=70;i++){auto item=key;item[0]=i;assert(owners.retain(item,original)==0);}
  fail_alloc=true;
  assert(owners.batch_after(cursor,batch)==32 && batch[0][0]==1 && batch[31][0]==32);
  fail_alloc=false;
  assert(owners.release_after_durable_exit(cursor)==0);
  fail_alloc=true;
  assert(owners.batch_after(cursor,batch)==32 && batch[0][0]==33 && batch[31][0]==64);
  assert(owners.batch_after(cursor,batch)==32 && batch[0][0]==65 && batch[6][0]==1 && batch[31][0]==26);
  fail_alloc=false;
 }
 assert(close(original)==0);
 return 0;
}
'''
(out/'owner.cc').write_text(fixture)
subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-pthread','-I'+str(root/'usr.sbin/dtraced'),str(out/'owner.cc'),'-Wl,--wrap=_Znwm','-o',str(out/'owner')],check=True)
subprocess.run([str(out/'owner')],check=True,timeout=30)
print('PASS: exact retained ownership, socket-side close, idempotent retry, allocation failure and descriptor cleanup')
