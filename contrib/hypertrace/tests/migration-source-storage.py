#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
fixture = r'''
#include <assert.h>
#include <sys/capsicum.h>
#include <sys/wait.h>
#include "migration_source_owner.h"
static int fixture_fd, opens, open_error;
static int open_fixture(int *result) {
 opens++;
 if (open_error) return open_error;
 *result=fcntl(fixture_fd,F_DUPFD_CLOEXEC,0);
 return *result<0?errno:0;
}
#define migration_source_canonical_root_open open_fixture
#include "migration_source_storage.h"
int main(void) {
 struct migration_source_storage storage={0}, missing={0}, unprepared={0};
 assert(migration_source_storage_check(&unprepared,0)==ENXIO);
 open_error=ENOENT;
 assert(migration_source_storage_prepare(&missing)==ENOENT);
 assert(missing.directory==-1 && opens==1);
 open_error=0;
 assert(migration_source_storage_prepare(&missing)==ENOENT && opens==1);
 assert(migration_source_storage_check(&missing,0)==ENOENT);
 char path[]="storage.XXXXXX", other[]="other.XXXXXX";
 assert(mkdtemp(path) && mkdtemp(other));
 fixture_fd=open(path,O_RDONLY|O_DIRECTORY); assert(fixture_fd>=0);
 int replacement=open(other,O_RDONLY|O_DIRECTORY); assert(replacement>=0);
 assert(migration_source_storage_prepare(&storage)==0 && opens==2);
 int alias=dup(fixture_fd); assert(alias>=0); close(fixture_fd);
 assert(storage.directory!=alias && (fcntl(storage.directory,F_GETFD)&FD_CLOEXEC));
 pid_t child=fork(); assert(child>=0);
 if (child==0) {
  assert(cap_enter()==0);
  int forbidden=open("/",O_RDONLY|O_DIRECTORY);
  assert(forbidden==-1 && errno==ECAPMODE);
  assert(migration_source_storage_prepare(&storage)==0 && opens==2);
  assert(migration_source_storage_check(&storage,alias)==0);
  assert(migration_source_storage_check(&storage,replacement)==EXDEV);
  struct migration_recovery_record record={.phase=MIGRATION_REC_SOURCE_INTENT,
   .destination_vmid=8,.destination_epoch=10};
  struct hypertrace_session_record stopped={.vmid=7,.epoch=9,.stop_token=11,
   .features=HYPERTRACE_SESSION_FEATURES};
  assert(hypertrace_session_record_encode(record.session,40,&stopped)==0);
  memset(record.challenge,1,32); memset(record.state_digest,2,32);
  memset(record.source_certificate_sha256,3,32); memset(record.destination_certificate_sha256,4,32);
  int controller=-1;
  assert(migration_source_controller_lock_at(storage.directory,7,9,&controller)==0);
  assert(migration_source_owner_at(storage.directory,&record,true)==0);
  assert(migration_recovery_store_at(storage.directory,&record)==0);
  uint16_t phase;
  assert(migration_recovery_load_at(storage.directory,&record,&phase)==0);
  assert(phase==MIGRATION_REC_SOURCE_INTENT);
  close(controller); _exit(0);
 }
 int status; assert(waitpid(child,&status,0)==child);
 assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
 close(alias); close(replacement); close(storage.directory);
 return 0;
}
'''
(out/'storage.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+str(root/'sys'),'-I'+str(root/'usr.sbin/bhyve'),str(out/'storage.c'),
 '-lmd','-o',str(out/'storage')],check=True)
subprocess.run([str(out/'storage')],cwd=out,check=True,timeout=30)
print('PASS: actual Capsicum child uses pinned storage for controller lock, immutable ownership and durable INTENT; absolute opens refused')
