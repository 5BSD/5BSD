# SPDX-License-Identifier: BSD-2-Clause
"""Actual client unlink/collect code with worker/session/descriptor seams."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
class Collection(unittest.TestCase):
 def test_retirement_preserves_live_clients_and_releases_once(self):
  source=(ROOT/'usr.sbin/switchboard/authority.c').read_text()
  begin=source.index('static void\nstorage_client_remove(')
  end=source.index('\nbool\nsvc_authority_storage_client_event',begin)
  harness=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
struct domain {uint64_t authority_issuer,authority_identity,session_id;};
struct storage_client {struct storage_client *next;uint64_t id,provider_issuer,provider_identity;struct domain domain;int pd;};
static struct storage_client *storage_clients;
static size_t storage_client_count;
static unsigned revoked[16],closed[16];
static void storage_workers_revoke_client(uint64_t id){assert(id<16);assert(!revoked[id]++);}
static int fake_close(int fd){assert(fd>0 && fd<16);assert(revoked[fd]==1);assert(!closed[fd]++);return 0;}
#define close fake_close
static bool session_valid(uint64_t id){return id==1;}
'''
  cases=r'''
static void add(unsigned id,uint64_t session,uint64_t provider,uint64_t owner){
 struct storage_client *c=calloc(1,sizeof(*c));assert(c);c->id=id;c->pd=id;
 c->domain.session_id=session;c->provider_issuer=provider;c->provider_identity=5;
 c->domain.authority_issuer=owner;c->domain.authority_identity=5;
 c->next=storage_clients;storage_clients=c;storage_client_count++;
}
int main(void){
 /* Head/tail/consecutive removals with both live and sessionless survivors. */
 add(1,2,0,0);add(2,1,7,0);add(3,2,0,0);add(4,2,0,0);add(5,0,0,7);add(6,2,0,0);
 svc_authority_storage_clients_collect();assert(storage_client_count==2);
 assert(storage_clients->id==5 && storage_clients->next->id==2 && !storage_clients->next->next);
 for(unsigned i=1;i<=6;i++)assert(closed[i]==(i!=2 && i!=5));
 svc_authority_storage_clients_collect();assert(storage_client_count==2);
 storage_clients_revoke(7,4);assert(storage_client_count==2);
 storage_clients_revoke(7,5);assert(storage_client_count==0 && !storage_clients);
 for(unsigned i=1;i<=6;i++)assert(closed[i]==1 && revoked[i]==1);
 add(7,1,0,0);add(8,1,0,0);add(9,1,0,0);
 svc_authority_storage_client_discard(8);assert(storage_client_count==2);
 assert(storage_clients->id==9 && storage_clients->next->id==7);
 svc_authority_storage_client_discard(8);assert(storage_client_count==2);
 svc_authority_storage_client_discard(9);svc_authority_storage_client_discard(7);
 assert(!storage_clients && storage_client_count==0);
 for(unsigned i=1;i<=9;i++)assert(closed[i]==1 && revoked[i]==1);
 return 0;
}
'''
  with tempfile.TemporaryDirectory(prefix='client-collection-') as d:
   c=Path(d)/'test.c';exe=Path(d)/'test';c.write_text(harness+source[begin:end]+cases)
   for cmd in (['cc','-Wall','-Wextra','-Werror',str(c),'-o',str(exe)],[str(exe)]):
    result=subprocess.run(cmd,capture_output=True,text=True)
    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
if __name__=='__main__':unittest.main()
