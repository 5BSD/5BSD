#!/usr/bin/env python3
"""Exercise actual pfctl raw-state I/O, including deferred close failures."""
from pathlib import Path
import os, shlex, subprocess, tempfile, unittest
ROOT = Path(__file__).resolve().parents[4]
STUBS = r'''
#include <sys/types.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct pfsync_state { unsigned char data[32]; };
struct pfioc_states { size_t ps_len; char *ps_buf; };
struct pfioc_state { struct pfsync_state state; };
#define DIOCGETSTATESEXPORT 1
#define DIOCADDSTATE 2
static int inject_close, add_error, added, snapshots;
static int checked_close(FILE *f) {
 int rc = fclose(f);
 if (inject_close) { errno = ENOSPC; return EOF; }
 return rc;
}
#define fclose checked_close
static int fake_ioctl(int dev, int cmd, void *arg) {
 (void)dev;
 if (cmd == DIOCGETSTATESEXPORT) {
  struct pfioc_states *s = arg;
  if (add_error == -1) { s->ps_len = 0; return 0; }
  if (add_error == -2) {
   if (++snapshots < 3) { s->ps_len = 32 * snapshots; return 0; }
   errno = EOPNOTSUPP; return -1;
  }
  if (add_error) { errno = add_error; return -1; }
  if (s->ps_len >= 32) memset(s->ps_buf, 0, 32);
  s->ps_len = 32;
  return 0;
 }
 assert(cmd == DIOCADDSTATE);
 added++;
 fprintf(stderr, "ADD=%d\n", added);
 if (add_error) { errno = add_error; return -1; }
 return 0;
}
#define ioctl fake_ioctl
'''
MAIN = r'''
int main(int argc, char **argv) {
 assert(argc == 5);
 inject_close = atoi(argv[3]); add_error = atoi(argv[4]);
 if (!strcmp(argv[1], "load")) pfctl_state_load(-1, argv[2]);
 else pfctl_state_store(-1, argv[2]);
 return 0;
}
'''
class StateFileIO(unittest.TestCase):
 def test_io_errors_and_raw_compatibility(self):
  source = (ROOT/'contrib/openbsd-pf/sbin/pfctl/pfctl.c').read_text()
  bodies = source[source.index('void\npfctl_state_store('):source.index('\nvoid\npfctl_reset(')]
  with tempfile.TemporaryDirectory() as tmp:
   p = Path(tmp); (p/'io.c').write_text(STUBS+bodies+MAIN)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror',str(p/'io.c'),'-o',str(p/'io')],check=True)
   def run(mode, path, expected, close=0, error=0, diagnostic=None):
    got=subprocess.run([str(p/'io'),mode,str(path),str(close),str(error)],capture_output=True,text=True)
    self.assertEqual(got.returncode,expected,got.stderr)
    if diagnostic: self.assertIn(diagnostic,got.stderr)
    return got
   raw=p/'raw'; raw.write_bytes(b'')
   run('load',raw,0)
   raw.write_bytes(bytes(32)); run('load',raw,0,diagnostic='ADD=1')
   import errno
   run('load',raw,0,error=errno.EEXIST)
   run('load',raw,0,error=errno.EINVAL)
   run('load',raw,1,error=errno.EPERM,diagnostic='DIOCADDSTATE')
   raw.write_bytes(b'x'); run('load',raw,1,diagnostic='truncated state record')
   raw.write_bytes(bytes(33)); got=run('load',raw,1,diagnostic='truncated state record')
   self.assertEqual(got.stderr.count('ADD='),1) # Existing incremental import contract.
   run('load',p,1,diagnostic='read:')
   raw.write_bytes(b''); run('load',raw,1,close=1,diagnostic='close:')
   run('store',raw,0); self.assertEqual(len(raw.read_bytes()),32)
   run('store',raw,0,error=-1); self.assertEqual(raw.read_bytes(),b'')
   run('store',raw,1,close=1,diagnostic='close:')
   raw.write_bytes(b'previous snapshot')
   run('store',raw,1,error=errno.EOPNOTSUPP,diagnostic='cannot preserve')
   self.assertEqual(raw.read_bytes(),b'previous snapshot')
   run('store',raw,1,error=-2,diagnostic='cannot preserve')
   self.assertEqual(raw.read_bytes(),b'previous snapshot')
   run('store',raw,1,error=errno.ENOTTY,diagnostic='DIOCGETSTATESEXPORT')
   self.assertEqual(raw.read_bytes(),b'previous snapshot')
if __name__ == '__main__': unittest.main()
