# SPDX-License-Identifier: BSD-2-Clause
# Synthetic runner refusal tests; never boots a VM. Requires writable /usr/obj/usr/src.
import hashlib,json,pathlib,subprocess,tempfile,unittest
class PreparedChecks(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(prefix='prepared-vm-check-',dir='/usr/obj/usr/src');self.w=pathlib.Path(self.t.name);(self.w/'guest.img').write_bytes(b'fixture, not a VM')
  self.q=self.w/'fake-qemu';self.q.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo test-emulator; exit 0; fi\ntouch "'+str(self.w/'unexpected-launch')+'"\nexit 99\n');self.q.chmod(0o755)
  self.r={'stage':'/usr/obj/usr/src/capimage-current-stage-4','cpus':2,'memory_mb':2048,'qemu_version':'test-emulator','guest_sha256':hashlib.sha256((self.w/'guest.img').read_bytes()).hexdigest()}
 def tearDown(self):self.t.cleanup()
 def reject(self,expected):
  (self.w/'run.json').write_text(json.dumps(self.r))
  r=subprocess.run(['python3.12',str(pathlib.Path(__file__).resolve().with_name('vm.py')),'--stage','/usr/obj/usr/src/capimage-current-stage-4','--work',str(self.w),'--run-prepared','--qemu',str(self.q)],capture_output=True,text=True)
  self.assertNotEqual(r.returncode,0);self.assertIn(expected,r.stderr);self.assertFalse((self.w/'unexpected-launch').exists())
 def test_changed_image(self):
  (self.w/'guest.img').write_bytes(b'changed');self.reject('digest missing or changed')
 def test_missing_digest(self):
  del self.r['guest_sha256'];self.reject('digest missing or changed')
 def test_wrong_size(self):
  self.r['memory_mb']=8192;self.reject('resource settings do not match')
 def test_wrong_stage(self):
  self.r['stage']='/elsewhere';self.reject('stage identity does not match')
 def test_existing_evidence(self):
  (self.w/'command.json').write_text('preserve');self.reject('execution evidence already exists');self.assertEqual((self.w/'command.json').read_text(),'preserve')
if __name__=='__main__':unittest.main()
