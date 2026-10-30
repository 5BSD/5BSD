# SPDX-License-Identifier: BSD-2-Clause
"""Native transition decoder against generated wire bytes; not authentication."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('boot', ROOT/'tools/build/capimage/generation_boot.py')
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class Transition(C.Structure):
    _fields_ = [('digest', C.c_ubyte*32), ('workers', C.c_uint32),
                ('filesystem', C.c_uint32), ('cache', C.c_uint64),
                ('window', C.c_uint64), ('budget', C.c_uint64),
                ('device', C.c_char*1024), ('image', C.c_char*1024),
                ('provider', C.c_char*64)]


class Decoder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        binary = Path(cls.work.name)/'transition.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        '-I'+str(ROOT/'sys'), '-o', str(binary),
                        str(ROOT/'sys/geom/verity/g_verity_transition.c')], check=True)
        cls.lib = C.CDLL(str(binary))
        cls.lib.g_verity_transition_decode.argtypes = [C.c_void_p, C.c_size_t,
                                                       C.POINTER(Transition)]
        cls.lib.g_verity_transition_decode.restype = C.c_int

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        # Synthetic checked-report identity exercises encoding, not signer trust.
        self.checked = dict(result='PASS', scope='collected-boot-transport-consistency',
                            verity=dict(internal_consistency_verified=True,
                                        descriptor_sha256='ab'*32))
        self.policy = dict(version=1, mode='verity', image='/boot/site-base.verity',
                           descriptor='/boot/site-base.root', cache_blocks=8,
                           heap_bytes=65536, transition=dict(version=1,
                           transport_fs='ufs', transport_device='/dev/gpt/site-boot',
                           provider='site-root', workers=2, cache_blocks=64,
                           window_bytes=131072, buffer_bytes=1048576))
        boot.render_boot_policy(self.policy, self.checked)
        self.wire = boot.render_boot_transition(self.policy, self.checked)

    def decode(self, wire, accept):
        result = Transition()
        C.memset(C.byref(result), 0xa5, C.sizeof(result))
        original = bytes(result)
        source = C.create_string_buffer(bytes(wire))
        status = self.lib.g_verity_transition_decode(source, len(wire), C.byref(result))
        self.assertEqual(status == 0, accept)
        if not accept:
            self.assertEqual(bytes(result), original)
        return result

    def test_generated_records(self):
        for filesystem, device, identifier in (('ufs','/dev/gpt/site-boot',1),
                                               ('zfs','pool/boot/generation',2)):
            policy = copy.deepcopy(self.policy)
            policy['transition'].update(transport_fs=filesystem, transport_device=device)
            value = self.decode(boot.render_boot_transition(policy,self.checked), True)
            self.assertEqual(bytes(value.digest), bytes.fromhex('ab'*32))
            self.assertEqual((value.workers,value.filesystem,value.cache,value.window,value.budget),
                             (2,identifier,64,131072,1048576))
            self.assertEqual(value.device,device.encode())
            self.assertEqual(value.image,policy['image'].encode())
            self.assertEqual(value.provider,b'site-root')

    def test_lengths_headers_and_resources(self):
        for length in range(len(self.wire)):
            self.decode(self.wire[:length],False)
        self.decode(self.wire+b'\0',False)
        for offset in range(16):
            changed=bytearray(self.wire);changed[offset]^=1
            self.decode(changed,False)
        for offset, fmt, value in ((48,'I',0),(52,'I',0),(52,'I',3),
                (56,'Q',2**63),(64,'Q',0),(64,'Q',2**63),
                (72,'Q',0),(72,'Q',2**63)):
            changed=bytearray(self.wire);struct.pack_into('>'+fmt,changed,offset,value)
            self.decode(changed,False)
        self.assertNotEqual(self.lib.g_verity_transition_decode(None,len(self.wire),None),0)
        # Parsing cannot authenticate a descriptor digest. Keep that distinction explicit.
        changed=bytearray(self.wire);changed[16]^=1
        self.decode(changed,True)

    def test_strings_and_padding(self):
        for offset,capacity in ((80,1024),(1104,1024),(2128,64)):
            changed=bytearray(self.wire)
            end=changed.index(0,offset,offset+capacity)
            for location in (end+1,offset+capacity-1):
                changed=bytearray(self.wire);changed[location]=1
                self.decode(changed,False)
            changed=bytearray(self.wire);changed[offset:offset+capacity]=b'x'*capacity
            self.decode(changed,False)
        for offset,capacity,text in ((80,1024,b'/dev/a/../b'),(80,1024,b'/dev//b'),
                (80,1024,b'/dev/'),(1104,1024,b'/etc/a'),
                (1104,1024,b'/boot/./a'),(1104,1024,b'/boot/a\n.ask'),
                (2128,64,b'..'),(2128,64,b'a/b'),(2128,64,b'a\xff')):
            changed=bytearray(self.wire)
            changed[offset:offset+capacity]=text+bytes(capacity-len(text))
            self.decode(changed,False)


if __name__ == '__main__':
    unittest.main()
