# SPDX-License-Identifier: BSD-2-Clause
"""Real artifact byte construction; synthetic payload is not a filesystem."""
import copy
import hashlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('artifacts',ROOT/'tools/build/capimage/verity_artifacts.py')
artifacts=importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class Artifacts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.data=bytes(range(256))*32
        (self.folder/'system.ufs').write_bytes(self.data)
        self.sha=hashlib.sha256(self.data).hexdigest()
        self.policy=dict(format=1,block_size=4096,salt_hex='aabb')

    def build(self):
        return artifacts.build(self.folder,self.policy,self.sha,len(self.data))

    def verify(self, receipt, policy=None):
        artifacts.verify(self.folder,receipt,self.policy if policy is None else policy,
                         self.sha,len(self.data))

    def test_round_trip(self):
        receipt=self.build()
        self.verify(receipt)
        combined=(self.folder/'system.verity').read_bytes()
        self.assertEqual(combined[:len(self.data)],self.data)
        with tempfile.TemporaryFile() as hashes, (self.folder/'system.ufs').open('rb') as data:
            hashes.write(combined[len(self.data):]);hashes.flush()
            for index in (0,1):
                actual=artifacts.tree.read_verified_block(data.fileno(),hashes.fileno(),
                    len(self.data),4096,b'\xaa\xbb',bytes.fromhex(receipt['root_sha256']),index)
                self.assertEqual(actual,self.data[index*4096:(index+1)*4096])

    def test_bad_policy(self):
        for change in ({'format':True},{'block_size':True},{'block_size':513},
                       {'salt_hex':'AABB'},{'salt_hex':'a'},{'extra':1}):
            value=dict(self.policy,**change)
            with self.subTest(change=change),self.assertRaises(ValueError):
                artifacts.policy(value)

    def test_changed_source_rejected_before_descriptor(self):
        (self.folder/'system.ufs').write_bytes(b'X'*len(self.data))
        with self.assertRaises(ValueError): self.build()
        self.assertFalse((self.folder/'root.descriptor').exists())

    def test_policy_and_missing_receipt_rejected(self):
        receipt=self.build()
        with self.assertRaises(ValueError): self.verify(None)
        with self.assertRaises(ValueError): self.verify(receipt,dict(self.policy,salt_hex=''))
        with self.assertRaises(FileExistsError): self.build()

    def test_artifact_corruption(self):
        receipt=self.build()
        for name in ('system.verity','root.descriptor'):
            path=self.folder/name;original=path.read_bytes()
            path.write_bytes(original[:-1]+bytes([original[-1]^1]))
            with self.assertRaises(ValueError): self.verify(receipt)
            path.write_bytes(original)

    def test_descriptor_must_match_geometry_even_with_updated_hash(self):
        receipt=self.build()
        path=self.folder/'root.descriptor'
        value=bytearray(path.read_bytes());value[48]^=1;path.write_bytes(value)
        receipt['descriptor_sha256']=hashlib.sha256(value).hexdigest()
        with self.assertRaises(ValueError): self.verify(receipt)

    def test_updated_outer_digest_cannot_hide_invalid_tree(self):
        receipt=self.build()
        path=self.folder/'system.verity'
        original=path.read_bytes()
        for offset in (0, len(self.data), len(original)-1):
            with self.subTest(offset=offset):
                changed=bytearray(original);changed[offset]^=1;path.write_bytes(changed)
                receipt['image_sha256']=hashlib.sha256(changed).hexdigest()
                with self.assertRaisesRegex(ValueError, 'tree differs'):
                    self.verify(receipt)
        path.write_bytes(original)

    def test_root_must_match_tree_even_with_rebound_descriptor(self):
        receipt=self.build()
        receipt['root_sha256']='00'*32
        descriptor=artifacts.tree.encode_root_descriptor(len(self.data),4096,
            b'\xaa\xbb',bytes(32))
        (self.folder/'root.descriptor').write_bytes(descriptor)
        receipt['descriptor_sha256']=hashlib.sha256(descriptor).hexdigest()
        with self.assertRaisesRegex(ValueError, 'root differs'):
            self.verify(receipt)

    def test_valid_other_tree_cannot_replace_selected_filesystem(self):
        receipt=self.build()
        other=bytes(reversed(self.data))
        (self.folder/'system.ufs').write_bytes(other)
        (self.folder/'system.verity').unlink()
        (self.folder/'root.descriptor').unlink()
        replacement=artifacts.build(self.folder,self.policy,
                                   hashlib.sha256(other).hexdigest(),len(other))
        replacement['source_image_sha256']=self.sha
        with self.assertRaisesRegex(ValueError, 'selected filesystem digest'):
            self.verify(replacement)

    def test_multilevel_read_volume_is_bounded(self):
        self.data=bytes(range(256))*1026  # 513 blocks: partial leaf and parent groups.
        (self.folder/'system.ufs').write_bytes(self.data)
        self.sha=hashlib.sha256(self.data).hexdigest()
        self.policy['block_size']=512
        receipt=self.build()
        calls=[];read_exact=artifacts.tree.read_exact
        def measured(fd,size,offset):
            calls.append((size,offset))
            return read_exact(fd,size,offset)
        with patch.object(artifacts.tree,'read_exact',side_effect=measured):
            self.verify(receipt)
        _,_,tree_bytes=artifacts.tree.geometry(len(self.data),512)
        self.assertTrue(all(size==512 for size,_ in calls))
        self.assertEqual(sum(size for size,_ in calls),len(self.data)+3*tree_bytes)
        self.assertEqual(sum(size for size,offset in calls if offset<len(self.data)),len(self.data))

    def test_implicit_boot_path_rejects_missing_artifacts(self):
        spec=importlib.util.spec_from_file_location('boot',ROOT/'tools/build/capimage/generation_boot.py')
        boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
        receipt=self.folder/'receipt.json';receipt.write_text('{"verity":{}}')
        with self.assertRaisesRegex(ValueError,'explicit image and descriptor'):
            boot.verify(self.folder/'missing-image',self.folder/'missing-archive',receipt)

    def test_descriptor_lengths_and_nonregular_inputs(self):
        receipt=self.build()
        path=self.folder/'root.descriptor';original=path.read_bytes()
        for wire in (original[:-1],original+b'x'):
            path.write_bytes(wire)
            with self.assertRaises(ValueError): self.verify(receipt)
        path.unlink();os.mkfifo(path)
        code = """
import importlib.util,sys
spec=importlib.util.spec_from_file_location('artifacts',sys.argv[1])
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
try:
    a._opened_artifact(sys.argv[2])
except ValueError as error:
    assert 'regular file' in str(error)
else:
    raise AssertionError('accepted FIFO')
"""
        subprocess.run([sys.executable,'-B','-c',code,str(ROOT/'tools/build/capimage/verity_artifacts.py'),str(path)],check=True,timeout=3)
        path.unlink();path.mkdir()
        with self.assertRaisesRegex(ValueError,'regular file'): self.verify(receipt)

    def test_symlink_rejected(self):
        receipt=self.build()
        path=self.folder/'system.verity';path.rename(self.folder/'other')
        path.symlink_to('other')
        with self.assertRaises(ValueError): self.verify(receipt)


if __name__=='__main__': unittest.main()
