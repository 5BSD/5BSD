# SPDX-License-Identifier: BSD-2-Clause
"""Image receipt failure cleanup; injected filesystem construction, no mounts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('generation_image',
    ROOT/'tools/build/capimage/generation_image.py')
image=importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class VerityLayout(unittest.TestCase):
    def setUp(self):
        self.base = dict(boundary=None, content='immutable', observed={
            path: dict(type='directory', uid=0, mode=0o755)
            for path in ('/', '/.mount', '/dev')})
        self.projections = [self.base]
        self.bindings = dict(verity_policy=dict(format=1, block_size=4096, salt_hex=''))

    def test_valid_and_conventional(self):
        image.validate_verity_layout(self.projections, self.bindings)
        image.validate_verity_layout([], None)

    def test_bad_mount_slots(self):
        import copy
        for path in ('/.mount', '/dev'):
            for bad in (None, dict(type='link', uid=0, mode=0o755, target='/'),
                        dict(type='directory', uid=1000, mode=0o755),
                        dict(type='directory', uid=0, mode=0o777)):
                projections=copy.deepcopy(self.projections)
                if bad is None:
                    del projections[0]['observed'][path]
                else:
                    projections[0]['observed'][path]=bad
                with self.subTest(path=path,bad=bad), self.assertRaises(ValueError):
                    image.validate_verity_layout(projections,self.bindings)

    def test_hidden_content_and_state_conflicts(self):
        import copy
        for path in ('/.mount', '/dev'):
            projections=copy.deepcopy(self.projections)
            projections[0]['observed'][path+'/hidden']=dict(type='file')
            with self.assertRaisesRegex(ValueError,'must be empty'):
                image.validate_verity_layout(projections,self.bindings)
            for boundary in (path,path+'/nested'):
                with self.assertRaisesRegex(ValueError,'writable-state boundary'):
                    image.validate_verity_layout(self.projections+[dict(boundary=boundary)],self.bindings)

    def test_materialization_rejects_before_tools_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'root';root.mkdir()
            output=Path(directory)/'output'
            del self.base['observed']['/dev']
            with patch.object(image,'require_policy_selection'), \
                 patch.object(image,'partitions',return_value=({},self.projections)), \
                 patch.object(image,'_materialize') as build:
                with self.assertRaisesRegex(ValueError,'verity staging requires'):
                    image.materialize_layout(root,{}, {}, {}, {},output,self.bindings)
                build.assert_not_called()
                self.assertFalse(output.exists())
                output.mkdir()
                with self.assertRaisesRegex(ValueError,'verity staging requires'):
                    image.verify_layout(output,{}, {}, {},self.bindings)


class Publication(unittest.TestCase):
    def exercise(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'source';root.mkdir()
            output=Path(directory)/'output'
            observed={}
            projections=[dict(boundary=None,content='base',observed={}),
                         dict(boundary='/state',content='ordinary',observed={})]
            written=[]
            write_record=image.construction.write_record

            def write(path, record):
                if failure=='second-receipt' and path==output/'seed-1/receipt.json':
                    raise OSError('injected receipt write failure')
                if (failure=='completion-record' and path==output/'construction.json'
                        and record.get('result')=='PASS'):
                    raise OSError('injected completion record failure')
                write_record(path, record)
                if path.name=='receipt.json':
                    written.append(path)

            def materialize(root, observed, tools, folder, **kwargs):
                folder.mkdir()
                (folder/'system.ufs').write_bytes(b'fixture image, not a filesystem')
                return dict(result='PASS')

            def verify(*args, **kwargs):
                self.assertTrue((output/'base/receipt.json').exists())
                self.assertTrue((output/'seed-1/receipt.json').exists())
                if failure=='final-verification':
                    raise ValueError('injected retained-artifact verification failure')
                return dict(result='PASS')

            with patch.object(image,'require_policy_selection'), \
                 patch.object(image,'partitions',return_value=({},projections)), \
                 patch.object(image.os,'geteuid',return_value=0), \
                 patch.object(image.construction.generation,'scan',return_value=observed), \
                 patch.object(image,'_materialize',side_effect=materialize), \
                 patch.object(image,'verify_layout',side_effect=verify), \
                 patch.object(image.construction,'write_record',side_effect=write):
                if failure:
                    with self.assertRaises((OSError,ValueError)):
                        image.materialize_layout(root,observed,{}, {},{},output)
                else:
                    self.assertEqual(image.materialize_layout(
                        root,observed,{}, {},{},output)['result'],'PASS')
            markers=[output/'receipt.json',output/'base/receipt.json',
                     output/'seed-1/receipt.json']
            if failure:
                self.assertIn(output/'base/receipt.json',written)
                self.assertFalse(any(p.exists() for p in markers))
                self.assertFalse((output/'verification.json').exists())
                self.assertEqual(json.loads((output/'construction.json').read_text())['result'],'FAIL')
            else:
                self.assertTrue(all(p.exists() for p in markers))
            # Keep failed artifacts for diagnosis, without success receipts.
            self.assertTrue((output/'base/system.ufs').exists())

    def test_final_verification_failure(self):
        self.exercise('final-verification')

    def test_receipt_write_failure(self):
        self.exercise('second-receipt')

    def test_completion_record_failure(self):
        self.exercise('completion-record')

    def test_success_retains_receipts(self):
        self.exercise(None)


if __name__=='__main__': unittest.main()
