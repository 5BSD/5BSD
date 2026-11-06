# SPDX-License-Identifier: BSD-2-Clause
import unittest
from directory_metadata import normalize
from world_layout import merge


def attrs(**values):
    return dict(type='dir',uname='root',gname='wheel',mode='0755',**values)


class Layout(unittest.TestCase):
    def test_complete_physical_policy_selected_ownership(self):
        physical,claims,unselected=merge([('/',attrs()),('/dev',attrs(tags='package=runtime')),('/optional',attrs(tags='package=optional'))],{'runtime'},[])
        self.assertEqual(set(physical),{'/','/dev','/optional'})
        self.assertEqual([r['destination'] for r in claims],['/dev'])
        self.assertEqual(unselected[0]['package'],'optional')
        self.assertEqual(physical['/optional']['tags'],[])

    def test_suffix_and_literal_directory_owners(self):
        physical,claims,_=merge([('/',attrs()),('/include',attrs(tags='package=example,dev')),('/include',attrs(tags='package=example-dev'))],{'example-dev'},['dev'])
        self.assertEqual(len(claims),1)
        self.assertEqual(set(physical),{'/','/include'})

    def test_sticky_modes_and_explicit_flag_support(self):
        a=attrs();a.update(mode='01777',flags='schg')
        physical,_,_=merge([('/',a)],set(),[])
        self.assertEqual(physical['/']['mode'],'1777')
        self.assertEqual(physical['/']['flags'],'schg')
        with self.assertRaisesRegex(ValueError,'flags'):normalize(a)

    def test_conflict_or_unmodeled_object_rejected(self):
        a=attrs();b=attrs();b['mode']='0700'
        with self.assertRaisesRegex(ValueError,'conflicting'):merge([('/',a),('/',b)],set(),[])
        a['type']='link'
        with self.assertRaisesRegex(ValueError,'directory'):merge([('/',a)],set(),[])


if __name__=='__main__':unittest.main()
