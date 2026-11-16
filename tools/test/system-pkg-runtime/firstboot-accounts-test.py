# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
import unittest
from firstboot_accounts import validate

class AccountChanges(unittest.TestCase):
    def setUp(self):
        self.master='root::0:0::0:0:Root:/root:/bin/zsh\ndaemon:*:1:1::0:0:Daemon:/root:/usr/sbin/nologin\n'
        self.group='wheel:*:0:root\nnogroup:*:65533:\n'
        self.actual=self.master.replace('root::','root:$6$root-salt$hash:').replace('/bin/zsh','/bin/sh')+'user:$6$user-salt$hash:2001:65533::0:0:User &:/home/user:/bin/sh\n'
        self.actual_group=self.group.replace('wheel:*:0:root','wheel:*:0:root,user')
        self.public='root:*:0:0:Root:/root:/bin/sh\ndaemon:*:1:1:Daemon:/root:/usr/sbin/nologin\nuser:*:2001:65533:User &:/home/user:/bin/sh\n'
        self.changes={'root':{'shell':'/bin/sh'},'user':dict(uid='2001',gid='65533',**{'class':'','change':'0','expire':'0'},gecos='User &',home='/home/user',shell='/bin/sh')}

    def check(self,master=None,group=None,public=None,authenticated=('root','user')):
        return validate(self.master,self.group,master or self.actual,group or self.actual_group,public or self.public,self.changes,{'wheel':['user']},authenticated)

    def test_exact_provisioning(self):
        self.assertEqual(self.check()['accounts'],3)
        self.assertEqual(self.check()['authenticated_password_accounts'],['root','user'])

    def test_unexplained_account_changes_rejected(self):
        for actual in (self.actual.replace('daemon:*:1:1','daemon:*:2:1'),
                       self.actual.replace('/home/user','/root'),
                       self.actual.replace('$6$root-salt$hash',''),
                       self.actual+'extra:*:2002:65533::0:0:Extra:/home/extra:/bin/sh\n',
                       self.actual.replace('daemon:*:','daemon:$6$unknown$hash:')):
            with self.subTest(actual=actual),self.assertRaises(ValueError):self.check(master=actual)

    def test_group_public_and_authentication_drift_rejected(self):
        for kwargs in ({'group':self.group},{'group':self.actual_group.replace('root,user','user')},
                       {'public':self.public.replace('user:*:2001','user:*:0')},
                       {'authenticated':('user',)}, {'authenticated':('root','user','extra')}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.check(**kwargs)

if __name__=='__main__':unittest.main()
