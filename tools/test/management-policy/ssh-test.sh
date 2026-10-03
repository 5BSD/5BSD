#!/bin/sh
# Entirely inside the disposable guest; no external network or host keys.
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
exec > /root/ssh-tests.log 2>&1
trap 'result=$?; trap - EXIT; [ ! -f /var/run/sshd-policy.pid ] || kill "$(cat /var/run/sshd-policy.pid)"; for log in /root/concurrent-user.log /root/concurrent-other.log; do [ ! -f "$log" ] || cat "$log" >> /root/ssh-tests.log; done; cat /root/ssh-tests.log > /dev/console; exit "$result"' EXIT
ssh-keygen -q -t ed25519 -N '' -f /root/policy-client-key
ssh-keygen -q -t ed25519 -N '' -f /root/policy-host-key
for user in policyuser otheruser adminuser alluser; do
    install -d -m 0700 -o "$user" -g policytest "/home/$user/.ssh"
    install -m 0600 -o "$user" -g policytest /root/policy-client-key.pub "/home/$user/.ssh/authorized_keys"
done
cat > /root/sshd-policy.conf <<'EOF'
ListenAddress 127.0.0.1
Port 2222
HostKey /root/policy-host-key
PidFile /var/run/sshd-policy.pid
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowUsers policyuser otheruser adminuser alluser
AllowTcpForwarding no
X11Forwarding no
Subsystem sftp internal-sftp
LogLevel VERBOSE
EOF
/usr/sbin/sshd -t -f /root/sshd-policy.conf
/usr/sbin/sshd -f /root/sshd-policy.conf -E /root/sshd.log
# Pin the freshly generated guest host key, without accepting unknown hosts.
awk '{print "[127.0.0.1]:2222 " $1 " " $2}' /root/policy-host-key.pub > /root/policy-known-hosts
cat > /root/ssh-client.conf <<'EOF'
Host policy-vm
    HostName 127.0.0.1
    Port 2222
    IdentityFile /root/policy-client-key
    IdentitiesOnly yes
    UserKnownHostsFile /root/policy-known-hosts
    StrictHostKeyChecking yes
    ConnectTimeout 10
    ConnectionAttempts 1
    NumberOfPasswordPrompts 1
EOF
for user in policyuser otheruser; do
    timeout 120 ssh -F /root/ssh-client.conf -o BatchMode=yes "$user@policy-vm" \
        'sh /usr/src/tools/test/management-policy/session-test.sh'
done
# ADMIN-only authority must not permit arbitrary session minting.
timeout 60 ssh -F /root/ssh-client.conf -o BatchMode=yes adminuser@policy-vm \
    'set -e; /usr/bin/policy-probe mint 0 1; /usr/bin/policy-probe open system.Trace 2; /usr/bin/policy-probe stop test.policy.network/worker 1'
# A deliberately all-granted non-root user retains its actual session identity.
timeout 60 ssh -F /root/ssh-client.conf -o BatchMode=yes alluser@policy-vm \
    'test "$(id -u)" = 2004 && switchboardctl tree' > /root/all-user-tree.log
grep -q 'session uid=2004' /root/all-user-tree.log
echo ALL_GRANT_IDENTITY_PASS
echo SSH_KEY_SESSIONS_PASS
# Password authentication over SSH exercises PAM as well as session minting.
timeout 120 policy-askpass policy-vm-only ssh -F /root/ssh-client.conf \
    -o PubkeyAuthentication=no policyuser@policy-vm \
    'sh /usr/src/tools/test/management-policy/session-test.sh'
echo SSH_PASSWORD_SESSION_PASS
if timeout 30 policy-askpass wrong-vm-password ssh -F /root/ssh-client.conf \
    -o PubkeyAuthentication=no policyuser@policy-vm true; then
    echo 'wrong SSH password was accepted'; exit 1
else
    result=$?
    [ "$result" = 255 ] || exit 1
fi
grep -q 'Failed password for policyuser' /root/sshd.log
echo SSH_BAD_PASSWORD_DENIED_PASS
# Test a password-authenticated login(1) shell on a real pseudo-terminal.
timeout 120 env POLICY_TEST_LOGIN=1 policy-askpass policy-vm-only \
    /usr/bin/login -p policyuser > /root/login-test.log 2>&1
cat /root/login-test.log
grep -q PASSWORD_LOGIN_PASS /root/login-test.log
# Exercise actual endpoint elevation, with no uid change or parent-shell grant.
su -l policyuser -c 'set -e
    /usr/bin/policy-probe open system.Notify.System 2
    timeout 30 policy-askpass policy-vm-only anoint system.notify.system /bin/sh /usr/src/tools/test/management-policy/elevated-test.sh
    /usr/bin/policy-probe open system.Notify.System 2
    if timeout 30 policy-askpass wrong-vm-password anoint system.notify.system /usr/bin/true; then exit 1; else [ "$?" = 1 ]; fi
    if anoint -n system.storage.admin /usr/bin/true; then exit 1; else [ "$?" = 1 ]; fi
'
echo SESSION_ELEVATION_PASS
# SFTP exercises a subsystem session and UNIX ownership on newly written files.
printf 'sftp compatibility\n' > /root/sftp-data
printf 'put /root/sftp-data incoming\nget incoming /root/sftp-return\n' > /root/sftp-batch
timeout 60 sftp -F /root/ssh-client.conf -b /root/sftp-batch policyuser@policy-vm
cmp /root/sftp-data /root/sftp-return
[ "$(stat -f %u /home/policyuser/incoming)" = 2001 ]
echo SSH_SFTP_PASS
# Simultaneous sessions must retain their distinct grants despite shared gid.
timeout 60 ssh -F /root/ssh-client.conf -o BatchMode=yes policyuser@policy-vm \
    'set -e; for n in 1 2 3; do /usr/bin/policy-probe open system.Trace 0; /usr/bin/policy-probe stop test.policy.storage/worker 1; done' > /root/concurrent-user.log 2>&1 &
first=$!
timeout 60 ssh -F /root/ssh-client.conf -o BatchMode=yes otheruser@policy-vm \
    'set -e; for n in 1 2 3; do /usr/bin/policy-probe open system.Trace 2; /usr/bin/policy-probe open system.Notify 0; done' > /root/concurrent-other.log 2>&1 &
second=$!
wait "$first"
wait "$second"
cat /root/concurrent-user.log /root/concurrent-other.log
echo SSH_CONCURRENT_GRANTS_PASS
# An unrelated key cannot authenticate, even for an otherwise allowed account.
ssh-keygen -q -t ed25519 -N '' -f /root/wrong-client-key
if timeout 30 ssh -F /dev/null -p 2222 -i /root/wrong-client-key \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 \
    -o UserKnownHostsFile=/root/policy-known-hosts -o StrictHostKeyChecking=yes \
    policyuser@127.0.0.1 true > /root/wrong-key.log 2>&1; then
    echo 'untrusted SSH key was accepted'; exit 1
else
    result=$?
    [ "$result" = 255 ] || exit 1
fi
cat /root/wrong-key.log
grep -q 'Permission denied' /root/wrong-key.log
grep -q 'Failed publickey for policyuser' /root/sshd.log
echo SSH_WRONG_KEY_DENIED_PASS
echo SSH_COMPAT_PASS
