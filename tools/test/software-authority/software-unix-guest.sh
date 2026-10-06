#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
# These are disposable guest credentials, not host authentication changes.
cat > /home/policyuser/.profile <<'PROFILE'
set -e
/usr/bin/authority-session-check check none
/usr/bin/application-probe check-application
switchboardctl status
printf '%s\n' SOFTWARE_STOCK_LOGIN_PASS
exit
PROFILE
chown 2001:2001 /home/policyuser/.profile
chmod 0644 /home/policyuser/.profile
timeout -k 5 120 /usr/bin/policy-askpass policy-vm-only /usr/bin/login policyuser
: > /home/policyuser/.profile
ifconfig lo0 inet 127.0.0.1 up
ssh-keygen -A
ssh-keygen -q -t ed25519 -N '' -f /root/software-client-key
install -d -o 2001 -g 2001 -m 0700 /home/policyuser/.ssh
install -o 2001 -g 2001 -m 0600 /root/software-client-key.pub /home/policyuser/.ssh/authorized_keys
install -d -m 0700 /root/.ssh
install -m 0600 /root/software-client-key.pub /root/.ssh/authorized_keys
/usr/sbin/sshd -f /dev/null -p 2222 -o ListenAddress=127.0.0.1 -o UsePAM=yes -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes -o PermitRootLogin=yes -o PidFile=/var/run/software-sshd.pid -E /root/software-sshd.log
/usr/sbin/sshd -f /dev/null -p 2224 -o ListenAddress=127.0.0.1 -o UsePAM=no -o PasswordAuthentication=no -o PermitRootLogin=yes -o PidFile=/var/run/software-sshd-nopam.pid -E /root/software-sshd-nopam.log
for port in 2222 2224; do
 for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if nc -z 127.0.0.1 "$port"; then break; fi
  sleep 1
 done
 nc -z 127.0.0.1 "$port"
done
command='set -e; /usr/bin/authority-session-check check none; /usr/bin/application-probe check-application; switchboardctl status; /usr/bin/authority-session-check check none'
for method in password keyboard-interactive; do
 timeout -k 5 60 /usr/bin/policy-askpass policy-vm-only ssh -F /dev/null -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications="$method" -o PubkeyAuthentication=no policyuser@127.0.0.1 "$command" </dev/null
 printf 'SOFTWARE_SSH_%s_PASS\n' "$method"
done
for port in 2222 2224; do
 for user in root policyuser; do
  timeout -k 5 60 ssh -F /dev/null -p "$port" -i /root/software-client-key -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$user"@127.0.0.1 "$command"
 done
done
printf '%s\n' SOFTWARE_SSH_KEYS_WITH_AND_WITHOUT_PAM_PASS
# Root changes UNIX credentials here; the executed image supplies its own attributes.
su - policyuser -c 'set -e; /usr/bin/authority-session-check check none; /usr/bin/application-probe check-application; switchboardctl status'
/usr/bin/authority-session-check check none
# Exercise password-authenticated elevation as an ordinary UNIX wheel member.
# Wheel permits stock su; it does not grant capability attributes.
pw groupmod wheel -m policyuser
cat > /tmp/software-su-root-check.sh <<'ROOTCHECK'
#!/bin/sh
set -eu
[ "$(id -u)" = 0 ]
/usr/bin/authority-session-check check none
/usr/bin/application-probe check-application
switchboardctl status
/usr/bin/authority-session-check check none
ROOTCHECK
cat > /tmp/software-su-as-user.sh <<'USERCHECK'
#!/bin/sh
set -eu
[ "$(id -u)" = 2001 ]
/usr/bin/authority-session-check check none
timeout -k 5 60 /usr/bin/policy-askpass policy-vm-only /usr/bin/su root -c /tmp/software-su-root-check.sh
timeout -k 5 60 /usr/bin/policy-askpass policy-vm-only /usr/bin/su - root -c /tmp/software-su-root-check.sh
/usr/bin/authority-session-check check none
USERCHECK
chmod 0555 /tmp/software-su-root-check.sh /tmp/software-su-as-user.sh
su - policyuser -c /tmp/software-su-as-user.sh
rm -f /tmp/software-su-root-check.sh /tmp/software-su-as-user.sh
printf '%s\n' SOFTWARE_SU_PASSWORD_TRANSITIONS_PASS
printf '%s\n' SOFTWARE_STOCK_UNIX_PASS
