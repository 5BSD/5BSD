#!/bin/sh
set -eu
exec > /dev/console 2>&1
trap 'code=$?; if [ "$code" -ne 0 ]; then echo SOFTWARE_APPLICATION_FAIL; tail -80 /var/log/capability.log; fi' EXIT
[ "$(hostname)" = auth-policy-vm ]
if [ -f /root/software-be-phase ]; then
 sh /root/software-be-guest.sh "$(cat /root/software-be-phase)"
 exit 0
fi
/usr/bin/authority-session-check check none
switchboardctl status
/usr/bin/application-probe check-application > /tmp/application-before
switchboardctl reload
/usr/bin/application-probe check-application > /tmp/application-after
cmp /tmp/application-before /tmp/application-after
su - policyuser -c 'set -e; /usr/bin/authority-session-check check none; /usr/bin/application-probe check-application; switchboardctl status'
env -i PATH=/bin:/usr/bin:/sbin:/usr/sbin /usr/sbin/switchboardctl status
/usr/bin/authority-session-check cleanexec /usr/sbin/switchboardctl status
cp /usr/sbin/switchboardctl /tmp/unapproved-control
if /tmp/unapproved-control status; then echo UNEXPECTED_COPY_AUTHORITY; exit 1; fi
printf '%s\n' SOFTWARE_APPLICATION_DISCOVERY_PASS
switchboardctl restart system.Trace/bsdtrace
kldstat -m dtrace
dtrace -qn 'BEGIN { printf("SOFTWARE_APPLICATION_DTRACE_PASS\n"); exit(0); }'
# A working control endpoint alone does not prove provider startup.
switchboardctl status > /tmp/software-service-status
for unit in system.Log/bsdlog system.Network/bsdnetwork system.Trace/bsdtrace system.Filesystem/bsdfilesystem system.Audit/bsdaudit system.Time/bsdtime system.SystemExtension/bsdextension system.Notify/bsdnotify system.Device/bsddevice system.Power/bsdpower system.Sysctl/bsdsysctl system.Crypto/bsdcrypto; do
    awk -v unit="$unit" '$1 == unit && $2 == "running" { found=1 } END { exit !found }' /tmp/software-service-status || {
        cat /tmp/software-service-status
        echo "Provider not running: $unit"
        exit 1
    }
done
printf '%s\n' SOFTWARE_APPLICATION_SERVICES_PASS
sh /root/software-unix-guest.sh
sh /root/software-regressions-guest.sh
sh /root/software-reload-guest.sh
sh /root/software-managed-guest.sh
sh /root/software-user-agent-guest.sh
sh /root/software-retired-package-guest.sh
if [ -f /root/software-be-guest.sh ]; then
 sh /root/software-be-guest.sh prepare
else
 printf '%s\n' SOFTWARE_APPLICATION_PASS
 /usr/sbin/capsulectl poweroff
fi
