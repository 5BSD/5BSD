#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
mkdir -p /root/software-regression-results
count=0
for program in libservice_api_test service_ambient_test software_identity_test anoint_test domain_test; do
 binary=/root/software-tests/$program
 "$binary" -l > /tmp/software-test-list
 for testcase in $(awk '$1 == "ident:" {print $2}' /tmp/software-test-list); do
  directory=/root/software-regression-results/$program.$testcase
  mkdir "$directory"
  if ! (cd "$directory" && timeout -k 5 30 "$binary" -r result "$testcase" > output 2>&1); then
   cat "$directory/output"
   [ ! -f "$directory/result" ] || cat "$directory/result"
   echo "Regression failed: $program.$testcase"
   exit 1
  fi
  if ! grep -qx passed "$directory/result"; then
   cat "$directory/result" "$directory/output"
   echo "Regression did not pass: $program.$testcase"
   exit 1
  fi
  printf 'SOFTWARE_CASE_PASS %s.%s\n' "$program" "$testcase"
  count=$((count + 1))
 done
done
[ "$count" -eq 74 ]
printf '%s\n' SOFTWARE_CLIENT_REGRESSIONS_PASS
# Exercise all parser/manifest cases on the installed architecture too.
policy_count=0
for program in lib/libcapbundle/api_test lib/libcapbundle/manifest_activation_test lib/libcapbundle/manifest_attributes_test lib/libcapbundle/management_test lib/libcapbundle/manifest_launch_test lib/libcapbundle/manifest_policy_test lib/libcapbundle/sysctl_isolate_test usr.sbin/switchboard/boot_authority_test; do
 binary=/usr/tests/$program
 "$binary" -l > /tmp/software-policy-test-list
 for testcase in $(awk '$1 == "ident:" {print $2}' /tmp/software-policy-test-list); do
  directory=$(mktemp -d /root/software-regression-results/policy.XXXXXX)
  if ! (cd "$directory" && timeout -k 5 120 "$binary" -r result "$testcase" > output 2>&1) || ! grep -qx passed "$directory/result"; then
   cat "$directory/output"
   [ ! -f "$directory/result" ] || cat "$directory/result"
   echo "Manifest regression failed: $program.$testcase"
   exit 1
  fi
  printf 'SOFTWARE_POLICY_CASE_PASS %s.%s\n' "$program" "$testcase"
  policy_count=$((policy_count + 1))
 done
done
[ "$policy_count" -eq 181 ]
printf '%s\n' SOFTWARE_MANIFEST_REGRESSIONS_PASS
# Even an attributed system-management client cannot restart a core provider.
if switchboardctl restart system.Time/bsdtime > /tmp/core-denial 2>&1; then
 cat /tmp/core-denial
 echo UNEXPECTED_CORE_MANAGEMENT
 exit 1
fi
cat /tmp/core-denial
grep -q 'is management class core and cannot be stopped at runtime' /tmp/core-denial
switchboardctl status > /tmp/core-status
awk '$1 == "system.Time/bsdtime" && $2 == "running" {found=1} END {exit !found}' /tmp/core-status
printf '%s\n' SOFTWARE_CORE_DENIAL_PASS
