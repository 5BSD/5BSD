#!/bin/sh
# Group containers e2e (docs/capability-container-model.md item 4):
#  A.cap, B.cap declare groups=["test.shared"]; C.cap does not.  Each runs a
#  groupprobe unit (A claims group claim "astate", B "bstate", C tries "cstate").
#  boot#1: Data/A/shared, Data/B/shared, Data/Shared/test.shared/{astate,bstate}
#          exist; cstate must NOT (C is not a member -> EPERM);
#          Run/groups/test.shared marker exists.
#  rm A.cap (watch unloads) + reboot: Data/A gone (incl shared), group container
#          SURVIVES (B still claims it), marker still there.
#  rm B.cap + reboot: Run/groups marker gone, Data/Shared/test.shared REAPED.
TOP=$(cd "$(dirname "$0")/.." && pwd); . "$TOP/lib/vmlib.sh"
stage() { # name bundle_id claim groups_line
  local TC=$R/Capabilities/System/$1.cap
  chmod -R u+w "$TC" 2>/dev/null; rm -rf "$TC"; mkdir -p "$TC/Units/groupprobe.unit/bin"
  cp "$PROBES/groupprobe" "$TC/Units/groupprobe.unit/bin/groupprobe"; chmod 0555 "$TC/Units/groupprobe.unit/bin/groupprobe"
  printf 'activation { boot = true; }\nprogram = "groupprobe";\narguments = ["%s"];\nrestart = "never";\nuser = "root";\n' "$3" > "$TC/Units/groupprobe.unit/Unit.ucl"
  printf 'schema = "org.5bsd.capability-bundle";\nschema_version = 1;\nbundle_id = "%s";\nversion = "1.0.0";\nsequence = 1;\nauthor = "5BSD";\npublisher = "org.5bsd.base";\nunits = ["groupprobe"];\n%s' "$2" "$4" > "$TC/Bundle.ucl"
  for p in "" /Bundle.ucl /Units /Units/groupprobe.unit /Units/groupprobe.unit/Unit.ucl /Units/groupprobe.unit/bin /Units/groupprobe.unit/bin/groupprobe; do
    case "$p" in *.ucl) t="type=file uname=root gname=wheel mode=0644";; *groupprobe) t="type=file uname=root gname=wheel mode=0555";; *) t="type=dir uname=root gname=wheel mode=0755";; esac
    echo "./Capabilities/System/$1.cap$p $t" >> "$R/METALOG"; done
}
echo "==> stage A, B (members), C (non-member)"
chmod u+w "$R/METALOG"; grep -vE 'Capabilities/System/(Test|A|B|C)\.cap' "$R/METALOG" > "$R/METALOG.new" && mv "$R/METALOG.new" "$R/METALOG"
for n in Test; do chmod -R u+w $R/Capabilities/System/$n.cap 2>/dev/null; rm -rf $R/Capabilities/System/$n.cap; done
stage A app.A astate 'groups = ["test.shared"];'
stage B app.B bstate 'groups = ["test.shared"];'
stage C app.C cstate ''
echo "==> build image"; build_image gr
echo "==> boot #1"
boot rw || exit 1
V "ps ax -o command | grep -c '[g]roupprobe' | sed 's/^/PROBES_UP=/'; ls /Capabilities/Run/groups 2>&1 | tr '\n' ' ' | sed 's/^/RUN_GROUPS=/'; echo" 15
V "zfs list -H -o name -r zroot/Capabilities/Data 2>&1 | grep -vE 'Data/Log' " 15
V "for d in A/shared/persistent/state B/shared/persistent/state Shared/test.shared/persistent/astate Shared/test.shared/persistent/bstate; do zfs list zroot/Capabilities/Data/\$d >/dev/null 2>&1 && echo \"HAVE \$d\" || echo \"MISSING \$d\"; done; zfs list zroot/Capabilities/Data/Shared/test.shared/persistent/cstate >/dev/null 2>&1 && echo NONMEMBER_CLAIM_EXISTS_FAIL || echo NONMEMBER_DENIED_PASS" 20
echo "==> remove A (watch unloads), settle, reboot"
V "chmod -R u+w /Capabilities/System/A.cap; rm -rf /Capabilities/System/A.cap; sleep 6; sync; sync; sleep 8" 30
boot rw || exit 1
V "grep -a 'reclaim:' /var/log/messages | tail -4" 12
V "zfs list zroot/Capabilities/Data/A >/dev/null 2>&1 && echo A_CONTAINER_PRESENT_FAIL || echo A_CONTAINER_REAPED_PASS; zfs list zroot/Capabilities/Data/Shared/test.shared/persistent/bstate >/dev/null 2>&1 && echo GROUP_SURVIVES_WITH_B_PASS || echo GROUP_REAPED_EARLY_FAIL; ls /Capabilities/Run/groups | grep -q test.shared && echo GROUP_MARKER_KEPT_PASS || echo GROUP_MARKER_LOST_FAIL" 20
echo "==> remove B (last member), settle, reboot"
V "chmod -R u+w /Capabilities/System/B.cap; rm -rf /Capabilities/System/B.cap; sleep 6; ls /Capabilities/Run/groups | grep -q test.shared && echo GROUP_MARKER_STILL_FAIL || echo GROUP_MARKER_DROPPED_PASS; sync; sync; sleep 8" 30
boot rw || exit 1
V "grep -a 'reclaim:' /var/log/messages | tail -4" 12
echo "=== verdicts ==="
V "zfs list zroot/Capabilities/Data/Shared/test.shared >/dev/null 2>&1 && echo GROUP_CONTAINER_PRESENT_FAIL || echo GROUP_CONTAINER_REAPED_PASS; zfs list zroot/Capabilities/Data/C >/dev/null 2>&1 && echo C_LIVE_PRESERVED_PASS || echo C_LIVE_MISSING_FAIL" 20
echo DONE
