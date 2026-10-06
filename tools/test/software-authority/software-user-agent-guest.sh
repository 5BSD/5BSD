#!/bin/sh
set -eux
[ "$(hostname)" = auth-policy-vm ]
[ "$(id -u policyuser)" = 2001 ]
# Earlier su tests intentionally made this account a wheel member. Remove
# that fixture grant so a wheel group in the agent is an actual escalation.
pw groupmod wheel -d policyuser
su - policyuser -c 'test ! -r /root'
bundle=/Capabilities/Users/2001/Agents/Hostile.cap
unit=$bundle/Units/hostile.unit
mkdir -p "$unit/bin"
cat > "$bundle/Bundle.ucl" <<'EOF'
schema="org.5bsd.capability-bundle";
bundle_id="org.test.hostile-user";
version="1.0.0"; sequence=1; publisher="org.test"; units=["hostile"];
EOF
cat > "$unit/Unit.ucl" <<'EOF'
program="hostile";
activation { boot=true; }
user="root"; group="wheel"; control="core"; domain="system";
ambient=true; restart="never";
attributes=["system.switchboard.admin","system.trace.client"];
directories=["/root","/tmp"];
arguments=["hostile-user-agent"];
EOF
cp /usr/bin/authority-session-check "$unit/bin/hostile"
chown -R policyuser:policyuser /Capabilities/Users/2001
chmod -R go-w /Capabilities/Users/2001
wait_for_agent() {
 expected=$1
 tries=0
 while :; do
  count=$(grep -c '^SOFTWARE_HOSTILE_USER_AGENT_PROCESS_PASS$' /var/log/capability.log || :)
  [ "$count" -lt "$expected" ] || break
  tries=$((tries + 1))
  if [ "$tries" -ge 45 ]; then
   switchboardctl status
   tail -80 /var/log/capability.log
   echo HOSTILE_USER_AGENT_TIMEOUT
   exit 1
  fi
  sleep 1
 done
}
switchboardctl reload
wait_for_agent 1
# Restart from the same writable declaration must not restore its grants.
switchboardctl restart org.test.hostile-user/hostile
wait_for_agent 2
switchboardctl reload > /tmp/user-agent-noop-reload
grep -Eq '^reload: [0-9]+ bundles, 0 new, 0 changed, 0 removed$' /tmp/user-agent-noop-reload
rm -rf "$bundle"
switchboardctl reload
printf '%s\n' SOFTWARE_HOSTILE_USER_AGENT_PASS
