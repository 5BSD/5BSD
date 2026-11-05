#!/bin/sh
# Preserve per-case verdicts only for a complete, consistent helper result.
[ "$#" -eq 3 ] || exit 2
awk -v rc="$2" -v wanted="$3" '
BEGIN { n=split("begin-end syscall-entry syscall-return syscall-exit proc-exec invalid-program", names, " "); for(i=1;i<=n;i++) expected[names[i]]=1 }
$1 == "DTRACE-CASE" {
 if (NF != 3 || !($2 in expected) || seen[$2]++ || ($3 != "PASS" && $3 != "FAIL")) bad=1
 result[$2]=$3; if ($3 == "FAIL") failed=1
}
$0 == "DTRACE-CASES-DONE" { done++ }
END {
 for(i=1;i<=n;i++) if(seen[names[i]] != 1) bad=1
 if(bad || done != 1 || rc != (failed ? 1 : 0)) exit 2
 exit (result[wanted] == "PASS" ? 0 : 1)
}' "$1"
