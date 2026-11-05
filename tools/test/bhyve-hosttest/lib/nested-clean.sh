#!/bin/sh
# Compare retained dmesg suffix with the next snapshot; fail on lost continuity.
[ "$#" -eq 3 ] || exit 2
for f in "$@"; do [ -r "$f" ] || { echo "UNREADABLE: $f"; exit 2; }; done
awk '
{ sub(/\r$/, "") }
NF == 0 { next }
FNR == NR { before[++nb]=$0; next }
{ after[++na]=$0 }
END {
 limit=(nb < na ? nb : na)
 for(k=limit;k>=3;k--) {
  same=1
  for(i=1;i<=k;i++) if(before[nb-k+i] != after[i]) { same=0; break }
  if(same) break
 }
 if(k<3) { print "DMESG-UNVERIFIED: no retained baseline suffix"; exit 2 }
 for(i=k+1;i<=na;i++) if(tolower(after[i]) ~ /vmm|svm|vmx|error|panic|fault|lock order|witness|eopnotsupp/) { print after[i]; bad=1 }
 exit bad ? 1 : 0
}' "$1" "$2"
rc=$?
[ "$rc" -eq 0 ] || exit "$rc"
grep -q '[^[:space:]]' "$3"
case $? in
0) cat "$3"; exit 1 ;;
1) exit 0 ;;
*) echo "INVENTORY-UNVERIFIED: $3"; exit 2 ;;
esac
