#!/bin/sh
# Tagged guest workload for HyperTrace: runs a uniquely named program in a
# loop so host-side aggregations keyed on execname can be asserted.
# usage: workload.sh TAG SECONDS
tag=${1:-htwork} secs=${2:-30}
d=/tmp/htw.$$; mkdir -p $d; cp /bin/echo "$d/$tag"
end=$(( $(date +%s) + secs ))
n=0
while [ "$(date +%s)" -lt "$end" ]; do "$d/$tag" x > /dev/null; n=$((n + 1)); done
rm -rf $d
echo "WORKLOAD tag=$tag runs=$n"
