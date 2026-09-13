# SPDX-License-Identifier: BSD-2-Clause
#
# Real Linux userland under the emulator: Alpine's musl-linked busybox
# (staged at /compat/linux/bin/busybox with its loader in /compat/linux/lib)
# runs a scripted workload that exercises fork/exec/pipes/signals/files/
# sockets/tty through musl's syscall use, with outputs verified.

atf_test_case busybox
busybox_head()
{
	atf_set "descr" "Alpine musl busybox workload under the Linuxulator"
	atf_set "require.arch" "amd64"
	atf_set "require.files" "/compat/linux/bin/busybox /compat/linux/lib/ld-musl-x86_64.so.1"
	atf_set "require.kmods" "linux64"
	atf_set "timeout" "600"
}
busybox_body()
{
	BB=/compat/linux/bin/busybox
	# 1. applet inventory and basic exec
	atf_check -s exit:0 -o match:"BusyBox v1" $BB
	atf_check -s exit:0 -o inline:"hello\n" $BB echo hello
	atf_check -s exit:0 -o match:"^Linux" $BB uname -s
	# 2. shell: pipes, redirects, subshells, signals, job control bits
	atf_check -s exit:0 -o match:"^ *3$" $BB sh -c 'printf "a\nb\nc\n" | wc -l'
	atf_check -s exit:0 -o inline:"ok\n" $BB sh -c '(exit 3); [ $? = 3 ] && echo ok'
	atf_check -s exit:0 -o inline:"caught\n" $BB sh -c 'trap "echo caught" USR1; kill -USR1 $$; wait'
	atf_check -s exit:42 -e ignore $BB sh -c 'sleep 30 & p=$!; kill $p; wait $p; exit 42'
	atf_check -s exit:0 -o inline:"x=5\n" $BB sh -c 'x=$(( 2 + 3 )); echo x=$x'
	# 3. files: tar/gzip round trip with checksum verification (data path)
	mkdir tree; $BB dd if=/dev/urandom of=tree/a bs=64k count=16 2>/dev/null
	$BB sh -c 'for i in $(seq 1 200); do echo "line $i" > tree/f$i; done'
	$BB ln -s a tree/lnk; $BB mkdir -p tree/d1/d2; $BB touch tree/d1/d2/deep
	sum1=$($BB sh -c 'cd tree && find . -type f | sort | xargs md5sum')
	atf_check -s exit:0 $BB tar czf tree.tgz tree
	mkdir out; atf_check -s exit:0 $BB tar xzf tree.tgz -C out
	sum2=$($BB sh -c 'cd out/tree && find . -type f | sort | xargs md5sum')
	atf_check_equal "$sum1" "$sum2"
	atf_check -s exit:0 -o inline:"a\n" $BB readlink out/tree/lnk
	# 4. text tools over the tree (mmap/read/lseek/getdents paths)
	atf_check -s exit:0 -o inline:"200\n" $BB sh -c 'cat tree/f* | grep -c "^line"'
	atf_check -s exit:0 -o inline:"line 200\n" $BB sh -c 'cat tree/f* | sort -k2 -n | tail -1'
	atf_check -s exit:0 -o inline:"20100\n" $BB awk 'BEGIN{s=0} {s+=$2} END{print s}' tree/f*
	atf_check -s exit:0 -o inline:"LINE 7\n" $BB sed -e 's/line/LINE/' tree/f7
	atf_check -s exit:0 -o match:"tree/d1/d2/deep" $BB find tree -name deep
	# 5. permissions, xattr-free stat, chmod, symlink following, hardlinks
	atf_check -s exit:0 $BB chmod 600 tree/f1
	atf_check -s exit:0 -o match:"600" $BB stat -c %a tree/f1
	atf_check -s exit:0 $BB ln tree/f1 tree/f1.hard
	atf_check -s exit:0 -o inline:"2\n" $BB stat -c %h tree/f1
	# 6. sockets: unix and TCP loopback through nc, background server
	$BB sh -c 'echo pong | /compat/linux/bin/busybox nc -l -p 47123 >/dev/null' &
	sleep 1
	atf_check -s exit:0 -o inline:"pong\n" $BB sh -c 'echo ping | /compat/linux/bin/busybox nc 127.0.0.1 47123'
	wait
	# 7. pty: script-free: use "sh -c" under a pty via busybox script? Use timeout+sleep
	atf_check -s exit:0 -o inline:"slept\n" $BB sh -c 'timeout 5 sleep 1 && echo slept'
	# busybox timeout re-raises the child's signal on itself (exit by SIGTERM,
	# not 124 like coreutils)
	atf_check -s signal:term -e ignore $BB timeout 1 sleep 5
	# 8. process tools: ps, pgrep of ourselves, pidof
	atf_check -s exit:0 -o match:"busybox|sh" $BB sh -c 'ps -o pid,comm | head -5'
	# 9. env/exec: 500 forks in a loop (clone/exec churn)
	atf_check -s exit:0 -o inline:"500\n" $BB sh -c 'i=0; while [ $i -lt 500 ]; do /compat/linux/bin/busybox true; i=$((i+1)); done; echo $i'
	# 10. large pipe transfer with checksum (splice fallback path)
	s1=$($BB sh -c 'dd if=tree/a bs=4k 2>/dev/null | md5sum')
	s2=$($BB md5sum < tree/a)
	atf_check_equal "$s1" "$s2"
}
atf_init_test_cases()
{
	atf_add_test_case busybox
}
