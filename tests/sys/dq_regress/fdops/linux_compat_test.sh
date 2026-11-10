# SPDX-License-Identifier: BSD-2-Clause
#
# Real Linux binaries (Rocky Linux 9 coreutils and util-linux, staged as
# test data under /compat/linux, never in base) against the descriptor
# kinds a shell can hand them, through /dev/fd/N (fdescfs mounted on
# /dev/fd for the case) and /proc/self/fd/N (linprocfs on
# /compat/linux/proc).  Every expectation is FreeBSD's behaviour at the
# project base 3b9f9873d291, cited per cell ("fv:" is
# sys/fs/fdescfs/fdesc_vnops.c, "lf:" sys/compat/linux/linux_file.c, "ls:"
# linux_stats.c, "vs:" sys/kern/vfs_syscalls.c, "sg:" sys/kern/sys_generic.c,
# all at 3b9f9873d291).  Where base hands the call to a filesystem the
# expectation is the same binary run on the vnode's own path (an oracle).
#
# Cells whose base value differs from the current tree (each fails on the
# current kernel until ux-0 restores it):
#   chown /dev/fd/N    pipe   base 0 (dropped)              now EINVAL   D232
#   touch -h /dev/fd/N pipe   base 0 (dropped)              now EINVAL   D232
#   chown /dev/fd/N    ptmx   base 0                        now EINVAL   D233
#   fallocate /dev/fd/N         fifo  base ENODEV (lf:2722, DTYPE_FIFO)
#   fallocate /proc/self/fd/N   fifo       now ESPIPE (fo_stat S_IFIFO)  D237*
#   (D237*: covered by D237's rule, not among its enumerated examples.)
#   (The chown and touch cells run the binary under ktrace and take the
#   return of the chown/utimensat call it made, so a binary that skips the
#   call fails the cell instead of passing it.)
#
# No chmod(1) cell on /dev/fd/N: Rocky's coreutils 8.32 chmod makes no
# chmod-family call for a /dev/fd/N operand.  ktrace -i on the host shows
# umask(0), linux_newfstatat(AT_FDCWD, "/dev/fd/3") = 0, then
# linux_exit_group(0), with exit status 0.  That is the binary's behaviour,
# not the kernel's.  The kernel's chmod through /dev/fd/N is covered by
# fdops_test:fdesc_setattr (native chmod(2)) and linux_fdops (fchmodat2 with
# AT_EMPTY_PATH).  chmod_procfd [reg] checks under ktrace that a Rocky chmod
# does reach the kernel through /proc/self/fd/N, which is linprocfs's link
# to the file (a plain path chmod, not a rewired path).
#
# Uncovered: flock(1) (util-linux flock) and getfattr/setfattr (attr) are
# not in the host's linux_base-rl9 nor in /var/cache/pkg, so the flock and
# xattr rows are covered only by linux_fdops (compiled program).
#
# Requirements: the overlay from stage-linux-compat.sh installed under
# /compat/linux (vm-provider LINUX_COMPAT_DIR), linux64 and fdescfs
# preloaded (the capability plane refuses a late kldload), linprocfs mounted
# on /compat/linux/proc for the /proc/self/fd cells (skipped otherwise).

L=/compat/linux/usr/bin
ncells=0
nfail=0

# cell NAME KIND WANT CITE -- command...
#   WANT is 0 or the Linux strerror text the tool must print.
cell()
{
	name=$1 kind=$2 want=$3 cite=$4
	shift 5
	ncells=$((ncells + 1))
	"$@" >cell.out 2>cell.err
	rc=$?
	if [ "$want" = 0 ]; then
		[ $rc -eq 0 ] && return 0
	elif [ $rc -ne 0 ] && grep -qF -- "$want" cell.err; then
		return 0
	fi
	nfail=$((nfail + 1))
	echo "FAIL $name [$kind]: exit $rc, stderr '$(tr '\n' ' ' <cell.err)'; base: $want ($cite)"
	return 1
}

# kcell NAME KIND REGEX CITE -- command...
#   The command runs a Linux binary under "ktrace -f ktr -t cn".  The cell
#   is the return of the first system call whose name matches REGEX
#   (kdump's RET record): base expects 0 for every kcell here.  A run with
#   no matching call fails the cell: the binary did not make the call.
kcell()
{
	name=$1 kind=$2 re=$3 cite=$4
	shift 5
	ncells=$((ncells + 1))
	rm -f ktr
	"$@" >cell.out 2>cell.err
	ret=$(kdump -f ktr 2>/dev/null | awk -v re="$re" \
	    '$3 == "RET" && $4 ~ re { print; exit }')
	if [ -z "$ret" ]; then
		nfail=$((nfail + 1))
		echo "FAIL $name [$kind]: no system call matching '$re' was made (stderr '$(tr '\n' ' ' <cell.err)'); base: 0 ($cite)"
		return 1
	fi
	# Any error return fails the cell.  kdump prints a Linux-ABI process's
	# error as the negated Linux errno ("errno -22"), a native one as
	# "errno 22".
	case "$ret" in
	*" errno "*) ;;
	*) return 0 ;;
	esac
	nfail=$((nfail + 1))
	echo "FAIL $name [$kind]: $(echo "$ret" | sed 's/^ *[0-9]* *[^ ]* *//'); base: 0 ($cite)"
	return 1
}

# effect NAME KIND GOT WANT CITE: where a successful call's change landed.
# Not a cell of its own; a mismatch fails the test case.
neffect=0
effect()
{
	[ "$3" = "$4" ] && return 0
	neffect=$((neffect + 1))
	echo "FAIL effect $1 [$2]: got '$3', base '$4' ($5)"
	return 1
}

# The descriptor kinds a shell can hand a Linux program as fd 3.  Each run
# uses fresh objects.  KIND names match fdops_test/linux_fdops.
mkobjs()
{
	rm -rf o && mkdir o
	printf '0123456789' > o/reg
	printf '0123456789' > o/reg_ro
	mkdir o/dir
	mkfifo o/fifo
}

# with KIND -- command (the command sees the kind as fd 3)
with()
{
	k=$1
	shift 2
	case $k in
	reg)	"$@" 3<>o/reg ;;
	reg_rdonly) "$@" 3<o/reg_ro ;;
	dir)	"$@" 3<o/dir ;;
	fifo)	"$@" 3<>o/fifo ;;
	pipe)	echo x | "$@" 3<&0 ;;
	devnull) "$@" 3<>/dev/null ;;
	ptmx)	"$@" 3<>/dev/ptmx ;;
	esac
}

# The vnode's own path, for oracles and for the values written back.
vpath()
{
	case $1 in
	reg) echo o/reg ;;
	reg_rdonly) echo o/reg_ro ;;
	dir) echo o/dir ;;
	fifo) echo o/fifo ;;
	devnull) echo /dev/null ;;
	ptmx) echo /dev/ptmx ;;
	*) echo "" ;;
	esac
}

atf_test_case linux_compat cleanup
linux_compat_head()
{
	atf_set "descr" "Rocky Linux binaries on /dev/fd/N and /proc/self/fd/N"
	atf_set "require.arch" "amd64"
	atf_set "require.kmods" "linux64 fdescfs"
	atf_set "require.progs" "ktrace kdump"
	atf_set "require.files" "$L/stat $L/truncate $L/touch $L/chmod $L/chown $L/sync $L/fallocate /compat/linux/lib64/ld-linux-x86-64.so.2"
	atf_set "require.user" "root"
	atf_set "timeout" "600"
}
linux_compat_body()
{
	mount -t fdescfs fdescfs /dev/fd ||
	    atf_skip "cannot mount fdescfs on /dev/fd (preload fdescfs)"
	touch mounted
	skipfifo=no
	case "$(atf_config_get pre1c no)" in
	[Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|1)
		[ "$(sysctl -n kern.features.invariants 2>/dev/null)" = 1 ] &&
		    skipfifo=yes ;;
	esac

	for k in reg reg_rdonly dir fifo pipe devnull ptmx; do
		mkobjs
		p=$(vpath $k)
		if [ -n "$p" ]; then
			mode=$(stat -f %Lp "$p")
			uid=$(stat -f %u "$p")
			mt=$(stat -f %.9Fm "$p")
		else
			mode=600 uid=0 mt=1000000000.0
		fi

		# chown and touch -h -m on /dev/fd/3: the fdesc node's
		# VOP_SETATTR, fdesc_setattr (fv:583-637).  Each runs under
		# ktrace(1); the cell is the return of the chown/utimensat call
		# the binary made (no such call fails the cell).  Both write back
		# the target's own owner and mtime (read from the vnode's path),
		# never fdescfs's node attributes.  No chmod(1) cell here: see
		# the header.
		case $k in
		pipe) cite="fv:612 getvnode_path EINVAL -> fv:619-626 dropped" ;;
		*) cite="fv:612, 630-633 VOP_SETATTR on the descriptor's vnode" ;;
		esac
		kcell chown_devfd $k 'chown' "$cite" \
		    -- with $k -- ktrace -f ktr -t cn $L/chown $uid /dev/fd/3
		kcell touch_devfd $k 'utimensat|utimes' "$cite" \
		    -- with $k -- ktrace -f ktr -t cn $L/touch -h -c -m -d "@$mt" /dev/fd/3

		# truncate(1): open (dupfdopen) then ftruncate (sg:667-688).
		case $k in
		reg) cell truncate_devfd $k 0 "sg:683 fo_truncate (own size)" \
		    -- with $k -- $L/truncate -s 10 /dev/fd/3 ;;
		reg_rdonly) cell truncate_devfd $k "Permission denied" \
		    "kern_descrip.c dupfdopen: write open of a read-only fd" \
		    -- with $k -- $L/truncate -s 10 /dev/fd/3 ;;
		pipe) cell truncate_devfd $k "Invalid argument" \
		    "sg:683 -> sys_pipe.c:1704 invfo_truncate" \
		    -- with $k -- $L/truncate -s 0 /dev/fd/3 ;;
		esac

		# sync -d: fdatasync -> kern_fsync (vs:3717-3735);
		# sync -f: syncfs -> fgetvp (ls:480-505).
		case $k in
		pipe)
			cell sync_d_devfd $k "Invalid argument" \
			    "vs:3723 -> 4632-4636 no vnode" \
			    -- with $k -- $L/sync -d /dev/fd/3
			cell sync_f_devfd $k "Invalid argument" \
			    "ls:485 fgetvp: no vnode" \
			    -- with $k -- $L/sync -f /dev/fd/3 ;;
		fifo|ptmx)
			if [ $skipfifo = yes ]; then
				echo "not run sync_d_devfd [$k]: base MPASS vs:3693 panics INVARIANTS"
			else
				cell sync_d_devfd $k 0 "vs:3686-3713 VOP_FDATASYNC" \
				    -- with $k -- $L/sync -d /dev/fd/3
			fi
			cell sync_f_devfd $k 0 "ls:485-504 VFS_SYNC" \
			    -- with $k -- $L/sync -f /dev/fd/3 ;;
		*)
			cell sync_d_devfd $k 0 "vs:3686-3713 VOP_FDATASYNC" \
			    -- with $k -- $L/sync -d /dev/fd/3
			cell sync_f_devfd $k 0 "ls:485-504 VFS_SYNC" \
			    -- with $k -- $L/sync -f /dev/fd/3 ;;
		esac

		# fallocate(1): open O_RDWR (dupfdopen), then fallocate(2):
		# linux_fallocate_check, lf:2702-2728.
		case $k in
		reg)
			$L/fallocate -l 4096 o/reg 2>oracle.err; orc=$?
			if [ $orc -eq 0 ]; then w=0; else
				w=$(sed -n 's/.*: //p' oracle.err | head -1); fi
			printf '0123456789' > o/reg
			cell fallocate_devfd $k "$w" \
			    "lf:2710-2727 VREG, FWRITE -> VOP_ALLOCATE (oracle: the path)" \
			    -- with $k -- $L/fallocate -l 4096 /dev/fd/3 ;;
		reg_rdonly|dir)
			cell fallocate_devfd $k "Permission denied" \
			    "dupfdopen: write open of a read-only fd" \
			    -- with $k -- $L/fallocate -l 4096 /dev/fd/3 ;;
		fifo)
			cell fallocate_devfd $k "No such device" \
			    "lf:2722-2724 DTYPE_FIFO is not DTYPE_VNODE: default ENODEV" \
			    -- with $k -- $L/fallocate -l 4096 /dev/fd/3 ;;
		pipe)
			cell fallocate_devfd $k "Illegal seek" \
			    "lf:2719-2721 DTYPE_PIPE" \
			    -- with $k -- $L/fallocate -l 4096 /dev/fd/3 ;;
		devnull)
			cell fallocate_devfd $k "No such device" \
			    "lf:2714-2715 DTYPE_VNODE not VREG" \
			    -- with $k -- $L/fallocate -l 4096 /dev/fd/3 ;;
		ptmx)
			cell fallocate_devfd $k "No such device" \
			    "lf:2722-2724 DTYPE_PTS: default ENODEV" \
			    -- with $k -- $L/fallocate -l 4096 /dev/fd/3 ;;
		esac
	done

	# /proc/self/fd/N (linprocfs symlinks to the vnode's path).
	if [ -d /compat/linux/proc/self ]; then
		mkobjs
		cell stat_procfd reg "regular file" "ls: statx follows the link" \
		    -- with reg -- sh -c "$L/stat -L -c %F /proc/self/fd/3 >&2; exit 1"
		cell stat_procfd dir "directory" "ls: statx follows the link" \
		    -- with dir -- sh -c "$L/stat -L -c %F /proc/self/fd/3 >&2; exit 1"
		cell stat_procfd fifo "fifo" "ls: statx follows the link" \
		    -- with fifo -- sh -c "$L/stat -L -c %F /proc/self/fd/3 >&2; exit 1"
		cell stat_procfd devnull "character special file" \
		    "ls: statx follows the link" \
		    -- with devnull -- sh -c "$L/stat -L -c %F /proc/self/fd/3 >&2; exit 1"
		cell fallocate_procfd fifo "No such device" \
		    "lf:2722-2724 a FIFO opened through the link is DTYPE_FIFO" \
		    -- with fifo -- $L/fallocate -l 4096 /proc/self/fd/3
		# chmod(1) through /proc/self/fd/3: linprocfs's link to the
		# file, so the call is a plain fchmodat on the file (not a rewired
		# path; kept so a Rocky chmod is shown to reach the kernel).
		m0=$(stat -f %Lp o/reg)
		m1=$(printf %o $((0$m0 ^ 1)))
		kcell chmod_procfd reg 'chmod' "vs:2974-3005 kern_fchmodat, setfmode" \
		    -- with reg -- ktrace -f ktr -t cn $L/chmod $m1 /proc/self/fd/3
		effect chmod_procfd reg "$(stat -f %Lp o/reg)" "$m1" \
		    "setfmode on the file"
		chmod "$m0" o/reg
		cell sync_d_procfd reg 0 "vs:3686-3713 VOP_FDATASYNC" \
		    -- with reg -- $L/sync -d /proc/self/fd/3
		$L/fallocate -l 4096 o/reg_ro 2>oracle.err; orc=$?
		if [ $orc -eq 0 ]; then w=0; else
			w=$(sed -n 's/.*: //p' oracle.err | head -1); fi
		cell fallocate_procfd reg "$w" \
		    "lf:2710-2727 VREG (oracle: the path)" \
		    -- with reg -- $L/fallocate -l 4096 /proc/self/fd/3
	else
		echo "not run: /proc/self/fd cells (linprocfs not mounted on /compat/linux/proc)"
	fi

	echo "linux_compat: $ncells cells, $nfail not as base, $neffect effects not as base"
	[ $nfail -eq 0 ] && [ $neffect -eq 0 ] ||
	    atf_fail "$nfail cells, $neffect effects not as base; see stdout"
}
linux_compat_cleanup()
{
	[ -f mounted ] && umount /dev/fd 2>/dev/null
	true
}

atf_init_test_cases()
{
	atf_add_test_case linux_compat
}
