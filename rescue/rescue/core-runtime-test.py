# SPDX-License-Identifier: BSD-2-Clause
"""Safe real rescue application dispatch with private files and stdin only."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PROGRAM = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / "rescue/rescue/rescue_core"

class RescueCore(unittest.TestCase):
    def run_app(self, *args, data=b"", name=None, cwd=None, environment=None):
        env = dict(os.environ, DTRACE_DOF_INIT_DISABLE="1", LC_ALL="C")
        if environment:
            env.update(environment)
        # This binary is statically linked. No host library/path fallback is used.
        return subprocess.run([name or str(PROGRAM), *args], executable=str(PROGRAM),
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=cwd, timeout=10, check=False)

    def test_catalog(self):
        p = self.run_app("--list")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(set(p.stdout.split()), {b'cat', b'chflags', b'chmod', b'cp', b'echo', b'ed', b'expr', b'getfacl', b'hostname', b'ln', b'mkdir', b'mv', b'pwd', b'realpath', b'rm', b'rmdir', b'sleep', b'test', b'head', b'date', b'chio', b'kenv', b'setfacl', b'stty', b'kill', b'sync', b'dd', b'ls', b'df', b'ps', b'pkill', b'tail', b'tee', b'id', b'chroot', b'chown', b'kldload', b'kldunload', b'kldstat', b'kldconfig', b'dmesg', b'rcorder', b'mknod', b'devfs', b'mount_cd9660', b'mount_nullfs', b'mount_unionfs', b'swapon', b'mdconfig', b'clri', b'fsirand', b'dumpfs', b'tunefs', b'newfs', b'fsck', b'newfs_msdos', b'umount', b'sed', b'gzip', b'bzip2', b'mt', b'md5', b'ldconfig', b'sysctl', b'fsck_msdosfs', b'xz', b'zstd', b'less', b'rtsol', b'mount_msdosfs', b'route', b'reboot', b'shutdown', b'dumpon', b'savecore', b'mount', b'mdmfs', b'nos-tun', b'nc', b'fetch', b'fastboot', b'halt', b'fasthalt', b'nextboot', b'poweroff', b'more', b'unxz', b'lzma', b'unlzma', b'xzcat', b'lzcat', b'unzstd', b'zstdcat', b'zstdmt', b'gunzip', b'gzcat', b'zcat', b'bunzip2', b'bzcat', b'pgrep', b'groups', b'whoami', b'chgrp', b'red', b'link', b'unlink', b'['})

    def test_echo(self):
        p = self.run_app("echo", "alpha", "beta")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha beta\n", b""))

    def test_echo_without_newline(self):
        p = self.run_app("echo", "-n", "alpha")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha", b""))

    def test_cat_binary_stdin(self):
        data = b"a\x00b\n" * 1000
        p = self.run_app("cat", data=data)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, data, b""))

    def test_cat_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"one\ntwo\n")
            p = self.run_app("cat", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"one\ntwo\n", b""))

    def test_head_stdin(self):
        p = self.run_app("head", "-n", "2", data=b"one\ntwo\nthree\n")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"one\ntwo\n", b""))

    def test_head_scaled_byte_count(self):
        p = self.run_app("head", "-c", "1k", data=b"x" * 2048)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"x" * 1024, b""))

    def test_head_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"one\ntwo\nthree\n")
            p = self.run_app("head", "-n", "1", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"one\n", b""))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "absent"
            p = self.run_app("cat", str(path))
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b"")
            self.assertIn(str(path).encode(), p.stderr)

    def test_unknown_program(self):
        p = self.run_app("missing-program")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_argv0_dispatch(self):
        p = self.run_app("alpha", "beta", name="echo")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha beta\n", b""))

    def test_pwd_private_directory(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            p = self.run_app("pwd", "-P", cwd=d)
            self.assertEqual((p.returncode, p.stdout, p.stderr),
                (0, (str(Path(d).resolve()) + "\n").encode(), b""))

    def test_expr_arithmetic(self):
        p = self.run_app("expr", "3", "+", "4")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"7\n", b""))

    def test_expr_regex(self):
        p = self.run_app("expr", "alpha", ":", "a.*")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"5\n", b""))

    def test_expr_overflow(self):
        p = self.run_app("expr", "9223372036854775807", "+", "1")
        self.assertEqual((p.returncode, p.stdout), (2, b""))
        self.assertIn(b"overflow", p.stderr)

    def test_test_true_and_false(self):
        p = self.run_app("test", "7", "-gt", "6")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
        p = self.run_app("test")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (1, b"", b""))

    def test_bracket_alias(self):
        p = self.run_app("[", "-n", "value", "]")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))

    def test_bracket_requires_closing_token(self):
        p = self.run_app("[", "-n", "value")
        self.assertEqual((p.returncode, p.stdout), (2, b""))
        self.assertIn(b"missing ']'", p.stderr)

    def test_ed_private_edit(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"alpha\n")
            p = self.run_app("ed", "-s", str(path), data=b"1s/alpha/beta/\nw\nq\n")
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(path.read_bytes(), b"beta\n")

    def test_red_alias(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            (Path(d) / "input").write_bytes(b"alpha\n")
            p = self.run_app("red", "-s", "input", data=b"1p\nq\n", cwd=d)
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha\n", b""))

    def test_getfacl_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("getfacl", str(path))
            self.assertEqual((p.returncode, p.stderr), (0, b""))
            self.assertIn(b"# file: " + str(path).encode(), p.stdout)

    def test_hostname_readonly(self):
        p = self.run_app("hostname")
        self.assertEqual((p.returncode, p.stdout, p.stderr),
            (0, (os.uname().nodename + "\n").encode(), b""))

    def test_ln_private_hardlink(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"private\n")
            p = self.run_app("ln", str(source), str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(source.stat().st_ino, dest.stat().st_ino)
            self.assertEqual(dest.read_bytes(), b"private\n")

    def test_link_alias_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"alias\n")
            p = self.run_app("link", str(source), str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(source.stat().st_ino, dest.stat().st_ino)

    def test_ln_private_symbolic_link(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            dest = Path(d) / "dest"
            p = self.run_app("ln", "-s", "relative-target", str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(os.readlink(dest), "relative-target")

    def test_mkdir_private_parents_mode(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            target = Path(d) / "parent" / "child"
            p = self.run_app("mkdir", "-p", "-m", "0700", str(target))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertTrue(target.is_dir())
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_realpath_private_symlink(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"private\n")
            dest.symlink_to("source")
            p = self.run_app("realpath", str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr),
                (0, (str(source.resolve()) + "\n").encode(), b""))

    def test_rmdir_private_empty(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            target = Path(d) / "empty"
            target.mkdir()
            p = self.run_app("rmdir", str(target))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertFalse(target.exists())

    def test_rmdir_rejects_nonempty(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            target = Path(d) / "nonempty"
            target.mkdir()
            (target / "input").write_bytes(b"retained\n")
            p = self.run_app("rmdir", str(target))
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual((target / "input").read_bytes(), b"retained\n")

    def test_sleep_zero(self):
        p = self.run_app("sleep", "0")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))

    def test_sleep_rejects_invalid(self):
        p = self.run_app("sleep", "invalid")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, b"")
        self.assertTrue(p.stderr)

    def test_chflags_private_nodump(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("chflags", "nodump", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertTrue(path.stat().st_flags & 1)  # UF_NODUMP
            p = self.run_app("chflags", "0", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(path.stat().st_flags, 0)

    def test_chflags_rejects_invalid_flag(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"unchanged\n")
            original = path.stat().st_flags
            p = self.run_app("chflags", "not-a-file-flag", str(path))
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(path.stat().st_flags, original)
            self.assertEqual(path.read_bytes(), b"unchanged\n")

    def test_chmod_private_numeric_mode(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("chmod", "0640", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_chmod_private_symbolic_mode(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("chmod", "u=rw,go=", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_cp_private_preserves_file_mode(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"copy data\x00\xff\n")
            source.chmod(0o640)
            p = self.run_app("cp", "-p", str(source), str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(dest.read_bytes(), source.read_bytes())
            self.assertEqual(dest.stat().st_mode & 0o777, 0o640)

    def test_cp_private_recursive_symlink(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.mkdir()
            (source / "input").write_bytes(b"tree\n")
            (source / "alias").symlink_to("input")
            p = self.run_app("cp", "-R", "-P", str(source), str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual((dest / "input").read_bytes(), b"tree\n")
            self.assertEqual(os.readlink(dest / "alias"), "input")

    def test_cp_private_no_clobber(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"new\n")
            dest.write_bytes(b"retained\n")
            p = self.run_app("cp", "-n", str(source), str(dest))
            # Original copy_file reports a skipped existing destination as 1.
            self.assertEqual((p.returncode, p.stdout, p.stderr), (1, b"", b""))
            self.assertEqual(dest.read_bytes(), b"retained\n")

    def test_mv_private_same_filesystem_rename(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"renamed\n")
            inode = source.stat().st_ino
            p = self.run_app("mv", str(source), str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertFalse(source.exists())
            self.assertEqual(dest.stat().st_ino, inode)
            self.assertEqual(dest.read_bytes(), b"renamed\n")

    def test_mv_private_no_clobber(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, dest = Path(d) / "source", Path(d) / "dest"
            source.write_bytes(b"source retained\n")
            dest.write_bytes(b"dest retained\n")
            p = self.run_app("mv", "-n", str(source), str(dest))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(source.read_bytes(), b"source retained\n")
            self.assertEqual(dest.read_bytes(), b"dest retained\n")

    def test_rm_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("rm", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertFalse(path.exists())

    def test_unlink_private_alias(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("unlink", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertFalse(path.exists())

    def test_rm_private_recursive_tree(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            tree = Path(d) / "tree"
            (tree / "nested").mkdir(parents=True)
            (tree / "nested" / "input").write_bytes(b"private\n")
            p = self.run_app("rm", "-r", str(tree))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertFalse(tree.exists())

    def test_date_epoch_read_only(self):
        p = self.run_app("date", "-u", "-r", "0", "+%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"1970-01-01T00:00:00Z\n", b""))

    def test_date_parse_without_setting_clock(self):
        p = self.run_app("date", "-j", "-u", "-f", "%Y-%m-%d", "2024-02-29", "+%Y%m%d")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"20240229\n", b""))

    def test_dd_binary_stdin(self):
        data = bytes(range(256)) * 3
        p = self.run_app("dd", "bs=17", "status=none", data=data)
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, data, b""))

    def test_dd_conversion(self):
        p = self.run_app("dd", "bs=4", "conv=swab", "status=none", data=b"abcdefgh")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"badcfehg", b""))

    def test_dd_private_sparse_output(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "output"
            data = b"\0" * 4096 + b"private\n"
            p = self.run_app("dd", "bs=4096", "conv=sparse", "status=none", "of=" + str(path), data=data)
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(path.read_bytes(), data)

    def test_kill_signal_names_without_signalling(self):
        p = self.run_app("kill", "-l", "15")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"TERM\n", b""))

    def test_kill_rejects_invalid_signal_without_signalling(self):
        p = self.run_app("kill", "-l", "999999")
        self.assertNotEqual(p.returncode, 0)

    def test_stty_requires_terminal(self):
        p = self.run_app("stty", "-a")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stderr, b"stty: stdin isn't a terminal\n")

    def test_chio_usage_without_opening_hardware(self):
        p = self.run_app("chio")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_kenv_invalid_option_without_changing_environment(self):
        p = self.run_app("kenv", "-Z")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_setfacl_rejects_invalid_acl_on_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            before = path.stat().st_mode
            p = self.run_app("setfacl", "-m", "invalid", str(path))
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(path.stat().st_mode, before)
            self.assertEqual(path.read_bytes(), b"private\n")

    def test_ls_private_directory(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            (Path(d) / "alpha").write_bytes(b"a")
            (Path(d) / "beta").mkdir()
            p = self.run_app("ls", "-1", d)
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha\nbeta\n", b""))

    def test_df_private_path(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            p = self.run_app("df", "-P", d)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(b"Filesystem", p.stdout)

    def test_ps_own_parent_without_modification(self):
        p = self.run_app("ps", "-p", str(os.getpid()), "-o", "pid=")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), str(os.getpid()).encode())

    def test_pkill_usage_without_signalling(self):
        p = self.run_app("pkill")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_tail_standard_input(self):
        p = self.run_app("tail", "-n", "2", data=b"one\ntwo\nthree\n")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"two\nthree\n", b""))

    def test_tail_private_binary_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(bytes(range(256)))
            p = self.run_app("tail", "-c", "17", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, bytes(range(239, 256)), b""))

    def test_tee_private_append(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "output"
            path.write_bytes(b"before\n")
            p = self.run_app("tee", "-a", str(path), data=b"after\n")
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"after\n", b""))
            self.assertEqual(path.read_bytes(), b"before\nafter\n")

    def test_id_numeric_credentials(self):
        p = self.run_app("id", "-u")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, str(os.geteuid()).encode() + b"\n", b""))

    def test_chroot_usage_without_changing_root(self):
        p = self.run_app("chroot")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_chown_current_identity_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"private\n")
            p = self.run_app("chown", str(os.geteuid()) + ":" + str(os.getegid()), str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (os.geteuid(), os.getegid()))
            self.assertEqual(path.read_bytes(), b"private\n")

    def test_system_programs_reject_invalid_option_before_mutation(self):
        programs = ["kldload", "kldunload", "kldstat", "kldconfig", "dmesg", "devfs",
                    "mount_cd9660", "mount_nullfs", "mount_unionfs", "swapon", "mdconfig"]
        for name in programs:
            with self.subTest(program=name):
                p = self.run_app(name, "-Z")
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b"usage:", p.stderr)

    def test_mknod_rejects_invalid_type_before_device_creation(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "invalid-device"
            p = self.run_app("mknod", str(path), "invalid", "1", "2")
            self.assertEqual(p.returncode, 1)
            self.assertIn(b"node must be type 'b' or 'c'", p.stderr)
            self.assertFalse(path.exists())

    def test_rcorder_private_dependency_graph(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            first, second = Path(d) / "first", Path(d) / "second"
            first.write_text("# PROVIDE: first\n# REQUIRE: second\n")
            second.write_text("# PROVIDE: second\n")
            p = self.run_app("rcorder", str(first), str(second))
            self.assertEqual((p.returncode, p.stdout, p.stderr),
                (0, (str(second) + "\n" + str(first) + "\n").encode(), b""))

    def test_rcorder_private_cycle_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            first, second = Path(d) / "first", Path(d) / "second"
            first.write_text("# PROVIDE: first\n# REQUIRE: second\n")
            second.write_text("# PROVIDE: second\n# REQUIRE: first\n")
            p = self.run_app("rcorder", str(first), str(second))
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(b"Circular dependency", p.stderr)

    def test_filesystem_program_usage_before_opening_devices(self):
        for name in ["clri", "fsirand", "dumpfs", "tunefs", "newfs", "newfs_msdos", "umount"]:
            with self.subTest(program=name):
                p = self.run_app(name)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b"usage:", p.stderr)
        p = self.run_app("fsck", "-Z")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)

    def test_private_ufs_image_tools(self):
        # Absolute paths identify existing regular files; -p selects newfs's
        # maintained file-image mode. No mount, host device or system fstab.
        for version in ["1", "2"]:
            with self.subTest(ufs=version), tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
                path = Path(d) / "private.ufs"
                with path.open("wb") as f:
                    f.truncate(16 * 1024 * 1024)
                p = self.run_app("newfs", "-O", version, "-b", "4096", "-f", "512", "-i", "4096", "-m", "0", "-p", "a", str(path))
                self.assertEqual(p.returncode, 0, p.stderr)
                p = self.run_app("dumpfs", "-s", str(path))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(("(UFS" + version + ")").encode(), p.stdout)
                p = self.run_app("tunefs", "-L", "rescue_test", str(path))
                self.assertEqual(p.returncode, 0, p.stderr)
                p = self.run_app("dumpfs", "-s", str(path))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(b"rescue_test", p.stdout)
                p = self.run_app("fsirand", "-b", str(path))
                self.assertEqual(p.returncode, 0, p.stderr)
                p = self.run_app("clri", str(path), "2")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(b"clearing 2", p.stdout)
                self.assertEqual(path.stat().st_size, 16 * 1024 * 1024)

    def test_private_fat_image_creation(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "private.fat"
            p = self.run_app("newfs_msdos", "-C", "4M", "-F", "12", str(path))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(path.stat().st_size, 4 * 1024 * 1024)
            with path.open("rb") as f:
                boot = f.read(512)
            self.assertEqual(boot[510:512], b"\x55\xaa")
            before = path.read_bytes()
            p = self.run_app("fsck_msdosfs", "-n", str(path))
            self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
            self.assertEqual(path.read_bytes(), before)

    def test_sed_extended_expression(self):
        p = self.run_app("sed", "-E", "s/([0-9]+)/[\\1]/g", data=b"alpha12 beta3\n")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"alpha[12] beta[3]\n", b""))

    def test_sed_private_inplace(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"before\n")
            p = self.run_app("sed", "-i", ".bak", "s/before/after/", str(path))
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"", b""))
            self.assertEqual(path.read_bytes(), b"after\n")
            self.assertEqual(Path(str(path) + ".bak").read_bytes(), b"before\n")

    def test_compression_roundtrip(self):
        data = bytes(range(256)) * 64 + b"private rescue compression\n"
        for name in ["gzip", "bzip2"]:
            with self.subTest(program=name):
                p = self.run_app(name, "-c", data=data)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertNotEqual(p.stdout, data)
                decoded = self.run_app(name, "-d", "-c", data=p.stdout)
                self.assertEqual((decoded.returncode, decoded.stdout, decoded.stderr), (0, data, b""))

    def test_compression_aliases(self):
        data = b"alias dispatch\n" * 100
        for program, aliases in [("gzip", ["gunzip", "gzcat", "zcat"]), ("bzip2", ["bunzip2", "bzcat"])]:
            compressed = self.run_app(program, "-c", data=data)
            self.assertEqual(compressed.returncode, 0, compressed.stderr)
            for alias in aliases:
                with self.subTest(alias=alias):
                    p = self.run_app(alias, "-c", data=compressed.stdout)
                    self.assertEqual((p.returncode, p.stdout, p.stderr), (0, data, b""))

    def test_md5_known_vector(self):
        p = self.run_app("md5", "-q", data=b"abc")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"900150983cd24fb0d6963f7d28e17f72\n", b""))

    def test_sysctl_readonly_osrelease(self):
        p = self.run_app("sysctl", "-n", "kern.osrelease")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, os.uname().release.encode() + b"\n", b""))

    def test_tape_and_linker_usage_before_open_or_write(self):
        for name in ["mt", "ldconfig"]:
            with self.subTest(program=name):
                p = self.run_app(name, "-Z")
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b"usage:", p.stderr)

    def test_xz_two_worker_roundtrip(self):
        data = bytes(range(256)) * (3 * 4096)
        p = self.run_app("xz", "-0", "-T2", "--block-size=1MiB", "-c", data=data)
        self.assertEqual(p.returncode, 0, p.stderr)
        decoded = self.run_app("xz", "-d", "-c", data=p.stdout)
        self.assertEqual((decoded.returncode, decoded.stdout, decoded.stderr), (0, data, b""))

    def test_zstd_two_worker_roundtrip(self):
        data = bytes(range(256)) * (3 * 4096)
        p = self.run_app("zstd", "-q", "-1", "-T2", "-B1M", "-c", data=data)
        self.assertEqual(p.returncode, 0, p.stderr)
        decoded = self.run_app("zstd", "-q", "-d", "-c", data=p.stdout)
        self.assertEqual((decoded.returncode, decoded.stdout, decoded.stderr), (0, data, b""))

    def test_xz_aliases(self):
        data = b"XZ alias dispatch\n" * 100
        for encoder, aliases in [("xz", ["unxz", "xzcat"]), ("lzma", ["unlzma", "lzcat"])]:
            p = self.run_app(encoder, "-c", data=data)
            self.assertEqual(p.returncode, 0, p.stderr)
            for alias in aliases:
                with self.subTest(alias=alias):
                    decoded = self.run_app(alias, "-c", data=p.stdout)
                    self.assertEqual((decoded.returncode, decoded.stdout, decoded.stderr), (0, data, b""))

    def test_zstd_aliases(self):
        data = b"Zstd alias dispatch\n" * 100
        p = self.run_app("zstdmt", "-q", "-T2", "-c", data=data)
        self.assertEqual(p.returncode, 0, p.stderr)
        for alias in ["unzstd", "zstdcat"]:
            with self.subTest(alias=alias):
                decoded = self.run_app(alias, "-q", "-c", data=p.stdout)
                self.assertEqual((decoded.returncode, decoded.stdout, decoded.stderr), (0, data, b""))

    def test_less_nonterminal_private_file_and_more_alias(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            path = Path(d) / "input"
            path.write_bytes(b"one\ntwo\nthree\n")
            for name in ["less", "more"]:
                with self.subTest(program=name):
                    p = self.run_app(name, str(path))
                    self.assertEqual((p.returncode, p.stdout, p.stderr), (0, path.read_bytes(), b""))

    def test_network_and_mount_usage_before_mutation(self):
        for name in ["route", "rtsol", "mount_msdosfs"]:
            with self.subTest(program=name):
                p = self.run_app(name, "-Z")
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b"usage:", p.stderr)

    def test_lifecycle_rejects_invalid_request(self):
        # Both source getopt paths reject -Z before any transition. Shutdown's
        # earlier privilege check is also required for unprivileged execution.
        p = self.run_app("reboot", "-Z")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"usage:", p.stderr)
        p = self.run_app("shutdown", "-Z")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"NOT super-user" if os.geteuid() else b"usage:", p.stderr)

    def test_storage_and_tunnel_argument_rejection(self):
        for name, option in [("dumpon", "-x"), ("savecore", "-Q"), ("mount", "-Z"), ("mdmfs", "-Z"), ("nos-tun", "-Z")]:
            with self.subTest(program=name):
                p = self.run_app(name, option)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b"usage:", p.stderr)

    def test_fetch_private_file(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
            source, output = Path(d) / "source", Path(d) / "output"
            data = bytes(range(256)) * 128
            source.write_bytes(data)
            p = self.run_app("fetch", "-q", "-o", str(output), source.as_uri())
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(output.read_bytes(), data)
            self.assertEqual(source.read_bytes(), data)

    def test_fetch_loopback_http(self):
        import http.server
        import threading
        data = bytes(range(256)) * 128
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as d:
                output = Path(d) / "download"
                url = "http://127.0.0.1:" + str(server.server_port) + "/payload"
                p = self.run_app("fetch", "-q", "-o", str(output), url,
                    environment={"HTTP_PROXY": "", "http_proxy": "", "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"})
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(output.read_bytes(), data)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())

    def test_netcat_loopback_binary_exchange(self):
        import socket
        import threading
        data = bytes(range(256)) * 32
        received, errors = [], []
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        def respond():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    parts = []
                    while True:
                        part = connection.recv(4096)
                        if not part:
                            break
                        parts.append(part)
                    received.append(b"".join(parts))
                    connection.sendall(b"reply:" + received[0])
            except Exception as error:
                errors.append(repr(error))
        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        try:
            p = self.run_app("nc", "-N", "127.0.0.1", str(server.getsockname()[1]), data=data)
        finally:
            worker.join(timeout=6)
            server.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [data])
        self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b"reply:" + data, b""))

if __name__ == "__main__":
    unittest.main()
