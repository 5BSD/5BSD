# SPDX-License-Identifier: BSD-2-Clause
"""Safe real rescue application dispatch with private files and stdin only."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PROGRAM = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / "rescue/rescue/rescue_core"

class RescueCore(unittest.TestCase):
    def run_app(self, *args, data=b"", name=None, cwd=None):
        env = dict(os.environ, DTRACE_DOF_INIT_DISABLE="1", LC_ALL="C")
        # This binary is statically linked. No host library/path fallback is used.
        return subprocess.run([name or str(PROGRAM), *args], executable=str(PROGRAM),
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=cwd, timeout=10, check=False)

    def test_catalog(self):
        p = self.run_app("--list")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(set(p.stdout.split()), {b'cat', b'chflags', b'chmod', b'cp', b'echo', b'ed', b'expr', b'getfacl', b'hostname', b'ln', b'mkdir', b'mv', b'pwd', b'realpath', b'rm', b'rmdir', b'sleep', b'test', b'head', b'red', b'link', b'unlink', b'['})

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

if __name__ == "__main__":
    unittest.main()
