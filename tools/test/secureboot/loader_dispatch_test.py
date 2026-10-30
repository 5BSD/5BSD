# SPDX-License-Identifier: BSD-2-Clause
"""Actual common executable dispatch with controlled handoff and exec results."""
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
struct preloaded_file { int f_loader; };
struct file_format { int (*l_exec)(struct preloaded_file *); };
static char *command_errmsg;
static int admission, checks, executed, result;
#ifdef LOADER_VERITY_SUPPORT
static int verity_check_handoff(void) { checks++; return admission; }
#endif
static int execute(struct preloaded_file *fp) {
 assert(fp->f_loader == 1); executed++; return result;
}
static struct file_format format = {execute};
static struct file_format *file_formats[] = {NULL, &format};
'''
MAIN = r'''
int main(void) {
 struct preloaded_file fp = {1};
 const int errors[] = {EAUTH, EIO, EINVAL};
 for (unsigned i = 0; i < sizeof(errors)/sizeof(errors[0]); i++) {
  admission = errors[i]; checks = executed = 0; result = ENOEXEC;
  command_errmsg = NULL;
#ifdef LOADER_VERITY_SUPPORT
  assert(file_exec(&fp) == admission);
  assert(checks == 1 && executed == 0);
  assert(command_errmsg && strstr(command_errmsg, "handoff"));
#else
  assert(file_exec(&fp) == ENOEXEC);
  assert(checks == 0 && executed == 1 && command_errmsg == NULL);
#endif
 }
 admission = 0; checks = executed = 0; result = ENOEXEC;
 assert(file_exec(&fp) == ENOEXEC && executed == 1);
#ifdef LOADER_VERITY_SUPPORT
 assert(checks == 1);
#else
 assert(checks == 0);
#endif
 return 0;
}
'''
def main():
    source = (ROOT / 'stand/common/module.c').read_text()
    start = source.index('int\nfile_exec(')
    body = source[start:source.index('\n}\n', start) + 3]
    with tempfile.TemporaryDirectory() as directory:
        c = Path(directory) / 'test.c'
        binary = Path(directory) / 'test'
        c.write_text(PRE + body + MAIN)
        for flags in ([], ['-DLOADER_VERITY_SUPPORT']):
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', *flags,
                            str(c), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=3)
    print('PASS: common dispatch rejects failed handoff; enabled and conventional paths preserve exec results')
if __name__ == '__main__':
    main()
