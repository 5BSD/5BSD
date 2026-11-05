import os, pty, select, subprocess, sys, tempfile, time, termios
from pathlib import Path
binary=sys.argv[1]
with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    # Reproduce the old reader's echo and line buffering with a real tty.
    m,s=pty.openpty()
    with (root/'old').open('wb') as out:
        p=subprocess.Popen(['cat'],stdin=s,stdout=out)
        try:
            os.write(m,b'5')
            assert select.select([m],[],[],2)[0], 'baseline did not echo'
            assert b'5' in os.read(m,128)
            time.sleep(.1)
            assert (root/'old').read_bytes()==b'', 'baseline was not canonical'
        finally:
            p.terminate();p.wait();os.close(m);os.close(s)
    print('PASS original cat echoes menu input and buffers without newline')
    m,s=pty.openpty()
    with (root/'new').open('wb') as out:
        p=subprocess.Popen([binary,os.ttyname(s),str(root/'ready')],stdout=out,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while not (root/'ready').exists():
                assert p.poll() is None, p.stderr.read()
                assert time.monotonic()<deadline
                time.sleep(.01)
            flags=termios.tcgetattr(s)
            assert not flags[3] & (termios.ECHO|termios.ICANON|termios.ISIG)
            payload=b'5\r\nHOSTTEST-L2-MARKER test\x11\x13\x03no-newline'
            os.write(m,payload)
            while (root/'new').read_bytes()!=payload:
                assert time.monotonic()<deadline,(root/'new').read_bytes()
                time.sleep(.01)
            assert not select.select([m],[],[],.2)[0], 'new reader echoed to loader'
            assert p.poll() is None
        finally:
            p.terminate();p.wait();os.close(m);os.close(s)
    print('PASS raw reader preserves CR/control bytes and unterminated output without echo')
    p=subprocess.run([binary,str(root/'missing'),str(root/'badready')],capture_output=True)
    assert p.returncode!=0 and not (root/'badready').exists()
    print('PASS reader setup failure never signals ready')
