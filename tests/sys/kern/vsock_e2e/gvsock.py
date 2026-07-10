import sys, socket, time
A = 40
def mk(t): return socket.socket(A, socket.SOCK_SEQPACKET if t=='seq' else socket.SOCK_STREAM)
cmd, t, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if cmd == 'echo-l':
    s = mk(t); s.bind((0xffffffff, port)); s.listen(1); print('up', flush=True)
    c,_ = s.accept()
    while True:
        d = c.recv(65536)
        if not d: break
        c.send(d)
elif cmd == 'recv-l':
    s = mk(t); s.bind((0xffffffff, port)); s.listen(1); print('up', flush=True)
    c,_ = s.accept(); recs=0; total=0
    while True:
        d = c.recv(4*1024*1024)
        if not d: break
        recs+=1; total+=len(d); print('RECORD len=%d'%len(d), flush=True)
    print('TOTAL recs=%d bytes=%d'%(recs,total), flush=True)
elif cmd == 'send':
    n = int(sys.argv[4]); s = mk(t); s.connect((2, port))
    s.send(b'G'*n); time.sleep(0.6); s.close(); print('sent %d'%n, flush=True)
elif cmd == 'send-echo':
    s = mk(t); s.connect((2, port)); s.send(sys.argv[4].encode())
    print('ECHO ' + s.recv(65536).decode(), flush=True)
