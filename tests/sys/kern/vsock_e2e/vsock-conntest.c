/*
 * vsock-conntest — open N concurrent AF_VSOCK connections to <cid>:<port>,
 * send a per-connection token, verify the echo, and print a single
 * "ok=<count>" line.  Self-contained so the e2e harness can exercise
 * concurrency with ONE guest command instead of N console-driven shell
 * jobs (which flood the serial console and desync the test rig).
 *
 * usage: vsock-conntest [-s] <cid> <port> <nconns>
 *   -s   SOCK_SEQPACKET instead of SOCK_STREAM
 *
 * The peer is expected to be an echo server (one fork per connection).
 * All connections are opened first, then each child sends+verifies, so
 * the server must handle them concurrently -- the actual thing under test.
 */
#include <sys/socket.h>
#include <stdint.h>
#include <sys/vsock.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int type = SOCK_STREAM, ch;
	unsigned cid, port, n, i, ok = 0;

	signal(SIGPIPE, SIG_IGN);
	while ((ch = getopt(argc, argv, "s")) != -1) {
		if (ch == 's')
			type = SOCK_SEQPACKET;
		else {
			fprintf(stderr, "usage: %s [-s] <cid> <port> <n>\n",
			    argv[0]);
			return (2);
		}
	}
	argc -= optind; argv += optind;
	if (argc < 3) {
		fprintf(stderr, "usage: vsock-conntest [-s] <cid> <port> <n>\n");
		return (2);
	}
	cid = (unsigned)strtoul(argv[0], NULL, 0);
	port = (unsigned)strtoul(argv[1], NULL, 0);
	n = (unsigned)strtoul(argv[2], NULL, 0);

	for (i = 0; i < n; i++) {
		pid_t p = fork();
		if (p == 0) {
			struct sockaddr_vm sa;
			char tok[32], buf[64];
			int s, len;
			ssize_t r;

			memset(&sa, 0, sizeof(sa));
			sa.svm_family = AF_VSOCK;
			sa.svm_len = sizeof(sa);
			sa.svm_cid = cid;
			sa.svm_port = port;
			s = socket(AF_VSOCK, type, 0);
			if (s < 0)
				_exit(1);
			if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
				_exit(1);
			len = snprintf(tok, sizeof(tok), "tok-%u", i);
			if (write(s, tok, len) != len)
				_exit(1);
			r = read(s, buf, sizeof(buf));
			if (r != len || memcmp(buf, tok, len) != 0)
				_exit(1);
			_exit(0);
		}
	}
	for (i = 0; i < n; i++) {
		int st;
		if (wait(&st) > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0)
			ok++;
	}
	printf("ok=%u\n", ok);
	return (ok == n ? 0 : 1);
}
