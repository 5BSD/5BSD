/*
 * DTrace USDT provider for meshd.
 */

provider meshd {
	/* Per-application Mesh socket lifecycle. */
	probe app__connect(int fd);
	probe app__disconnect(int fd);

	/* Application model registration and event delivery. */
	probe app__register(int fd, int model, int vendor);
	probe app__event__queue(int fd, int opcode, int count);
	probe app__event__drop(int fd, int dropped);
	probe app__event__send(int fd, int opcode, int len);
};
