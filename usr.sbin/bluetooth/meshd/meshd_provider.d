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
	probe bearer__queue(int a0, uint16_t a1, uint64_t a2, uint64_t a3);
	probe bearer__full(int a0, uint64_t a1, uint64_t a2);
	probe bearer__failed(int a0, int a1);
	probe persist__write__start(uint64_t a0);
	probe persist__write__done(uint64_t a0, int a1);
};
