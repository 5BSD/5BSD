provider libchannel {
	probe request__start(uintptr_t channel, uint64_t token, uint64_t bytes,
	    uint64_t fds);
	probe request__done(uintptr_t channel, uint64_t token, int error);
	probe dispatch__start(uintptr_t channel, uint64_t pending, uint64_t queued);
	probe dispatch__done(uintptr_t channel, int messages, int error);
	probe handler__start(uintptr_t channel, uint64_t token, uint32_t kind);
	probe handler__done(uintptr_t channel, uint64_t token, uint32_t kind);
	probe create(int fd, uint32_t role, int result);
	probe queue(uint64_t token, uint64_t bytes, uint64_t fds,
	    uint64_t depth);
	probe send(uint64_t token, uint64_t bytes, uint64_t fds, int result);
	probe receive(uint32_t kind, uint64_t token, uint64_t bytes,
	    uint64_t fds);
	probe complete(uint64_t token, int result);
	probe discard(uint64_t token, uint64_t fds, uint32_t reason);
	probe peer__death(int error, uint64_t pending);
	probe queue__limit(uint64_t a0, uint64_t a1, uint64_t a2);
	probe pending__limit(uint64_t a0, uint64_t a1);
};
