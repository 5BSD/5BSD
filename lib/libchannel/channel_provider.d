provider libchannel {
	probe create(int fd, uint32_t role, int result);
	probe queue(uint64_t token, uint64_t bytes, uint64_t fds,
	    uint64_t depth);
	probe send(uint64_t token, uint64_t bytes, uint64_t fds, int result);
	probe receive(uint32_t kind, uint64_t token, uint64_t bytes,
	    uint64_t fds);
	probe complete(uint64_t token, int result);
	probe discard(uint64_t token, uint64_t fds, uint32_t reason);
	probe peer__death(int error, uint64_t pending);
};
