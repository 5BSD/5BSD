provider logcmp {
	probe component__open(const char *name, int result);
	probe message__send(uint16_t opcode, uint32_t length, uint32_t nfds,
	    int result);
	probe message__receive(uint16_t opcode, uint32_t length, uint32_t nfds,
	    int result);
	probe message__reject(uint16_t opcode, uint32_t length, int error);
	probe record__enqueue(uint64_t sequence, uint32_t length, int result);
	probe wakeup__send(uint64_t sequence, int result);
	probe ring__attach(uint32_t shape, uint64_t capacity,
	    uint64_t generation, int result);
	probe flush__complete(uint64_t duration_ns, int result);
	probe query__complete(uint64_t generation, uint64_t offset,
	    uint32_t minimum_severity, uint32_t record_length, int result);
	probe reconnect(int result);
};
