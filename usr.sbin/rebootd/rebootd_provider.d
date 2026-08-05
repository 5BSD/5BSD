provider rebootd {
	probe session__start(const char *label);
	probe session__end(const char *label, int result);
	probe request(const char *label, uint32_t opcode, int result);
	probe malformed(const char *label, int result);
	probe schedule__create(const char *label, uint64_t request_id,
	    uint64_t execute_at_ns, uint32_t howto);
	probe schedule__imminent(uint64_t request_id, uint32_t remaining_ms);
	probe schedule__cancel(uint64_t request_id, int error);
	probe schedule__execute(uint64_t request_id, uint32_t howto, int result);
};
