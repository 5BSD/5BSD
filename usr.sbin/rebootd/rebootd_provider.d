provider rebootd {
	probe session__start(const char *label);
	probe session__end(const char *label, int result);
	probe request(const char *label, uint32_t opcode, int result);
	probe malformed(const char *label, int result);
};
