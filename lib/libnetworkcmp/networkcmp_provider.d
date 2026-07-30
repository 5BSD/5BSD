provider networkcmp {
	probe component__open(const char *component_name, int result);
	probe message__send(uint16_t opcode, uint32_t length, uint32_t nfds,
	    int result);
	probe message__receive(uint16_t opcode, uint32_t length, uint32_t nfds,
	    int result);
	probe message__reject(uint16_t opcode, uint32_t length, int error_code);
};
