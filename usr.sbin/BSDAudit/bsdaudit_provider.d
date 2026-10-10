provider bsdaudit {
	probe request__done(uint32_t opcode, int status, int transport_error);
	probe session(char *, int);
	probe submit(char *, int, int, int);
	probe reject(char *, int);
};
