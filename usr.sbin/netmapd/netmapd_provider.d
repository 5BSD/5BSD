provider netmapd {
	probe request(const char *client_label, uint16_t opcode, uint32_t length);
	probe bearer__create(const char *client_label, const char *interface,
	    uint64_t bearer_id, int result);
};
