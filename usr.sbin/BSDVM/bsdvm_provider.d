provider bsdvm {
	/* UINT32_MAX opcode means no complete request header was available. */
	probe request__done(uint32_t opcode, int status, int transport_error);
	probe vsock__list(const char *client, uint32_t port_base,
	    uint32_t port_limit, int result);
};
