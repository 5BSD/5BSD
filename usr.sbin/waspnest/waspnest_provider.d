provider waspnest {
	probe vsock__list(const char *client, uint32_t port_base,
	    uint32_t port_limit, int result);
	probe reclaim(const char *label, int reclaimed, const char *reason);
};
