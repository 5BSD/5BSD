provider sysextd {
	probe list(const char *client, uint32_t count, int result);
	/* One reconcile pass (when: 0 boot, 1 timer); counts as libcapreclaim. */
	probe reclaim_pass(int when, uint32_t live, uint32_t owned,
	    uint32_t orphans, uint32_t destroyed, uint32_t failed);
};
