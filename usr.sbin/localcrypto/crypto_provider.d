provider crypto {
	probe named__list(const char *owner, uint32_t count, int result);
	/* Container-model reconcile pass: when (0 boot/1 timer), live, owned,
	 * orphans, destroyed, failed. */
	probe reclaim__pass(int when, unsigned int live, unsigned int owned,
	    unsigned int orphans, unsigned int destroyed, unsigned int failed);
	/* A gone bundle's keys dropped: bundle, keys dropped (-1 on failure), errno. */
	probe reclaim__drop(const char *bundle, int nkeys, int error);
};
