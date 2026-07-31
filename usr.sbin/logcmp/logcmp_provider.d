provider logcmp_provider {
	probe session__start(const char *label, uint64_t instance, int result);
	probe record__write(const char *label, uint32_t severity, uint32_t length,
	    int result);
	probe record__drop(const char *label, uint64_t sequence, int error);
};
