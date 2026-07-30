provider networkcmp_provider {
	probe session__start(const char *, unsigned int);
	probe resolve__start(const char *, const char *);
	probe resolve__done(const char *, unsigned int, int);
	probe reject(const char *, int);
};
