provider localnetwork {
	probe session__start(const char *, unsigned int);
	probe session__end(const char *, int);
	probe request__done(const char *, unsigned short, int);
	probe resolve__start(const char *, const char *);
	probe resolve__done(const char *, unsigned int, int);
	probe connect__done(const char *, const char *, unsigned int, int);
	probe reject(const char *, int);
};
