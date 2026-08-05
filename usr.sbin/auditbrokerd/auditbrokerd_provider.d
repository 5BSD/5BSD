provider auditbrokerd {
	probe session(char *, int);
	probe submit(char *, int, int, int);
	probe reject(char *, int);
};
