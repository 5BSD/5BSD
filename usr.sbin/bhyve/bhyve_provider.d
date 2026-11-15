provider netbe {
	probe tap__recv(char *, void *);
	probe tap__send(char *, void *);
	probe tap__recv__v2(char *, void *);
	probe tap__send__v2(char *, void *);
};
