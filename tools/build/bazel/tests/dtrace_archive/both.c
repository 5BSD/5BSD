extern int selected(int);
extern int unselected(int);
int dependency_not_linked(void) { return 7; }
int main(void) { return selected(41) == 42 && unselected(0) == 7 ? 0 : 1; }
