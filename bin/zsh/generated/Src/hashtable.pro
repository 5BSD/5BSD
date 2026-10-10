/* Generated automatically */
static int hnamcmp(const void*ap,const void*bp);
static void expandhashtable(HashTable ht);
static void resizehashtable(HashTable ht,int newsize);
#ifdef ZSH_HASH_DEBUG
static void printhashtabinfo(HashTable ht);
#endif /* ZSH_HASH_DEBUG */
static void emptycmdnamtable(HashTable ht);
static void fillcmdnamtable(UNUSED(HashTable ht));
static void freecmdnamnode(HashNode hn);
static void printcmdnamnode(HashNode hn,int printflags);
static HashNode removeshfuncnode(UNUSED(HashTable ht),const char*nam);
static void disableshfuncnode(HashNode hn,UNUSED(int flags));
static void enableshfuncnode(HashNode hn,UNUSED(int flags));
static void freeshfuncnode(HashNode hn);
static void printshfuncnode(HashNode hn,int printflags);
static void printreswdnode(HashNode hn,int printflags);
static void freealiasnode(HashNode hn);
static void printaliasnode(HashNode hn,int printflags);
