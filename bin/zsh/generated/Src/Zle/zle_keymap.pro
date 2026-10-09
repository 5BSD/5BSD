/* Generated automatically */
static void createkeymapnamtab(void);
static KeymapName makekeymapnamnode(Keymap keymap);
static void emptykeymapnamtab(HashTable ht);
static void freekeymapnamnode(HashNode hn);
static HashTable newkeytab(char*kmname);
static Key makekeynode(Thingy t,char*str);
static void freekeynode(HashNode hn);
static void scancopykeys(HashNode hn,UNUSED(int flags));
static void scankeys(HashNode hn,UNUSED(int flags));
static int keyisprefix(Keymap km,char*seq);
static int bin_bindkey_lsmaps(char*name,UNUSED(char*kmname),UNUSED(Keymap km),char**argv,Options ops,UNUSED(char func));
static void scanlistmaps(HashNode hn,int list_verbose);
static int bin_bindkey_delall(UNUSED(char*name),UNUSED(char*kmname),UNUSED(Keymap km),UNUSED(char**argv),UNUSED(Options ops),UNUSED(char func));
static int bin_bindkey_del(char*name,UNUSED(char*kmname),UNUSED(Keymap km),char**argv,UNUSED(Options ops),UNUSED(char func));
static int bin_bindkey_link(char*name,UNUSED(char*kmname),Keymap km,char**argv,UNUSED(Options ops),UNUSED(char func));
static int bin_bindkey_new(char*name,UNUSED(char*kmname),Keymap km,char**argv,UNUSED(Options ops),UNUSED(char func));
static int bin_bindkey_meta(char*name,char*kmname,Keymap km,UNUSED(char**argv),UNUSED(Options ops),UNUSED(char func));
static int bin_bindkey_bind(char*name,char*kmname,Keymap km,char**argv,Options ops,char func);
static void scanremoveprefix(char*seq,UNUSED(Thingy bind),UNUSED(char*str),void*magic);
static int bin_bindkey_list(char*name,char*kmname,Keymap km,char**argv,Options ops,UNUSED(char func));
static void scanbindlist(char*seq,Thingy bind,char*str,void*magic);
static void bindlistout(struct bindstate*bs);
static void add_cursor_key(Keymap km,int tccode,Thingy thingy,int defchar);
static void default_bindings(void);
#ifdef MULTIBYTE_SUPPORT
static ZLE_INT_T getrestchar_keybuf(void);
#endif
static void addkeybuf(int c);
static int getkeybuf(int w);
