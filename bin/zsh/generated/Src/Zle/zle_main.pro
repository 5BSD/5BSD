/* Generated automatically */
static int pre_zle_status;
#ifdef MULTIBYTE_SUPPORT
#endif
static int execimmortal(Thingy func,char**args);
static void initmodifier(struct modifier*mp);
static void handleprefixes(void);
static int savekeymap(char*cmdname,char*oldname,char*newname,Keymap*savemapptr);
static void restorekeymap(char*cmdname,char*oldname,char*newname,Keymap savemap);
static int bin_vared(char*name,char**args,Options ops,UNUSED(int func));
static void scanfindfunc(char*seq,Thingy func,UNUSED(char*str),void*magic);
static void zle_resetprompt(void);
