/* Generated automatically */
static void zle_set_highlight(void);
static void zle_free_highlight(void);
static void scrollwindow(int tline);
static void settextattributes(zattr atr);
static void refreshline(int ln);
static void tc_rightcurs(int ct);
static void tcout_via_func(int cap,int arg,int(*outc)(int));
static void tcoutarg(int cap,int arg);
static void singlerefresh(ZLE_STRING_T tmpline,int tmpll,int tmpcs);
static void singmoveto(int pos);
