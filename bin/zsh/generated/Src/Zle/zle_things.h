/** zle_things.h                              **/
/** indices of and pointers to known thingies **/

enum {
    z_acceptandhold,
#define t_acceptandhold (&thingies[z_acceptandhold])
    z_acceptandinfernexthistory,
#define t_acceptandinfernexthistory (&thingies[z_acceptandinfernexthistory])
    z_acceptandmenucomplete,
#define t_acceptandmenucomplete (&thingies[z_acceptandmenucomplete])
    z_acceptline,
#define t_acceptline (&thingies[z_acceptline])
    z_acceptlineanddownhistory,
#define t_acceptlineanddownhistory (&thingies[z_acceptlineanddownhistory])
    z_acceptsearch,
#define t_acceptsearch (&thingies[z_acceptsearch])
    z_argumentbase,
#define t_argumentbase (&thingies[z_argumentbase])
    z_autosuffixremove,
#define t_autosuffixremove (&thingies[z_autosuffixremove])
    z_autosuffixretain,
#define t_autosuffixretain (&thingies[z_autosuffixretain])
    z_backwardchar,
#define t_backwardchar (&thingies[z_backwardchar])
    z_backwarddeletechar,
#define t_backwarddeletechar (&thingies[z_backwarddeletechar])
    z_backwarddeleteword,
#define t_backwarddeleteword (&thingies[z_backwarddeleteword])
    z_backwardkillline,
#define t_backwardkillline (&thingies[z_backwardkillline])
    z_backwardkillword,
#define t_backwardkillword (&thingies[z_backwardkillword])
    z_backwardword,
#define t_backwardword (&thingies[z_backwardword])
    z_beep,
#define t_beep (&thingies[z_beep])
    z_beginningofbufferorhistory,
#define t_beginningofbufferorhistory (&thingies[z_beginningofbufferorhistory])
    z_beginningofhistory,
#define t_beginningofhistory (&thingies[z_beginningofhistory])
    z_beginningofline,
#define t_beginningofline (&thingies[z_beginningofline])
    z_beginningoflinehist,
#define t_beginningoflinehist (&thingies[z_beginningoflinehist])
    z_bracketedpaste,
#define t_bracketedpaste (&thingies[z_bracketedpaste])
    z_capitalizeword,
#define t_capitalizeword (&thingies[z_capitalizeword])
    z_clearscreen,
#define t_clearscreen (&thingies[z_clearscreen])
    z_completeword,
#define t_completeword (&thingies[z_completeword])
    z_copyprevword,
#define t_copyprevword (&thingies[z_copyprevword])
    z_copyprevshellword,
#define t_copyprevshellword (&thingies[z_copyprevshellword])
    z_copyregionaskill,
#define t_copyregionaskill (&thingies[z_copyregionaskill])
    z_deactivateregion,
#define t_deactivateregion (&thingies[z_deactivateregion])
    z_deletechar,
#define t_deletechar (&thingies[z_deletechar])
    z_deletecharorlist,
#define t_deletecharorlist (&thingies[z_deletecharorlist])
    z_deleteword,
#define t_deleteword (&thingies[z_deleteword])
    z_describekeybriefly,
#define t_describekeybriefly (&thingies[z_describekeybriefly])
    z_digitargument,
#define t_digitargument (&thingies[z_digitargument])
    z_downcaseword,
#define t_downcaseword (&thingies[z_downcaseword])
    z_downhistory,
#define t_downhistory (&thingies[z_downhistory])
    z_downline,
#define t_downline (&thingies[z_downline])
    z_downlineorhistory,
#define t_downlineorhistory (&thingies[z_downlineorhistory])
    z_downlineorsearch,
#define t_downlineorsearch (&thingies[z_downlineorsearch])
    z_emacsbackwardword,
#define t_emacsbackwardword (&thingies[z_emacsbackwardword])
    z_emacsforwardword,
#define t_emacsforwardword (&thingies[z_emacsforwardword])
    z_endofbufferorhistory,
#define t_endofbufferorhistory (&thingies[z_endofbufferorhistory])
    z_endofhistory,
#define t_endofhistory (&thingies[z_endofhistory])
    z_endofline,
#define t_endofline (&thingies[z_endofline])
    z_endoflinehist,
#define t_endoflinehist (&thingies[z_endoflinehist])
    z_endoflist,
#define t_endoflist (&thingies[z_endoflist])
    z_exchangepointandmark,
#define t_exchangepointandmark (&thingies[z_exchangepointandmark])
    z_executelastnamedcmd,
#define t_executelastnamedcmd (&thingies[z_executelastnamedcmd])
    z_executenamedcmd,
#define t_executenamedcmd (&thingies[z_executenamedcmd])
    z_expandcmdpath,
#define t_expandcmdpath (&thingies[z_expandcmdpath])
    z_expandhistory,
#define t_expandhistory (&thingies[z_expandhistory])
    z_expandorcomplete,
#define t_expandorcomplete (&thingies[z_expandorcomplete])
    z_expandorcompleteprefix,
#define t_expandorcompleteprefix (&thingies[z_expandorcompleteprefix])
    z_expandword,
#define t_expandword (&thingies[z_expandword])
    z_forwardchar,
#define t_forwardchar (&thingies[z_forwardchar])
    z_forwardword,
#define t_forwardword (&thingies[z_forwardword])
    z_getline,
#define t_getline (&thingies[z_getline])
    z_gosmacstransposechars,
#define t_gosmacstransposechars (&thingies[z_gosmacstransposechars])
    z_historybeginningsearchbackward,
#define t_historybeginningsearchbackward (&thingies[z_historybeginningsearchbackward])
    z_historybeginningsearchforward,
#define t_historybeginningsearchforward (&thingies[z_historybeginningsearchforward])
    z_historyincrementalsearchbackward,
#define t_historyincrementalsearchbackward (&thingies[z_historyincrementalsearchbackward])
    z_historyincrementalsearchforward,
#define t_historyincrementalsearchforward (&thingies[z_historyincrementalsearchforward])
    z_historyincrementalpatternsearchbackward,
#define t_historyincrementalpatternsearchbackward (&thingies[z_historyincrementalpatternsearchbackward])
    z_historyincrementalpatternsearchforward,
#define t_historyincrementalpatternsearchforward (&thingies[z_historyincrementalpatternsearchforward])
    z_historysearchbackward,
#define t_historysearchbackward (&thingies[z_historysearchbackward])
    z_historysearchforward,
#define t_historysearchforward (&thingies[z_historysearchforward])
    z_infernexthistory,
#define t_infernexthistory (&thingies[z_infernexthistory])
    z_insertlastword,
#define t_insertlastword (&thingies[z_insertlastword])
    z_killbuffer,
#define t_killbuffer (&thingies[z_killbuffer])
    z_killline,
#define t_killline (&thingies[z_killline])
    z_killregion,
#define t_killregion (&thingies[z_killregion])
    z_killwholeline,
#define t_killwholeline (&thingies[z_killwholeline])
    z_killword,
#define t_killword (&thingies[z_killword])
    z_listchoices,
#define t_listchoices (&thingies[z_listchoices])
    z_listexpand,
#define t_listexpand (&thingies[z_listexpand])
    z_magicspace,
#define t_magicspace (&thingies[z_magicspace])
    z_menucomplete,
#define t_menucomplete (&thingies[z_menucomplete])
    z_menuexpandorcomplete,
#define t_menuexpandorcomplete (&thingies[z_menuexpandorcomplete])
    z_negargument,
#define t_negargument (&thingies[z_negargument])
    z_overwritemode,
#define t_overwritemode (&thingies[z_overwritemode])
    z_poundinsert,
#define t_poundinsert (&thingies[z_poundinsert])
    z_pushinput,
#define t_pushinput (&thingies[z_pushinput])
    z_pushline,
#define t_pushline (&thingies[z_pushline])
    z_pushlineoredit,
#define t_pushlineoredit (&thingies[z_pushlineoredit])
    z_putreplaceselection,
#define t_putreplaceselection (&thingies[z_putreplaceselection])
    z_quotedinsert,
#define t_quotedinsert (&thingies[z_quotedinsert])
    z_quoteline,
#define t_quoteline (&thingies[z_quoteline])
    z_quoteregion,
#define t_quoteregion (&thingies[z_quoteregion])
    z_readcommand,
#define t_readcommand (&thingies[z_readcommand])
    z_recursiveedit,
#define t_recursiveedit (&thingies[z_recursiveedit])
    z_redisplay,
#define t_redisplay (&thingies[z_redisplay])
    z_redo,
#define t_redo (&thingies[z_redo])
    z_resetprompt,
#define t_resetprompt (&thingies[z_resetprompt])
    z_reversemenucomplete,
#define t_reversemenucomplete (&thingies[z_reversemenucomplete])
    z_runhelp,
#define t_runhelp (&thingies[z_runhelp])
    z_selectaword,
#define t_selectaword (&thingies[z_selectaword])
    z_selectinword,
#define t_selectinword (&thingies[z_selectinword])
    z_selectablankword,
#define t_selectablankword (&thingies[z_selectablankword])
    z_selectinblankword,
#define t_selectinblankword (&thingies[z_selectinblankword])
    z_selectashellword,
#define t_selectashellword (&thingies[z_selectashellword])
    z_selectinshellword,
#define t_selectinshellword (&thingies[z_selectinshellword])
    z_selfinsert,
#define t_selfinsert (&thingies[z_selfinsert])
    z_selfinsertunmeta,
#define t_selfinsertunmeta (&thingies[z_selfinsertunmeta])
    z_sendbreak,
#define t_sendbreak (&thingies[z_sendbreak])
    z_setmarkcommand,
#define t_setmarkcommand (&thingies[z_setmarkcommand])
    z_splitundo,
#define t_splitundo (&thingies[z_splitundo])
    z_spellword,
#define t_spellword (&thingies[z_spellword])
    z_setlocalhistory,
#define t_setlocalhistory (&thingies[z_setlocalhistory])
    z_transposechars,
#define t_transposechars (&thingies[z_transposechars])
    z_transposewords,
#define t_transposewords (&thingies[z_transposewords])
    z_undefinedkey,
#define t_undefinedkey (&thingies[z_undefinedkey])
    z_undo,
#define t_undo (&thingies[z_undo])
    z_universalargument,
#define t_universalargument (&thingies[z_universalargument])
    z_upcaseword,
#define t_upcaseword (&thingies[z_upcaseword])
    z_uphistory,
#define t_uphistory (&thingies[z_uphistory])
    z_upline,
#define t_upline (&thingies[z_upline])
    z_uplineorhistory,
#define t_uplineorhistory (&thingies[z_uplineorhistory])
    z_uplineorsearch,
#define t_uplineorsearch (&thingies[z_uplineorsearch])
    z_viaddeol,
#define t_viaddeol (&thingies[z_viaddeol])
    z_viaddnext,
#define t_viaddnext (&thingies[z_viaddnext])
    z_vibackwardblankword,
#define t_vibackwardblankword (&thingies[z_vibackwardblankword])
    z_vibackwardchar,
#define t_vibackwardchar (&thingies[z_vibackwardchar])
    z_vibackwarddeletechar,
#define t_vibackwarddeletechar (&thingies[z_vibackwarddeletechar])
    z_vibackwardkillword,
#define t_vibackwardkillword (&thingies[z_vibackwardkillword])
    z_vibackwardword,
#define t_vibackwardword (&thingies[z_vibackwardword])
    z_vibackwardwordend,
#define t_vibackwardwordend (&thingies[z_vibackwardwordend])
    z_vibackwardblankwordend,
#define t_vibackwardblankwordend (&thingies[z_vibackwardblankwordend])
    z_vibeginningofline,
#define t_vibeginningofline (&thingies[z_vibeginningofline])
    z_vicapslockpanic,
#define t_vicapslockpanic (&thingies[z_vicapslockpanic])
    z_vichange,
#define t_vichange (&thingies[z_vichange])
    z_vichangeeol,
#define t_vichangeeol (&thingies[z_vichangeeol])
    z_vichangewholeline,
#define t_vichangewholeline (&thingies[z_vichangewholeline])
    z_vicmdmode,
#define t_vicmdmode (&thingies[z_vicmdmode])
    z_videlete,
#define t_videlete (&thingies[z_videlete])
    z_videletechar,
#define t_videletechar (&thingies[z_videletechar])
    z_vidigitorbeginningofline,
#define t_vidigitorbeginningofline (&thingies[z_vidigitorbeginningofline])
    z_vidowncase,
#define t_vidowncase (&thingies[z_vidowncase])
    z_vidownlineorhistory,
#define t_vidownlineorhistory (&thingies[z_vidownlineorhistory])
    z_viendofline,
#define t_viendofline (&thingies[z_viendofline])
    z_vifetchhistory,
#define t_vifetchhistory (&thingies[z_vifetchhistory])
    z_vifindnextchar,
#define t_vifindnextchar (&thingies[z_vifindnextchar])
    z_vifindnextcharskip,
#define t_vifindnextcharskip (&thingies[z_vifindnextcharskip])
    z_vifindprevchar,
#define t_vifindprevchar (&thingies[z_vifindprevchar])
    z_vifindprevcharskip,
#define t_vifindprevcharskip (&thingies[z_vifindprevcharskip])
    z_vifirstnonblank,
#define t_vifirstnonblank (&thingies[z_vifirstnonblank])
    z_viforwardblankword,
#define t_viforwardblankword (&thingies[z_viforwardblankword])
    z_viforwardblankwordend,
#define t_viforwardblankwordend (&thingies[z_viforwardblankwordend])
    z_viforwardchar,
#define t_viforwardchar (&thingies[z_viforwardchar])
    z_viforwardword,
#define t_viforwardword (&thingies[z_viforwardword])
    z_viforwardwordend,
#define t_viforwardwordend (&thingies[z_viforwardwordend])
    z_vigotocolumn,
#define t_vigotocolumn (&thingies[z_vigotocolumn])
    z_vigotomark,
#define t_vigotomark (&thingies[z_vigotomark])
    z_vigotomarkline,
#define t_vigotomarkline (&thingies[z_vigotomarkline])
    z_vihistorysearchbackward,
#define t_vihistorysearchbackward (&thingies[z_vihistorysearchbackward])
    z_vihistorysearchforward,
#define t_vihistorysearchforward (&thingies[z_vihistorysearchforward])
    z_viindent,
#define t_viindent (&thingies[z_viindent])
    z_viinsert,
#define t_viinsert (&thingies[z_viinsert])
    z_viinsertbol,
#define t_viinsertbol (&thingies[z_viinsertbol])
    z_vijoin,
#define t_vijoin (&thingies[z_vijoin])
    z_vikilleol,
#define t_vikilleol (&thingies[z_vikilleol])
    z_vikillline,
#define t_vikillline (&thingies[z_vikillline])
    z_vimatchbracket,
#define t_vimatchbracket (&thingies[z_vimatchbracket])
    z_viopenlineabove,
#define t_viopenlineabove (&thingies[z_viopenlineabove])
    z_viopenlinebelow,
#define t_viopenlinebelow (&thingies[z_viopenlinebelow])
    z_vioperswapcase,
#define t_vioperswapcase (&thingies[z_vioperswapcase])
    z_vipoundinsert,
#define t_vipoundinsert (&thingies[z_vipoundinsert])
    z_viputafter,
#define t_viputafter (&thingies[z_viputafter])
    z_viputbefore,
#define t_viputbefore (&thingies[z_viputbefore])
    z_viquotedinsert,
#define t_viquotedinsert (&thingies[z_viquotedinsert])
    z_virepeatchange,
#define t_virepeatchange (&thingies[z_virepeatchange])
    z_virepeatfind,
#define t_virepeatfind (&thingies[z_virepeatfind])
    z_virepeatsearch,
#define t_virepeatsearch (&thingies[z_virepeatsearch])
    z_vireplace,
#define t_vireplace (&thingies[z_vireplace])
    z_vireplacechars,
#define t_vireplacechars (&thingies[z_vireplacechars])
    z_virevrepeatfind,
#define t_virevrepeatfind (&thingies[z_virevrepeatfind])
    z_virevrepeatsearch,
#define t_virevrepeatsearch (&thingies[z_virevrepeatsearch])
    z_visetbuffer,
#define t_visetbuffer (&thingies[z_visetbuffer])
    z_visetmark,
#define t_visetmark (&thingies[z_visetmark])
    z_visubstitute,
#define t_visubstitute (&thingies[z_visubstitute])
    z_viswapcase,
#define t_viswapcase (&thingies[z_viswapcase])
    z_viundochange,
#define t_viundochange (&thingies[z_viundochange])
    z_viunindent,
#define t_viunindent (&thingies[z_viunindent])
    z_viupcase,
#define t_viupcase (&thingies[z_viupcase])
    z_viuplineorhistory,
#define t_viuplineorhistory (&thingies[z_viuplineorhistory])
    z_viyank,
#define t_viyank (&thingies[z_viyank])
    z_viyankeol,
#define t_viyankeol (&thingies[z_viyankeol])
    z_viyankwholeline,
#define t_viyankwholeline (&thingies[z_viyankwholeline])
    z_visuallinemode,
#define t_visuallinemode (&thingies[z_visuallinemode])
    z_visualmode,
#define t_visualmode (&thingies[z_visualmode])
    z_whatcursorposition,
#define t_whatcursorposition (&thingies[z_whatcursorposition])
    z_whereis,
#define t_whereis (&thingies[z_whereis])
    z_whichcommand,
#define t_whichcommand (&thingies[z_whichcommand])
    z_yank,
#define t_yank (&thingies[z_yank])
    z_yankpop,
#define t_yankpop (&thingies[z_yankpop])
    z_Dacceptandhold,
#define t_Dacceptandhold (&thingies[z_Dacceptandhold])
    z_Dacceptandinfernexthistory,
#define t_Dacceptandinfernexthistory (&thingies[z_Dacceptandinfernexthistory])
    z_Dacceptandmenucomplete,
#define t_Dacceptandmenucomplete (&thingies[z_Dacceptandmenucomplete])
    z_Dacceptline,
#define t_Dacceptline (&thingies[z_Dacceptline])
    z_Dacceptlineanddownhistory,
#define t_Dacceptlineanddownhistory (&thingies[z_Dacceptlineanddownhistory])
    z_Dacceptsearch,
#define t_Dacceptsearch (&thingies[z_Dacceptsearch])
    z_Dargumentbase,
#define t_Dargumentbase (&thingies[z_Dargumentbase])
    z_Dautosuffixremove,
#define t_Dautosuffixremove (&thingies[z_Dautosuffixremove])
    z_Dautosuffixretain,
#define t_Dautosuffixretain (&thingies[z_Dautosuffixretain])
    z_Dbackwardchar,
#define t_Dbackwardchar (&thingies[z_Dbackwardchar])
    z_Dbackwarddeletechar,
#define t_Dbackwarddeletechar (&thingies[z_Dbackwarddeletechar])
    z_Dbackwarddeleteword,
#define t_Dbackwarddeleteword (&thingies[z_Dbackwarddeleteword])
    z_Dbackwardkillline,
#define t_Dbackwardkillline (&thingies[z_Dbackwardkillline])
    z_Dbackwardkillword,
#define t_Dbackwardkillword (&thingies[z_Dbackwardkillword])
    z_Dbackwardword,
#define t_Dbackwardword (&thingies[z_Dbackwardword])
    z_Dbeep,
#define t_Dbeep (&thingies[z_Dbeep])
    z_Dbeginningofbufferorhistory,
#define t_Dbeginningofbufferorhistory (&thingies[z_Dbeginningofbufferorhistory])
    z_Dbeginningofhistory,
#define t_Dbeginningofhistory (&thingies[z_Dbeginningofhistory])
    z_Dbeginningofline,
#define t_Dbeginningofline (&thingies[z_Dbeginningofline])
    z_Dbeginningoflinehist,
#define t_Dbeginningoflinehist (&thingies[z_Dbeginningoflinehist])
    z_Dbracketedpaste,
#define t_Dbracketedpaste (&thingies[z_Dbracketedpaste])
    z_Dcapitalizeword,
#define t_Dcapitalizeword (&thingies[z_Dcapitalizeword])
    z_Dclearscreen,
#define t_Dclearscreen (&thingies[z_Dclearscreen])
    z_Dcompleteword,
#define t_Dcompleteword (&thingies[z_Dcompleteword])
    z_Dcopyprevword,
#define t_Dcopyprevword (&thingies[z_Dcopyprevword])
    z_Dcopyprevshellword,
#define t_Dcopyprevshellword (&thingies[z_Dcopyprevshellword])
    z_Dcopyregionaskill,
#define t_Dcopyregionaskill (&thingies[z_Dcopyregionaskill])
    z_Ddeactivateregion,
#define t_Ddeactivateregion (&thingies[z_Ddeactivateregion])
    z_Ddeletechar,
#define t_Ddeletechar (&thingies[z_Ddeletechar])
    z_Ddeletecharorlist,
#define t_Ddeletecharorlist (&thingies[z_Ddeletecharorlist])
    z_Ddeleteword,
#define t_Ddeleteword (&thingies[z_Ddeleteword])
    z_Ddescribekeybriefly,
#define t_Ddescribekeybriefly (&thingies[z_Ddescribekeybriefly])
    z_Ddigitargument,
#define t_Ddigitargument (&thingies[z_Ddigitargument])
    z_Ddowncaseword,
#define t_Ddowncaseword (&thingies[z_Ddowncaseword])
    z_Ddownhistory,
#define t_Ddownhistory (&thingies[z_Ddownhistory])
    z_Ddownline,
#define t_Ddownline (&thingies[z_Ddownline])
    z_Ddownlineorhistory,
#define t_Ddownlineorhistory (&thingies[z_Ddownlineorhistory])
    z_Ddownlineorsearch,
#define t_Ddownlineorsearch (&thingies[z_Ddownlineorsearch])
    z_Demacsbackwardword,
#define t_Demacsbackwardword (&thingies[z_Demacsbackwardword])
    z_Demacsforwardword,
#define t_Demacsforwardword (&thingies[z_Demacsforwardword])
    z_Dendofbufferorhistory,
#define t_Dendofbufferorhistory (&thingies[z_Dendofbufferorhistory])
    z_Dendofhistory,
#define t_Dendofhistory (&thingies[z_Dendofhistory])
    z_Dendofline,
#define t_Dendofline (&thingies[z_Dendofline])
    z_Dendoflinehist,
#define t_Dendoflinehist (&thingies[z_Dendoflinehist])
    z_Dendoflist,
#define t_Dendoflist (&thingies[z_Dendoflist])
    z_Dexchangepointandmark,
#define t_Dexchangepointandmark (&thingies[z_Dexchangepointandmark])
    z_Dexecutelastnamedcmd,
#define t_Dexecutelastnamedcmd (&thingies[z_Dexecutelastnamedcmd])
    z_Dexecutenamedcmd,
#define t_Dexecutenamedcmd (&thingies[z_Dexecutenamedcmd])
    z_Dexpandcmdpath,
#define t_Dexpandcmdpath (&thingies[z_Dexpandcmdpath])
    z_Dexpandhistory,
#define t_Dexpandhistory (&thingies[z_Dexpandhistory])
    z_Dexpandorcomplete,
#define t_Dexpandorcomplete (&thingies[z_Dexpandorcomplete])
    z_Dexpandorcompleteprefix,
#define t_Dexpandorcompleteprefix (&thingies[z_Dexpandorcompleteprefix])
    z_Dexpandword,
#define t_Dexpandword (&thingies[z_Dexpandword])
    z_Dforwardchar,
#define t_Dforwardchar (&thingies[z_Dforwardchar])
    z_Dforwardword,
#define t_Dforwardword (&thingies[z_Dforwardword])
    z_Dgetline,
#define t_Dgetline (&thingies[z_Dgetline])
    z_Dgosmacstransposechars,
#define t_Dgosmacstransposechars (&thingies[z_Dgosmacstransposechars])
    z_Dhistorybeginningsearchbackward,
#define t_Dhistorybeginningsearchbackward (&thingies[z_Dhistorybeginningsearchbackward])
    z_Dhistorybeginningsearchforward,
#define t_Dhistorybeginningsearchforward (&thingies[z_Dhistorybeginningsearchforward])
    z_Dhistoryincrementalsearchbackward,
#define t_Dhistoryincrementalsearchbackward (&thingies[z_Dhistoryincrementalsearchbackward])
    z_Dhistoryincrementalsearchforward,
#define t_Dhistoryincrementalsearchforward (&thingies[z_Dhistoryincrementalsearchforward])
    z_Dhistoryincrementalpatternsearchbackward,
#define t_Dhistoryincrementalpatternsearchbackward (&thingies[z_Dhistoryincrementalpatternsearchbackward])
    z_Dhistoryincrementalpatternsearchforward,
#define t_Dhistoryincrementalpatternsearchforward (&thingies[z_Dhistoryincrementalpatternsearchforward])
    z_Dhistorysearchbackward,
#define t_Dhistorysearchbackward (&thingies[z_Dhistorysearchbackward])
    z_Dhistorysearchforward,
#define t_Dhistorysearchforward (&thingies[z_Dhistorysearchforward])
    z_Dinfernexthistory,
#define t_Dinfernexthistory (&thingies[z_Dinfernexthistory])
    z_Dinsertlastword,
#define t_Dinsertlastword (&thingies[z_Dinsertlastword])
    z_Dkillbuffer,
#define t_Dkillbuffer (&thingies[z_Dkillbuffer])
    z_Dkillline,
#define t_Dkillline (&thingies[z_Dkillline])
    z_Dkillregion,
#define t_Dkillregion (&thingies[z_Dkillregion])
    z_Dkillwholeline,
#define t_Dkillwholeline (&thingies[z_Dkillwholeline])
    z_Dkillword,
#define t_Dkillword (&thingies[z_Dkillword])
    z_Dlistchoices,
#define t_Dlistchoices (&thingies[z_Dlistchoices])
    z_Dlistexpand,
#define t_Dlistexpand (&thingies[z_Dlistexpand])
    z_Dmagicspace,
#define t_Dmagicspace (&thingies[z_Dmagicspace])
    z_Dmenucomplete,
#define t_Dmenucomplete (&thingies[z_Dmenucomplete])
    z_Dmenuexpandorcomplete,
#define t_Dmenuexpandorcomplete (&thingies[z_Dmenuexpandorcomplete])
    z_Dnegargument,
#define t_Dnegargument (&thingies[z_Dnegargument])
    z_Doverwritemode,
#define t_Doverwritemode (&thingies[z_Doverwritemode])
    z_Dpoundinsert,
#define t_Dpoundinsert (&thingies[z_Dpoundinsert])
    z_Dpushinput,
#define t_Dpushinput (&thingies[z_Dpushinput])
    z_Dpushline,
#define t_Dpushline (&thingies[z_Dpushline])
    z_Dpushlineoredit,
#define t_Dpushlineoredit (&thingies[z_Dpushlineoredit])
    z_Dputreplaceselection,
#define t_Dputreplaceselection (&thingies[z_Dputreplaceselection])
    z_Dquotedinsert,
#define t_Dquotedinsert (&thingies[z_Dquotedinsert])
    z_Dquoteline,
#define t_Dquoteline (&thingies[z_Dquoteline])
    z_Dquoteregion,
#define t_Dquoteregion (&thingies[z_Dquoteregion])
    z_Dreadcommand,
#define t_Dreadcommand (&thingies[z_Dreadcommand])
    z_Drecursiveedit,
#define t_Drecursiveedit (&thingies[z_Drecursiveedit])
    z_Dredisplay,
#define t_Dredisplay (&thingies[z_Dredisplay])
    z_Dredo,
#define t_Dredo (&thingies[z_Dredo])
    z_Dresetprompt,
#define t_Dresetprompt (&thingies[z_Dresetprompt])
    z_Dreversemenucomplete,
#define t_Dreversemenucomplete (&thingies[z_Dreversemenucomplete])
    z_Drunhelp,
#define t_Drunhelp (&thingies[z_Drunhelp])
    z_Dselectaword,
#define t_Dselectaword (&thingies[z_Dselectaword])
    z_Dselectinword,
#define t_Dselectinword (&thingies[z_Dselectinword])
    z_Dselectablankword,
#define t_Dselectablankword (&thingies[z_Dselectablankword])
    z_Dselectinblankword,
#define t_Dselectinblankword (&thingies[z_Dselectinblankword])
    z_Dselectashellword,
#define t_Dselectashellword (&thingies[z_Dselectashellword])
    z_Dselectinshellword,
#define t_Dselectinshellword (&thingies[z_Dselectinshellword])
    z_Dselfinsert,
#define t_Dselfinsert (&thingies[z_Dselfinsert])
    z_Dselfinsertunmeta,
#define t_Dselfinsertunmeta (&thingies[z_Dselfinsertunmeta])
    z_Dsendbreak,
#define t_Dsendbreak (&thingies[z_Dsendbreak])
    z_Dsetmarkcommand,
#define t_Dsetmarkcommand (&thingies[z_Dsetmarkcommand])
    z_Dsplitundo,
#define t_Dsplitundo (&thingies[z_Dsplitundo])
    z_Dspellword,
#define t_Dspellword (&thingies[z_Dspellword])
    z_Dsetlocalhistory,
#define t_Dsetlocalhistory (&thingies[z_Dsetlocalhistory])
    z_Dtransposechars,
#define t_Dtransposechars (&thingies[z_Dtransposechars])
    z_Dtransposewords,
#define t_Dtransposewords (&thingies[z_Dtransposewords])
    z_Dundefinedkey,
#define t_Dundefinedkey (&thingies[z_Dundefinedkey])
    z_Dundo,
#define t_Dundo (&thingies[z_Dundo])
    z_Duniversalargument,
#define t_Duniversalargument (&thingies[z_Duniversalargument])
    z_Dupcaseword,
#define t_Dupcaseword (&thingies[z_Dupcaseword])
    z_Duphistory,
#define t_Duphistory (&thingies[z_Duphistory])
    z_Dupline,
#define t_Dupline (&thingies[z_Dupline])
    z_Duplineorhistory,
#define t_Duplineorhistory (&thingies[z_Duplineorhistory])
    z_Duplineorsearch,
#define t_Duplineorsearch (&thingies[z_Duplineorsearch])
    z_Dviaddeol,
#define t_Dviaddeol (&thingies[z_Dviaddeol])
    z_Dviaddnext,
#define t_Dviaddnext (&thingies[z_Dviaddnext])
    z_Dvibackwardblankword,
#define t_Dvibackwardblankword (&thingies[z_Dvibackwardblankword])
    z_Dvibackwardchar,
#define t_Dvibackwardchar (&thingies[z_Dvibackwardchar])
    z_Dvibackwarddeletechar,
#define t_Dvibackwarddeletechar (&thingies[z_Dvibackwarddeletechar])
    z_Dvibackwardkillword,
#define t_Dvibackwardkillword (&thingies[z_Dvibackwardkillword])
    z_Dvibackwardword,
#define t_Dvibackwardword (&thingies[z_Dvibackwardword])
    z_Dvibackwardwordend,
#define t_Dvibackwardwordend (&thingies[z_Dvibackwardwordend])
    z_Dvibackwardblankwordend,
#define t_Dvibackwardblankwordend (&thingies[z_Dvibackwardblankwordend])
    z_Dvibeginningofline,
#define t_Dvibeginningofline (&thingies[z_Dvibeginningofline])
    z_Dvicapslockpanic,
#define t_Dvicapslockpanic (&thingies[z_Dvicapslockpanic])
    z_Dvichange,
#define t_Dvichange (&thingies[z_Dvichange])
    z_Dvichangeeol,
#define t_Dvichangeeol (&thingies[z_Dvichangeeol])
    z_Dvichangewholeline,
#define t_Dvichangewholeline (&thingies[z_Dvichangewholeline])
    z_Dvicmdmode,
#define t_Dvicmdmode (&thingies[z_Dvicmdmode])
    z_Dvidelete,
#define t_Dvidelete (&thingies[z_Dvidelete])
    z_Dvideletechar,
#define t_Dvideletechar (&thingies[z_Dvideletechar])
    z_Dvidigitorbeginningofline,
#define t_Dvidigitorbeginningofline (&thingies[z_Dvidigitorbeginningofline])
    z_Dvidowncase,
#define t_Dvidowncase (&thingies[z_Dvidowncase])
    z_Dvidownlineorhistory,
#define t_Dvidownlineorhistory (&thingies[z_Dvidownlineorhistory])
    z_Dviendofline,
#define t_Dviendofline (&thingies[z_Dviendofline])
    z_Dvifetchhistory,
#define t_Dvifetchhistory (&thingies[z_Dvifetchhistory])
    z_Dvifindnextchar,
#define t_Dvifindnextchar (&thingies[z_Dvifindnextchar])
    z_Dvifindnextcharskip,
#define t_Dvifindnextcharskip (&thingies[z_Dvifindnextcharskip])
    z_Dvifindprevchar,
#define t_Dvifindprevchar (&thingies[z_Dvifindprevchar])
    z_Dvifindprevcharskip,
#define t_Dvifindprevcharskip (&thingies[z_Dvifindprevcharskip])
    z_Dvifirstnonblank,
#define t_Dvifirstnonblank (&thingies[z_Dvifirstnonblank])
    z_Dviforwardblankword,
#define t_Dviforwardblankword (&thingies[z_Dviforwardblankword])
    z_Dviforwardblankwordend,
#define t_Dviforwardblankwordend (&thingies[z_Dviforwardblankwordend])
    z_Dviforwardchar,
#define t_Dviforwardchar (&thingies[z_Dviforwardchar])
    z_Dviforwardword,
#define t_Dviforwardword (&thingies[z_Dviforwardword])
    z_Dviforwardwordend,
#define t_Dviforwardwordend (&thingies[z_Dviforwardwordend])
    z_Dvigotocolumn,
#define t_Dvigotocolumn (&thingies[z_Dvigotocolumn])
    z_Dvigotomark,
#define t_Dvigotomark (&thingies[z_Dvigotomark])
    z_Dvigotomarkline,
#define t_Dvigotomarkline (&thingies[z_Dvigotomarkline])
    z_Dvihistorysearchbackward,
#define t_Dvihistorysearchbackward (&thingies[z_Dvihistorysearchbackward])
    z_Dvihistorysearchforward,
#define t_Dvihistorysearchforward (&thingies[z_Dvihistorysearchforward])
    z_Dviindent,
#define t_Dviindent (&thingies[z_Dviindent])
    z_Dviinsert,
#define t_Dviinsert (&thingies[z_Dviinsert])
    z_Dviinsertbol,
#define t_Dviinsertbol (&thingies[z_Dviinsertbol])
    z_Dvijoin,
#define t_Dvijoin (&thingies[z_Dvijoin])
    z_Dvikilleol,
#define t_Dvikilleol (&thingies[z_Dvikilleol])
    z_Dvikillline,
#define t_Dvikillline (&thingies[z_Dvikillline])
    z_Dvimatchbracket,
#define t_Dvimatchbracket (&thingies[z_Dvimatchbracket])
    z_Dviopenlineabove,
#define t_Dviopenlineabove (&thingies[z_Dviopenlineabove])
    z_Dviopenlinebelow,
#define t_Dviopenlinebelow (&thingies[z_Dviopenlinebelow])
    z_Dvioperswapcase,
#define t_Dvioperswapcase (&thingies[z_Dvioperswapcase])
    z_Dvipoundinsert,
#define t_Dvipoundinsert (&thingies[z_Dvipoundinsert])
    z_Dviputafter,
#define t_Dviputafter (&thingies[z_Dviputafter])
    z_Dviputbefore,
#define t_Dviputbefore (&thingies[z_Dviputbefore])
    z_Dviquotedinsert,
#define t_Dviquotedinsert (&thingies[z_Dviquotedinsert])
    z_Dvirepeatchange,
#define t_Dvirepeatchange (&thingies[z_Dvirepeatchange])
    z_Dvirepeatfind,
#define t_Dvirepeatfind (&thingies[z_Dvirepeatfind])
    z_Dvirepeatsearch,
#define t_Dvirepeatsearch (&thingies[z_Dvirepeatsearch])
    z_Dvireplace,
#define t_Dvireplace (&thingies[z_Dvireplace])
    z_Dvireplacechars,
#define t_Dvireplacechars (&thingies[z_Dvireplacechars])
    z_Dvirevrepeatfind,
#define t_Dvirevrepeatfind (&thingies[z_Dvirevrepeatfind])
    z_Dvirevrepeatsearch,
#define t_Dvirevrepeatsearch (&thingies[z_Dvirevrepeatsearch])
    z_Dvisetbuffer,
#define t_Dvisetbuffer (&thingies[z_Dvisetbuffer])
    z_Dvisetmark,
#define t_Dvisetmark (&thingies[z_Dvisetmark])
    z_Dvisubstitute,
#define t_Dvisubstitute (&thingies[z_Dvisubstitute])
    z_Dviswapcase,
#define t_Dviswapcase (&thingies[z_Dviswapcase])
    z_Dviundochange,
#define t_Dviundochange (&thingies[z_Dviundochange])
    z_Dviunindent,
#define t_Dviunindent (&thingies[z_Dviunindent])
    z_Dviupcase,
#define t_Dviupcase (&thingies[z_Dviupcase])
    z_Dviuplineorhistory,
#define t_Dviuplineorhistory (&thingies[z_Dviuplineorhistory])
    z_Dviyank,
#define t_Dviyank (&thingies[z_Dviyank])
    z_Dviyankeol,
#define t_Dviyankeol (&thingies[z_Dviyankeol])
    z_Dviyankwholeline,
#define t_Dviyankwholeline (&thingies[z_Dviyankwholeline])
    z_Dvisuallinemode,
#define t_Dvisuallinemode (&thingies[z_Dvisuallinemode])
    z_Dvisualmode,
#define t_Dvisualmode (&thingies[z_Dvisualmode])
    z_Dwhatcursorposition,
#define t_Dwhatcursorposition (&thingies[z_Dwhatcursorposition])
    z_Dwhereis,
#define t_Dwhereis (&thingies[z_Dwhereis])
    z_Dwhichcommand,
#define t_Dwhichcommand (&thingies[z_Dwhichcommand])
    z_Dyank,
#define t_Dyank (&thingies[z_Dyank])
    z_Dyankpop,
#define t_Dyankpop (&thingies[z_Dyankpop])
    ZLE_BUILTIN_THINGY_COUNT
};
