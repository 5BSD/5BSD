/** zle_widget.h                                **/
/** indices of and pointers to internal widgets **/

enum {
    wi_acceptandhold,
#define w_acceptandhold (&widgets[wi_acceptandhold])
    wi_acceptandinfernexthistory,
#define w_acceptandinfernexthistory (&widgets[wi_acceptandinfernexthistory])
    wi_acceptandmenucomplete,
#define w_acceptandmenucomplete (&widgets[wi_acceptandmenucomplete])
    wi_acceptline,
#define w_acceptline (&widgets[wi_acceptline])
    wi_acceptlineanddownhistory,
#define w_acceptlineanddownhistory (&widgets[wi_acceptlineanddownhistory])
    wi_acceptsearch,
#define w_acceptsearch (&widgets[wi_acceptsearch])
    wi_argumentbase,
#define w_argumentbase (&widgets[wi_argumentbase])
    wi_autosuffixremove,
#define w_autosuffixremove (&widgets[wi_autosuffixremove])
    wi_autosuffixretain,
#define w_autosuffixretain (&widgets[wi_autosuffixretain])
    wi_backwardchar,
#define w_backwardchar (&widgets[wi_backwardchar])
    wi_backwarddeletechar,
#define w_backwarddeletechar (&widgets[wi_backwarddeletechar])
    wi_backwarddeleteword,
#define w_backwarddeleteword (&widgets[wi_backwarddeleteword])
    wi_backwardkillline,
#define w_backwardkillline (&widgets[wi_backwardkillline])
    wi_backwardkillword,
#define w_backwardkillword (&widgets[wi_backwardkillword])
    wi_backwardword,
#define w_backwardword (&widgets[wi_backwardword])
    wi_beep,
#define w_beep (&widgets[wi_beep])
    wi_beginningofbufferorhistory,
#define w_beginningofbufferorhistory (&widgets[wi_beginningofbufferorhistory])
    wi_beginningofhistory,
#define w_beginningofhistory (&widgets[wi_beginningofhistory])
    wi_beginningofline,
#define w_beginningofline (&widgets[wi_beginningofline])
    wi_beginningoflinehist,
#define w_beginningoflinehist (&widgets[wi_beginningoflinehist])
    wi_bracketedpaste,
#define w_bracketedpaste (&widgets[wi_bracketedpaste])
    wi_capitalizeword,
#define w_capitalizeword (&widgets[wi_capitalizeword])
    wi_clearscreen,
#define w_clearscreen (&widgets[wi_clearscreen])
    wi_completeword,
#define w_completeword (&widgets[wi_completeword])
    wi_copyprevword,
#define w_copyprevword (&widgets[wi_copyprevword])
    wi_copyprevshellword,
#define w_copyprevshellword (&widgets[wi_copyprevshellword])
    wi_copyregionaskill,
#define w_copyregionaskill (&widgets[wi_copyregionaskill])
    wi_deactivateregion,
#define w_deactivateregion (&widgets[wi_deactivateregion])
    wi_deletechar,
#define w_deletechar (&widgets[wi_deletechar])
    wi_deletecharorlist,
#define w_deletecharorlist (&widgets[wi_deletecharorlist])
    wi_deleteword,
#define w_deleteword (&widgets[wi_deleteword])
    wi_describekeybriefly,
#define w_describekeybriefly (&widgets[wi_describekeybriefly])
    wi_digitargument,
#define w_digitargument (&widgets[wi_digitargument])
    wi_downcaseword,
#define w_downcaseword (&widgets[wi_downcaseword])
    wi_downhistory,
#define w_downhistory (&widgets[wi_downhistory])
    wi_downline,
#define w_downline (&widgets[wi_downline])
    wi_downlineorhistory,
#define w_downlineorhistory (&widgets[wi_downlineorhistory])
    wi_downlineorsearch,
#define w_downlineorsearch (&widgets[wi_downlineorsearch])
    wi_emacsbackwardword,
#define w_emacsbackwardword (&widgets[wi_emacsbackwardword])
    wi_emacsforwardword,
#define w_emacsforwardword (&widgets[wi_emacsforwardword])
    wi_endofbufferorhistory,
#define w_endofbufferorhistory (&widgets[wi_endofbufferorhistory])
    wi_endofhistory,
#define w_endofhistory (&widgets[wi_endofhistory])
    wi_endofline,
#define w_endofline (&widgets[wi_endofline])
    wi_endoflinehist,
#define w_endoflinehist (&widgets[wi_endoflinehist])
    wi_endoflist,
#define w_endoflist (&widgets[wi_endoflist])
    wi_exchangepointandmark,
#define w_exchangepointandmark (&widgets[wi_exchangepointandmark])
    wi_executelastnamedcmd,
#define w_executelastnamedcmd (&widgets[wi_executelastnamedcmd])
    wi_executenamedcmd,
#define w_executenamedcmd (&widgets[wi_executenamedcmd])
    wi_expandcmdpath,
#define w_expandcmdpath (&widgets[wi_expandcmdpath])
    wi_expandhistory,
#define w_expandhistory (&widgets[wi_expandhistory])
    wi_expandorcomplete,
#define w_expandorcomplete (&widgets[wi_expandorcomplete])
    wi_expandorcompleteprefix,
#define w_expandorcompleteprefix (&widgets[wi_expandorcompleteprefix])
    wi_expandword,
#define w_expandword (&widgets[wi_expandword])
    wi_forwardchar,
#define w_forwardchar (&widgets[wi_forwardchar])
    wi_forwardword,
#define w_forwardword (&widgets[wi_forwardword])
    wi_getline,
#define w_getline (&widgets[wi_getline])
    wi_gosmacstransposechars,
#define w_gosmacstransposechars (&widgets[wi_gosmacstransposechars])
    wi_historybeginningsearchbackward,
#define w_historybeginningsearchbackward (&widgets[wi_historybeginningsearchbackward])
    wi_historybeginningsearchforward,
#define w_historybeginningsearchforward (&widgets[wi_historybeginningsearchforward])
    wi_historyincrementalsearchbackward,
#define w_historyincrementalsearchbackward (&widgets[wi_historyincrementalsearchbackward])
    wi_historyincrementalsearchforward,
#define w_historyincrementalsearchforward (&widgets[wi_historyincrementalsearchforward])
    wi_historyincrementalpatternsearchbackward,
#define w_historyincrementalpatternsearchbackward (&widgets[wi_historyincrementalpatternsearchbackward])
    wi_historyincrementalpatternsearchforward,
#define w_historyincrementalpatternsearchforward (&widgets[wi_historyincrementalpatternsearchforward])
    wi_historysearchbackward,
#define w_historysearchbackward (&widgets[wi_historysearchbackward])
    wi_historysearchforward,
#define w_historysearchforward (&widgets[wi_historysearchforward])
    wi_infernexthistory,
#define w_infernexthistory (&widgets[wi_infernexthistory])
    wi_insertlastword,
#define w_insertlastword (&widgets[wi_insertlastword])
    wi_killbuffer,
#define w_killbuffer (&widgets[wi_killbuffer])
    wi_killline,
#define w_killline (&widgets[wi_killline])
    wi_killregion,
#define w_killregion (&widgets[wi_killregion])
    wi_killwholeline,
#define w_killwholeline (&widgets[wi_killwholeline])
    wi_killword,
#define w_killword (&widgets[wi_killword])
    wi_listchoices,
#define w_listchoices (&widgets[wi_listchoices])
    wi_listexpand,
#define w_listexpand (&widgets[wi_listexpand])
    wi_magicspace,
#define w_magicspace (&widgets[wi_magicspace])
    wi_menucomplete,
#define w_menucomplete (&widgets[wi_menucomplete])
    wi_menuexpandorcomplete,
#define w_menuexpandorcomplete (&widgets[wi_menuexpandorcomplete])
    wi_negargument,
#define w_negargument (&widgets[wi_negargument])
    wi_overwritemode,
#define w_overwritemode (&widgets[wi_overwritemode])
    wi_poundinsert,
#define w_poundinsert (&widgets[wi_poundinsert])
    wi_pushinput,
#define w_pushinput (&widgets[wi_pushinput])
    wi_pushline,
#define w_pushline (&widgets[wi_pushline])
    wi_pushlineoredit,
#define w_pushlineoredit (&widgets[wi_pushlineoredit])
    wi_putreplaceselection,
#define w_putreplaceselection (&widgets[wi_putreplaceselection])
    wi_quotedinsert,
#define w_quotedinsert (&widgets[wi_quotedinsert])
    wi_quoteline,
#define w_quoteline (&widgets[wi_quoteline])
    wi_quoteregion,
#define w_quoteregion (&widgets[wi_quoteregion])
    wi_readcommand,
#define w_readcommand (&widgets[wi_readcommand])
    wi_recursiveedit,
#define w_recursiveedit (&widgets[wi_recursiveedit])
    wi_redisplay,
#define w_redisplay (&widgets[wi_redisplay])
    wi_redo,
#define w_redo (&widgets[wi_redo])
    wi_resetprompt,
#define w_resetprompt (&widgets[wi_resetprompt])
    wi_reversemenucomplete,
#define w_reversemenucomplete (&widgets[wi_reversemenucomplete])
    wi_runhelp,
#define w_runhelp (&widgets[wi_runhelp])
    wi_selectaword,
#define w_selectaword (&widgets[wi_selectaword])
    wi_selectinword,
#define w_selectinword (&widgets[wi_selectinword])
    wi_selectablankword,
#define w_selectablankword (&widgets[wi_selectablankword])
    wi_selectinblankword,
#define w_selectinblankword (&widgets[wi_selectinblankword])
    wi_selectashellword,
#define w_selectashellword (&widgets[wi_selectashellword])
    wi_selectinshellword,
#define w_selectinshellword (&widgets[wi_selectinshellword])
    wi_selfinsert,
#define w_selfinsert (&widgets[wi_selfinsert])
    wi_selfinsertunmeta,
#define w_selfinsertunmeta (&widgets[wi_selfinsertunmeta])
    wi_sendbreak,
#define w_sendbreak (&widgets[wi_sendbreak])
    wi_setmarkcommand,
#define w_setmarkcommand (&widgets[wi_setmarkcommand])
    wi_splitundo,
#define w_splitundo (&widgets[wi_splitundo])
    wi_spellword,
#define w_spellword (&widgets[wi_spellword])
    wi_setlocalhistory,
#define w_setlocalhistory (&widgets[wi_setlocalhistory])
    wi_transposechars,
#define w_transposechars (&widgets[wi_transposechars])
    wi_transposewords,
#define w_transposewords (&widgets[wi_transposewords])
    wi_undefinedkey,
#define w_undefinedkey (&widgets[wi_undefinedkey])
    wi_undo,
#define w_undo (&widgets[wi_undo])
    wi_universalargument,
#define w_universalargument (&widgets[wi_universalargument])
    wi_upcaseword,
#define w_upcaseword (&widgets[wi_upcaseword])
    wi_uphistory,
#define w_uphistory (&widgets[wi_uphistory])
    wi_upline,
#define w_upline (&widgets[wi_upline])
    wi_uplineorhistory,
#define w_uplineorhistory (&widgets[wi_uplineorhistory])
    wi_uplineorsearch,
#define w_uplineorsearch (&widgets[wi_uplineorsearch])
    wi_viaddeol,
#define w_viaddeol (&widgets[wi_viaddeol])
    wi_viaddnext,
#define w_viaddnext (&widgets[wi_viaddnext])
    wi_vibackwardblankword,
#define w_vibackwardblankword (&widgets[wi_vibackwardblankword])
    wi_vibackwardchar,
#define w_vibackwardchar (&widgets[wi_vibackwardchar])
    wi_vibackwarddeletechar,
#define w_vibackwarddeletechar (&widgets[wi_vibackwarddeletechar])
    wi_vibackwardkillword,
#define w_vibackwardkillword (&widgets[wi_vibackwardkillword])
    wi_vibackwardword,
#define w_vibackwardword (&widgets[wi_vibackwardword])
    wi_vibackwardwordend,
#define w_vibackwardwordend (&widgets[wi_vibackwardwordend])
    wi_vibackwardblankwordend,
#define w_vibackwardblankwordend (&widgets[wi_vibackwardblankwordend])
    wi_vibeginningofline,
#define w_vibeginningofline (&widgets[wi_vibeginningofline])
    wi_vicapslockpanic,
#define w_vicapslockpanic (&widgets[wi_vicapslockpanic])
    wi_vichange,
#define w_vichange (&widgets[wi_vichange])
    wi_vichangeeol,
#define w_vichangeeol (&widgets[wi_vichangeeol])
    wi_vichangewholeline,
#define w_vichangewholeline (&widgets[wi_vichangewholeline])
    wi_vicmdmode,
#define w_vicmdmode (&widgets[wi_vicmdmode])
    wi_videlete,
#define w_videlete (&widgets[wi_videlete])
    wi_videletechar,
#define w_videletechar (&widgets[wi_videletechar])
    wi_vidigitorbeginningofline,
#define w_vidigitorbeginningofline (&widgets[wi_vidigitorbeginningofline])
    wi_vidowncase,
#define w_vidowncase (&widgets[wi_vidowncase])
    wi_vidownlineorhistory,
#define w_vidownlineorhistory (&widgets[wi_vidownlineorhistory])
    wi_viendofline,
#define w_viendofline (&widgets[wi_viendofline])
    wi_vifetchhistory,
#define w_vifetchhistory (&widgets[wi_vifetchhistory])
    wi_vifindnextchar,
#define w_vifindnextchar (&widgets[wi_vifindnextchar])
    wi_vifindnextcharskip,
#define w_vifindnextcharskip (&widgets[wi_vifindnextcharskip])
    wi_vifindprevchar,
#define w_vifindprevchar (&widgets[wi_vifindprevchar])
    wi_vifindprevcharskip,
#define w_vifindprevcharskip (&widgets[wi_vifindprevcharskip])
    wi_vifirstnonblank,
#define w_vifirstnonblank (&widgets[wi_vifirstnonblank])
    wi_viforwardblankword,
#define w_viforwardblankword (&widgets[wi_viforwardblankword])
    wi_viforwardblankwordend,
#define w_viforwardblankwordend (&widgets[wi_viforwardblankwordend])
    wi_viforwardchar,
#define w_viforwardchar (&widgets[wi_viforwardchar])
    wi_viforwardword,
#define w_viforwardword (&widgets[wi_viforwardword])
    wi_viforwardwordend,
#define w_viforwardwordend (&widgets[wi_viforwardwordend])
    wi_vigotocolumn,
#define w_vigotocolumn (&widgets[wi_vigotocolumn])
    wi_vigotomark,
#define w_vigotomark (&widgets[wi_vigotomark])
    wi_vigotomarkline,
#define w_vigotomarkline (&widgets[wi_vigotomarkline])
    wi_vihistorysearchbackward,
#define w_vihistorysearchbackward (&widgets[wi_vihistorysearchbackward])
    wi_vihistorysearchforward,
#define w_vihistorysearchforward (&widgets[wi_vihistorysearchforward])
    wi_viindent,
#define w_viindent (&widgets[wi_viindent])
    wi_viinsert,
#define w_viinsert (&widgets[wi_viinsert])
    wi_viinsertbol,
#define w_viinsertbol (&widgets[wi_viinsertbol])
    wi_vijoin,
#define w_vijoin (&widgets[wi_vijoin])
    wi_vikilleol,
#define w_vikilleol (&widgets[wi_vikilleol])
    wi_vikillline,
#define w_vikillline (&widgets[wi_vikillline])
    wi_vimatchbracket,
#define w_vimatchbracket (&widgets[wi_vimatchbracket])
    wi_viopenlineabove,
#define w_viopenlineabove (&widgets[wi_viopenlineabove])
    wi_viopenlinebelow,
#define w_viopenlinebelow (&widgets[wi_viopenlinebelow])
    wi_vioperswapcase,
#define w_vioperswapcase (&widgets[wi_vioperswapcase])
    wi_vipoundinsert,
#define w_vipoundinsert (&widgets[wi_vipoundinsert])
    wi_viputafter,
#define w_viputafter (&widgets[wi_viputafter])
    wi_viputbefore,
#define w_viputbefore (&widgets[wi_viputbefore])
    wi_viquotedinsert,
#define w_viquotedinsert (&widgets[wi_viquotedinsert])
    wi_virepeatchange,
#define w_virepeatchange (&widgets[wi_virepeatchange])
    wi_virepeatfind,
#define w_virepeatfind (&widgets[wi_virepeatfind])
    wi_virepeatsearch,
#define w_virepeatsearch (&widgets[wi_virepeatsearch])
    wi_vireplace,
#define w_vireplace (&widgets[wi_vireplace])
    wi_vireplacechars,
#define w_vireplacechars (&widgets[wi_vireplacechars])
    wi_virevrepeatfind,
#define w_virevrepeatfind (&widgets[wi_virevrepeatfind])
    wi_virevrepeatsearch,
#define w_virevrepeatsearch (&widgets[wi_virevrepeatsearch])
    wi_visetbuffer,
#define w_visetbuffer (&widgets[wi_visetbuffer])
    wi_visetmark,
#define w_visetmark (&widgets[wi_visetmark])
    wi_visubstitute,
#define w_visubstitute (&widgets[wi_visubstitute])
    wi_viswapcase,
#define w_viswapcase (&widgets[wi_viswapcase])
    wi_viundochange,
#define w_viundochange (&widgets[wi_viundochange])
    wi_viunindent,
#define w_viunindent (&widgets[wi_viunindent])
    wi_viupcase,
#define w_viupcase (&widgets[wi_viupcase])
    wi_viuplineorhistory,
#define w_viuplineorhistory (&widgets[wi_viuplineorhistory])
    wi_viyank,
#define w_viyank (&widgets[wi_viyank])
    wi_viyankeol,
#define w_viyankeol (&widgets[wi_viyankeol])
    wi_viyankwholeline,
#define w_viyankwholeline (&widgets[wi_viyankwholeline])
    wi_visuallinemode,
#define w_visuallinemode (&widgets[wi_visuallinemode])
    wi_visualmode,
#define w_visualmode (&widgets[wi_visualmode])
    wi_whatcursorposition,
#define w_whatcursorposition (&widgets[wi_whatcursorposition])
    wi_whereis,
#define w_whereis (&widgets[wi_whereis])
    wi_whichcommand,
#define w_whichcommand (&widgets[wi_whichcommand])
    wi_yank,
#define w_yank (&widgets[wi_yank])
    wi_yankpop,
#define w_yankpop (&widgets[wi_yankpop])
    ZLE_BUILTIN_WIDGET_COUNT
};
