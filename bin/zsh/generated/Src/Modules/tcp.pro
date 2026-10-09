/* Generated automatically */
#ifndef HAVE_INET_NTOP
#else /* !HAVE_INET_NTOP */
# define zsh_inet_ntop inet_ntop
#endif /* !HAVE_INET_NTOP */
#ifndef HAVE_INET_ATON
#else /* !HAVE_INET_ATON */
# define zsh_inet_aton inet_aton
#endif /* !HAVE_INET_ATON */
#ifndef HAVE_INET_PTON
#endif /* !HAVE_INET_PTON */
#ifndef HAVE_GETIPNODEBYNAME
# ifndef HAVE_GETHOSTBYNAME2
#else /* !HAVE_GETHOSTBYNAME2 */
# define zsh_gethostbyname2 gethostbyname2
# endif /* !HAVE_GETHOSTBYNAME2 */
#else /* !HAVE_GETIPNODEBYNAME */
# define zsh_getipnodebyname getipnodebyname
#endif /* !HAVE_GETIPNODEBYNAME */
