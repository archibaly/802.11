#ifndef _UTIL_H_
#define _UTIL_H_

#include "netdissect.h"

const char *tok2str(const struct tok *lp, const char *fmt, u_int v);
const char *etheraddr_string(netdissect_options * ndo, const u_char * ep);
const char *etherproto_string(u_short port);
int fn_print(netdissect_options * ndo, const u_char * s, const u_char * ep);

#endif /* _UTIL_H_ */
