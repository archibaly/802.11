#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "oui.h"
#include "extract.h"

#define BUFSIZE	128
#define HASHNAMESIZE 4096

struct hnamemem {
	uint32_t addr;
	const char *name;
	struct hnamemem *nxt;
};

struct enamemem {
	u_short e_addr0;
	u_short e_addr1;
	u_short e_addr2;
	const char *e_name;
	u_char *e_nsap;				/* used only for nsaptable[] */
#define e_bs e_nsap				/* for bytestringtable */
	struct enamemem *e_nxt;
};

static const char hex[] = "0123456789abcdef";

/*
 * Convert a token value to a string; use "fmt" if not found.
 */
const char *tok2strbuf(const struct tok *lp, const char *fmt, u_int v, char *buf, size_t bufsize)
{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}

/*
 * Convert a token value to a string; use "fmt" if not found.
 */
const char *tok2str(const struct tok *lp, const char *fmt, u_int v)
{
	static char buf[4][128];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx + 1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

static struct enamemem enametable[HASHNAMESIZE];

/* Find the hash node that corresponds the ether address 'ep' */
static inline struct enamemem *lookup_emem(const u_char * ep)
{
	u_int i, j, k;
	struct enamemem *tp;

	k = (ep[0] << 8) | ep[1];
	j = (ep[2] << 8) | ep[3];
	i = (ep[4] << 8) | ep[5];

	tp = &enametable[(i ^ j) & (HASHNAMESIZE - 1)];
	while (tp->e_nxt)
		if (tp->e_addr0 == i && tp->e_addr1 == j && tp->e_addr2 == k)
			return tp;
		else
			tp = tp->e_nxt;
	tp->e_addr0 = i;
	tp->e_addr1 = j;
	tp->e_addr2 = k;
	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
#if 0
	if (tp->e_nxt == NULL)
		error("lookup_emem: calloc");
#endif

	return tp;
}

const char *etheraddr_string(netdissect_options * ndo, const u_char * ep)
{
	int i;
	char *cp;
	struct enamemem *tp;
	int oui;
	char buf[BUFSIZE];

	tp = lookup_emem(ep);
	if (tp->e_name)
		return (tp->e_name);
#ifdef USE_ETHER_NTOHOST
	if (!ndo->ndo_nflag) {
		char buf2[BUFSIZE];

		/*
		 * We don't cast it to "const struct ether_addr *"
		 * because some systems fail to declare the second
		 * argument as a "const" pointer, even though they
		 * don't modify what it points to.
		 */
		if (ether_ntohost(buf2, (struct ether_addr *)ep) == 0) {
			tp->e_name = strdup(buf2);
			return (tp->e_name);
		}
	}
#endif
	cp = buf;
	oui = EXTRACT_24BITS(ep);
	*cp++ = hex[*ep >> 4];
	*cp++ = hex[*ep++ & 0xf];
	for (i = 5; --i >= 0;) {
		*cp++ = ':';
		*cp++ = hex[*ep >> 4];
		*cp++ = hex[*ep++ & 0xf];
	}

	if (!ndo->ndo_nflag) {
		snprintf(cp, BUFSIZE - (2 + 5 * 3), " (oui %s)", tok2str(oui_values, "Unknown", oui));
	} else
		*cp = '\0';
	tp->e_name = strdup(buf);
	return (tp->e_name);
}

/* Return a zero'ed hnamemem struct and cuts down on calloc() overhead */
struct hnamemem *newhnamemem(void)
{
	struct hnamemem *p;
	static struct hnamemem *ptr = NULL;
	static u_int num = 0;

	if (num <= 0) {
		num = 64;
		ptr = (struct hnamemem *)calloc(num, sizeof(*ptr));
#if 0
		if (ptr == NULL)
			error("newhnamemem: calloc");
#endif
	}
	--num;
	p = ptr++;
	return (p);
}

static struct hnamemem eprototable[HASHNAMESIZE];

const char *etherproto_string(u_short port)
{
	char *cp;
	struct hnamemem *tp;
	uint32_t i = port;
	char buf[sizeof("0000")];

	for (tp = &eprototable[i & (HASHNAMESIZE - 1)]; tp->nxt; tp = tp->nxt)
		if (tp->addr == i)
			return (tp->name);

	tp->addr = i;
	tp->nxt = newhnamemem();

	cp = buf;
	NTOHS(port);
	*cp++ = hex[port >> 12 & 0xf];
	*cp++ = hex[port >> 8 & 0xf];
	*cp++ = hex[port >> 4 & 0xf];
	*cp++ = hex[port & 0xf];
	*cp++ = '\0';
	tp->name = strdup(buf);
	return (tp->name);
}

/*
 * Print out a null-terminated filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */
int fn_print(netdissect_options * ndo, const u_char * s, const u_char * ep)
{
	int ret;
	u_char c;

	ret = 1;					/* assume truncated */
	while (ep == NULL || s < ep) {
		c = *s++;
		if (c == '\0') {
			ret = 0;
			break;
		}
		if (!ND_ISASCII(c)) {
			c = ND_TOASCII(c);
			ND_PRINT((ndo, "M-"));
		}
		if (!ND_ISPRINT(c)) {
			c ^= 0x40;			/* DEL to ?, others to alpha */
			ND_PRINT((ndo, "^"));
		}
		ND_PRINT((ndo, "%c", c));
	}
	return ret;
}
