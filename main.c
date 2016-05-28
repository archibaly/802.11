#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pcap.h>

//#include "print-802_11.h"
//#include "print-ascii.h"
#include "netdissect.h"

/*
 * By default, print the specified data out in hex and ASCII.
 */
static void ndo_default_print(netdissect_options * ndo, const u_char * bp, u_int length)
{
	hex_and_ascii_print(ndo, "\n\t", bp, length);	/* pass on lf and indentation string */
}

static int tcpdump_printf(netdissect_options * ndo, const char *fmt, ...)
{

	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf(stdout, fmt, args);
	va_end(args);

	return ret;
}

static void ndo_error(netdissect_options * ndo, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(1);
	/* NOTREACHED */
}

static void ndo_warning(netdissect_options * ndo, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

int main()
{
	netdissect_options ndo;
	struct pcap_pkthdr h;
	unsigned char packet[128];

	ndo.ndo_Oflag = 1;
	ndo.ndo_Rflag = 1;
	ndo.ndo_dlt = -1;
	ndo.ndo_default_print = ndo_default_print;
	ndo.ndo_printf = tcpdump_printf;
	ndo.ndo_error = ndo_error;
	ndo.ndo_warning = ndo_warning;
	ndo.ndo_snaplen = DEFAULT_SNAPLEN;
	ndo.ndo_immediate = 0;

	ieee802_11_if_print(&ndo, &h, packet);

	return 0;
}
