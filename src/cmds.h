/*
 * File: cmds.h
 *
 * Simple local nameserver for OS/2.
 *
 * Command codes and table.
 *
 * Bob Eager   August 2000
 *
 */

/* Internal command codes */

#define	CMD_PORT		1
#define	CMD_AUTH_NETWORK	2
#define	CMD_AUTH_NETMASK	3
#define	CMD_AUTH_DOMAIN		4
#define	CMD_REFER_INTERFACE	5
#define	CMD_REFER_SERVERS	6
#define	CMD_BAD			7

static	struct {
	UCHAR	*cmdname;		/* Command name */
	INT	cmdcode;		/* Command code */
} cmdtab[] = {
	{ "PORT",		CMD_PORT },
	{ "AUTH_NETWORK",	CMD_AUTH_NETWORK },
	{ "AUTH_NETMASK",	CMD_AUTH_NETMASK },
	{ "AUTH_DOMAIN",	CMD_AUTH_DOMAIN },
	{ "REFER_INTERFACE",	CMD_REFER_INTERFACE },
	{ "REFER_SERVERS",	CMD_REFER_SERVERS },
	{ "",			CMD_BAD }	/* End of table marker */
};

/*
 * End of file: cmds.h
 *
 */

