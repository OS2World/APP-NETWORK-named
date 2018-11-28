/*
 * File: named.h
 *
 * Simple local nameserver for OS/2.
 *
 * Header file
 *
 * Bob Eager   August 2000
 *
 */

#include <os2.h>

#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef	DEBUG
#include <stddef.h>
#endif

#define	OS2
#include <netdb.h>
#include <types.h>
#include <utils.h>
#include <netinet\in.h>
#include <sys\socket.h>
#include <sys\ioctl.h>
#include <net\if.h>
#include <arpa\nameser.h>
#include <resolv.h>
#include <nerrno.h>

#define	VERSION			1	/* Major version number */
#define	EDIT			4	/* Edit number within major version */

#define	FALSE			0
#define	TRUE			1

#define	DOMAINSERVICE	"domain"	/* Name of nameserver service */
#define	UDP		"udp"		/* UDP protocol */

/* Configuration constants */

#define	DEFAULT_AUTH_NETWORK	"0.0.0.0"
#define	DEFAULT_AUTH_NETMASK	"255.255.255.255"
#define	DEFAULT_REFER_INTERFACE	"sl0"

#define	INITIAL_REFER_TIMEOUT	5	/* For referral calls (seconds) */
#define	REFER_RETRY_LIMIT	4	/* Number of retries per name server */
#define	LOCAL_TTL		86400	/* Local names live for a day */
#define	MAXDNPTRS		50	/* Maximum number of compressed names */
#define	MAXINTERFACES		15	/* Maximum number of interfaces */
#define	MAXLOG			200	/* Maximum length of a logfile line */

/* Database entry types */

#define	ENT_TYPE_PRIMARY	0	/* Primary name */
#define	ENT_TYPE_ALIAS		1	/* Alias name */

/* Type definitions */

typedef	struct hostent		HOST, *PHOST;		/* Host structure */
typedef	struct ifconf		IFCONF, *PIFCONF;	/* Interface configuration */
typedef	struct ifreq		IFREQ, *PIFREQ;		/* Interface information */
typedef struct in_addr		INADDR, *PINADDR;	/* Internet address */
typedef	struct servent		SERV, *PSERV;		/* Service structure */
typedef	struct sockaddr		SOCKG, *PSOCKG;		/* Generic structure */
typedef	struct sockaddr_in	SOCK, *PSOCK;		/* Internet structure */

/* Structure definitions */

typedef struct _DBENT {			/* Name database entry */
struct _DBENT	*next;			/* Next entry in chain */
PUCHAR		name;			/* Host name */
ULONG		ttl;			/* Time to live */
union info {
 INADDR		address;		/* IP address */
 struct _DBENT	*primary;		/* Entry for primary name */
};
USHORT		type;			/* Entry type */
} DBENT, *PDBENT;

typedef struct _SERVERS {		/* Server address list */
struct _SERVERS	*next;			/* Next entry in chain */
INADDR		if_addr;		/* Interface address */
INADDR		if_mask;		/* Interface mask */
INT		nservers;		/* Number of servers */
INADDR		servers[MAXNS];		/* List of servers */
} SERVERS, *PSERVERS;

typedef struct _CONFIG {		/* Configuration information */
PUCHAR		myname;			/* Name of this server */
PUCHAR		domain;			/* Domain we are authority for */
PUCHAR		refer_interface;	/* Interface to use for referrals */
INADDR		network;		/* Network we are authority for */
INADDR		netmask;		/* Mask for above network */
PUCHAR		pktbuf;			/* Packet buffer */
PDBENT		dbhead;			/* Head of name chain */
PSERVERS	servlist;		/* Head of server chain */
INT		sockno;			/* Socket used for all work */
USHORT		port;			/* Port to listen on */
USHORT		nsport;			/* Well-known name server port */
} CONFIG, *PCONFIG;

typedef struct _THREADINFO {		/* Thread information */
PCONFIG		config;			/* Configuration information */
PUCHAR		buf;			/* Packet buffer */
INT		pktlen;			/* Length of current packet */
PUCHAR		dnptrs[MAXDNPTRS];	/* Used by 'dn_compress' */
SOCK		sa;			/* Source address of packet */
INT		sockno;			/* Socket for reply */
INT		rsockno;		/* Socket for queries */
PUCHAR		qp;			/* Query pointer */
PUCHAR		rp;			/* Reply pointer */
PSERVERS	ps;			/* List of servers to consult */
UCHAR		logmsg[MAXLOG];		/* Logging buffer */
#ifdef	DEBUG
UINT		thread;			/* Thread identification */
#endif
} THREADINFO, *PTHREADINFO;

/* External references */

extern	BOOL	db_add_host(PCONFIG, PDBENT);
extern	PDBENT	db_find_address(PCONFIG, INADDR);
extern	PDBENT	db_find_name(PCONFIG, PUCHAR);
extern	BOOL	db_init(PCONFIG);
extern	VOID	error(PUCHAR, ...);
extern	INT	read_config(PUCHAR, PUCHAR, PCONFIG);
extern	VOID	refer(PTHREADINFO);
extern	INT	server(PCONFIG);

/*
 * End of file: named.h
 *
 */
