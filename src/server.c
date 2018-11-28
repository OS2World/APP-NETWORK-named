/*
 * File: server.c
 *
 * Name server for OS/2.
 *
 * Protocol handler for server
 *
 * Bob Eager   August 2000
 *
 */

#pragma	strings(readonly)

#include "named.h"
#include "log.h"

#pragma	alloc_text(init_seg, readhosts)
#pragma	alloc_text(init_seg, process_entry)
#pragma	alloc_text(init_seg, fix_domain)

#define	THREAD_STACK	16384		/* Stack size for worker threads */

/* Forward references */

static	VOID	catch_signal(INT);
static	BOOL	checkrp(PTHREADINFO, INT);
static	VOID	fix_domain(PCONFIG, PUCHAR);
static	VOID	handle_packet(PVOID);
static	VOID	handle_packet_worker(PTHREADINFO);
static	PUCHAR	makepktbuf(VOID);
static	VOID	process_address_query(PTHREADINFO, PUCHAR);
static	BOOL	process_entry(PCONFIG, PHOST);
static	VOID	process_pointer_query(PTHREADINFO, PUCHAR);
static	VOID	process_query(PTHREADINFO);
static	VOID	process_standard_query(PTHREADINFO, INT, INT, PUCHAR);
static	BOOL	readhosts(PCONFIG);

/* Local storage */

static	volatile BOOL	shutting_down;


/*
 * This is the main server code.
 *
 * Returns:
 *	TRUE		server ran and terminated
 *	FALSE		server failed to start
 *
 */

INT server(PCONFIG config)
{	INT i, param, rc;
	INT pktlen;
	SOCK sa;
	INT sockset[2];
	PTHREADINFO ti;
	UCHAR logmsg[MAXLOG];

	/* Initialise the in-memory database */

	if(db_init(config) == FALSE) return(FALSE);

	/* Add local HOSTS file to database */

	if(readhosts(config) == FALSE) return(FALSE);

	/* Allocate a packet buffer */

	config->pktbuf = makepktbuf();
	if(config->pktbuf == (PUCHAR) NULL) return(FALSE);

	/* Create a socket for listening, and bind it */

	config->sockno = socket(AF_INET, SOCK_DGRAM, 0);
	if(config->sockno < 0) {
		sprintf(
			logmsg,
			"failed to allocate socket: rc = %d",
			sock_errno());
		dolog(logmsg);
		return(FALSE);
	}	

	memset((PUCHAR) &sa, 0, sizeof(SOCK));
	sa.sin_family = AF_INET;
	sa.sin_port = config->port;
	sa.sin_addr.s_addr = INADDR_ANY;

	rc = bind(config->sockno, (PSOCKG) &sa, sizeof(SOCK));
	if(rc < 0) {
		sprintf(
			logmsg,
			"failed to bind socket to interfaces: rc = %d",
			sock_errno());
		dolog(logmsg);
		return(FALSE);
	}

	/* Set up signal handlers */

	signal(SIGTERM, catch_signal);
	signal(SIGBREAK, catch_signal);
	signal(SIGINT, catch_signal);

	/* Main listening loop */

	shutting_down = FALSE;

	while(shutting_down != TRUE) {

		/* Set up and perform select call */

		sockset[0] = config->sockno;	/* Read waiting */
		sockset[1] = config->sockno;	/* Exception */

		if(select(
			sockset,		/* List of sockets */
			1,			/* Sockets for read check */
			0,			/* Sockets for write check */
			1,			/* Sockets for exception check */
			-1L)			/* No timeout */
			== -1) {
			if(sock_errno() != SOCEINTR) {
				sprintf(
					logmsg,
					"main select failed: rc = %d",
					sock_errno());
				dolog(logmsg);
				return(FALSE);
			}
			continue;
		}

		if(sockset[1] != -1) {		/* Exception */
			dolog("exception on socket");
			continue;
		}

		if(sockset[0] != -1) {		/* Read ready */
			SOCK csa;
			INT namelen = sizeof(SOCK);

			pktlen = recvfrom(
				config->sockno,
				config->pktbuf,
				PACKETSZ,
				0,		/* No flags */
				(PSOCKG) &csa,
				&namelen);
			if(pktlen <= 0) {
				sprintf(
					logmsg,
					"recvfrom failed: rc = %d",
					sock_errno());
				dolog(logmsg);
				continue;
			}
			if(pktlen > PACKETSZ) {
				sprintf(
					logmsg,
					"dropped packet (pktlen=%d, "
					"pktbuflen=%d)",
					pktlen,
					PACKETSZ);
				dolog(logmsg);
				continue;	/* Drop this packet */
			}
#ifdef	DEBUG
			trace(
				"packet received from %s",
				inet_ntoa(csa.sin_addr));
#endif

			/* We have a packet. Pass it to a new thread */

			ti = malloc(sizeof(THREADINFO));
			if(ti == (PTHREADINFO) NULL) {
				dolog("failed to allocate thread block");
				continue;	/* Drop packet */
			}

			ti->config = config;
			ti->buf = config->pktbuf;
			ti->pktlen = pktlen;
			ti->sockno = config->sockno;
			memcpy((PUCHAR) &ti->sa, (PUCHAR) &csa, sizeof(SOCK));
			config->pktbuf = makepktbuf();
			if(config->pktbuf == (PUCHAR) NULL) {
				config->pktbuf = ti->buf;/* Restore old buffer */
				free(ti);		/* Return thread block */
				continue;	/* Drop packet */
			}
			rc = _beginthread(
				handle_packet,
				NULL,
				THREAD_STACK,
				(PVOID) ti);
			if(rc == -1) {
				dolog("failed to create thread");
				free(ti->buf);
				free(ti);		/* Return storage */
			}
		}
	} /* main loop */

	soclose(config->sockno);

	dolog("shutdown complete");

	return(TRUE);
}


/*
 * Signal handler for the main listening thread.
 * Simply set shutdown flag and continue.
 *
 */

static VOID catch_signal(INT sig)
{	UCHAR msg[100];

	sprintf(
		msg,
		"%s detected, initiating shutdown",
		sig == SIGBREAK	? "Ctrl-Break" :
		sig == SIGINT	? "Ctrl-C" :
		sig == SIGTERM	? "Termination signal" :
				  "Unknown signal");
	dolog(msg);
	shutting_down = TRUE;
}


/*
 * Handle an incoming packet from client. This runs in a separate thread
 * for each packet; if it did not, and if we have to refer the operation,
 * there may be a significant delay which may cause other packets to be
 * dropped.
 *
 * This is just a wrapper for the real worker function below it; its main
 * purpose is to ensure that all resources are freed.
 *
 */

static VOID handle_packet(PVOID param)
{	PTHREADINFO ti = (PTHREADINFO) param;

#ifdef	DEBUG
	ti->thread = *_threadid;	/* Use thread ID for logging */
#endif

	handle_packet_worker(ti);

	/* Free resources */

	free(ti->buf);
	free((PUCHAR) ti);
}


/*
 * The real thread worker function.
 *
 */

static VOID handle_packet_worker(PTHREADINFO ti)
{	INT i, rc;
	HEADER *h;
	PUCHAR qp;

	h = (HEADER *) ti->buf;

#ifdef	DEBUG
	trace(
		"thread %d started; packet length = %d; ID = %04x; type = %s",
		ti->thread,
		ti->pktlen,
		h->id,
		h->qr == 0 ? "query" : "response");
	trace(
		"opcode = %s",
		h->opcode == QUERY  ? "standard query" :
		h->opcode == IQUERY ? "inverse query"  :
			     	      "????");
	trace(
		"rd=%d, tc=%d, aa=%d, ra=%d, rcode=%d",
		h->rd,
		h->tc,
		h->aa,
		h->ra,
		h->rcode);
	trace(
		"qdcount=%hu, ancount=%hu, nscount=%hu, arcount=%hu",
		ntohs(h->qdcount),
		ntohs(h->ancount),
		ntohs(h->nscount),
		ntohs(h->arcount));
#endif
	if(h->ancount != 0 || h->nscount != 0 || h->arcount != 0) {
		dolog("something other than a query");
		return;			/* Drop packet */
	}

	ti->rp = ti->buf + ti->pktlen;		/* Start of reply space */
	ti->qp = ti->buf + sizeof(HEADER);	/* Start of query area */
	h->rcode = NOERROR;			/* Assume success */

	for(i = 0; i < ntohs(h->qdcount); i++) {
		process_query(ti);
		if(h->rcode != NOERROR) break;
	}

	/* Now send the reply */

	h->qr = 1;			/* This is a response */
	h->ra = 1;			/* Recursion available */

	rc = sendto(
		ti->sockno,
		ti->buf,
		ti->pktlen,
		0,			/* No flags */
		(PSOCKG) &ti->sa,
		sizeof(SOCK));
	if(rc == -1) {
		sprintf(
			ti->logmsg,
			"failed to send reply packet: rc = %d",
			sock_errno());
		dolog(ti->logmsg);
		return;
	}
#ifdef	DEBUG
	trace("thread %d; sent reply and now dying", ti->thread);
#endif
}


/*
 * Process one query and place the reply into the packet buffer.
 *
 *	ti	points to the thread information structure
 *
 * On return, the response code in the header has been updated.
 *
 */

static VOID process_query(PTHREADINFO ti)
{	INT n;
	USHORT qtype, qclass;
	HEADER *h = (HEADER *) ti->buf;
	UCHAR namebuf[MAXDNAME+1];

	n = dn_expand(			/* Length of compressed name */
		ti->buf,
		ti->buf+ti->pktlen,
		ti->qp,
		namebuf,
		sizeof(namebuf));
	if(n < 0) {
		dolog("dn_expand failed");
		return;
	}
	strlwr(namebuf);		/* To make matches easier */
	ti->qp += n;			/* Move past name */
	qtype = _getshort(ti->qp);	/* Query type */
	ti->qp += 2;
	qclass = _getshort(ti->qp);	/* Query class */
	ti->qp += 2;			/* Move to next query, if any */

	switch(h->opcode) {
		case QUERY:		/* Standard query */
			process_standard_query(ti, qtype, qclass, namebuf);
			break;

		case IQUERY:		/* Inverse query */
		default:		/* Unrecognised or not implemented */
			h->rcode = NOTIMP;
			break;
	}
	ti->pktlen = ti->rp - ti->buf;	/* Fill in new packet length */
}


/*
 * Process a standard query
 *
 *	ti	points to the thread information structure
 *	qtype	is the query type
 *	qclass	is the query class
 *	name	is the domain name being queried
 *
 * On return, the response code in the header has been updated if necessary.
 *
 */

static VOID process_standard_query(PTHREADINFO ti, INT qtype, INT qclass,
					PUCHAR name)
{	INT i;
	HEADER *h = (HEADER *) ti->buf;

#ifdef	DEBUG
	trace(
		"proc_stan_q: type=%d, class=%d, name=%s",
		qtype, qclass, name);
#endif

	switch(qtype) {
		case T_PTR:			/* Domain name pointer */
			process_pointer_query(ti, name);
			break;

		case T_A:			/* Host address */
			process_address_query(ti, name);
			break;

		case T_NS:			/* Authoritative server */
		case T_CNAME:			/* Canonical name */
		case T_SOA:			/* Start of authority zone */
		case T_MB:			/* Mailbox domain name */
		case T_MG:			/* Mail group member */
		case T_WKS:			/* Well known service */
		case T_HINFO:			/* Host information */
		case T_MINFO:			/* Mailbox information */
		case T_MX:			/* Mail routing information */

		case T_NULL:			/* Null resource record */
		default:
			h->rcode = NOTIMP;	/* Not implemented */
			break;
	}
}


/*
 * Process an address (A) pointer query. In this type of query,
 * the domain name is input, and an IP address is requested.
 *
 *	ti	points to the thread information structure
 *	name	is the domain name being queried
 *
 * On return, the response code in the header has been updated.
 *
 */

static VOID process_address_query(PTHREADINFO ti, PUCHAR name)
{	INT n;
	HEADER *h = (HEADER *) ti->buf;
	PUCHAR p;
	PDBENT dbent;

	dbent = db_find_name(ti->config, name);
	if(dbent == (PDBENT) NULL) {
		refer(ti);
		return;
	}

	/* Initialise for loading the reply packet */

	ti->dnptrs[0] = ti->buf;	/* Set up for 'dn_comp' */
	ti->dnptrs[1] = (PUCHAR) NULL;

	/* If this is an alias name, insert a CNAME record to indicate
	   the canonical name */

	if(dbent->type == ENT_TYPE_ALIAS) {
		n = dn_comp(name,
			ti->rp,
			PACKETSZ - (ti->rp - (PUCHAR) h),
			ti->dnptrs,
			&ti->dnptrs[MAXDNPTRS-1]);
		if(n < 0) {
			h->tc = 1;		/* Truncation */
			return;
		}
		ti->rp += n;		/* Point past the name to TYPE field */
		if(checkrp(ti, RRFIXEDSZ) == FALSE) return;
		putshort(T_CNAME, ti->rp);	/* Store RR type code */
		ti->rp += 2;			/* Move to CLASS field */
		putshort(C_IN, ti->rp);		/* Store class */
		ti->rp += 2;			/* Move to TTL field */
		putlong(LOCAL_TTL, ti->rp);	/* Time to live */
		ti->rp += 4;			/* Move to RDLENGTH field */
		p = ti->rp;			/* Save for filling in length */
		putshort(0, p);			/* In case of failure */
		ti->rp += 2;			/* Move to RDATA field */
		n = dn_comp(dbent->primary->name,
			ti->rp,
			PACKETSZ - (ti->rp - (PUCHAR) h),
			ti->dnptrs,
			&ti->dnptrs[MAXDNPTRS-1]);
		if(n < 0) {
			h->tc = 1;		/* Truncation */
			return;
		}
		putshort(n, p);			/* Fill in RDLENGTH */
		h->ancount = ntohs(htons(h->ancount) + 1);
		ti->rp += n;			/* Move past stored name */
		dbent = dbent->primary;		/* Use type A record now */
		name = dbent->name;
	}

	/* Insert a type A record for the name (if an alias, this is the
	   canonical name) */

	n = dn_comp(name,
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	ti->rp += n;			/* Point past the name to TYPE field */
	if(checkrp(ti, RRFIXEDSZ + sizeof(dbent->address.s_addr)) == FALSE)
		return;
	putshort(T_A, ti->rp);		/* Store RR type code */
	ti->rp += 2;			/* Move to CLASS field */
	putshort(C_IN, ti->rp);		/* Store class */
	ti->rp += 2;			/* Move to TTL field */
	putlong(LOCAL_TTL, ti->rp);	/* Time to live */
	ti->rp += 4;			/* Move to RDLENGTH field */
	putshort(sizeof(dbent->address.s_addr), ti->rp);/* Set length */
	ti->rp += 2;			/* Move to RDATA field */
	putlong(htonl(dbent->address.s_addr), ti->rp);	/* Set IP address */
	ti->rp += sizeof(dbent->address.s_addr);/* Point past this entry */
	h->ancount = ntohs(htons(h->ancount) + 1);
	h->aa = 1;			/* Authoritative answer */

	/* Now fill in the authority part. This is the domain name for the
	   query, and an NS record giving the domain name of the
	   nameserver */

	n = dn_comp(ti->config->domain,
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	ti->rp += n;			/* Point past the name to TYPE field */
	if(checkrp(ti, RRFIXEDSZ) == FALSE) return;
	putshort(T_NS, ti->rp);		/* Store RR type code */
	ti->rp += 2;			/* Move to CLASS field */
	putshort(C_IN, ti->rp);		/* Store class */
	ti->rp += 2;			/* Move to TTL field */
	putlong(LOCAL_TTL, ti->rp);	/* Time to live */
	ti->rp += 4;			/* Move to RDLENGTH field */
	p = ti->rp;			/* Save for filling in length */
	putshort(0, p);			/* In case of failure */
	ti->rp += 2;			/* Move to RDATA field */
	n = dn_comp(ti->config->myname,	/* Fill in our own name */
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	putshort(n, p);			/* Fill in RDLENGTH */
	h->nscount = ntohs(htons(h->nscount) + 1);
	ti->rp += n;			/* Point past this entry */

	/* Now fill in the additional part. This is the domain name given
	   in the authority part, as an A record. */

	dbent = db_find_name(ti->config, ti->config->myname);
	if(dbent == (PDBENT) NULL) {
		dolog("cannot find own name!");
		h->rcode = SERVFAIL;
		return;
	}
	n = dn_comp(dbent->name,
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	ti->rp += n;			/* Point past the name to TYPE field */
	if(checkrp(ti, RRFIXEDSZ + sizeof(dbent->address.s_addr)) == FALSE)
		return;
	putshort(T_A, ti->rp);		/* Store RR type code */
	ti->rp += 2;			/* Move to CLASS field */
	putshort(C_IN, ti->rp);		/* Store class */
	ti->rp += 2;			/* Move to TTL field */
	putlong(LOCAL_TTL, ti->rp);	/* Time to live */
	ti->rp += 4;			/* Move to RDLENGTH field */
	putshort(sizeof(dbent->address.s_addr), ti->rp);/* Set length */
	ti->rp += 2;			/* Move to RDATA field */
	putlong(htonl(dbent->address.s_addr), ti->rp);	/* Set IP address */
	ti->rp += sizeof(dbent->address.s_addr);/* Point past this entry */
	h->arcount = ntohs(htons(h->arcount) + 1);
}


/*
 * Process a pointer (PTR) query. In this type of query, the domain name is
 * input, and is of the form:
 *	ddd.ccc.bbb.aaa.in-addr.arpa
 * where aaa.bbb.ccc.ddd is the dotted quad IP address for which the
 * domain name is required.
 *
 *	ti	points to the thread information structure
 *	name	is the domain name being queried
 *
 * On return, the response code in the header has been updated.
 *
 */

static VOID process_pointer_query(PTHREADINFO ti, PUCHAR name)
{	INT i, n;
	HEADER *h = (HEADER *) ti->buf;
	PUCHAR p;
	PUCHAR revdom = ".in-addr.arpa";
	INADDR ad;
	PDBENT dbent;
	UCHAR temp[MAXDNAME+1];

	/* Check that name ends in the correct domain */

	p = strstr(name, revdom);
	if((p == (PUCHAR) NULL) ||
	   (p != (name + strlen(name) - strlen(revdom)))) {
		h->rcode = FORMERR;
		return;
	}

	*p = '\0';		/* Truncate name to just the dotted quad */
	ad.s_addr = lswap(inet_addr(name));	/* Extract IP address */
	*p = '.';		/* Restore name */

#ifdef	DEBUG
	trace(
		"address match check: query=%08x; net=%08x; mask=%08x",
		ad.s_addr,
		ti->config->network.s_addr,
		ti->config->netmask.s_addr);
#endif

	if((ad.s_addr & ti->config->netmask.s_addr) != ti->config->network.s_addr) {
		refer(ti);
		return;
	}

	dbent = db_find_address(ti->config, ad);
	if(dbent == (PDBENT) NULL) {
		refer(ti);
		return;
	}

#ifdef	DEBUG
	trace("address lookup succeeded, name = |%s|", dbent->name);
#endif
	/* Initialise for loading the reply packet */

	ti->dnptrs[0] = ti->buf;	/* Set up for 'dn_comp' */
	ti->dnptrs[1] = (PUCHAR) NULL;

	/* First, the answer part. This is the input name, and the domain name
	   to which it refers. */

	n = dn_comp(name,
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	ti->rp += n;			/* Point past the name to TYPE field */
	if(checkrp(ti, RRFIXEDSZ) == FALSE) return;
	putshort(T_PTR, ti->rp);	/* Store RR type code */
	ti->rp += 2;			/* Move to CLASS field */
	putshort(C_IN, ti->rp);		/* Store class */
	ti->rp += 2;			/* Move to TTL field */
	putlong(LOCAL_TTL, ti->rp);	/* Time to live */
	ti->rp += 4;			/* Move to RDLENGTH field */
	p = ti->rp;			/* Save for filling in length */
	putshort(0, p);			/* In case of failure */
	ti->rp += 2;			/* Move to RDATA field */
	n = dn_comp(dbent->name,	/* Fill in the required name */
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	putshort(n, p);			/* Fill in RDLENGTH */
	h->ancount = ntohs(htons(h->ancount) + 1);
	ti->rp += n;			/* Move past stored name */
	h->aa = 1;			/* This answer is authoritative */
	
	/* Now fill in the authority part. This is the reverse domain name
	   for the network, and an NS record giving the domain name of the
	   nameserver */

	ad.s_addr = lswap(ti->config->network.s_addr & ti->config->netmask.s_addr);
	strcpy(temp, inet_ntoa(ad));
	while(temp[0] == '0' && temp[1] == '.')
		memccpy(&temp[0], &temp[2], '\0', MAXDNAME);
	strcat(temp, revdom);
#ifdef	DEBUG
	trace("reverse domain for network = |%s|", temp);
#endif
	n = dn_comp(temp,
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	ti->rp += n;			/* Point past the name to TYPE field */
	if(checkrp(ti, RRFIXEDSZ) == FALSE) return;
	putshort(T_NS, ti->rp);		/* Store RR type code */
	ti->rp += 2;			/* Move to CLASS field */
	putshort(C_IN, ti->rp);		/* Store class */
	ti->rp += 2;			/* Move to TTL field */
	putlong(LOCAL_TTL, ti->rp);	/* Time to live */
	ti->rp += 4;			/* Move to RDLENGTH field */
	p = ti->rp;			/* Save for filling in length */
	putshort(0, p);			/* In case of failure */
	ti->rp += 2;			/* Move to RDATA field */
	n = dn_comp(ti->config->myname,	/* Fill in our own name */
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	putshort(n, p);			/* Fill in RDLENGTH */
	h->nscount = ntohs(htons(h->nscount) + 1);
	ti->rp += n;			/* Point past this entry */

	/* Now fill in the additional part. This is the domain name given
	   in the answer, as an A record. */

	n = dn_comp(ti->config->myname,
		ti->rp,
		PACKETSZ - (ti->rp - (PUCHAR) h),
		ti->dnptrs,
		&ti->dnptrs[MAXDNPTRS-1]);
	if(n < 0) {
		h->tc = 1;		/* Truncation */
		return;
	}
	ti->rp += n;			/* Point past the name to TYPE field */
	if(checkrp(ti, RRFIXEDSZ + sizeof(dbent->address.s_addr)) == FALSE)
		return;
	putshort(T_A, ti->rp);		/* Store RR type code */
	ti->rp += 2;			/* Move to CLASS field */
	putshort(C_IN, ti->rp);		/* Store class */
	ti->rp += 2;			/* Move to TTL field */
	putlong(LOCAL_TTL, ti->rp);	/* Time to live */
	ti->rp += 4;			/* Move to RDLENGTH field */
	putshort(sizeof(dbent->address.s_addr), ti->rp);/* Set length */
	ti->rp += 2;			/* Move to RDATA field */
	putlong(htonl(dbent->address.s_addr), ti->rp);	/* Set IP address */
	ti->rp += sizeof(dbent->address.s_addr);/* Point past this entry */
	h->arcount = ntohs(htons(h->arcount) + 1);
}


/*
 * Check that there is sufficient space left in the buffer for
 * the next piece of information.
 *
 * Returns TRUE for success, FALSE for failure. In the case of failure,
 * the truncation flag is set in the packet header.
 *
 */

static BOOL checkrp(PTHREADINFO ti, INT nbytes)
{	if(ti->rp + nbytes > ti->buf + PACKETSZ) {
		HEADER *h = (HEADER *) ti->buf;

		h->tc = 1;		/* Mark truncation */
#ifdef	DEBUG
		trace("packet truncated");
#endif
		return(FALSE);
	}

	return(TRUE);
}


/*
 * Read the local HOSTS file, and add its contents to the in-memory
 * database.
 *
 * Returns TRUE if completed OK; FALSE if there was a fatal error.
 *
 */

static BOOL readhosts(PCONFIG config)
{	PHOST h;
	PUCHAR p;

	sethostent(TRUE);		/* Ensure HOSTS file stays open */

	for(;;) {
		h = gethostent();	/* Get next entry in HOSTS file */
		if(h == (PHOST) NULL) break;	/* Stop if all seen now */

		if(process_entry(config, h) == FALSE) {
			error("failed to allocate memory");
			dolog("failed to allocate memory");
			return(FALSE);
		}
	}
	
	sethostent(FALSE);		/* Ensure HOSTS file is closed */
	endhostent();			/* Close HOSTS file */

	return(TRUE);
}


/*
 * Process one entry in the local HOSTS file.
 *
 * Returns TRUE if the entry was completely processed and the in-memory
 * database was successfully updated; returns FALSE if failed to allocate
 * memory.
 *
 */

static BOOL process_entry(PCONFIG config, PHOST h)
{	INT i;
	PDBENT entry, alias;
	PUCHAR p;
	UCHAR temp[MAXDNAME+1];

	/* The primary name entry may be malformed on OS/2 (it may include
	   alias names). Copy the string and pick the first token. The alias
	   names will appear again in the alias list, anyway. */

	strncpy(temp, h->h_name, MAXDNAME);
	temp[MAXDNAME] = '\0';			/* In case too big */
	p = strtok(temp, " \t");		/* Extract primary name */
	fix_domain(config, p);

	entry = (PDBENT) malloc(sizeof(DBENT));
	if(entry == (PDBENT) NULL) return(FALSE);

	entry->name = (PUCHAR) malloc(strlen(p)+1);
	if(entry->name == (PUCHAR) NULL) return(FALSE);
	strcpy(entry->name, p);
	strlwr(entry->name);			/* For matching purposes */

	entry->type = ENT_TYPE_PRIMARY;
	entry->next = (PDBENT) NULL;
	entry->address = *((PINADDR) h->h_addr);

	if(db_add_host(config, entry) == FALSE) return(FALSE);

	/* Now handle aliases */

	for(i = 0;;) {
		p = h->h_aliases[i++];
		if(p == (PUCHAR) NULL) break;
		strcpy(temp, p);
		p = temp;
		fix_domain(config, p);
		alias = (PDBENT) malloc(sizeof(DBENT));
		if(alias == (PDBENT) NULL) return(FALSE);
		alias->name = (PUCHAR) malloc(strlen(p)+1);
		if(alias->name == (PUCHAR) NULL) return(FALSE);
		strcpy(alias->name, p);
		strlwr(entry->name);		/* For matching purposes */
		alias->type = ENT_TYPE_ALIAS;
		alias->next = (PDBENT) NULL;
		alias->primary = entry;

		if(db_add_host(config, alias) == FALSE) return(FALSE);
	}

	return(TRUE);
}


/*
 * Allocate the packet buffer.
 *
 * Return TRUE if success, FALSE if failure.
 *
 */

static PUCHAR makepktbuf(VOID)
{	PUCHAR p = malloc(PACKETSZ);

	if(p == (PUCHAR) NULL)
		dolog("failed to allocate packet buffer");

	return(p);
}


/*
 * Check for a full domain name; if not present, add default domain name.
 *
 */

static VOID fix_domain(PCONFIG config, PUCHAR name)
{	if(strchr(name, '.') == NULL) {
		strcat(name, ".");
		strcat(name, config->domain);
	}
}

/*
 * End of file: server.c
 *
 */
