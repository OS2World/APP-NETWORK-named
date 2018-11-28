/*
 * File: refer.c
 *
 * Name server for OS/2.
 *
 * Referral handler for server
 *
 * Bob Eager   August 2000
 *
 */

#pragma	strings(readonly)

#include "named.h"
#include "log.h"

/* Forward references */

static	BOOL	consult_nameserver(PTHREADINFO, INT, INADDR);
static	BOOL	referral_interface_up(PTHREADINFO);

/* Local storage */

static	UCHAR		logmsg[MAXLOG];


/*
 * Refer a query to the ISP's name server(s), if we currently have a
 * connection.
 *
 * The retry algorithm used is the same as that used by BIND 4.9.3;
 * the same number of retries are always done, but the second and
 * subsequent timeout values depend on the number of name servers
 * configured.
 *
 * On return, the packet is ready for sending back to the client, apart
 * from the packet length field in the thread information structure.
 * However, the 'rp' field is set to the next free byte in the reply area.
 *
 */

VOID refer(PTHREADINFO ti)
{	INT i, retries, rc;
	INT timeout = INITIAL_REFER_TIMEOUT;
	INT itimeout;
	SOCK sa;
	HEADER *h = (HEADER *) ti->buf;
	PSERVERS ps;
#ifdef	DEBUG
	INT namelen;
#endif

	if(referral_interface_up(ti) == TRUE) {
		ps = ti->ps;
#ifdef	DEBUG
		trace("nservers = %d", ps->nservers);
		for(i = 0; i < ps->nservers; i++) {
			trace(
				"server %d is %s",
				i + 1,
				inet_ntoa(ps->servers[i]));
		}
#endif
		/* Create a socket for doing the queries */

		ti->rsockno = socket(AF_INET, SOCK_DGRAM, 0);
		if(ti->rsockno < 0) {
			sprintf(
				ti->logmsg,
				"failed to allocate socket for refer: rc = %d",
				sock_errno());
			dolog(ti->logmsg);
			h->rcode = NXDOMAIN;
			return;
		}	

		/* Bind the socket to an arbitrary port */

		memset((PUCHAR) &sa, 0, sizeof(SOCK));
		sa.sin_family = AF_INET;
		sa.sin_port = 0;		/* Let system select port */
		sa.sin_addr.s_addr = INADDR_ANY;

		rc = bind(ti->rsockno, (PSOCKG) &sa, sizeof(SOCK));
		if(rc < 0) {
			sprintf(
				ti->logmsg,
				"failed to bind referral socket: rc = %d",
				sock_errno());
			dolog(ti->logmsg);
			h->rcode = NXDOMAIN;
			return;
		}

#ifdef	DEBUG
		namelen = sizeof(SOCK);
		rc = getsockname(ti->rsockno, (PSOCKG) &sa, &namelen);
		if(rc < 0) {
			sprintf(
				ti->logmsg,
				"getsockname failed on referral socket: "
				"rc = %d",
				sock_errno());
			dolog(ti->logmsg);
		} else {
			trace(
				"referral socket bound to port %hu",
				ntohs(sa.sin_port));
		}
#endif

		if(ps->nservers == 1) {		/* Algorithm differs */
			for(retries = 0;
			    retries < REFER_RETRY_LIMIT;
			    retries++) {
				if(consult_nameserver(
					ti,
					timeout,
					ps->servers[0]) == TRUE) {
						soclose(ti->rsockno);
						return;
				}
				timeout *= 2;	/* Double timeout each time */
			}
		} else {
			itimeout = timeout;
			for(retries = 0;
			    retries < REFER_RETRY_LIMIT;
			    retries++) {
				for(i = 0; i < ps->nservers; i++) {
					if(consult_nameserver(
						ti,
						itimeout,
						ps->servers[i]) == TRUE) {
							soclose(ti->rsockno);
							return;
					}
				}
				timeout *= 2;	/* Double and reduce */
				itimeout = timeout/ps->nservers;
			}
		}
	}

	soclose(ti->rsockno);
	h->rcode = NXDOMAIN;	/* Name server(s) not accessible or responding */
}


/*
 * Refer a query to a specified name server.
 *
 * Returns TRUE if the name server responds, regardless of whether the actual
 * query succeeds; returns FALSE if the name server is not responding or there
 * is some other error.
 *
 */

static BOOL consult_nameserver(PTHREADINFO ti, INT timeout, INADDR addr)
{	INT rc, pktlen, namelen;
	INT sockset[2];
	SOCK nsa;
	SOCK sa;
	UCHAR rbuf[PACKETSZ];

	memset((PUCHAR) &nsa, 0, sizeof(SOCK));
	nsa.sin_family = AF_INET;
	nsa.sin_port = ti->config->nsport;
	nsa.sin_addr = addr;

#ifdef	DEBUG
	trace(
		"thread %d; referring to nameserver %s:%hu (family %d), timeout %d seconds",
		ti->thread,
		inet_ntoa(nsa.sin_addr),
		ntohs(nsa.sin_port),
		nsa.sin_family,
		timeout);
#endif

	/* Send the query to the specified name server */

	rc = sendto(
		ti->rsockno,
		ti->buf,
		ti->pktlen,
		0,			/* No flags */
		(PSOCKG) &nsa,
		sizeof(SOCK));
	if(rc == -1) {
		sprintf(
			ti->logmsg,
			"failed to send referral packet: rc = %d",
			sock_errno());
		dolog(ti->logmsg);
		return(FALSE);
	}

	/* Now wait for a reply, an exception or a timeout */

	sockset[0] = ti->rsockno;		/* Read waiting */
	sockset[1] = ti->rsockno;		/* Exception */

	if(select(
		sockset,			/* List of sockets */
		1,				/* Sockets for read check */
		0,				/* Sockets for write check */
		1,				/* Sockets for exception check */
		timeout*1000) == -1) {		/* Timeout in milliseconds */
		sprintf(
			ti->logmsg,
			"referral select failed: rc = %d",
			sock_errno());
		dolog(ti->logmsg);
		return(FALSE);
	}

	if(sockset[1] != -1) {			/* Exception */
#ifdef	DEBUG
		sprintf(
			ti->logmsg,
			"thread %d; exception on referral socket: rc = %d",
			ti->thread,
			errno);
#else
		sprintf(
			ti->logmsg,
			"exception on referral socket: rc = %d",
			errno);
#endif
		dolog(ti->logmsg);
		return(FALSE);
	}

	if(sockset[0] == -1) return(FALSE);	/* Should not happen */

	namelen = sizeof(SOCK);
	pktlen = recvfrom(
		ti->rsockno,
		rbuf,
		PACKETSZ,
		0,				/* No flags */
		(PSOCKG) &sa,
		&namelen);
	if(pktlen <= 0) {
		sprintf(
			ti->logmsg,
			"referral recvfrom failed: rc = %d",
			sock_errno());
			dolog(ti->logmsg);
			return(FALSE);
	}
	if(pktlen > PACKETSZ) {
		sprintf(
			ti->logmsg,
			"dropped referral reply packet (pktlen=%d, "
			"pktbuflen=%d)",
			pktlen,
			PACKETSZ);
		dolog(ti->logmsg);
		return(FALSE);
	}

#ifdef	DEBUG
	trace(
		"packet received from %s",
		inet_ntoa(sa.sin_addr));
#endif

	memcpy(ti->buf, rbuf, pktlen);		/* Copy reply */
	memset(ti->buf + pktlen, '\0', PACKETSZ - pktlen);	/* Clean up rest */
	ti->rp = ti->buf + pktlen;	/* Packet length set later */

	return(TRUE);
}


/*
 * Check the status of the referral interface.
 *
 * Returns TRUE if the interface is up, and FALSE if it is down (or if
 * there is an error).
 *
 * Has the side effect (if the interface is up) of setting the 'servers' field
 * in the thread information block to a SERVERS structure containing the
 * addresses of the name servers to which the referral is to be made.
 *
 */

static BOOL referral_interface_up(PTHREADINFO ti)
{	INT rc, i;
	INT sockno;
	IFCONF ifc;
	PIFREQ ifr;
	UCHAR buf[sizeof(IFREQ)*MAXINTERFACES];
	SOCK ppsa;
	PSERVERS ps;

#ifdef	DEBUG
	if(getenv("REFER_INTERFACE_UP") != (PUCHAR) NULL) {
		trace(
			"interface %s is deemed to be up",
			ti->config->refer_interface);
		return(TRUE);
	}
#endif

	/* Create a socket for performing ioctl calls */

	sockno = socket(AF_INET, SOCK_DGRAM, 0);	/* Type is immaterial */
	if(sockno < 0) {
		sprintf(
			ti->logmsg,
			"failed to allocate socket for interface check: "
			"rc = %d",
			sock_errno());
		dolog(ti->logmsg);
		return(FALSE);
	}

	/* Get the interface configuration */

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;

	rc = ioctl(sockno, SIOCGIFCONF, (PUCHAR) &ifc, sizeof(ifc));
	if(rc < 0) {
		sprintf(
			ti->logmsg,
			"get interface configuration failed: rc = %d",
			sock_errno());
		dolog(ti->logmsg);
		soclose(sockno);
		return(FALSE);
	}

	/* Search for the referral interface and determine if it is up */

	ifr = ifc.ifc_req;
	for(i = 0; i < ifc.ifc_len/sizeof(IFREQ); i++, ifr++) {

		/* Check that this interface is a TCP/IP one */

		if(ifr->ifr_addr.sa_family != AF_INET) continue;

		/* See if this is the interface we want */

		if(stricmp(ti->config->refer_interface, ifr->ifr_name) != 0)
			continue;

		/* Now get the interface flags and see if it is up */

		rc = ioctl(
			sockno,
			SIOCGIFFLAGS,
			(PUCHAR) ifr,
			sizeof(IFREQ));
		if(rc < 0) {
			sprintf(
				ti->logmsg,
				"get interface flags for %s failed: rc = %d",
				ti->config->refer_interface,
				sock_errno());
			dolog(ti->logmsg);
			break;
		}
		if((ifr->ifr_flags & IFF_UP) != 0) {
#ifdef	DEBUG
			trace("interface %s is up", ifr->ifr_name);
#endif
			rc = ioctl(
				sockno,
#if 0
				SIOCGIFDSTADDR,
#endif
				SIOCGIFADDR,
				(PUCHAR) ifr,
				sizeof(IFREQ));
			if(rc < 0) {
				sprintf(
					ti->logmsg,
					"get interface destination address "
					"for %s failed: rc = %d",
					ti->config->refer_interface,
					sock_errno());
				dolog(ti->logmsg);
				break;
			}
			memcpy(&ppsa, &ifr->ifr_dstaddr, sizeof(SOCK));
#ifdef	DEBUG
			trace(
				"destination address for %s is %s",
				ti->config->refer_interface,
				inet_ntoa(ppsa.sin_addr));
#endif
			ti->ps = (PSERVERS) NULL;	/* In case of error */
			for(ps = ti->config->servlist;
			    ps != (PSERVERS) NULL;
			    ps = ps->next) {
				if((ps->if_addr.s_addr & ps->if_mask.s_addr) ==
				   (ppsa.sin_addr.s_addr & ps->if_mask.s_addr)) {
					ti->ps = ps;
					break;
				}
			}

			soclose(sockno);
			return(TRUE);
		}
#ifdef	DEBUG
		trace("interface %s is down", ifr->ifr_name);
#endif
		break;			/* No point in looking further */
	}

	soclose(sockno);
	return(FALSE);
}

/*
 * End of file: refer.c
 *
 */
