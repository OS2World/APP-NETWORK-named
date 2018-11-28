/*
 * File: config.c
 *
 * Simple local nameserver for OS/2.
 *
 * Configuration file handler.
 *
 * Bob Eager   August 2000
 *
 */

#pragma	strings(readonly)

#include "named.h"
#include "cmds.h"
#include "log.h"

#pragma	alloc_text(init_seg, read_config)
#pragma	alloc_text(init_seg, config_error)
#pragma	alloc_text(init_seg, getcmd)
#pragma	alloc_text(init_seg, process_servers)

#define	MAXLINE		200		/* Maximum length of a config line */

#define	DOMAINSERVICE	"domain"	/* Name of domain name server service */
#define	UDP		"udp"		/* UDP protocol */

/* Forward references */

static	VOID	config_error(INT, PUCHAR, ...);
static	INT	getcmd(PUCHAR);
static	VOID	process_servers(PCONFIG, PUCHAR, PUCHAR, INT, PINT);


/*
 * Read and parse the configuration file specified by 'configfile'.
 *
 * Returns:
 *	Number of errors encountered.
 *	Any error messages have already been issued.
 *
 * The configuration information is returned in the structure 'config'.
 *
 */

INT read_config(PUCHAR direnv, PUCHAR configfile, PCONFIG config)
{	INT i;
	PUCHAR p, q, r, temp;
	UCHAR filename[CCHMAXPATH];
	PSERV domainserv;
	FILE *fp;
	UCHAR buf[MAXLINE];
	PSERVERS dservers;
	BOOL port_seen = FALSE;
	BOOL network_seen = FALSE;
	BOOL netmask_seen = FALSE;
	BOOL domain_seen = FALSE;
	BOOL refer_interface_seen = FALSE;
	INT errors = 0;
	ULONG addr;
	INT line = 0;

	p = getenv(direnv);
	if(p == (PUCHAR) NULL) {
		config_error(0, "environment variable %s is not set", direnv);
		return(++errors);
	}
	strcpy(filename, p);
	p = p + strlen(filename) - 1;	/* Point to last character */
	if(*p != '/' && *p != '\\') strcat(filename, "\\");
	strcat(filename, configfile);

	domainserv = getservbyname(DOMAINSERVICE, UDP);
	if(domainserv == (PSERV) NULL) {
		config_error(0, "cannot find port for %s/%s service",
			DOMAINSERVICE, UDP);
		return(++errors);
	}

	/* Set defaults */

	config->port = domainserv->s_port;
	config->nsport = domainserv->s_port;
	config->network.s_addr = inet_addr(DEFAULT_AUTH_NETWORK);
	config->netmask.s_addr = inet_addr(DEFAULT_AUTH_NETMASK);
	config->domain = _res.defdname;
	config->refer_interface = DEFAULT_REFER_INTERFACE;

	/* Set up the default server structure. This is derived from the
	   nameserver directives in the RESOLV file. It appears at the end
	   of the servers chain, and will match any interface address. */

	dservers = (PSERVERS) malloc(sizeof(SERVERS));
	if(dservers == (PSERVERS) NULL) {
		config_error(
			0,
			"cannot allocate memory for default server list");
		return(++errors);
	}
	dservers->next = (PSERVERS) NULL;
	dservers->if_addr.s_addr = INADDR_ANY;	/* Will match anything... */
	dservers->if_mask.s_addr = INADDR_ANY;	/* ...if this mask is used */
	dservers->nservers = _res.nscount;
	for(i = 0; i < MAXNS; i++)
		dservers->servers[i] = _res.nsaddr_list[i].sin_addr;
	config->servlist = dservers;

	fp = fopen(filename, "r");
	if(fp == (FILE *) NULL) {
		config_error(
			0,
			"warning - cannot open configuration file %s; "
			"using defaults",
			filename);
		return(0);
	}

	for(;;) {
		p = fgets(buf, MAXLINE, fp);
		if(p == (PUCHAR) NULL) break;
		temp = p + strlen(p) - 1;	/* Point to last character */
		if(*temp == '\n') *temp = '\0';	/* Remove any newline */
		line++;

		p = strchr(buf, '#');		/* Strip comments */
		if(p != (PUCHAR) NULL) *p = '\0';

		p = strtok(buf, " \t");
		q = strtok(NULL, " \t");
		r = strtok(NULL, " \t");

		/* Skip non-information lines */

		if((p == (PUCHAR) NULL) ||	/* No tokens */
		   (*p == '\n'))		/* Empty line */
			continue;

		switch(getcmd(p)) {
			case CMD_PORT:
				if(r != (PUCHAR) NULL) {
					config_error(
						line,
						"syntax error (extra on end)");
					errors++;
					continue;
				}
				if(q == (PUCHAR) NULL) {
					config_error(
						line,
						"no port number after PORT command");
					errors++;
					break;
				}
				if(port_seen == TRUE) {
					config_error(
						line,
						"only one PORT command "
						"permitted");
					errors++;
					break;
				}
				port_seen = TRUE;
				p = q;
				while(*p != '\0') {
					if(!isdigit(*p)) {
						config_error(
							line,
							"invalid port number '%s'",
							q);
						errors++;
						break;
					}
					p++;
				}
				if(*p == '\0')
					config->port = htons((USHORT) atoi(q));
				break;

			case CMD_AUTH_NETWORK:
				if(r != (PUCHAR) NULL) {
					config_error(
						line,
						"syntax error (extra on end)");
					errors++;
					continue;
				}
				if(q == (PUCHAR) NULL) {
					config_error(
						line,
						"no network address after "
						"AUTH_NETWORK command");
					errors++;
					break;
				}
				if(network_seen == TRUE) {
					config_error(
						line,
						"only one AUTH_NETWORK command "
						"permitted");
					errors++;
					break;
				}
				network_seen = TRUE;
				addr = inet_addr(q);
				if(addr == INADDR_NONE) {
					config_error(
						line,
						"malformed network address "
						"'%s'",
						q);
					errors++;
					break;
				}
				config->network.s_addr = addr;
				break;

			case CMD_AUTH_NETMASK:
				if(r != (PUCHAR) NULL) {
					config_error(
						line,
						"syntax error (extra on end)");
					errors++;
					continue;
				}
				if(q == (PUCHAR) NULL) {
					config_error(
						line,
						"no network mask after "
						"AUTH_NETMASK command");
					errors++;
					break;
				}
				if(netmask_seen == TRUE) {
					config_error(
						line,
						"only one AUTH_NETMASK command "
						"permitted");
					errors++;
					break;
				}
				netmask_seen = TRUE;
				config->netmask.s_addr = inet_addr(q);
				break;

			case CMD_AUTH_DOMAIN:
				if(r != (PUCHAR) NULL) {
					config_error(
						line,
						"syntax error (extra on end)");
					errors++;
					continue;
				}
				if(q == (PUCHAR) NULL) {
					config_error(
						line,
						"no domain after AUTH_DOMAIN "
						"command");
					errors++;
					break;
				}
				if(domain_seen == TRUE) {
					config_error(
						line,
						"only one AUTH_DOMAIN command "
						"permitted");
					errors++;
					break;
				}
				domain_seen = TRUE;
				p = malloc(strlen(q)+1);
				if(p == (PUCHAR) NULL) {
					config_error(
						line,
						"cannot allocate memory");
					errors++;
					break;
				}
				strcpy(p, q);
				config->domain = p;
				break;

			case CMD_REFER_INTERFACE:
				if(r != (PUCHAR) NULL) {
					config_error(
						line,
						"syntax error (extra on end)");
					errors++;
					continue;
				}
				if(q == (PUCHAR) NULL) {
					config_error(
						line,
						"no interface name after "
						"REFER_INTERFACE command");
					errors++;
					break;
				}
				if(refer_interface_seen == TRUE) {
					config_error(
						line,
						"only one REFER_INTERFACE "
						"command permitted");
					errors++;
					break;
				}
				refer_interface_seen = TRUE;
				p = malloc(strlen(q)+1);
				if(p == (PUCHAR) NULL) {
					config_error(
						line,
						"cannot allocate memory");
					errors++;
					break;
				}
				strcpy(p, q);
				config->refer_interface = p;
				break;

			case CMD_REFER_SERVERS:
				process_servers(config, q, r, line, &errors);
				break;

			default:
				config_error(
					line,
					"unrecognised command '%s'", p);
				errors++;
				break;
		}
	}

	fclose (fp);

	return(errors);
}


/*
 * Process a REFER_SERVERS command.
 *
 */

static VOID process_servers(PCONFIG config, PUCHAR if_addr, PUCHAR if_mask,
				INT line, PINT errors)
{	INT i;
	PUCHAR p;
	PSERVERS servers = (PSERVERS) malloc(sizeof(SERVERS));

	if(servers == (PSERVERS) NULL) {
		config_error(
			line,
			"cannot allocate memory for a server list");
		(*errors)++;
		return;
	}

	/* Process the interface matching information; IP address and mask */

	if(if_addr == (PUCHAR) NULL) {
		config_error(
			line,
			"missing interface address");
		(*errors)++;
		free(servers);
		return;
	}

	if(if_mask == (PUCHAR) NULL) {
		config_error(
			line,
			"missing interface mask");
		(*errors)++;
		free(servers);
		return;
	}

	servers->if_addr.s_addr = inet_addr(if_addr);
	if(servers->if_addr.s_addr == INADDR_NONE) {
		config_error(
			line,
			"malformed interface address %s",
			if_addr);
		free(servers);
		(*errors)++;
		return;
	}
	servers->if_mask.s_addr = inet_addr(if_mask);

	/* Now read the server address list */

	servers->nservers = 0;
	for(i = 0; i < MAXNS; i++) {
		p = strtok(NULL, " \t");
		if(p == (PUCHAR) NULL) break;
		servers->servers[i].s_addr = inet_addr(p);
		if(servers->servers[i].s_addr == INADDR_NONE) {
			config_error(
				line,
				"malformed name server address %s",
				p);
			free(servers);
			(*errors)++;
			return;
		}
		servers->nservers++;
	}

	if(servers->nservers == 0) {
		config_error(
			line,
			"no server addresses specified");
		free(servers);
		(*errors)++;
		return;
	}

	p = strtok(NULL, " \t");
	if(p != (PUCHAR) NULL) {
		config_error(
			line,
			"syntax error (extra on end)");
		free(servers);
		(*errors)++;
		return;
	}

	/* The new list has been built. Add to the start of the server
	   list chain, so that later entries supersede earlier ones. */

	servers->next = config->servlist;
	config->servlist = servers;
}


/*
 * Check command in 's' for validity, and return command code.
 * Case is immaterial.
 *
 * Returns CMD_BAD if command not recognised.
 *
 */

static INT getcmd(PUCHAR s)
{	INT i;

	for(i = 0; ; i++) {
		if(cmdtab[i].cmdcode == CMD_BAD) return(CMD_BAD);
		if(stricmp(s, cmdtab[i].cmdname) == 0) break;
	}

	return(cmdtab[i].cmdcode);
}


/*
 * Output configuration error message to standard error in printf style,
 * with a copy to the logfile.
 *
 */

static VOID config_error(INT line, PUCHAR mes, ...)
{	va_list ap;
	UCHAR buf[MAXLOG];
	UCHAR logmsg[MAXLOG];

	va_start(ap, mes);
	vsprintf(buf, mes, ap);
	va_end(ap);

	if(line == 0)
		sprintf(logmsg, "config: %s", buf);
	else
		sprintf(logmsg, "config: line %d: %s", line, buf);

	dolog(logmsg);
}

/*
 * End of file: config.c
 *
 */
