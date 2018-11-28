/*
 * File: named.c
 *
 * Simple local nameserver for OS/2.
 *
 * Main program
 *
 * Bob Eager   July 1999
 *
 */

/*
 * History:
 *	1.0	Initial version.
 *	1.1	Added version number to startup message.
 *		Grouped initialisation code together.
 *	1.2	Fix exceptions on referral socket.
 *	1.3	Fix problem with getting IP address on non
 *		point to point interfaces.
 *	1.4	Corrected handling of part line comments in config file.
 *
 */

#pragma	strings(readonly)

#include "named.h"
#include "log.h"

#pragma	alloc_text(init_seg, main)
#pragma	alloc_text(init_seg, error)
#pragma	alloc_text(init_seg, log_startup)
#pragma	alloc_text(init_seg, putusage)

#define	CONFIGFILE	"NameD.Cnf"	/* Name of configuration file */
#define	LOGFILE		"NameD.Log"	/* Name of log file */
#define	ETC		"ETC"		/* Environment variable for misc files */

/* Forward references */

static	VOID	log_startup(PCONFIG);
static	VOID	putusage(VOID);

/* Local storage */

static	CONFIG	config;
static	PUCHAR	progname;

/* Help text */

static	const	UCHAR *helpinfo[] = {
"%s: name server",
"Synopsis: %s [options]",
" Options:",
"    -h           display this help",
""
};


/*
 * Parse arguments and handle options.
 *
 */

INT main(INT argc, UCHAR *argv[])
{	INT i, rc;
	BOOL ok;
	UCHAR *argp;
	PSERV nameserv;
	PUCHAR p;
	UCHAR myname[MAXHOSTNAMELEN+1];
#ifdef	DEBUG
	INT n;
	PSERVERS ps;
#endif

	progname = strrchr(argv[0], '\\');
	if(progname != (PUCHAR) NULL)
		progname++;
	else
		progname = argv[0];
	p = strchr(progname, '.');
	if(p != (PUCHAR) NULL) *p = '\0';
	strlwr(progname);

	tzset();			/* Set time zone */
	res_init();			/* Initialise resolver */

	/* Process input options */

	for(i = 1; i < argc; i++) {
		argp = argv[i];
		if(argp[0] == '-') {		/* Option */
			switch(argp[1]) {
				case 'h':	/* Display help */
					putusage();
					exit(EXIT_SUCCESS);

				case '\0':
					error("missing flag after '-'");
					exit(EXIT_FAILURE);

				default:
					error("invalid flag '%c'", argp[1]);
					exit(EXIT_FAILURE);
			}
		} else {
			error("invalid argument '%s'", argp);
			exit(EXIT_FAILURE);
		}
	}

	rc = sock_init();		/* Initialise socket library */
	if(rc != 0) {
		error("INET.SYS not running");
		exit(EXIT_FAILURE);
	}

	/* Get the host name of this server */

	rc = gethostname(myname, sizeof(myname));
	if(rc != 0) {
		error("cannot get host name");
		exit(EXIT_SUCCESS);
	} else {
		if(strchr(myname, '.') == NULL && _res.defdname[0] != '\0') {
			strcat(myname, ".");
			strcat(myname, _res.defdname);
		}
	}
	config.myname = myname;

	/* Start logging */

	rc = open_logfile(ETC, LOGFILE);
	if(rc != LOG_OK) {
		error("logging initialisation failed - %s",
		rc == LOG_NOENV ? "environment variable "ETC" not set" :
				  "file open failed");
		exit(EXIT_FAILURE);
	}
	log_startup(&config);

	/* Read configuration */

	rc = read_config(ETC, CONFIGFILE, &config);
	if(rc != 0) {
		error(
			"%d configuration error%s - see logfile",
			rc, rc == 1 ? "" : "s");
		exit(EXIT_FAILURE);
	}

#ifdef	DEBUG
	trace("config: using port:            %d", ntohs(config.port));
	trace("config: authority for network: %s", inet_ntoa(config.network));
	trace("config: authority netmask:     %s", inet_ntoa(config.netmask));
	trace("config: authority domain:      %s", config.domain);
	trace("config: referral interface:    %s", config.refer_interface);

	trace("Server list chain:");
	n = 0;
	for(ps = config.servlist; ps != (PSERVERS) NULL; ps = ps->next) {
		UCHAR temp[16];

		trace("Server list %d:", ++n);
		strcpy(temp, inet_ntoa(ps->if_addr));
		trace(
			"Interface address: %s mask %s",
			temp,
			inet_ntoa(ps->if_mask));
		for(i = 0; i < ps->nservers; i++)
			trace(
				"server %d: %s",
				i + 1,
				inet_ntoa(ps->servers[i]));
	}
#endif

	/* Run the server */

	ok = server(&config);

	/* Shut down */

	close_logfile();

	return(ok == TRUE ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
 * Print message on standard error in printf style,
 * accompanied by program name.
 *
 */

VOID error(PUCHAR mes, ...)
{	va_list ap;

	fprintf(stderr, "%s: ", progname);

	va_start(ap, mes);
	vfprintf(stderr, mes, ap);
	va_end(ap);

	fputc('\n', stderr);
}


/*
 * Log details of the daemon startup.
 *
 */

static VOID log_startup(PCONFIG config)
{	time_t tod;
	UCHAR timeinfo[35];
	UCHAR buf[100];

	time(&tod);
	strftime(
		timeinfo,
		sizeof(timeinfo),
		"on %a %d %b %Y at %X %Z",
		localtime(&tod));
	sprintf(
		buf,
		"%s: v%d.%d started on %s, %s",
		progname,
		VERSION,
		EDIT,
		config->myname,
		timeinfo);
	fprintf(stdout, "%s\n", buf);

	sprintf(
		buf,
		"v%d.%d started on %s",
		VERSION,
		EDIT,
		config->myname);
	dolog(buf);
}


/*
 * Output program usage information.
 *
 */

static VOID putusage(VOID)
{	PUCHAR *p = (PUCHAR *) helpinfo;
	PUCHAR q;

	for(;;) {
		q = *p++;
		if(*q == '\0') break;

		fprintf(stderr, q, progname);
		fputc('\n', stderr);
	}
	fprintf(stderr, "\nThis is version %d.%d\n", VERSION, EDIT);
}

/*
 * End of file: named.c
 *
 */
