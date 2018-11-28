/*
 * File: log.c
 *
 * General logging and tracing routines
 *
 * Bob Eager   August 2000
 *
 */

#pragma	strings(readonly)

#pragma	alloc_text(init_seg, open_logfile)

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <os2.h>

#include "log.h"

#ifdef	DEBUG
#define	MAXTRACE	200		/* Maximum length of trace line */
#endif

/* Local storage */

static	FILE	*logfp;


/*
 * Open the logfile. This is in the directory specified by the
 * environment variable given by 'direnv'; open fails if that
 * environment variable is not found. The actual name of the logfile
 * is given by 'file'.
 *
 * Returns:
 *	LOG_OK		logfile successfully opened
 *	LOG_NOENV	environment variable not set for log directory
 *	LOG_OPENFAIL	failed to open logfile
 *
 */

INT open_logfile(PUCHAR direnv, PUCHAR file)
{	PUCHAR etc = getenv(direnv);
	UCHAR logname[CCHMAXPATH+1];

	if(etc == NULL) return(LOG_NOENV);

	sprintf(logname, "%s\\%s", etc, file);
	logfp = fopen(logname, "a");
	if(logfp == (FILE *) NULL) return(LOG_OPENFAIL);

#ifdef	DEBUG
	_set_crt_msg_handle(fileno(logfp));
#endif

	return(LOG_OK);
}


/*
 * Close the logfile.
 *
 */

VOID close_logfile(VOID)
{	fclose(logfp);
}


/*
 * Write a string to the logfile. The string is timestamped, and a newline
 * appended to the end unless there is one there already.
 *
 * This routine is thread-safe; it writes only ONE string to the logfile,
 * ensuring that the file does not become garbled.
 *
 */

VOID dolog(PUCHAR s)
{	time_t tod;
	UCHAR timeinfo[35];
	UCHAR buf[MAXLOG+1];

	(VOID) time(&tod);
	(VOID) strftime(timeinfo, sizeof(timeinfo),
		"%d/%m/%y %X>", localtime(&tod));
	sprintf(buf, "%s %s", timeinfo, s);
	if(s[strlen(s)-1] != '\n') strcat(buf, "\n");

	fputs(buf, logfp);
	fflush(logfp);
}


#ifdef	DEBUG
/*
 * Output trace message, in printf style, to the logfile.
 *
 */

VOID trace(PUCHAR mes, ...)
{	va_list ap;
	UCHAR buf[MAXTRACE+1];

	strcpy(buf, "trace: ");

	va_start(ap, mes);
	vsprintf(buf+strlen(buf), mes, ap);
	va_end(ap);

	dolog(buf);
}
#endif

/*
 * End of file: log.c
 *
 */
