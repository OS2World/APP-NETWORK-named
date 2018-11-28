/*
 * File: log.h
 *
 * General logging and tracing routines; header file.
 *
 * Bob Eager   August 2000
 *
 */

/* Tunable constants */

#define	MAXLOG			200	/* Maximum length of a logfile line */

/* Error codes */

#define	LOG_OK			0	/* Logfile successfully opened */
#define	LOG_NOENV		1	/* Env variable not set for log dir */
#define	LOG_OPENFAIL		2	/* Failed to open logfile */

/* External references */

extern	VOID	close_logfile(VOID);
extern	VOID	dolog(PUCHAR);
extern	INT	open_logfile(PUCHAR, PUCHAR);
#ifdef	DEBUG
extern	VOID	trace(PUCHAR, ...);
#endif

/*
 * End of file: log.h
 *
 */

