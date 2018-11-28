/*
 * File: db.c
 *
 * Name server for OS/2.
 *
 * Database handler.
 *
 * Bob Eager   August 2000
 *
 */

#pragma	strings(readonly)

#include "named.h"
#include "log.h"

#pragma	alloc_text(init_seg, db_init)
#pragma	alloc_text(init_seg, db_add_host)


/*
 * Initialise the in-memory database.
 *
 * Returns:
 *	TRUE		initialised OK
 *	FALSE		failed to initialise
 *
 */

BOOL db_init(PCONFIG config)
{	config->dbhead = (PDBENT) NULL;
	return(TRUE);
}


/*
 * Add a new host entry to the in-memory database.
 *
 * Returns TRUE if the addition succeeded, and FALSE if it failed.
 *
 */

BOOL db_add_host(PCONFIG config, PDBENT entry)
{	entry->next = config->dbhead;
	config->dbhead = entry;
#ifdef	DEBUG
	trace(
		"add host: at %08x; %s; type: %s",
		(ULONG) entry,
		entry->name,
		entry->type == ENT_TYPE_PRIMARY     ? "primary" :
		entry->type == ENT_TYPE_ALIAS       ? "alias"   :
						      "????");
	if(entry->type == ENT_TYPE_PRIMARY)
		trace(
			"addr: %s (%#08x)",
			inet_ntoa(entry->address),
			entry->address.s_addr);
	if(entry->type == ENT_TYPE_ALIAS)
		trace(
			"points to %08x",
			(ULONG) entry->primary);
#endif
	return(TRUE);
}


/*
 * Search the in-memory database for a record that matches a name.
 *
 */

PDBENT db_find_name(PCONFIG config, PUCHAR name)
{	PDBENT p = config->dbhead;

	while(p != (PDBENT) NULL) {
		if(stricmp(p->name, name) == 0)
			return(p);
		p = p->next;
	}

	return(PDBENT) NULL;
}


/*
 * Search the in-memory database for a record that matches an IP address.
 *
 */

PDBENT db_find_address(PCONFIG config, INADDR address)
{	PDBENT p = config->dbhead;

	while(p != (PDBENT) NULL) {
		if(p->type == ENT_TYPE_PRIMARY &&
		   p->address.s_addr == address.s_addr)
			return(p);
		p = p->next;
	}

	return(PDBENT) NULL;
}

/*
 * End of file: db.c
 *
 */
