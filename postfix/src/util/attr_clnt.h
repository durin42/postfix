#ifndef _ATTR_CLNT_H_INCLUDED_
#define _ATTR_CLNT_H_INCLUDED_

/*++
/* NAME
/*	attr_clnt 3h
/* SUMMARY
/*	attribute query-reply client
/* SYNOPSIS
/*	#include <attr_clnt.h>
/* DESCRIPTION
/* .nf

 /*
  * Utility library.
  */
#include <attr.h>

 /*
  * External interface.
  */
typedef struct ATTR_CLNT ATTR_CLNT;

extern ATTR_CLNT *attr_clnt_create(const char *, int, int, int);
extern int attr_clnt_request(ATTR_CLNT *, int,...);
extern void attr_clnt_free(ATTR_CLNT *);

/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

#endif