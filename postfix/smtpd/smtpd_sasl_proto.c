/*++
/* NAME
/*	smtpd_sasl_proto 3
/* SUMMARY
/*	Postfix SMTP protocol support for SASL authentication
/* SYNOPSIS
/*	#include "smtpd.h"
/*	#include "smtpd_sasl.h"
/*
/*	void	smtpd_sasl_auth_cmd(state, argc, argv)
/*	SMTPD_STATE *state;
/*	int	argc;
/*	SMTPD_TOKEN *argv;
/*
/*	void	smtpd_sasl_auth_reset(state)
/*	SMTPD_STATE *state;
/*
/*	char	*smtpd_sasl_mail_opt(state, sender)
/*	SMTPD_STATE *state;
/*	const char *sender;
/*
/*	void	smtpd_sasl_mail_log(state)
/*	SMTPD_STATE *state;
/*
/*	void	smtpd_sasl_mail_reset(state)
/*	SMTPD_STATE *state;
/* DESCRIPTION
/*	This module contains random chunks of code that implement
/*	the SMTP protocol interface for SASL negotiation. The goal 
/*	is to reduce clutter of the main SMTP server source code.
/*
/*	smtpd_sasl_auth_cmd() implements the AUTH command.
/*
/*	smtpd_sasl_auth_reset() cleans up after the AUTH command.
/*
/*	smtpd_sasl_mail_opt() implements the AUTH=sender option
/*	to the MAIL FROM command. The result is an error response
/*	in case of problems.
/*
/*	smtpd_sasl_mail_log() logs the queue ID and client information.
/*
/*	smtpd_sasl_mail_reset() cleans up after the AUTH=sender option.
/*
/*	Arguments:
/* .IP state
/*	SMTP session context.
/* .IP argc
/*	Number of command line tokens.
/* .IP argv
/*	The command line parsed into tokens.
/* .IP sender
/*	Sender address from the AUTH=sender option in the MAIL FROM
/*	command.
/* DIAGNOSTICS
/*	All errors are fatal.
/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Initial implementation by:
/*	Till Franke
/*	SuSE Rhein/Main AG
/*	65760 Eschborn, Germany
/*
/*	Adopted by:
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>
#include <string.h>

/* Utility library. */

#include <msg.h>
#include <mymalloc.h>

/* Global library. */

#include <mail_params.h>
#include <mail_proto.h>
#include <mail_error.h>

/* Application-specific. */

#include "smtpd.h"
#include "smtpd_token.h"
#include "smtpd_chat.h"
#include "smtpd_sasl_proto.h"
#include "smtpd_sasl_glue.h"

#ifdef USE_SASL_AUTH

/* smtpd_sasl_auth_cmd - process AUTH command */

int     smtpd_sasl_auth_cmd(SMTPD_STATE *state, int argc, SMTPD_TOKEN *argv)
{
    char   *auth_mechanism;
    char   *initial_response;
    char   *err;

    if (var_helo_required && state->helo_name == 0) {
	state->error_mask |= MAIL_ERROR_POLICY;
	smtpd_chat_reply(state, "503 Error: send HELO/EHLO first");
	return (-1);
    }
    if (!var_smtpd_sasl_enable) {
	state->error_mask |= MAIL_ERROR_PROTOCOL;
	smtpd_chat_reply(state, "503 Error: authentication not enabled");
	return (-1);
    }
    if (state->sasl_username) {
	state->error_mask |= MAIL_ERROR_PROTOCOL;
	smtpd_chat_reply(state, "503 Error: already authenticated");
	return (-1);
    }
    if (argc < 2 || argc > 3) {
	state->error_mask |= MAIL_ERROR_PROTOCOL;
	smtpd_chat_reply(state, "501 Syntax: AUTH mechanism");
	return (-1);
    }

    /*
     * All authentication failures shall be logged. The 5xx reply code
     * triggers tar-pit delays in order to slow down password guessing
     * attacks.
     */
    auth_mechanism = argv[1].strval;
    initial_response = (argc == 3 ? argv[2].strval : 0);
    err = smtpd_sasl_authenticate(state, auth_mechanism, initial_response);
    if (err != 0) {
	msg_warn("%s[%s]: SASL authentication failed",
		 state->name, state->addr);
	smtpd_chat_reply(state, "%s", err);
	return (-1);
    }
    smtpd_chat_reply(state, "235 Authentication successful");
    return (0);
}

/* smtpd_sasl_auth_reset - clean up after AUTH command */

void    smtpd_sasl_auth_reset(SMTPD_STATE *state)
{
    smtpd_sasl_logout(state);
}

/* smtpd_sasl_mail_opt - SASL-specific AUTH=sender option */

char   *smtpd_sasl_mail_opt(SMTPD_STATE *state, const char *addr)
{
    if (!var_smtpd_sasl_enable) {
	state->error_mask |= MAIL_ERROR_PROTOCOL;
	return ("503 Error: authentication disabled");
    }
    if (state->sasl_username == 0) {
	state->error_mask |= MAIL_ERROR_PROTOCOL;
	return ("503 Error: send AUTH command first");
    }
    if (state->sasl_sender != 0) {
	state->error_mask |= MAIL_ERROR_PROTOCOL;
	return ("503 Error: multiple AUTH= options");
    }
    if (strcmp(addr, "<>") != 0)
	state->sasl_sender = mystrdup(addr);
    return (0);
}

/* smtpd_sasl_mail_log - SASL-specific MAIL FROM command logging */

void    smtpd_sasl_mail_log(SMTPD_STATE *state)
{
#define IFELSE(e1,e2,e3) ((e1) ? (e2) : (e3))
#define LOG_IFSET(text,var) IFELSE((var),(text),""), IFELSE((var),(var),"")

    msg_info("%s: client=%s[%s]%s%s%s%s",
	     state->queue_id, state->name, state->addr,
	     LOG_IFSET(", sasl_method=", state->sasl_method),
	     LOG_IFSET(", sasl_username=", state->sasl_username),
	     LOG_IFSET(", sasl_sender=", state->sasl_sender));
}

/* smtpd_sasl_mail_reset - SASL-specific MAIL FROM cleanup */

void    smtpd_sasl_mail_reset(SMTPD_STATE *state)
{
    if (state->sasl_sender) {
	myfree(state->sasl_sender);
	state->sasl_sender = 0;
    }
}

#endif
