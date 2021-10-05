/*
 * Copyright (c) 2016 Mike Quin
 * Rights to this code are as documented in doc/LICENSE.
 *
 * libera on-identify notice to users with no valid email address set
 *
 */

#include "lc-compat.h"
#include "atheme.h"

static void user_identify_notice(user_t *u);

static void mod_init(module_t *m)
{
	hook_add_user_identify(user_identify_notice);
}

static void mod_deinit(module_unload_intent_t intentvoid)
{
	hook_del_user_identify(user_identify_notice);
}

static void user_identify_notice(user_t *u)
{
	myuser_t *mu = u->myuser;
	if (mu->flags & MU_WAITAUTH)
	{
		return;
	}
	if (!validemail(mu->email))
	{
		notice(nicksvs.nick, u->nick, "WARNING: Your NickServ account does not have a valid email address set.");
		notice(nicksvs.nick, u->nick, "Should you forget your password it may not be possible to recover your acccount.");
		notice(nicksvs.nick, u->nick, "For help setting an email address, see \2/msg NickServ HELP SET EMAIL\2.");
		notice(nicksvs.nick, u->nick, "Should you need more assistance you can /join #libera to find network staff.");
	}
}

DECLARE_MODULE_V1
(
	"libera/noemailnotice", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	PACKAGE_STRING,
	"libera <http://libera.chat>"
);
