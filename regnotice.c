/*
 * Copyright (c) 2007 Jilles Tjoelker
 * Rights to this code are as documented in doc/LICENSE.
 *
 * libera on-registration notices and default settings
 *
 * $Id: regnotice.c 69 2013-03-25 13:07:19Z stephen $
 */

#include "lc-compat.h"
#include "atheme.h"

static void nick_reg_notice(myuser_t *mu)
{
	myuser_notice(nicksvs.nick, mu, " ");
	myuser_notice(nicksvs.nick, mu, "For frequently-asked questions about the network, please see the");
	myuser_notice(nicksvs.nick, mu, "Knowledge Base page (https://freenode.net/kb/all). Should you need more");
	myuser_notice(nicksvs.nick, mu, "help you can /join #freenode to find network staff.");
}

static void chan_reg_notice(hook_channel_req_t *hdata)
{
	sourceinfo_t *si = hdata->si;
	mychan_t *mc = hdata->mc;

	if (si == NULL || mc == NULL)
		return;

	command_success_nodata(si, " ");
	command_success_nodata(si, "Channel guidelines can be found on the freenode website:");
	command_success_nodata(si, "https://freenode.net/changuide");
	if (mc->name[1] != '#')
	{
		command_success_nodata(si, "This is a primary namespace channel as per\n"
				"https://freenode.net/policies#channel-ownership");
		command_success_nodata(si, "If you do not own this name, please consider\n"
				"dropping %s and using #%s instead.",
				mc->name, mc->name);
	}
	else
	{
		command_success_nodata(si, "This is an \"about\" channel as per");
		command_success_nodata(si, "https://freenode.net/policies#channel-ownership");
	}

	mc->mlock_on = CMODE_NOEXT | CMODE_TOPIC | mode_to_flag('c');
	mc->mlock_off |= CMODE_SEC;
	/* not needed now that we have founder_flags in config */
	/*chanacs_change_simple(mc, &si->smu->ent, NULL, 0, CA_AUTOOP);*/
}

static void mod_init(module_t *m)
{
	hook_add_user_register(nick_reg_notice);
	hook_add_first_channel_register(chan_reg_notice);
}

static void mod_deinit(module_unload_intent_t intentvoid)
{
	hook_del_user_register(nick_reg_notice);
	hook_del_channel_register(chan_reg_notice);
}

DECLARE_MODULE_V1
(
	"libera/regnotice", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"$Id: regnotice.c 69 2013-03-25 13:07:19Z stephen $",
	"libera chat <https://libera.chat>"
);
