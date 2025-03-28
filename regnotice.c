/*
 * Copyright (C) 2007 Jilles Tjoelker
 * Copyright (C) 2025 Libera Chat <https://libera.chat/>
 *
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Notices upon the registration of accounts and channels.
 */

#include "atheme.h"

static void
user_reg_notice(struct myuser *const mu)
{
	return_if_fail(mu != NULL);

	(void) myuser_notice(nicksvs.nick, mu, " ");
	(void) myuser_notice(nicksvs.nick, mu, "For help using the network, please see the Guides");
	(void) myuser_notice(nicksvs.nick, mu, "section on our website: https://libera.chat/guides/");
	(void) myuser_notice(nicksvs.nick, mu, " ");
	(void) myuser_notice(nicksvs.nick, mu, "If you still need help you can /JOIN #libera to find");
	(void) myuser_notice(nicksvs.nick, mu, "network staff.");
}

static void
chan_reg_notice(struct hook_channel_req *const hdata)
{
	return_if_fail(hdata != NULL);
	return_if_fail(hdata->si != NULL);
	return_if_fail(hdata->mc != NULL);
	return_if_fail(hdata->mc->name != NULL);

	(void) command_success_nodata(hdata->si, " ");
	(void) command_success_nodata(hdata->si, "Note that channels on Libera.Chat are created secret");
	(void) command_success_nodata(hdata->si, "(+s) by default. If you wish for your channel to be");
	(void) command_success_nodata(hdata->si, "discoverable by network users (for example with ALIS");
	(void) command_success_nodata(hdata->si, "or /LIST), you will need to unset this channel mode:");
	(void) command_success_nodata(hdata->si, " ");
	(void) command_success_nodata(hdata->si, "/MODE %s -s", hdata->mc->name);
}

static void
mod_init(struct module *const ATHEME_VATTR_UNUSED m)
{
	(void) hook_add_user_register(&user_reg_notice);
	(void) hook_add_channel_register(&chan_reg_notice);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	(void) hook_del_user_register(&user_reg_notice);
	(void) hook_del_channel_register(&chan_reg_notice);
}

VENDOR_DECLARE_MODULE_V1("freenode/regnotice", MODULE_UNLOAD_CAPABILITY_OK, "Libera Chat <https://libera.chat/>")
