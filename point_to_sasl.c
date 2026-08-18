/*
 * Copyright (C) 2026 Libera.Chat <https://libera.chat/>
 * Rights to this code are as documented in doc/LICENSE
 */

#include "atheme.h"

static void
on_user_identify(struct hook_user_identify *hdata)
{
	if (hdata->svs == service_find("nickserv"))
	{
		(void) notice(nicksvs.nick, hdata->u->nick, "You have logged in using NickServ. We recommend logging in via SASL instead.");
		(void) notice(nicksvs.nick, hdata->u->nick, "For more information please see https://libera.chat/guides/sasl");
	}
}

static void
mod_init(struct module *const m)
{
	(void) hook_add_user_identify(&on_user_identify);
}

static void
mod_deinit(const enum module_unload_intent intent)
{
	(void) hook_del_user_identify(&on_user_identify);
}

VENDOR_DECLARE_MODULE_V1("freenode/point_to_sasl", MODULE_UNLOAD_CAPABILITY_OK, "Libera.Chat <https://libera.chat/>");
