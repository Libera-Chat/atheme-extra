/*
 * SPDX-License-Identifier: ISC
 * SPDX-URL: https://spdx.org/licenses/ISC.html
 *
 * Copyright (C) 2005 Atheme Project (http://atheme.org/)
 * Copyright (C) 2025 Libera Chat (https://libera.chat/)
 */

#include <atheme.h>

static const char *
channel_modes_restricted(struct sourceinfo *const restrict si, const struct channel *const restrict c)
{
	static char result[BUFSIZE];
	char *p = result;

	*p++ = '+';

	for (size_t i = 0; mode_list[i].mode != '\0'; i++)
	{
		if ((ircd->oper_only_modes & mode_list[i].value) && ! has_priv(si, PRIV_CHAN_CMODES))
			continue;

		if (c->modes & mode_list[i].value)
			*p++ = mode_list[i].mode;
	}

	if (c->key)
		*p++ = 'k';

	if (c->limit)
		*p++ = 'l';

	for (size_t i = 0; i < ignore_mode_list_size; i++)
		if (c->extmodes[i])
			*p++ = ignore_mode_list[i].mode;

	*p++ = 0x00;

	return result;
}

static void
cs_cmd_listmodes_fn(struct sourceinfo *si, int parc, char *parv[])
{
	const mowgli_node_t *n;
	unsigned int chancount = 0;

	MOWGLI_ITER_FOREACH(n, entity(si->smu)->chanacs.head)
	{
		const struct chanacs *const ca = n->data;

		if (ca->level & CA_AKICK)
			continue;

		struct mychan *const mc = ca->mychan;

		continue_if_fail(mc != NULL);

		const char *const cmodes = mc->chan ? channel_modes_restricted(si, mc->chan) : _("<channel empty>");

		if (! chancount)
			(void) command_success_nodata(si, _("%-32s %-16s %s"), _("Channel"), _("Modes"), _("MLOCK"));

		(void) command_success_nodata(si, _("%-32s %-16s %s"), mc->name, cmodes, mychan_get_mlock(mc));

		chancount++;
	}

	if (chancount)
	{
		(void) command_success_nodata(si, " ");
		(void) command_success_nodata(si, ngettext(N_("\2%u\2 channel returned."),
		                                           N_("\2%u\2 channels returned."),
		                                           chancount), chancount);
	}
	else
		(void) command_success_nodata(si, _("You do not have access to any channels."));

	(void) logcommand(si, CMDLOG_GET, "LISTMODES");
}

static struct command cs_cmd_listmodes = {
	.name           = "LISTMODES",
	.desc           = N_("Lists the modes of channels that you have access to."),
	.access         = AC_AUTHENTICATED,
	.maxparc        = 1,
	.cmd            = &cs_cmd_listmodes_fn,
	.help           = { .path = "freenode/cs_listmodes" },
};

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "chanserv/main")

	(void) service_named_bind_command("chanserv", &cs_cmd_listmodes);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	(void) service_named_unbind_command("chanserv", &cs_cmd_listmodes);
}

VENDOR_DECLARE_MODULE_V1("freenode/cs_listmodes", MODULE_UNLOAD_CAPABILITY_OK, "Libera Chat <https://libera.chat/>")
