/*
 * Copyright (c) 2003-2004 E. Will et al.
 * Copyright (c) 2005-2006 Atheme Development Group
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Help command, adapted from the operserv/help code
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_help(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_help = { "HELP", N_("Displays contextual help information."), AC_NONE, 1, cmd_help, { .path = "help" } };

static void cmd_help(sourceinfo_t *si, int parc, char *parv[])
{
	char *command = parv[0];

	if (!has_any_privs(si))
	{
		command_fail(si, fault_noprivs, _("%s provides utility functionality for network staff. It has no public interface."), si->service->nick);
		return;
	}

	if (!command)
	{
		command_success_nodata(si, _("***** \2%s Help\2 *****"), si->service->nick);
		command_success_nodata(si, _("\2%s\2 allows you to query and manipulate registered projects."), si->service->nick);
		command_success_nodata(si, " ");
		command_success_nodata(si, _("For information on a command, type:"));
		command_success_nodata(si, "\2/%s%s help <command>\2", (ircd->uses_rcommand == false) ? "msg " : "", si->service->disp);
		command_success_nodata(si, " ");

		command_help(si, si->service->commands);

		command_success_nodata(si, _("***** \2End of Help\2 *****"));
		return;
	}

	/* take the command through the hash table */
	help_display(si, si->service, command, si->service->commands);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_help);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_help);
}

DECLARE_MODULE_V1
(
	"libera/projectns/help", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
