/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Command to display information about registered projects
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_list(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_list = { "LIST", N_("Lists project registrations."), PRIV_PROJECT_AUSPEX, 1, cmd_list, { .path = "libera/project_list" } };

static void cmd_list(sourceinfo_t *si, int parc, char *parv[])
{
	char *pattern = parv[0];

	if (!pattern)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "LIST");
		command_fail(si, fault_needmoreparams, _("Syntax: LIST <pattern>"));
		return;
	}

	mowgli_patricia_iteration_state_t state;
	struct projectns *project;
	unsigned int matches = 0;

	command_success_nodata(si, _("Registered projects matching pattern \2%s\2:"), pattern);

	MOWGLI_PATRICIA_FOREACH(project, &state, projectsvs->projects)
	{
		if (!match(pattern, project->name))
		{
			matches++;
			char channels[BUFSIZE] = "";
			mowgli_node_t *n;
			MOWGLI_ITER_FOREACH(n, project->channel_ns.head)
			{
				if (channels[0])
					mowgli_strlcat(channels, ", ", sizeof channels);
				mowgli_strlcat(channels, (const char*)n->data, sizeof channels);
			}

			char contacts[BUFSIZE] = "";
			MOWGLI_ITER_FOREACH(n, project->contacts.head)
			{
				struct project_contact *contact = n->data;
				if (contacts[0])
					mowgli_strlcat(contacts, ", ", sizeof contacts);
				mowgli_strlcat(contacts, ((myentity_t*)contact->mu)->name, sizeof contacts);
			}
			command_success_nodata(si, _("- %s (%s; %s)"), project->name,
			                           (channels[0] ? channels : _("\2no channels\2")),
			                           (contacts[0] ? contacts : _("\2no contacts\2")));
		}
	}

	if (matches == 0)
		command_success_nodata(si, _("No projects matched pattern \2%s\2"), pattern);
	else
		command_success_nodata(si, ngettext(N_("\2%d\2 match for pattern \2%s\2"), N_("\2%d\2 matches for pattern \2%s\2"), matches), matches, pattern);
	logcommand(si, CMDLOG_ADMIN, "PROJECT:LIST: \2%s\2 (\2%d\2 matches)", pattern, matches);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_list);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_list);
}

DECLARE_MODULE_V1
(
	"libera/projectns/list", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
