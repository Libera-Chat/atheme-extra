/*
 * Copyright (c) 2020 Gareth Pulham, Nicole Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Command to audit incompletely registered projects
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_audit(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_audit = {
	.name       = "AUDIT",
	.desc       = N_("Lists projects with incomplete registrations"),
	.access     = PRIV_PROJECT_AUSPEX,
	.maxparc    = 1,
	.cmd        = cmd_audit,
	.help       = { .path = "libera/project_audit" },
};

static void cmd_audit(sourceinfo_t *si, int parc, char *parv[])
{
	bool check_channels = false;
	bool check_contacts = false;

	const char *what = "";

	if (parc == 0)
	{
		check_channels = check_contacts = true;
	}
	else if (strcasecmp(parv[0], "CHANNELS") == 0)
	{
		check_channels = true;
		what = "CHANNELS:";
	}
	else if (strcasecmp(parv[0], "CONTACTS") == 0)
	{
		check_contacts = true;
		what = "CONTACTS:";
	}
	else
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "AUDIT");
		command_fail(si, fault_badparams, _("Syntax: AUDIT [CHANNELS|CONTACTS]"));
		return;
	}

	mowgli_patricia_iteration_state_t state;
	struct projectns *project;
	unsigned int matches = 0;

	command_success_nodata(si, _("Projects in need of attention:"));

	MOWGLI_PATRICIA_FOREACH(project, &state, projectsvs->projects)
	{
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

		if ((check_channels && !channels[0]) || (check_contacts && !contacts[0]))
		{
			matches++;
			command_success_nodata(si, _("- %s (%s; %s)"), project->name,
			                           (channels[0] ? channels : _("\2no channels\2")),
			                           (contacts[0] ? contacts : _("\2no contacts\2")));
		}
	}

	if (matches == 0)
		command_success_nodata(si, _("All projects correctly registered."));
	else
		command_success_nodata(si, ngettext(N_("\2%d\2 project in need of attention."),
		                                    N_("\2%d\2 projects in need of attention."),
		                                    matches), matches);
	logcommand(si, CMDLOG_ADMIN, "PROJECT:AUDIT:%s \2%d\2 projects", what, matches);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_audit);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_audit);
}

DECLARE_MODULE_V1
(
	"libera/projectns/audit", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
