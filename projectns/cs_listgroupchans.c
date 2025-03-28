/*
 * Copyright (c) 2023 Ryan Schmidt
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * ChanServ command for contacts to list channels within their namespaces
 */

#include "fn-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_listgroupchans(sourceinfo_t *si, int parc, char *parv[]);

command_t cs_listgroupchans = { "LISTGROUPCHANS", N_("List channels belonging to your projects."), AC_AUTHENTICATED, 2, cmd_listgroupchans, { .path = "freenode/cs_listgroupchans" } };

static void cmd_listgroupchans(sourceinfo_t *si, int parc, char *parv[])
{
	char *filter = parv[0];

	mowgli_node_t *n;
	mowgli_list_t *plist = projectsvs->myuser_get_projects(si->smu);

	if (!MOWGLI_LIST_LENGTH(plist))
	{
		command_fail(si, fault_noprivs, _("You are not an authorized group contact for any project."));
		return;
	}

	if (filter)
		command_success_nodata(si, _("Channels in your projects matching \2%s\2:"), filter);
	else
		command_success_nodata(si, _("Channels in your projects:"));

	unsigned int matches = 0;
	struct mychan *mc;
	mowgli_patricia_iteration_state_t state;

	MOWGLI_PATRICIA_FOREACH(mc, &state, mclist)
	{
		if (filter != NULL && match(filter, mc->name))
			continue;

		struct projectns *project = projectsvs->channame_get_project(mc->name, NULL);
		MOWGLI_ITER_FOREACH(n, plist->head)
		{
			struct project_contact *contact = n->data;
			if (project == contact->project)
			{
				if (mc->chan && mc->chan->modes & CMODE_SEC)
					command_success_nodata(si, "- %s (SECRET) (%s) [%s]", mc->name, mychan_founder_names(mc), project->name);
				else if (mc->mlock_on & CMODE_SEC)
					command_success_nodata(si, "- %s (SECRET) (%s) [%s]", mc->name, mychan_founder_names(mc), project->name);
				else
					command_success_nodata(si, "- %s (%s) [%s]", mc->name, mychan_founder_names(mc), project->name);

				matches++;
			}
		}
	}

	if (matches == 0)
	{
		if (filter)
			command_success_nodata(si, _("No channels matched pattern \2%s\2"), filter);
		else
			command_success_nodata(si, _("There are no registered channels in your projects."));
	}
	else
	{
		if (filter)
			command_success_nodata(si, ngettext(N_("\2%u\2 match for pattern \2%s\2"), N_("\2%u\2 matches for pattern \2%s\2"), matches),
			                       matches, filter);
		else
			command_success_nodata(si, ngettext(N_("\2%u\2 match"), N_("\2%u\2 matches"), matches), matches);
	}

	if (filter)
		logcommand(si, CMDLOG_GET, "LISTGROUPCHANS: \2%s\2", filter);
	else
		logcommand(si, CMDLOG_GET, "LISTGROUPCHANS");
}

static void mod_init(module_t *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "chanserv/main");
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("chanserv", &cs_listgroupchans);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("chanserv", &cs_listgroupchans);
}

DECLARE_MODULE_V1
(
		"freenode/projectns/cs_listgroupchans", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
		"", "Libera Chat <https://libera.chat>"
);
