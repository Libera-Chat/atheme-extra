/*
 * Copyright (c) 2023 Ryan Schmidt
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * NickServ command for contacts to list cloaks within their namespaces
 */

#include "fn-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_listgroupcloaks(sourceinfo_t *si, int parc, char *parv[]);

command_t ns_listgroupcloaks = { "LISTGROUPCLOAKS", N_("List accounts with cloaks belonging to your projects."), AC_AUTHENTICATED, 2, cmd_listgroupcloaks, { .path = "freenode/ns_listgroupcloaks" } };

struct cloak_ns {
	struct projectns *project;
	size_t main_len;
	size_t dual_len;
	char main_pattern[HOSTLEN + 1];
	char dual_pattern[HOSTLEN + 1];
};

static void cmd_listgroupcloaks(sourceinfo_t *si, int parc, char *parv[])
{
	char *filter = parv[0];

	mowgli_node_t *n, *tn;
	mowgli_list_t *plist = projectsvs->myuser_get_projects(si->smu);
	unsigned int num_projects = 0;
	mowgli_list_t cloak_ns_list = { NULL, NULL, 0 };

	MOWGLI_ITER_FOREACH(n, plist->head)
	{
		struct project_contact *contact = n->data;
		mowgli_node_t *n2;

		MOWGLI_ITER_FOREACH(n2, contact->project->cloak_ns.head)
		{
			struct cloak_ns *cns = smalloc(sizeof *cns);
			cns->project = contact->project;
			// main pattern matches project/* for regular cloaks
			mowgli_strlcpy(cns->main_pattern, (const char *)n2->data, sizeof cns->main_pattern);
			mowgli_strlcat(cns->main_pattern, "/", sizeof cns->main_pattern);
			// dual pattern matches project.* after the rightmost / for dual cloaks (project1/project2.foo)
			mowgli_strlcpy(cns->dual_pattern, (const char *)n2->data, sizeof cns->dual_pattern);
			mowgli_strlcat(cns->dual_pattern, ".", sizeof cns->dual_pattern);
			cns->main_len = strlen(cns->main_pattern);
			cns->dual_len = strlen(cns->dual_pattern);
			mowgli_node_add(cns, mowgli_node_create(), &cloak_ns_list);
		}

		num_projects++;
	}

	if (!num_projects)
	{
		command_fail(si, fault_noprivs, _("You are not an authorized group contact for any project."));
		return;
	}

	if (filter)
		command_success_nodata(si, _("Assigned cloaks in your projects matching \2%s\2:"), filter);
	else
		command_success_nodata(si, _("Assigned cloaks in your projects:"));

	unsigned int matches = 0;
	struct myentity *mt;
	struct myuser *mu;
	struct metadata *md;
	struct myentity_iteration_state state;
	const char *slash;

	MYENTITY_FOREACH_T(mt, &state, ENT_USER)
	{
		mu = user(mt);
		md = metadata_find(mu, "private:usercloak");
		if (md == NULL)
			continue;

		slash = strrchr(md->value, '/');
		if (slash == NULL)
			continue;

		if (filter != NULL && match(filter, md->value))
			continue;

		MOWGLI_ITER_FOREACH(n, cloak_ns_list.head)
		{
			struct cloak_ns *cns = (struct cloak_ns*)n->data;
			if (!strncmp(cns->main_pattern, md->value, cns->main_len) || !strncmp(cns->dual_pattern, slash + 1, cns->dual_len))
			{
				command_success_nodata(si, "- %s (%s) [%s]", md->value, mt->name, cns->project->name);
				matches++;
				break;
			}
		}
	}

	if (matches == 0)
	{
		if (filter)
			command_success_nodata(si, _("No assigned cloaks matched pattern \2%s\2"), filter);
		else
			command_success_nodata(si, _("There are no assigned cloaks in your projects."));
	}
	else
	{
		if (filter)
			command_success_nodata(si,
				ngettext(N_("\2%u\2 match for pattern \2%s\2"), N_("\2%u\2 matches for pattern \2%s\2"), matches),
				matches, filter);
		else
			command_success_nodata(si, ngettext(N_("\2%u\2 match"), N_("\2%u\2 matches"), matches), matches);
	}

	if (filter)
		logcommand(si, CMDLOG_GET, "LISTGROUPCLOAKS: \2%s\2", filter);
	else
		logcommand(si, CMDLOG_GET, "LISTGROUPCLOAKS");

	MOWGLI_ITER_FOREACH_SAFE(n, tn, cloak_ns_list.head)
	{
		sfree(n->data);
		mowgli_node_free(n);
	}
}

static void mod_init(module_t *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/main");
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("nickserv", &ns_listgroupcloaks);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("nickserv", &ns_listgroupcloaks);
}

DECLARE_MODULE_V1
(
		"freenode/projectns/ns_listgroupcloaks", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
		"", "Libera Chat <https://libera.chat>"
);
