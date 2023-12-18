/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Copyright (c) 2019 Eric Mertens
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Command to display information about registered projects
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_listcloak(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_listcloak = { "LISTCLOAK", N_("Lists cloak namespaces."), PRIV_PROJECT_AUSPEX, 1, cmd_listcloak, { .path = "libera/project_listcloak" } };

struct each_cloak_state
{
	sourceinfo_t *si;
	unsigned int matches;
	const char *pattern;
};

// Called once for each entry in the cloak->project mapping
static int cmd_listcloak_cb(const char *cloakns, void *data, void *privdata)
{
	struct projectns * const project = data;
	struct each_cloak_state * const st = privdata;

	if (!match(st->pattern, cloakns))
	{
		// We have to find the actual entry as patricia tree keys are
		// stored in case-normalized form
		mowgli_node_t *n;
		MOWGLI_ITER_FOREACH(n, project->cloak_ns.head)
		{
			const char * const actual_cloakns = n->data;
			if (0 == strcasecmp(actual_cloakns, cloakns))
			{
				st->matches++;
				command_success_nodata(st->si, _("- %s (%s)"), actual_cloakns, project->name);
				break;
			}
		}
	}

	return 0; // unused by foreach
}

static void cmd_listcloak(sourceinfo_t *si, int parc, char *parv[])
{
	const char *pattern = parv[0];

	if (!pattern)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "LISTCLOAK");
		command_fail(si, fault_needmoreparams, _("Syntax: LISTCLOAK <pattern>"));
		return;
	}

	command_success_nodata(si, _("Cloak namespaces matching pattern \2%s\2:"), pattern);

	struct each_cloak_state st =
		{
			.si = si,
			.matches = 0,
			.pattern = pattern,
		};

	mowgli_patricia_foreach(projectsvs->projects_by_cloakns, cmd_listcloak_cb, &st);

	if (st.matches == 0)
		command_success_nodata(si, _("No cloak namespaces matched pattern \2%s\2"), pattern);
	else
		command_success_nodata(si, ngettext(N_("\2%d\2 match for pattern \2%s\2"), N_("\2%d\2 matches for pattern \2%s\2"), st.matches), st.matches, pattern);
	logcommand(si, CMDLOG_ADMIN, "PROJECT:LISTCLOAK: \2%s\2 (\2%d\2 matches)", pattern, st.matches);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_listcloak);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_listcloak);
}

DECLARE_MODULE_V1
(
	"libera/projectns/listcloak", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
