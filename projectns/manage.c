/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Commands to register and drop projects
 */

#include "fn-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_register(sourceinfo_t *si, int parc, char *parv[]);
static void cmd_drop(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_register = { "REGISTER", N_("Adds a project registration."), PRIV_PROJECT_ADMIN, 2, cmd_register, { .path = "freenode/project_register" } };
command_t ps_drop = { "DROP", N_("Deletes a project registration."), PRIV_PROJECT_ADMIN, 1, cmd_drop, { .path = "freenode/project_drop" } };

static void cmd_register(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];

	if (!name)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "REGISTER");
		command_fail(si, fault_needmoreparams, _("Syntax: REGISTER <project>"));
		return;
	}

	if (parc > 1)
	{
		command_fail(si, fault_badparams, _("For technical reasons, project names cannot contain spaces."));
		return;
	}

	if (projectsvs->project_find(name))
	{
		command_fail(si, fault_alreadyexists, _("\2%s\2 is already registered."), name);
		return;
	}

	if (!projectsvs->is_valid_project_name(name))
	{
		command_fail(si, fault_badparams, _("\2%s\2 is not a valid project name."), name);
		return;
	}

	struct projectns *p = projectsvs->project_new(name);
	p->creation_time = CURRTIME;
	p->creator       = strshare_get(get_storage_oper_name(si));

	logcommand(si, CMDLOG_ADMIN, "PROJECT:REGISTER: \2%s\2", name);
	command_success_nodata(si, _("The project \2%s\2 has been registered."), name);
}

static void cmd_drop(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];

	if (!name)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DROP");
		command_fail(si, fault_needmoreparams, _("Syntax: DROP <project>"));
		return;
	}

	struct projectns *p = projectsvs->project_find(name);
	if(!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), name);
		return;
	}

	// get the correct name casing before destroying the project
	name = sstrdup(p->name);

	projectsvs->project_destroy(p);

	logcommand(si, CMDLOG_ADMIN, "PROJECT:DROP: \2%s\2", name);
	command_success_nodata(si, _("The registration for the project \2%s\2 has been dropped."), name);
	free(name);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_register);
	service_named_bind_command("projectserv", &ps_drop);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_register);
	service_named_unbind_command("projectserv", &ps_drop);
}

DECLARE_MODULE_V1
(
	"freenode/projectns/manage", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "freenode <http://www.freenode.net>"
);
