/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Commands to manipulate projects' settings
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_set(sourceinfo_t *si, int parc, char *parv[]);
static void help_set(sourceinfo_t *si, const char *subcmd);
static void set_openreg(sourceinfo_t *si, int parc, char *parv[]);
static void set_reginfo(sourceinfo_t *si, int parc, char *parv[]);
static void set_name(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_set = { "SET", N_("Manipulates basic project settings."), PRIV_PROJECT_ADMIN, 3, cmd_set, { .func = help_set } };
command_t ps_set_name = { "NAME", N_("Changes the name used to identify the project."), PRIV_PROJECT_ADMIN, 2, set_name, { .path = "libera/project_set_name" } };
command_t ps_set_openreg = { "OPENREG", N_("Allow non-contacts to register channels."), PRIV_PROJECT_ADMIN, 2, set_openreg, { .path = "libera/project_set_openreg" } };
command_t ps_set_reginfo = { "REGINFO", N_("Public information about the project namespace."), PRIV_PROJECT_ADMIN, 2, set_reginfo, { .path = "libera/project_set_reginfo" } };

mowgli_patricia_t *set_cmdtree;

static void help_set(sourceinfo_t *si, const char *subcmd)
{
	if (!subcmd)
	{
		command_success_nodata(si, _("***** \2%s Help\2 *****"), projectsvs->me->nick);
		command_success_nodata(si, _("Help for \2SET\2:"));
		command_success_nodata(si, " ");
		command_success_nodata(si, _("SET allows you to manipulate various properties\n"
					"of a group registration."));
		command_success_nodata(si, " ");
		command_help(si, set_cmdtree);
		command_success_nodata(si, " ");
		command_success_nodata(si, _("For more specific help use \2/msg %s HELP SET \37command\37\2."), projectsvs->me->disp);
		command_success_nodata(si, _("***** \2End of Help\2 *****"));
	}
	else
		help_display_as_subcmd(si, si->service, "SET", subcmd, set_cmdtree);
}

static void cmd_set(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];
	char *setting = parv[1];
	command_t *c;

	if (!setting)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "SET");
		command_fail(si, fault_needmoreparams, _("Syntax: SET <project> <setting> [parameters]"));
		return;
	}

	c = command_find(set_cmdtree, setting);
	if (c == NULL)
	{
		command_fail(si, fault_badparams, _("Invalid command. Use \2/%s%s help\2 for a command listing."), (ircd->uses_rcommand == false) ? "msg " : "", projectsvs->me->disp);
		return;
	}

	parv[1] = name;
	command_exec(si->service, si, c, parc - 1, parv + 1);
}

static void set_openreg(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];
	char *mode = parv[1];

	enum {
		OPENREG_BAD = 0,
		OPENREG_ON,
		OPENREG_OFF,
	} on_or_off = OPENREG_BAD;

	if (mode)
	{
		if (strcasecmp(mode, "ON") == 0)
			on_or_off = OPENREG_ON;
		else if (strcasecmp(mode, "OFF") == 0)
			on_or_off = OPENREG_OFF;
	}

	if (!on_or_off)
	{
		cmd_faultcode_t fault = (mode ? fault_badparams : fault_needmoreparams);

		if (fault == fault_badparams)
			command_fail(si, fault, STR_INVALID_PARAMS, "SET OPENREG");
		else
			command_fail(si, fault, STR_INSUFFICIENT_PARAMS, "SET OPENREG");
		command_fail(si, fault, _("Syntax: SET <project> OPENREG ON|OFF"));
		return;
	}

	struct projectns *p = projectsvs->project_find(name);
	if (!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), name);
		return;
	}

	bool new_openreg = (on_or_off == OPENREG_ON);
	const char *onoff_str = (new_openreg ? "ON" : "OFF");
	if (p->any_may_register == new_openreg)
	{
		command_fail(si, fault_nochange, _("The OPENREG flag is already set to %s for the project \2%s\2."), onoff_str, p->name);
		return;
	}

	p->any_may_register = new_openreg;

	logcommand(si, CMDLOG_ADMIN, "PROJECT:SET:OPENREG:%s: \2%s\2", onoff_str, name);
	if (new_openreg)
		command_success_nodata(si, _("The OPENREG flag has been set for the project \2%s\2."), name);
	else
		command_success_nodata(si, _("The OPENREG flag has been unset for the project \2%s\2."), name);
}

static void set_reginfo(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];
	char *info = parv[1];

	struct projectns *p = projectsvs->project_find(name);
	if (!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), name);
		return;
	}

	if (info)
	{
		free(p->reginfo);
		p->reginfo = sstrdup(info);
		logcommand(si, CMDLOG_ADMIN, "PROJECT:SET:REGINFO: \2%s\2 to \2%s\2", p->name, info);
		command_success_nodata(si, _("The public namespace information for project \2%s\2 has been set to \2%s\2."), p->name, info);
	}
	else
	{
		free(p->reginfo);
		p->reginfo = NULL;
		logcommand(si, CMDLOG_ADMIN, "PROJECT:SET:REGINFO:CLEAR: \2%s\2", p->name);
		command_success_nodata(si, _("The public namespace information for project \2%s\2 has been cleared."), p->name);
	}
}

static void set_name(sourceinfo_t *si, int parc, char *parv[])
{
	char *target = parv[0];
	char *newname = parv[1];

	if (!newname)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "SET NAME");
		command_fail(si, fault_needmoreparams, _("Syntax: SET <project> NAME <new>"));
		return;
	}

	struct projectns *p = projectsvs->project_find(target);
	if (!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), target);
		return;
	}

	char *oldname = p->name;

	if (!projectsvs->is_valid_project_name(newname))
	{
		command_fail(si, fault_badparams, _("\2%s\2 is not a valid project name."), newname);
		return;
	}

	if (strcmp(oldname, newname) == 0)
	{
		command_fail(si, fault_nochange, _("The project name is already set to \2%s\2."), newname);
		return;
	}

	struct projectns *existing = projectsvs->project_find(newname);
	if (existing && existing != p)
	{
		command_fail(si, fault_alreadyexists, _("A project named \2%s\2 already exists. Please choose a different name."), newname);
		return;
	}

	p->name = sstrdup(newname);

	// must be in this order or this will break if only casing is changed
	mowgli_patricia_delete(projectsvs->projects, oldname);
	mowgli_patricia_add(projectsvs->projects, newname, p);

	logcommand(si, CMDLOG_ADMIN, "PROJECT:SET:NAME: \2%s\2 to \2%s\2", oldname, newname);
	command_success_nodata(si, _("The \2%s\2 project has been renamed to \2%s\2."), oldname, newname);

	free(oldname);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_set);
	set_cmdtree = mowgli_patricia_create(strcasecanon);
	command_add(&ps_set_openreg, set_cmdtree);
	command_add(&ps_set_reginfo, set_cmdtree);
	command_add(&ps_set_name, set_cmdtree);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_set);
	command_delete(&ps_set_openreg, set_cmdtree);
	command_delete(&ps_set_reginfo, set_cmdtree);
	command_delete(&ps_set_name, set_cmdtree);
	mowgli_patricia_destroy(set_cmdtree, NULL, NULL);
}

DECLARE_MODULE_V1
(
	"libera/projectns/set", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
