/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Commands to manage registered contacts
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_contact(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_contact = { "CONTACT", N_("Manages project contacts."), PRIV_PROJECT_ADMIN, 5, cmd_contact, { .path = "libera/project_contact" } };

static void cmd_contact(sourceinfo_t *si, int parc, char *parv[])
{
	char *project   = parv[0];
	char *mode      = parv[1];
	char *target    = parv[2];
	char **extra    = parv + 3;

	enum {
		CONTACT_BAD = 0,
		CONTACT_ADD,
		CONTACT_DEL,
		CONTACT_SET,
	} add_or_del = CONTACT_BAD;

	enum {
		VIS_UNSPEC = 0,
		VIS_PUBLIC,
		VIS_PRIVATE,
	} change_visible = VIS_UNSPEC;

	enum {
		GC_UNSPEC = 0,
		GC_PRIMARY,
		GC_SECONDARY,
	} change_secondary = GC_UNSPEC;

	bool bad_params = false;

	for (unsigned char i = 0; extra[i] != NULL; i++)
	{
		if (strcasecmp(extra[i], "PUBLIC") == 0 && !change_visible)
			change_visible = VIS_PUBLIC;
		else if (strcasecmp(extra[i], "PRIVATE") == 0 && !change_visible)
			change_visible = VIS_PRIVATE;
		else if (strcasecmp(extra[i], "PRIMARY") == 0 && !change_secondary)
			change_secondary = GC_PRIMARY;
		else if (strcasecmp(extra[i], "SECONDARY") == 0 && !change_secondary)
			change_secondary = GC_SECONDARY;
		else
			bad_params = true;
	}

	if (mode)
	{
		if (strcasecmp(mode, "ADD") == 0)
			add_or_del = CONTACT_ADD;
		else if (strcasecmp(mode, "DEL") == 0)
			add_or_del = CONTACT_DEL;
		else if (strcasecmp(mode, "SET") == 0)
			add_or_del = CONTACT_SET;
		else
			bad_params = true;
	}

	bool settings_given = change_visible || change_secondary;

	if ((add_or_del == CONTACT_DEL && settings_given) || (add_or_del == CONTACT_SET && !settings_given))
		bad_params = true;

	if (bad_params || !target)
	{
		cmd_faultcode_t fault = (bad_params ? fault_badparams : fault_needmoreparams);

		if (fault == fault_badparams)
			command_fail(si, fault, STR_INVALID_PARAMS, "CONTACT");
		else
			command_fail(si, fault, STR_INSUFFICIENT_PARAMS, "CONTACT");
		command_fail(si, fault, _("Syntax: CONTACT <project> ADD|DEL|SET <account> [PRIVATE|PUBLIC] [PRIMARY|SECONDARY]"));
		return;
	}

	myuser_t *mu = myuser_find_ext(target);

	if (!mu)
	{
		command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
		return;
	}

	struct projectns *p = projectsvs->project_find(project);

	if (!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), project);
		return;
	}

	if (add_or_del == CONTACT_ADD)
	{
		struct project_contact *c = projectsvs->contact_new(p, mu);
		if (c != NULL)
		{
			if (change_visible == VIS_PUBLIC)
				c->visible = true;
			if (change_secondary == GC_SECONDARY)
				c->secondary = true;

			logcommand(si, CMDLOG_ADMIN, "PROJECT:CONTACT:ADD: \2%s\2 to \2%s\2 (%s, %s)", entity(mu)->name, p->name, c->secondary ? "secondary" : "primary", c->visible ? "public" : "private");

			if (c->secondary)
			{
				if (c->visible)
					command_success_nodata(si, _("\2%s\2 was set as a secondary contact for project \2%s\2 (user-visible)."), entity(mu)->name, p->name);
				else
					command_success_nodata(si, _("\2%s\2 was set as a secondary contact for project \2%s\2 (only visible to staff)."), entity(mu)->name, p->name);
			}
			else
			{
				if (c->visible)
					command_success_nodata(si, _("\2%s\2 was set as a primary contact for project \2%s\2 (user-visible)."), entity(mu)->name, p->name);
				else
					command_success_nodata(si, _("\2%s\2 was set as a primary contact for project \2%s\2 (only visible to staff)."), entity(mu)->name, p->name);
			}
		}
		else
		{
			command_fail(si, fault_nochange, _("\2%s\2 is already listed as contact for project \2%s\2."), entity(mu)->name, p->name);
		}
	}
	else if (add_or_del == CONTACT_SET)
	{
		mowgli_node_t *n;
		struct project_contact *c;
		MOWGLI_ITER_FOREACH(n, p->contacts.head)
		{
			c = n->data;
			if (c->mu == mu)
				break;
		}

		if (!n)
		{
			command_fail(si, fault_nosuch_key, _("\2%s\2 was not listed as a contact for project \2%s\2."), entity(mu)->name, p->name);
		}
		else
		{
			if ((c->visible && change_visible == VIS_PUBLIC) || (!c->visible && change_visible == VIS_PRIVATE))
				change_visible = VIS_UNSPEC;
			if ((c->secondary && change_secondary == GC_SECONDARY) || (!c->secondary && change_secondary == GC_PRIMARY))
				change_secondary = GC_UNSPEC;

			if (change_visible == VIS_PUBLIC)
			{
				c->visible = true;
				logcommand(si, CMDLOG_ADMIN, "PROJECT:CONTACT:SET: \2%s\2 on \2%s\2 to %s", entity(mu)->name, p->name, "public");
				command_success_nodata(si, _("\2%s\2 is now listed as a public contact for project \2%s\2."), entity(mu)->name, p->name);
			}
			else if (change_visible == VIS_PRIVATE)
			{
				c->visible = false;
				logcommand(si, CMDLOG_ADMIN, "PROJECT:CONTACT:SET: \2%s\2 on \2%s\2 to %s", entity(mu)->name, p->name, "private");
				command_success_nodata(si, _("\2%s\2 is now only displayed to staff as contact for project \2%s\2."), entity(mu)->name, p->name);
			}
			if (change_secondary == GC_SECONDARY)
			{
				c->secondary = true;
				logcommand(si, CMDLOG_ADMIN, "PROJECT:CONTACT:SET: \2%s\2 on \2%s\2 to %s", entity(mu)->name, p->name, "secondary");
				command_success_nodata(si, _("\2%s\2 is now considered a secondary contact for project \2%s\2."), entity(mu)->name, p->name);
			}
			else if (change_secondary == GC_PRIMARY)
			{
				c->secondary = false;
				logcommand(si, CMDLOG_ADMIN, "PROJECT:CONTACT:SET: \2%s\2 on \2%s\2 to %s", entity(mu)->name, p->name, "primary");
				command_success_nodata(si, _("\2%s\2 is now considered a primary contact for project \2%s\2."), entity(mu)->name, p->name);
			}

			if (!change_visible && !change_secondary)
				command_fail(si, fault_nochange, _("Settings for \2%s\2 as a contact for project \2%s\2 were not changed."), entity(mu)->name, p->name);
		}
	}
	else // CONTACT_DEL
	{
		if (projectsvs->contact_destroy(p, mu))
		{
			logcommand(si, CMDLOG_ADMIN, "PROJECT:CONTACT:DEL: \2%s\2 from \2%s\2", entity(mu)->name, p->name);
			command_success_nodata(si, _("\2%s\2 was removed as a contact for project \2%s\2."), entity(mu)->name, p->name);
			if (!p->contacts.count)
				command_success_nodata(si, _("The project \2%s\2 now has no contacts."), p->name);
		}
		else
		{
			command_fail(si, fault_nochange, _("\2%s\2 was not listed as a contact for project \2%s\2."), entity(mu)->name, p->name);
		}
	}
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_contact);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_contact);
}

DECLARE_MODULE_V1
(
	"libera/projectns/contact", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
