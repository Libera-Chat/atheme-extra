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

static void cmd_info(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_info = { "INFO", N_("Displays information about a project registration."), PRIV_PROJECT_AUSPEX, 1, cmd_info, { .path = "libera/project_info" } };

struct info_item
{
	sourceinfo_t *si;
	const char *title;
	unsigned int count;
	char buf[BUFSIZE];
};

static void info_item_add(struct info_item *item, const char *text)
{
	item->count++;
	if (strlen(item->buf) > 80)
	{
		command_success_nodata(item->si, _("%s: %s"), item->title, item->buf);
		item->buf[0] = '\0';
	}
	if (item->buf[0])
		mowgli_strlcat(item->buf, ", ", sizeof item->buf);
	mowgli_strlcat(item->buf, text, sizeof item->buf);
}

static void info_item_done(struct info_item *item, bool note_empty)
{
	if (item->buf[0])
		command_success_nodata(item->si, _("%s: %s"), item->title, item->buf);
	else if (note_empty)
		command_success_nodata(item->si, _("%s: %s"), item->title, "(none)");

	item->buf[0] = '\0';
}

static void cmd_info(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];

	if (!name)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "INFO");
		command_fail(si, fault_needmoreparams, _("Syntax: INFO <project>"));
		return;
	}

	struct projectns *p = projectsvs->project_find(name);
	if(!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), name);
		return;
	}

	logcommand(si, CMDLOG_GET, "PROJECT:INFO: \2%s\2", p->name);
	command_success_nodata(si, _("Information on \2%s\2:"), p->name);

	char buf[BUFSIZE] = "";

	if (p->creation_time)
	{
		struct tm *tm = localtime(&p->creation_time);
		strftime(buf, sizeof buf, TIME_FORMAT, tm);
	}

	if (p->creation_time && p->creator)
		command_success_nodata(si, _("Registered on %s by %s"), buf, p->creator);
	else if (p->creation_time)
		command_success_nodata(si, _("Registered on %s"), buf);
	else if (p->creator)
		command_success_nodata(si, _("Registered by %s"), p->creator);

	struct info_item info =
	{
		.si    = si,
		.title = "Channel namespaces",
		.count = 0,
		.buf   = { 0 },
	};

	mowgli_node_t *n;
	MOWGLI_ITER_FOREACH(n, p->channel_ns.head)
	{
		info_item_add(&info, n->data);
	}
	info_item_done(&info, true);

	info.title = "Cloak namespaces";
	info.count = 0;

	MOWGLI_ITER_FOREACH(n, p->cloak_ns.head)
	{
		info_item_add(&info, n->data);
	}
	info_item_done(&info, true);

	info.title = "Group contacts (public)";
	info.count = 0;

	MOWGLI_ITER_FOREACH(n, p->contacts.head)
	{
		struct project_contact *contact = n->data;
		if (contact->secondary)
			continue;
		if (!contact->visible)
			continue;
		info_item_add(&info, entity(contact->mu)->name);
	}
	info_item_done(&info, false);

	info.title = "Group contacts (private)";
	// let count accumulate

	MOWGLI_ITER_FOREACH(n, p->contacts.head)
	{
		struct project_contact *contact = n->data;
		if (contact->secondary)
			continue;
		if (contact->visible)
			continue;
		info_item_add(&info, entity(contact->mu)->name);
	}
	info_item_done(&info, false);

	if (!info.count)
		command_success_nodata(si, _("Group contacts: (none)"));

	info.title = "Secondary contacts (public)";
	info.count = 0;

	MOWGLI_ITER_FOREACH(n, p->contacts.head)
	{
		struct project_contact *contact = n->data;
		if (!contact->secondary)
			continue;
		if (!contact->visible)
			continue;
		info_item_add(&info, entity(contact->mu)->name);
	}
	info_item_done(&info, false);

	info.title = "Secondary contacts (private)";
	info.count = 0;

	MOWGLI_ITER_FOREACH(n, p->contacts.head)
	{
		struct project_contact *contact = n->data;
		if (!contact->secondary)
			continue;
		if (contact->visible)
			continue;
		info_item_add(&info, entity(contact->mu)->name);
	}
	info_item_done(&info, false);

	if (p->reginfo)
		command_success_nodata(si, _("\"See also\" displayed when registering channels: %s"), p->reginfo);

	if (p->any_may_register)
		command_success_nodata(si, _("Anyone may register channels in the project namespace"));
	else
		command_success_nodata(si, _("Only group contacts may register channels in the project namespace"));

	projectsvs->show_marks(si, p);

	command_success_nodata(si, _("*** \2End of Info\2 ***"));
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_info);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_info);
}

DECLARE_MODULE_V1
(
	"libera/projectns/info", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
