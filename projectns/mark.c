/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Commands to set marks on projects
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_mark(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_mark = { "MARK", N_("Sets internal notes on projects."), PRIV_PROJECT_ADMIN, 3, cmd_mark, { .path = "libera/project_mark" } };

static unsigned int get_last_mark_id(struct projectns *p)
{
	if (!p->marks.tail)
		return 0;
	else
		return ((struct project_mark*)p->marks.tail->data)->number;
}

static void cmd_mark(sourceinfo_t *si, int parc, char *parv[])
{
	char *project = parv[0];
	char *mode    = parv[1];
	char *param   = parv[2];

	enum {
		MARK_BAD = 0,
		MARK_ADD,
		MARK_DEL,
		MARK_LIST,
	} op = MARK_BAD;

	if (mode)
	{
		if (strcasecmp(mode, "ADD") == 0)
			op = MARK_ADD;
		else if (strcasecmp(mode, "DEL") == 0)
			op = MARK_DEL;
		else if (strcasecmp(mode, "LIST") == 0)
			op = MARK_LIST;
	}

	if (!op)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "MARK");
		command_fail(si, fault_needmoreparams, _("Syntax: MARK <project> ADD|DEL|LIST <note or ID>"));
		return;
	}

	struct projectns *p = projectsvs->project_find(project);

	if (!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), project);
		return;
	}

	if (op == MARK_DEL)
	{
		if (!param)
		{
			command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "MARK");
			command_fail(si, fault_needmoreparams, _("Syntax: MARK <project> DEL <ID>"));
			return;
		}

		errno = 0;
		unsigned long num = strtoul(param, NULL, 10);

		if (errno)
		{
			command_fail(si, fault_badparams, STR_INVALID_PARAMS, "MARK");
			command_fail(si, fault_badparams, _("Syntax: MARK <project> DEL <ID>"));
			return;
		}

		bool found = false;
		mowgli_node_t *n, *tn;
		MOWGLI_ITER_FOREACH_SAFE(n, tn, p->marks.head)
		{
			struct project_mark *mark = n->data;
			if (mark->number == num)
			{
				free(mark->setter_id);
				free(mark->setter_name);
				free(mark->mark);
				free(mark);

				mowgli_node_delete(n, &p->marks);
				mowgli_node_free(n);

				found = true;
				logcommand(si, CMDLOG_ADMIN, "MARK:DEL: \2%s\2 \2%lu\2", p->name, num);
				command_success_nodata(si, _("The mark has been deleted."));

				break;
			}
		}

		if (!found)
			command_fail(si, fault_nosuch_key, _("This mark does not exist."));
	}
	else if (op == MARK_ADD)
	{
		if (!param)
		{
			command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "MARK");
			command_fail(si, fault_needmoreparams, _("Syntax: MARK <project> ADD <text>"));
			return;
		}

		struct project_mark *mark = smalloc(sizeof *mark);
		mark->number = get_last_mark_id(p) + 1;
		mark->time   = CURRTIME;
		mark->mark   = sstrdup(param);
		mark->setter_id   = sstrdup(entity(si->smu)->id);
		mark->setter_name = sstrdup(entity(si->smu)->name);

		mowgli_node_add(mark, mowgli_node_create(), &p->marks);

		command_success_nodata(si, _("\2%s\2 has been marked."), p->name);
		logcommand(si, CMDLOG_ADMIN, "MARK:ADD: \2%s\2 \2%s\2", p->name, mark->mark);
	}
	else if (op == MARK_LIST)
	{
		if (param)
		{
			command_fail(si, fault_badparams, STR_INVALID_PARAMS, "MARK");
			command_fail(si, fault_badparams, _("Syntax: MARK <project> LIST"));
			return;
		}

		command_success_nodata(si, _("Marks for project \2%s\2:"), p->name);
		projectsvs->show_marks(si, p);
		command_success_nodata(si, _("End of list."));

		logcommand(si, CMDLOG_GET, "MARK:LIST: \2%s\2", p->name);
	}
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_mark);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_mark);
}

DECLARE_MODULE_V1
(
	"libera/projectns/mark", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
