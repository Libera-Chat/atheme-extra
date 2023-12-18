/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Hooks into existing functionality
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static bool register_require_namespace;
static char *register_require_namespace_exempt;
static char *register_project_advice;

static void userinfo_hook(hook_user_req_t *hdata)
{
	bool priv = has_priv(hdata->si, PRIV_PROJECT_AUSPEX);

	if (hdata->si->smu == hdata->mu || priv)
	{
		mowgli_node_t *n;
		mowgli_list_t *plist = projectsvs->myuser_get_projects(hdata->mu);
		MOWGLI_ITER_FOREACH(n, plist->head)
		{
			struct project_contact *contact = n->data;
			struct projectns *project = contact->project;

			const char *format, *format_empty;

			if (contact->visible)
			{
				if (contact->secondary)
				{
					format       = "Secondary contact (public) for %s (%s)";
					format_empty = "Secondary contact (public) for %s";
				}
				else
				{
					format       = "Group contact (public) for %s (%s)";
					format_empty = "Group contact (public) for %s";
				}
			}
			else
			{
				if (contact->secondary)
				{
					format       = "Secondary contact for %s (%s)";
					format_empty = "Secondary contact for %s";
				}
				else
				{
					format       = "Group contact for %s (%s)";
					format_empty = "Group contact for %s";
				}
			}

			mowgli_node_t *n2;
			char buf[BUFSIZE] = "";

			bool channels_need_separator = false;

			if (priv && project->marks.head != NULL)
			{
				mowgli_strlcpy(buf, _("\2MARKED\2"), sizeof buf);
				channels_need_separator = true;
			}

			bool cloaks_need_separator = channels_need_separator;
			MOWGLI_ITER_FOREACH(n2, project->channel_ns.head)
			{
				if (strlen(buf) > 80)
				{
					command_success_nodata(hdata->si, format, project->name, buf);
					buf[0] = '\0';
					channels_need_separator = false;
				}
				if (buf[0])
				{
					if (channels_need_separator)
					{
						mowgli_strlcat(buf, "; ", sizeof buf);
						channels_need_separator = false;
					}
					else
					{
						mowgli_strlcat(buf, ", ", sizeof buf);
					}
				}
				mowgli_strlcat(buf, (const char*)n2->data, sizeof buf);
				cloaks_need_separator = true;
			}

			MOWGLI_ITER_FOREACH(n2, project->cloak_ns.head)
			{
				if (strlen(buf) > 80)
				{
					command_success_nodata(hdata->si, format, project->name, buf);
					buf[0] = '\0';
					cloaks_need_separator = false;
				}
				if (buf[0])
				{
					if (cloaks_need_separator)
					{
						mowgli_strlcat(buf, "; ", sizeof buf);
						cloaks_need_separator = false;
					}
					else
					{
						mowgli_strlcat(buf, ", ", sizeof buf);
					}
				}

				char ns[BUFSIZE];
				snprintf(ns, sizeof ns, "%s/*", (const char*)n2->data);
				mowgli_strlcat(buf, ns, sizeof buf);
			}

			if (buf[0])
				command_success_nodata(hdata->si, format, project->name, buf);
			else
				command_success_nodata(hdata->si, format_empty, project->name);
		}
	}
}

static void chaninfo_hook(hook_channel_req_t *hdata)
{
	char *namespace = NULL;
	struct projectns *p = projectsvs->channame_get_project(hdata->mc->name, &namespace);

	bool priv = has_priv(hdata->si, PRIV_PROJECT_AUSPEX);

	if (p)
	{
		mowgli_node_t *n;
		bool is_gc = false;
		MOWGLI_ITER_FOREACH(n, p->contacts.head)
		{
			struct project_contact *contact = n->data;
			if (hdata->si->smu == contact->mu)
			{
				is_gc = true;
				break;
			}
		}

		bool marked = p->marks.head != NULL;
		if (marked && priv)
			command_success_nodata(hdata->si, _("The \2%s\2 namespace is registered to the \2%s\2 project (\2MARKED\2)"), namespace, p->name);
		else
			command_success_nodata(hdata->si, _("The \2%s\2 namespace is registered to the \2%s\2 project"), namespace, p->name);

		char buf[BUFSIZE] = "";

		MOWGLI_ITER_FOREACH(n, p->contacts.head)
		{
			struct project_contact *c = n->data;
			if (!c->visible)
				continue;

			if (strlen(buf) > 80)
			{
				command_success_nodata(hdata->si, _("Public contacts: %s"), buf);
				buf[0] = '\0';
			}
			if (buf[0])
				mowgli_strlcat(buf, ", ", sizeof buf);
			mowgli_strlcat(buf, entity(c->mu)->name, sizeof buf);

			if (priv && c->secondary)
				mowgli_strlcat(buf, _(" (secondary)"), sizeof buf);
		}

		if (buf[0])
			command_success_nodata(hdata->si, _("Public contacts: %s"), buf);

		if (priv || is_gc)
		{
			buf[0] = '\0';
			MOWGLI_ITER_FOREACH(n, p->contacts.head)
			{
				struct project_contact *c = n->data;
				if (c->visible)
					continue;

				if (strlen(buf) > 80)
				{
					command_success_nodata(hdata->si, _("Unlisted contacts: %s"), buf);
					buf[0] = '\0';
				}
				if (buf[0])
					mowgli_strlcat(buf, ", ", sizeof buf);
				mowgli_strlcat(buf, entity(c->mu)->name, sizeof buf);

				if (priv && c->secondary)
					mowgli_strlcat(buf, _(" (secondary)"), sizeof buf);
			}

			if (buf[0])
				command_success_nodata(hdata->si, _("Unlisted contacts: %s"), buf);
		}
	}

	free(namespace);
}

static void try_register_hook(hook_channel_register_check_t *hdata)
{
	char *namespace = NULL;
	struct projectns *project = projectsvs->channame_get_project(hdata->name, &namespace);

	if (register_require_namespace && !project && match(register_require_namespace_exempt, hdata->name))
	{
		hdata->approved = 1;
		command_fail(hdata->si, fault_noprivs, _("The given channel name is not registered to any project, so you cannot use it."));
		if (register_project_advice)
			command_fail(hdata->si, fault_noprivs, "%s", register_project_advice);
	}
	else if (project && !project->any_may_register)
	{
		mowgli_node_t *n;
		bool is_gc = false;
		MOWGLI_ITER_FOREACH(n, project->contacts.head)
		{
			struct project_contact *contact = n->data;
			if (hdata->si->smu == contact->mu)
			{
				is_gc = true;
				break;
			}
		}

		if (!is_gc)
		{
			hdata->approved = 1;
			command_fail(hdata->si, fault_noprivs, _("The \2%s\2 namespace is registered to the \2%s\2 project, so only authorized contacts may register new channels."), namespace, project->name);
			if (project->reginfo)
				command_fail(hdata->si, fault_noprivs, _("See %s for more information."), project->reginfo);
		}
	}

	free(namespace);
}

static void did_register_hook(hook_channel_req_t *hdata)
{
	char *namespace = NULL;
	struct projectns *project = projectsvs->channame_get_project(hdata->mc->name, &namespace);

	if (project && hdata->si->su)
	{
		mowgli_node_t *n;
		MOWGLI_ITER_FOREACH(n, project->contacts.head)
		{
			const struct project_contact *const contact = n->data;

			myuser_notice(projectsvs->me->nick, contact->mu, "The user \2%s\2 (account name \2%s\2) has "
			              "registered the channel \2%s\2 which is within the namespace (\2%s\2) of a "
			              "project that you are a group contact for (\2%s\2)", hdata->si->su->nick,
			              entity(hdata->si->smu)->name, hdata->mc->name, namespace, project->name);
		}
	}

	if (project)
	{
		command_success_nodata(hdata->si, _("The \2%s\2 namespace is managed by the \2%s\2 project."), namespace, project->name);
		if (project->reginfo)
			command_success_nodata(hdata->si, _("See %s for more information."), project->reginfo);
	}

	free(namespace);
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;

	hook_add_user_info(userinfo_hook);
	hook_add_channel_info(chaninfo_hook);
	hook_add_channel_can_register(try_register_hook);
	hook_add_channel_register(did_register_hook);

	add_bool_conf_item("REGISTER_REQUIRE_NAMESPACE", &projectsvs->me->conf_table, 0, &register_require_namespace, false);
	add_dupstr_conf_item("REGISTER_REQUIRE_NAMESPACE_EXEMPT", &projectsvs->me->conf_table, 0, &register_require_namespace_exempt, NULL);
	add_dupstr_conf_item("REGISTER_PROJECT_ADVICE", &projectsvs->me->conf_table, 0, &register_project_advice, NULL);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	hook_del_user_info(userinfo_hook);
	hook_del_channel_info(chaninfo_hook);
	hook_del_channel_can_register(try_register_hook);
	hook_del_channel_register(did_register_hook);

	del_conf_item("REGISTER_REQUIRE_NAMESPACE", &projectsvs->me->conf_table);
	del_conf_item("REGISTER_REQUIRE_NAMESPACE_EXEMPT", &projectsvs->me->conf_table);
	del_conf_item("REGISTER_PROJECT_ADVICE", &projectsvs->me->conf_table);
}

DECLARE_MODULE_V1
(
	"libera/projectns/hooks", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
