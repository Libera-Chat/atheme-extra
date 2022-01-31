/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Commands to manage channel namespaces
 */

#include "lc-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_channel(sourceinfo_t *si, int parc, char *parv[]);

command_t ps_channel = { "CHANNEL", N_("Manages project channel namespaces."), PRIV_PROJECT_ADMIN, 4, cmd_channel, { .path = "libera/project_channel" } };

static void cmd_channel(sourceinfo_t *si, int parc, char *parv[])
{
	char *project   = parv[0];
	char *mode      = parv[1];
	char *namespace = parv[2];
	char *trailing  = parv[3];

	enum {
		CHANNS_BAD = 0,
		CHANNS_ADD,
		CHANNS_DEL,
	} add_or_del = CHANNS_BAD;

	if (mode)
	{
		if (strcasecmp(mode, "ADD") == 0)
			add_or_del = CHANNS_ADD;
		else if (strcasecmp(mode, "DEL") == 0)
			add_or_del = CHANNS_DEL;
	}

	if (!namespace || !add_or_del || trailing)
	{
		cmd_faultcode_t fault = (namespace ? fault_badparams : fault_needmoreparams);

		if (fault == fault_badparams)
			command_fail(si, fault, STR_INVALID_PARAMS, "CHANNEL");
		else
			command_fail(si, fault, STR_INSUFFICIENT_PARAMS, "CHANNEL");
		command_fail(si, fault, _("Syntax: CHANNEL <project> ADD|DEL <#namespace>"));
		return;
	}

	// Only check for new namespaces, in case we have bad entries from a previous configuration
	// as we wouldn't be able to delete them otherwise
	if (add_or_del == CHANNS_ADD)
	{
		for (char *c = namespace; *c; c++)
		{
			if (!isprint(*c))
			{
				// Don't echo it back, since non-printables might mess with the output
				command_fail(si, fault_badparams, _("The provided channel name contains invalid characters."));
				return;
			}
		}

		if (namespace[0] != '#' || strlen(namespace) >= CHANNELLEN)
		{
			command_fail(si, fault_badparams, _("\2%s\2 is not a valid channel name."), namespace);
			return;
		}
	}

	struct projectns *p = projectsvs->project_find(project);

	if (!p)
	{
		command_fail(si, fault_nosuch_target, _("The project \2%s\2 does not exist."), project);
		return;
	}

	struct projectns *chan_p = mowgli_patricia_retrieve(projectsvs->projects_by_channelns, namespace);
	if (chan_p && add_or_del == CHANNS_ADD)
	{
		command_fail(si, fault_alreadyexists, _("The \2%s\2 namespace already belongs to project \2%s\2."), namespace, chan_p->name);
		return;
	}
	if (!chan_p && add_or_del == CHANNS_DEL)
	{
		command_fail(si, fault_nochange, _("The \2%s\2 namespace is not registered to any project."), namespace);
		return;
	}

	if (add_or_del == CHANNS_DEL)
	{
		if (chan_p != p)
		{
			command_fail(si, fault_nosuch_key, _("The \2%s\2 namespace is registered to project \2%s\2, but you tried to remove it from project \2%s\2."), namespace, chan_p->name, p->name);
			return;
		}

		mowgli_patricia_delete(projectsvs->projects_by_channelns, namespace);

		mowgli_node_t *n, *tn;
		MOWGLI_ITER_FOREACH_SAFE(n, tn, chan_p->channel_ns.head)
		{
			const char *ns = n->data;
			if (irccasecmp(ns, namespace) == 0)
			{
				free(n->data);

				mowgli_node_delete(n, &chan_p->channel_ns);
				mowgli_node_free(n);

				break;
			}
		}

		logcommand(si, CMDLOG_ADMIN, "PROJECT:CHANNEL:DEL: \2%s\2 from \2%s\2", namespace, chan_p->name);
		command_success_nodata(si, _("The namespace \2%s\2 was unregistered from project \2%s\2."), namespace, chan_p->name);
	}
	else // CHANNS_ADD
	{
		/* We've checked above that this namespace isn't already registered */
		mowgli_patricia_add(projectsvs->projects_by_channelns, namespace, p);
		mowgli_node_add(sstrdup(namespace), mowgli_node_create(), &p->channel_ns);

		logcommand(si, CMDLOG_ADMIN, "PROJECT:CHANNEL:ADD: \2%s\2 to \2%s\2", namespace, p->name);
		command_success_nodata(si, _("The namespace \2%s\2 was registered to project \2%s\2."), namespace, p->name);
	}
}

static void mod_init(module_t *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_channel);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_channel);
}

DECLARE_MODULE_V1
(
	"libera/projectns/channel", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
