/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * ChanServ command for contacts to claim channels
 */

#include "fn-compat.h"
#include "atheme.h"
#include "projectns.h"

static void cmd_claim(sourceinfo_t *si, int parc, char *parv[]);

command_t cs_claim = { "CLAIM", N_("Grants you access to a channel belonging to your project."), AC_AUTHENTICATED, 2, cmd_claim, { .path = "freenode/cs_claim" } };

static void cmd_claim(sourceinfo_t *si, int parc, char *parv[])
{
	char *name = parv[0];

	if (!name)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "CLAIM");
		command_fail(si, fault_needmoreparams, _("Syntax: CLAIM <channel>"));
		return;
	}

	// make sure the channel exists
	if (!channel_find(name))
	{
		command_fail(si, fault_nosuch_target, _("The channel \2%s\2 must exist in order to register it."), name);
		return;
	}

	char *namespace = NULL;
	struct projectns *p = projectsvs->channame_get_project(name, &namespace);

	if (!p)
	{
		command_fail(si, fault_noprivs, _("\2%s\2 does not belong to any registered project."), name);
		free(namespace);
		return;
	}
	else
	{
		mowgli_node_t *n;
		bool is_gc = false;
		MOWGLI_ITER_FOREACH(n, p->contacts.head)
		{
			struct project_contact *contact = n->data;
			if (si->smu == contact->mu)
			{
				is_gc = true;
				break;
			}
		}

		if (!is_gc)
		{
			command_fail(si, fault_noprivs, _("You are not an authorized group contact for the \2%s\2 namespace."), namespace);
			free(namespace);
			return;
		}
	}

	free(namespace);

	mychan_t *mc = mychan_find(name);

	unsigned int founder_flags = flags_to_bitmask(chansvs.founder_flags, 0);

	if (!mc)
	{
		logcommand(si, CMDLOG_REGISTER, "CLAIM:REGISTER: \2%s\2 for \2%s\2", name, p->name);

		mc = mychan_add(name);
		mc->registered = CURRTIME;
		mc->used = CURRTIME;
		mc->mlock_on |= (CMODE_NOEXT | CMODE_TOPIC);
		mc->mlock_off |= CMODE_LIMIT;
		mc->mlock_off |= CMODE_KEY;
		mc->flags |= config_options.defcflags;

		chanacs_add(mc, entity(si->smu), founder_flags, CURRTIME, entity(si->smu));

		if (mc->chan && mc->chan->ts > 0)
		{
			char str[21];
			snprintf(str, sizeof str, "%lu", (unsigned long)mc->chan->ts);
			metadata_add(mc, "private:channelts", str);
		}

		if (chansvs.deftemplates != NULL && *chansvs.deftemplates != '\0')
			metadata_add(mc, "private:templates",
					chansvs.deftemplates);

		command_success_nodata(si, _("\2%s\2 is now registered to \2%s\2, on behalf of the \2%s\2 project."), mc->name, entity(si->smu)->name, p->name);

		hook_channel_req_t hdata;
		hdata.si = si;
		hdata.mc = mc;
		hook_call_channel_register(&hdata);
	}
	else
	{
		/*
		 * This exposes the fact that a channel is set as a klinechan.
		 * While this isn't normally exposed, this only tells GCs,
		 * and it's usually not very hard to tell anyway given that
		 * joining the channel tends to inform you in a less courteous fashion.
		 *
		 * Besides, the alternative would be to let them claim the channel,
		 * only to get klined; or to lift the klinechan status, allowing
		 * whatever was meant to get klined to not get klined.
		 */
		if (metadata_find(mc, "private:close:closer") || metadata_find(mc, "private:klinechan:closer"))
		{
			command_fail(si, fault_noprivs, _("\2%s\2 is closed."), mc->name);
			return;
		}

		chanacs_t *ca = chanacs_open(mc, entity(si->smu), NULL, true, entity(si->smu));
		if ((ca->level & founder_flags) == founder_flags)
		{
			command_fail(si, fault_nochange, _("You already have full access to \2%s\2."), mc->name);
			return;
		}

		logcommand(si, CMDLOG_SET, "CLAIM: \2%s\2 for \2%s\2", name, p->name);
		hook_channel_acl_req_t req;
		req.ca = ca;
		req.oldlevel = ca->level;

		chanacs_modify_simple(ca, founder_flags, 0, si->smu);

		req.newlevel = ca->level;

		command_success_nodata(si, _("Full access to \2%s\2 has been granted to \2%s\2 on behalf of the \2%s\2 project."), mc->name, entity(si->smu)->name, p->name);
		verbose(mc, "Full access to \2%s\2 has been granted to \2%s\2 on behalf of the \2%s\2 project.", mc->name, entity(si->smu)->name, p->name);

		hook_call_channel_acl_change(&req);
		chanacs_close(ca);
	}
}

static void mod_init(module_t *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "chanserv/main");
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("chanserv", &cs_claim);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("chanserv", &cs_claim);
}

DECLARE_MODULE_V1
(
	"freenode/projectns/cs_claim", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "freenode <http://www.freenode.net>"
);
