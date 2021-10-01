/*
 * Copyright (c) 2005-2016 Atheme Development Group
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Autokline channels.
 *
 * Default AKILL Time is based on the value of SET KLINETIME.
 */

#include "atheme-compat.h"

static void
klinechan_check_join(hook_channel_joinpart_t *hdata)
{
	mychan_t *mc;
	chanuser_t *cu = hdata->cu;
	service_t *svs;
	const char *khost;
	kline_t *k;

	svs = service_find("operserv");
	if (svs == NULL)
		return;

	if (cu == NULL || is_internal_client(cu->user))
		return;

	if (!(mc = mychan_from(cu->chan)))
		return;

	/* If they've already been sent a kline, do nothing */
	if (cu->user->flags & UF_KLINESENT)
		return;

	if (metadata_find(mc, "private:klinechan:closer"))
	{
		khost = cu->user->ip ? cu->user->ip : cu->user->host;
		if (has_priv_user(cu->user, PRIV_JOIN_STAFFONLY))
			notice(svs->me->nick, cu->user->nick,
					"Warning: %s klines normal users",
					cu->chan->name);
		else if (is_autokline_exempt(cu->user))
		{
			char buf[BUFSIZE];
			snprintf(buf, sizeof(buf), "Not klining *@%s due to klinechan %s (user %s!%s@%s is exempt)",
					khost, cu->chan->name,
					cu->user->nick, cu->user->user, cu->user->host);
			wallops_sts(buf);
		}
		else
		{
		        const char *reason = metadata_find(mc, "private:klinechan:reason")->value;
			slog(LG_INFO, "klinechan_check_join(): klining \2*@%s\2 (user \2%s!%s@%s\2 joined \2%s\2)",
					khost, cu->user->nick,
					cu->user->user, cu->user->host,
					cu->chan->name);

			k = kline_add("*", khost, reason, config_options.kline_time, "*");
			cu->user->flags |= UF_KLINESENT;
		}
	}
}

static void
klinechan_show_info(hook_channel_req_t *hdata)
{
	metadata_t *md;
	const char *setter, *reason;
	time_t ts;
	struct tm tm;
	char strfbuf[BUFSIZE];

	if (!has_priv(hdata->si, PRIV_CHAN_AUSPEX))
		return;
	md = metadata_find(hdata->mc, "private:klinechan:closer");
	if (md == NULL)
		return;
	setter = md->value;
	md = metadata_find(hdata->mc, "private:klinechan:reason");
	reason = md != NULL ? md->value : "unknown";
	md = metadata_find(hdata->mc, "private:klinechan:timestamp");
	ts = md != NULL ? atoi(md->value) : 0;

	tm = *localtime(&ts);
	strftime(strfbuf, sizeof strfbuf, TIME_FORMAT, &tm);

	command_success_nodata(hdata->si, "%s had \2automatic klines\2 enabled on it by %s on %s (%s)", hdata->mc->name, setter, strfbuf, reason);
}

static void
os_cmd_klinechan(sourceinfo_t *si, int parc, char *parv[])
{
	char *target = parv[0];
	char *action = parv[1];
	char *reason = parv[2];
	mychan_t *mc;

	if (!target || !action)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "KLINECHAN");
		command_fail(si, fault_needmoreparams, "Usage: KLINECHAN <#channel> <ON|OFF> [reason]");
		return;
	}

	if (!(mc = mychan_find(target)))
	{
		command_fail(si, fault_nosuch_target, STR_IS_NOT_REGISTERED, target);
		return;
	}

	if (!strcasecmp(action, "ON"))
	{
		if (!reason)
		{
			command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "KLINECHAN");
			command_fail(si, fault_needmoreparams, "Usage: KLINECHAN <#channel> ON <reason>");
			return;
		}

		if (mc->flags & CHAN_LOG)
		{
			command_fail(si, fault_noprivs, "\2%s\2 cannot be closed.", target);
			return;
		}

		if (metadata_find(mc, "private:klinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is already on autokline.", target);
			return;
		}

		metadata_add(mc, "private:klinechan:closer", si->su->nick);
		metadata_add(mc, "private:klinechan:reason", reason);
		metadata_add(mc, "private:klinechan:timestamp", number_to_string(CURRTIME));

		wallops("%s enabled automatic klines on the channel \2%s\2 (%s).", get_oper_name(si), target, reason);
		logcommand(si, CMDLOG_ADMIN, "KLINECHAN:ON: \2%s\2 (reason: \2%s\2)", target, reason);
		command_success_nodata(si, "Klining all users joining \2%s\2.", target);
	}
	else if (!strcasecmp(action, "OFF"))
	{
		if (!metadata_find(mc, "private:klinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is not closed.", target);
			return;
		}

		metadata_delete(mc, "private:klinechan:closer");
		metadata_delete(mc, "private:klinechan:reason");
		metadata_delete(mc, "private:klinechan:timestamp");

		wallops("%s disabled automatic klines on the channel \2%s\2.", get_oper_name(si), target);
		logcommand(si, CMDLOG_ADMIN, "KLINECHAN:OFF: \2%s\2", target);
		command_success_nodata(si, "No longer klining users joining \2%s\2.", target);
	}
	else
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "KLINECHAN");
		command_fail(si, fault_badparams, "Usage: KLINECHAN <#channel> <ON|OFF> [reason]");
	}
}

static void
os_cmd_listklinechans(sourceinfo_t *si, int parc, char *parv[])
{
	const char *pattern;
	mowgli_patricia_iteration_state_t state;
	mychan_t *mc;
	metadata_t *md;
	unsigned int matches = 0;

	pattern = parc >= 1 ? parv[0] : "*";

	MOWGLI_PATRICIA_FOREACH(mc, &state, mclist)
	{
		md = metadata_find(mc, "private:klinechan:closer");
		if (md == NULL)
			continue;
		if (!match(pattern, mc->name))
		{
			command_success_nodata(si, "- %-30s", mc->name);
			matches++;
		}
	}

	logcommand(si, CMDLOG_ADMIN, "LISTKLINECHANS: \2%s\2 (\2%u\2 matches)", pattern, matches);

	if (matches == 0)
		command_success_nodata(si, _("No K:line channels matched pattern \2%s\2"), pattern);
	else
		command_success_nodata(si, ngettext(N_("\2%u\2 match for pattern \2%s\2"),
						    N_("\2%u\2 matches for pattern \2%s\2"), matches), matches, pattern);
}

static command_t os_klinechan = {
	.name           = "KLINECHAN",
	.desc           = N_("Klines all users joining a channel for the duration set by SET KLINETIME."),
	.access         = PRIV_MASS_AKILL,
	.maxparc        = 3,
	.cmd            = &os_cmd_klinechan,
	.help           = { .path = "contrib/klinechan" },
};

static command_t os_listklinechans = {
	.name           = "LISTKLINECHAN",
	.desc           = N_("Lists active K:line channels."),
	.access         = PRIV_MASS_AKILL,
	.maxparc        = 1,
	.cmd            = &os_cmd_listklinechans,
	.help           = { .path = "contrib/listklinechans" },
};

static void
mod_init(module_t *const restrict m)
{
	service_named_bind_command("operserv", &os_klinechan);
	service_named_bind_command("operserv", &os_listklinechans);

	hook_add_event("channel_join");
	hook_add_first_channel_join(klinechan_check_join);

	hook_add_event("channel_info");
	hook_add_channel_info(klinechan_show_info);
}

static void
mod_deinit(const module_unload_intent_t intent)
{
	service_named_unbind_command("operserv", &os_klinechan);
	service_named_unbind_command("operserv", &os_listklinechans);

	hook_del_channel_join(klinechan_check_join);
	hook_del_channel_info(klinechan_show_info);
}

SIMPLE_DECLARE_MODULE_V1("contrib/os_klinechan", MODULE_UNLOAD_CAPABILITY_OK)
