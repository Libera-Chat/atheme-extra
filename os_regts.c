/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Allows network staff to manipulate registration timestamps.
 */

#include "lc-compat.h"
#include "atheme.h"

static void os_cmd_regts(sourceinfo_t *si, int parc, char *parv[]);

command_t os_regts = { "REGTS", N_("Adjusts registration timestamps."), PRIV_ADMIN, 3, os_cmd_regts, { .path = "libera/os_regts" } };

static void
os_cmd_regts(sourceinfo_t *si, int parc, char *parv[])
{
	const char *type   = parv[0];
	const char *target = parv[1];
	const char *ts_str = parv[2];

	if (!ts_str)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "REGTS");
		command_fail(si, fault_needmoreparams, _("Syntax: REGTS USER|NICK|CHANNEL <target> <timestamp>"));
		return;
	}

	char *end;
	errno = 0;
	time_t newts = strtol(ts_str, &end, 10);

	if (*end || errno == ERANGE)
	{
		command_fail(si, fault_badparams, _("Please specify a valid UNIX timestamp."));
		return;
	}

	if (newts > CURRTIME)
	{
		command_fail(si, fault_badparams, _("You cannot specify a timestamp in the future."));
		return;
	}

	if (!strcasecmp(type, "USER"))
	{
		myuser_t *mu = myuser_find(target);

		if (!mu)
		{
			command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
			return;
		}

		if (mu->registered == newts)
		{
			command_fail(si, fault_nochange, _("The registration timestamp for \2%s\2 was unchanged."), entity(mu)->name);
			return;
		}

		unsigned int nicks_affected = 0;
		mowgli_node_t *n, *tn;
		MOWGLI_ITER_FOREACH(n, mu->nicks.head)
		{
			mynick_t *mn = n->data;
			if (mn->registered < newts)
			{
				logcommand(si, CMDLOG_ADMIN, "REGTS:NICK: \2%s\2 \2%ld\2 -> \2%ld\2 (adjusting to match account \2%s\2)", mn->nick, mn->registered, newts, entity(mu)->name);
				mn->registered = newts;
				nicks_affected++;
			}
		}

		logcommand(si, CMDLOG_ADMIN, "REGTS:USER: \2%s\2 \2%ld\2 -> \2%ld\2", entity(mu)->name, mu->registered, newts);
		wallops("%s changed the registration timestamp for account \2%s\2 (%ld -> %ld)", get_oper_name(si), entity(mu)->name, mu->registered, newts);
		mu->registered = newts;

		/*
		 * ircd-seven does not care about the registration timestamp on accounts,
		 * and in fact we do not send it out at all.
		 *
		 * Other protocols do care, and in fact we reject bursted logins if the
		 * registration timestamp doesn't match. In case we change this for ircd-seven
		 * or someone tries to use this with an ircd that does care, make sure
		 * we let the ircd know about the different registration timestamp.
		 *
		 * As per nickserv/set_accountname we have precedent for handling re-login
		 * as a logout followed immediately by a login. This shouldn't be strictly
		 * necessary, but whatever.
		 */
		unsigned int logins = 0;
		bool killed = false;

		MOWGLI_ITER_FOREACH_SAFE(n, tn, mu->logins.head)
		{
			user_t *u = n->data;

			slog(LG_VERBOSE, "os_cmd_regts(): ts for account %s changed, resending login data for user %s", entity(mu)->name, u->nick);
			logins++;

			if (! ircd_on_logout(u, entity(mu)->name) )
			{
				ircd_on_login(u, mu, NULL);
			}
			else
			{
				killed = true;
			}
		}

		command_success_nodata(si, _("The registration timestamp for the account \2%s\2 has been adjusted."), entity(mu)->name);

		if (logins)
		{
			if (killed)
			{
				command_success_nodata(si, ngettext(
							N_("To ensure consistency, %d user logged in as \2%s\2 has been disconnected."),
							N_("To ensure consistency, %d users logged in as \2%s\2 have been disconnected."),
							logins), logins, entity(mu)->name);
			}
			else
			{
				command_success_nodata(si, ngettext(
							N_("To ensure consistency, %d user logged in as \2%s\2 has had their login re-applied."),
							N_("To ensure consistency, %d users logged in as \2%s\2 have had their logins re-applied."),
							logins), logins, entity(mu)->name);
			}
		}

		if (nicks_affected)
		{
			command_success_nodata(si, ngettext(
						N_("Additionally, %u nick has had its registration timestamp updated."),
						N_("Additionally, %u nicks have had their registration timestamps updated."),
						nicks_affected), nicks_affected);
		}
	}
	else if (!strcasecmp(type, "NICK"))
	{
		mynick_t *mn = mynick_find(target);

		if (!mn)
		{
			command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
			return;
		}

		if (mn->registered == newts)
		{
			command_fail(si, fault_nochange, _("The registration timestamp for \2%s\2 was unchanged."), mn->nick);
			return;
		}

		if (mn->owner->registered > newts)
		{
			command_fail(si, fault_badparams, _("Individual nicks cannot be older than the account registration itself."));
			return;
		}

		logcommand(si, CMDLOG_ADMIN, "REGTS:NICK: \2%s\2 \2%ld\2 -> \2%ld\2 (account \2%s\2)", mn->nick, mn->registered, newts, entity(mn->owner)->name);
		wallops("%s changed the registration timestamp for nick \2%s\2 of account \2%s\2 (%ld -> %ld)", get_oper_name(si), mn->nick, entity(mn->owner)->name, mn->registered, newts);
		mn->registered = newts;

		command_success_nodata(si, _("The registration timestamp for the nick \2%s\2 (account \2%s\2) has been adjusted."), mn->nick, entity(mn->owner)->name);
	}
	else if (!strcasecmp(type, "CHANNEL"))
	{
		mychan_t *mc = mychan_find(target);

		if (!mc)
		{
			command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
			return;
		}

		if (mc->registered == newts)
		{
			command_fail(si, fault_nochange, _("The registration timestamp for \2%s\2 was unchanged."), mc->name);
			return;
		}

		logcommand(si, CMDLOG_ADMIN, "REGTS:CHANNEL: \2%s\2 \2%ld\2 -> \2%ld\2", mc->name, mc->registered, newts);
		wallops("%s changed the registration timestamp for channel \2%s\2 (%ld -> %ld)", get_oper_name(si), mc->name, mc->registered, newts);
		mc->registered = newts;

		command_success_nodata(si, _("The registration timestamp for the channel \2%s\2 has been adjusted."), mc->name);
	}
	else
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "REGTS");
		command_fail(si, fault_badparams, _("Syntax: REGTS USER|NICK|CHANNEL <target> <timestamp>"));
		return;
	}
}

static void
mod_init(module_t *const restrict m)
{
	service_named_bind_command("operserv", &os_regts);
}

static void
mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("operserv", &os_regts);
}

DECLARE_MODULE_V1
(
	"libera/os_regts", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	PACKAGE_STRING,
	"libera chat <https://libera.chat>"
);
