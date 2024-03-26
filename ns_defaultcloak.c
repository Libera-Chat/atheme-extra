/*
 * Modification of code that is copyright (c) 2005-2006 William Pitcock, et al.
 *
 * Sets usercloak metadata on register and allows opers to change cloaks to the default
 */

#include "atheme.h"

// Cloak prefix, must be non-empty
#define CLOAK_PREFIX        "user/"
#define CLOAK_PREFIX_LEN    strlen(CLOAK_PREFIX)

struct setter
{
	struct sourceinfo * si;
	const char *        marker;
	bool                needs_force;
};

static uint32_t hash_iv = 0;

static void
nsdc_init_hash(void)
{
	// FNV-0 to calculate an offset that isn't the default one
	for (const char *p = CLOAK_PREFIX; *p != '\0'; p++)
	{
		hash_iv ^= (uint32_t) *p;
		hash_iv *= 16777619;
	}
}

static bool
nsdc_build_cloak(const char *const restrict accname, char *const restrict newhost, const size_t hostlen)
{
	size_t i = (CLOAK_PREFIX_LEN - 1);
	bool invalidchar = false;
	uint32_t hash = hash_iv;

	(void) mowgli_strlcpy(newhost, CLOAK_PREFIX, hostlen);

	// Search for invalid characters. This changes copying behavior
	for (const char *p = accname; *p != '\0'; p++)
	{
		if (*p == '-')
			continue;

		if (isalnum((unsigned char) *p))
			continue;

		invalidchar = true;
		break;
	}

	// Copy the cloak and calculate the hash from casefolded characters
	for (const char *p = accname; *p != '\0'; p++)
	{
		const int c = ToUpper((unsigned char) *p);

		hash ^= (uint32_t) c;
		hash *= 16777619;

		if (i >= (hostlen - 1))
			continue;

		if (isalnum(c))
		{
			newhost[++i] = *p;
		}
		else if (c == '-')
		{
			if ((! invalidchar) || (newhost[i] != '-'))
				newhost[++i] = '-';
		}
		else if (c == '_')
		{
			if (newhost[i] != '-')
				newhost[++i] = '-';
		}
	}

	// Bump i to denote the number of bytes written
	i++;

	if (i == CLOAK_PREFIX_LEN)
	{
		// Yes, you're very clever. Have an easter egg
		(void) mowgli_strlcpy(newhost + i, "...", hostlen - i);

		i += 3;
	}

	if (invalidchar)
	{
		// Fold hash value to fit in 5 digits
		hash = (hash >> 17) + (hash & 0xFFFF);

		(void) snprintf(newhost + i, hostlen - i, ":%05" PRIu32, hash);
	}
	else
		newhost[i] = '\0';

	return invalidchar;
}

static void
nsdc_change_vhost(struct myuser *const restrict mu, const char *const restrict newhost, const bool invalidchar,
                  const struct setter *const restrict setter)
{
	char timestring[16];
	mowgli_node_t *n;

	if (setter)
	{
		(void) command_success_nodata(setter->si, _("Assigned default cloak to \2%s\2."), entity(mu)->name);

		if (setter->needs_force)
		{
			(void) wallops("\2%s\2 reset vhost of the \2MARKED\2 account %s.",
			               get_oper_name(setter->si), entity(mu)->name);

			if (setter->marker)
				(void) command_success_nodata(setter->si,
				                              _("Overriding MARK placed by %s on the account %s."),
				                              setter->marker, entity(mu)->name);
			else
				(void) command_success_nodata(setter->si,
				                              _("Overriding MARK(s) placed on the account %s."),
				                              entity(mu)->name);
		}

		(void) metadata_add(mu, "private:usercloak-assigner", get_source_name(setter->si));
		(void) logcommand(setter->si, CMDLOG_ADMIN, "DEFAULTCLOAK: \2%s\2", entity(mu)->name);
	}

	(void) snprintf(timestring, sizeof timestring, "%lu", (unsigned long) time(NULL));
	(void) metadata_add(mu, "private:usercloak-timestamp", timestring);
	(void) metadata_add(mu, "private:usercloak", newhost);

	(void) myuser_notice(nicksvs.nick, mu, "You have been given a default user cloak.");

	if (invalidchar)
		(void) myuser_notice(nicksvs.nick, mu, "Your account name cannot be used in a cloak directly. "
		                                       "To ensure uniqueness, a number was added.");

	MOWGLI_ITER_FOREACH(n, mu->logins.head)
		(void) user_sethost(nicksvs.me->me, n->data, newhost);
}

static void
nsdc_user_verify_register(struct hook_user_req *const restrict req)
{
	char newhost[HOSTLEN + 1];
	const bool cloaktype = nsdc_build_cloak(entity(req->mu)->name, newhost, sizeof newhost);

	(void) nsdc_change_vhost(req->mu, newhost, cloaktype, NULL);
}

static void
ns_cmd_defaultcloak_func(struct sourceinfo *const restrict si, const int parc, char **const restrict parv)
{
	struct setter setter = {
		.si             = si,
		.marker         = NULL,
		.needs_force    = false,
	};

	const struct metadata *md;
	bool missingforce = false;
	char newhost[HOSTLEN + 1];
	bool force = false;
	struct myuser *mu;

	if (! parv[0])
	{
		(void) command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DEFAULTCLOAK");
		(void) command_fail(si, fault_needmoreparams, _("Syntax: DEFAULTCLOAK <account> [FORCE|SHOW]"));

		return;
	}

	if (! (mu = myuser_find_ext(parv[0])))
	{
		(void) command_fail(si, fault_nosuch_target, STR_IS_NOT_REGISTERED, parv[0]);

		return;
	}

	const bool cloaktype = nsdc_build_cloak(entity(mu)->name, newhost, sizeof newhost);

	if (parv[1])
	{
		if (strcasecmp(parv[1], "SHOW") == 0)
		{
			(void) command_success_nodata(si, _("Default cloak for \2%s\2: %s"),
			                                    entity(mu)->name, newhost);

			return;
		}
		if (strcasecmp(parv[1], "FORCE") != 0)
		{
			(void) command_fail(si, fault_badparams, _("Invalid keyword \2%s\2."), parv[1]);
			(void) command_fail(si, fault_badparams, _("Syntax: DEFAULTCLOAK <account> [FORCE|SHOW]"));

			return;
		}

		force = true;
	}

	if ((md = metadata_find(mu, "private:usercloak")) && strcmp(md->value, newhost) == 0)
	{
		(void) command_fail(si, fault_nochange, _("\2%s\2 already has a default cloak."), entity(mu)->name);

		return;
	}

	// Require force for resetting your own cloak
	if (mu == si->smu && ! force)
	{
		(void) command_fail(si, fault_badparams, _("You are attempting to set your own cloak to default."));
		(void) command_fail(si, fault_badparams, _("Add %s to confirm you want to do this."), "FORCE");

		return;
	}

	// Check if force is required due to marks
	if ((md = metadata_find(mu, "private:mark:setter")))
	{
		setter.marker = md->value;
		setter.needs_force = true;
	}
	else
	{
		struct hook_user_needforce needforce_hdata = {
			.si         = si,
			.mu         = mu,
			.allowed    = 1,
		};

		(void) hook_call_user_needforce(&needforce_hdata);

		setter.needs_force = !needforce_hdata.allowed;
	}

	// Check permissions and force if required due to marks
	if (setter.needs_force)
	{
		if (! has_priv(si, PRIV_MARK))
		{
			missingforce = true;

			(void) command_fail(si, fault_noprivs, STR_NO_PRIVILEGE, PRIV_MARK);
		}
		else if (!force)
		{
			missingforce = true;

			if (setter.marker)
				(void) command_fail(si, fault_badparams, _("This operation cannot be performed on "
				                                           "%s, because the account has been marked "
				                                           "by %s."), entity(mu)->name,
				                                           setter.marker);
			else
				(void) command_fail(si, fault_badparams, _("This operation cannot be performed on %s, "
				                                           "because the account has been marked."),
				                                           entity(mu)->name);

			(void) command_fail(si, fault_badparams, _("Add %s to override this restriction."), "FORCE");
		}
	}

	if (missingforce)
	{
		if (setter.marker)
			(void) logcommand(si, CMDLOG_ADMIN, "failed DEFAULTCLOAK \2%s\2 (marked by \2%s\2)",
			                                    entity(mu)->name, setter.marker);
		else
			(void) logcommand(si, CMDLOG_ADMIN, "failed DEFAULTCLOAK \2%s\2 (marked)", entity(mu)->name);

		return;
	}

	(void) nsdc_change_vhost(mu, newhost, cloaktype, &setter);
}

static struct command ns_cmd_defaultcloak = {
	.name           = "DEFAULTCLOAK",
	.desc           = N_("Resets cloaks to default."),
	.access         = PRIV_USER_VHOST,
	.maxparc        = 2,
	.cmd            = &ns_cmd_defaultcloak_func,
	.help           = { .path = "nickserv/defaultcloak" },
};

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/vhost");

	(void) nsdc_init_hash();

	(void) hook_add_user_verify_register(&nsdc_user_verify_register);
	(void) service_named_bind_command("nickserv", &ns_cmd_defaultcloak);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	(void) hook_del_user_verify_register(&nsdc_user_verify_register);
	(void) service_named_unbind_command("nickserv", &ns_cmd_defaultcloak);
}

SIMPLE_DECLARE_MODULE_V1("freenode/ns_defaultcloak", MODULE_UNLOAD_CAPABILITY_OK)
