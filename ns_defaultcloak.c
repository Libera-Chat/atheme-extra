/*
 * Modification of code that is copyright (c) 2005-2006 William Pitcock, et al.
 *
 * Sets usercloak metadata on register and
 * allows opers to change cloaks to the default.
 */

#include "atheme.h"
#include <assert.h>
#include <stdint.h>

/* cloak prefix, must be non-empty. */
#define CLOAK_PREFIX "user/"

/* Colon, five digits, null. */
#define CLOAK_SUFFIX_LEN 7

static uint32_t hash_iv;

/* Fills "newhost" with the default cloak for the account name given by "src". */
/* `hostlen` is the length of the buffer pointed to by newhost. It must be at least 12 bytes large. */
static bool
build_cloak(char *newhost, size_t hostlen, const char *src)
{
	size_t i;
	unsigned char hash_char;
	/* FNV-1a hash */
	uint32_t hash = hash_iv;
	bool invalidchar = false;
	const size_t CLOAK_PREFIX_LEN = strlen(CLOAK_PREFIX);
	assert(hostlen >= CLOAK_SUFFIX_LEN + CLOAK_PREFIX_LEN);
	/* Safety: ^ assert ensures there's enough space. */
	strcpy(newhost, CLOAK_PREFIX);
	/* Index of the last byte written. */
	i = CLOAK_PREFIX_LEN - 1;
	/* Temporarily reduce hostlen to be the index of the last byte. */
	--hostlen;
	/* Search for invalid characters. This changes copying behavior. */
	for (const char *p = src; *p != '\0'; ++p)
	{
		if (!isalnum((unsigned char)*p) && *p != '-') {
			invalidchar = true;
			break;
		}
	}
	/* Copy the cloak and calculate the hash from casefolded characters. */
	for (; *src != '\0'; ++src)
	{
		const int c = ToUpper((unsigned char)*src);
		if (i < hostlen)
		{
			if (isalnum(c))
				newhost[++i] = *src;
			else if (c == '-')
			{
				if (!invalidchar || newhost[i] != '-')
					newhost[++i] = '-';
			}
			else if (c == '_')
			{
				if (newhost[i] != '-')
					newhost[++i] = '-';
			}
		}
		hash ^= c;
		hash *= 16777619;
	}
	/* Defensive programming assert. This should never trigger for any input. */
	assert(i <= hostlen);
	/* Change i to be the number of bytes written. */
	++i;
	/* Restore hostlen to be one past the end. */
	++hostlen;
	if (i == hostlen)
		invalidchar = true;
	else if (i == CLOAK_PREFIX_LEN)
		/* Yes, you're very clever. Have an easter egg. */
		i += snprintf(newhost + i, hostlen - i, "...");
	if (invalidchar)
	{
		if (i > hostlen - CLOAK_SUFFIX_LEN)
			i = hostlen - CLOAK_SUFFIX_LEN;
		/* Fold hash value to fit in 5 digits. */
		hash = (hash >> 17) + (hash & 0xffff);
		snprintf(newhost + i, hostlen - i, ":%05d", hash);
	}
	else
		newhost[i] = '\0';
	return invalidchar;
}

struct setter
{
	struct sourceinfo *si;
	const char *marker; /* Nullable */
	bool needs_force;
};

static void
change_vhost(struct myuser *mu, const char* newhost, bool invalidchar, struct setter *setter) {
	mowgli_node_t *n;
	struct user *u;
	char timestring[16];

	if (setter) {
		command_success_nodata(setter->si, _("Assigned default cloak to \2%s\2."), entity(mu)->name);
		if (setter->needs_force)
		{
			wallops("\2%s\2 reset vhost of the \2MARKED\2 account %s.", get_oper_name(setter->si), entity(mu)->name);
			if (setter->marker) {
				command_success_nodata(setter->si, _("Overriding MARK placed by %s on the account %s."), setter->marker, entity(mu)->name);
			} else {
				command_success_nodata(setter->si, _("Overriding MARK(s) placed on the account %s."), entity(mu)->name);
			}
		}
		logcommand(setter->si, CMDLOG_ADMIN, "DEFAULTCLOAK: \2%s\2", entity(mu)->name);
		metadata_add(mu, "private:usercloak-assigner", get_source_name(setter->si));
	}

	snprintf(timestring, 16, "%lu", (unsigned long)time(NULL));
	metadata_add(mu, "private:usercloak-timestamp", timestring);
	metadata_add(mu, "private:usercloak", newhost);
	if (nicksvs.me != NULL)
	{
		myuser_notice(nicksvs.nick, mu, "You have been given a default cloak.");
		if (invalidchar)
			myuser_notice(nicksvs.nick, mu, "Your account name cannot be used in a cloak directly. To ensure uniqueness, a number was added.");
	}
	MOWGLI_ITER_FOREACH(n, mu->logins.head)
	{
		u = n->data;
		user_sethost(nicksvs.me->me, u, newhost);
	}
}

static void
handle_verify_register(struct hook_user_req *req)
{
	char newhost[HOSTLEN + 1];
	struct myuser *mu = req->mu;
	bool cloaktype = build_cloak(newhost, sizeof newhost, entity(mu)->name);
	change_vhost(mu, newhost, cloaktype, NULL);
}

static void
ns_cmd_defaultcloak(struct sourceinfo *si, int parc, char *parv[])
{
	struct setter setter = {
		.si = si,
		.marker = NULL,
		.needs_force = false
	};
	struct myuser *mu;
	struct metadata *md;
	int cloaktype;
	char newhost[HOSTLEN + 1];
	struct hook_user_needforce needforce_hdata;
	bool force = false;
	bool missingforce = false;
	char *target = parv[0];

	/* Parse arguments. */
	if (!target)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DEFAULTCLOAK");
		command_fail(si, fault_needmoreparams, _("Syntax: DEFAULTCLOAK <account> [FORCE|SHOW]"));
		return;
	}
	if (!(mu = myuser_find_ext(target)))
	{
		command_fail(si, fault_nosuch_target, STR_IS_NOT_REGISTERED, target);
		return;
	}
	if (parv[1])
	{
		if(!strcasecmp(parv[1], "SHOW"))
		{
			build_cloak(newhost, sizeof newhost, entity(mu)->name);
			command_success_nodata(si, _("Default cloak for \2%s\2: %s"), entity(mu)->name, newhost);
			return;
		}
		else if(strcasecmp(parv[1], "FORCE"))
		{
			command_fail(si, fault_badparams, _("Invalid keyword \2%s\2."), parv[1]);
			command_fail(si, fault_badparams, _("Syntax: DEFAULTCLOAK <account> [FORCE|SHOW]"));
			return;
		}
		force = true;
	}

	/* Make default cloak, check if target already has it. */
	cloaktype = build_cloak(newhost, sizeof newhost, entity(mu)->name);
	md = metadata_find(mu, "private:usercloak");
	if (md && !strcmp(md->value, newhost))
	{
		command_fail(si, fault_nochange, _("\2%s\2 already has a default cloak."), entity(mu)->name);
		return;
	}

	/* Require force for resetting your own cloak. */
	if (!force && mu == si->smu)
	{
		command_fail(si, fault_badparams, _("You are attempting to set your own cloak to default."));
		command_fail(si, fault_badparams, _("Add %s to confirm you want to do this."), "FORCE");
		logcommand(si, CMDLOG_ADMIN, "failed DEFAULTCLOAK \2%s\2 (self)", entity(mu)->name);
		return;
	}

	/* Check if force is required due to marks. */
	if ((md = metadata_find(mu, "private:mark:setter")))
	{
		setter.needs_force = true;
		setter.marker = md->value;
	}
	else
	{
		needforce_hdata.si = si;
		needforce_hdata.mu = mu;
		needforce_hdata.allowed = 1;
		hook_call_user_needforce(&needforce_hdata);
		setter.needs_force = !needforce_hdata.allowed;
	}

	/* Check permissions and force if required due to marks. */
	if (setter.needs_force)
	{
		if (!has_priv(si, PRIV_MARK))
		{
			missingforce = true;
			command_fail(si, fault_noprivs, STR_NO_PRIVILEGE, PRIV_MARK);
		}
		else if (!force)
		{
			missingforce = true;
			if (setter.marker)
				command_fail(si, fault_badparams, _("This operation cannot be performed on %s, because the account has been marked by %s."), entity(mu)->name, setter.marker);
			else
				command_fail(si, fault_badparams, _("This operation cannot be performed on %s, because the account has been marked."), entity(mu)->name);
			command_fail(si, fault_badparams, _("Add %s to override this restriction."), "FORCE");
		}
	}
	if (missingforce)
	{
			if (setter.marker)
				logcommand(si, CMDLOG_ADMIN, "failed DEFAULTCLOAK \2%s\2 (marked by \2%s\2)", entity(mu)->name, setter.marker);
			else
				logcommand(si, CMDLOG_ADMIN, "failed DEFAULTCLOAK \2%s\2 (marked)", entity(mu)->name);
			return;
	}

	change_vhost(mu, newhost, cloaktype, &setter);
}

static struct command ns_defaultcloak = {
	.name           = "DEFAULTCLOAK",
	.desc           = N_("Resets cloaks to default."),
	.access         = PRIV_USER_VHOST,
	.maxparc        = 2,
	.cmd            = &ns_cmd_defaultcloak,
	.help           = { .path = "nickserv/defaultcloak" },
};

static void
init_hash(void)
{
	const char *p = CLOAK_PREFIX;
	/* FNV-0 to calculate an offset that isn't the default one. */
	hash_iv = 0;
	while (*p != 0)
	{
		hash_iv ^= *p++;
		hash_iv *= 16777619;
	}
}

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/vhost");
	init_hash();
	hook_add_user_verify_register(handle_verify_register);
	service_named_bind_command("nickserv", &ns_defaultcloak);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	hook_del_user_verify_register(handle_verify_register);
	service_named_unbind_command("nickserv", &ns_defaultcloak);
}

SIMPLE_DECLARE_MODULE_V1("nickserv/defaultcloak", MODULE_UNLOAD_CAPABILITY_OK)
