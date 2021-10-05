/*
 * Copyright (c) 2018-2019 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Core functionality - Persistence when reloading
 */

#include "lc-compat.h"
#include "main.h"

#define PERSIST_STORAGE_NAME "atheme.freenode.projectns.main.persist"

struct projectns_main_persist {
	unsigned int version;

	service_t *service;
	mowgli_patricia_t *projects;
};

void persist_save_data(void)
{
	struct projectns_main_persist *rec = smalloc(sizeof *rec);
	rec->version  = PROJECTNS_ABIREV;
	rec->service  = projectsvs.me;
	rec->projects = projectsvs.projects;

	mowgli_global_storage_put(PERSIST_STORAGE_NAME, rec);
}

bool persist_load_data(module_t *m)
{
	struct projectns_main_persist *rec = mowgli_global_storage_get(PERSIST_STORAGE_NAME);

	if (!rec)
		return true;

	// Disallow live downgrading
	if (rec->version > PROJECTNS_ABIREV)
	{
		slog(LG_ERROR, "libera/projectns/main: attempted to load data from newer module (%u > %u)", rec->version, PROJECTNS_ABIREV);
		slog(LG_ERROR, "libera/projectns/main: This module cannot be safely reloaded without restarting services");
		/* (among other things, it would cause us memory leaks as there may be pointers in the
		 * newer struct projectns that we won't know to free, plus data might be lost.
		 * Best to play it safe.)
		 */
		m->mflags = MODFLAG_FAIL;
		return false;
	}
	slog(LG_DEBUG, "libera/projectns/main: restoring pre-reload structures (old: %u; new: %u)", rec->version, PROJECTNS_ABIREV);
	projectsvs.me = rec->service;

	/* If rec->version == PROJECTNS_ABIREV, we could probably re-use rec->projects safely.
	 * However, this would mean the upgrade codepath would be separate and much less tested.
	 */

	mowgli_patricia_iteration_state_t state;
	struct projectns *old_p;

	MOWGLI_PATRICIA_FOREACH(old_p, &state, rec->projects)
	{
		mowgli_patricia_delete(rec->projects, old_p->name);
		struct projectns *new = smalloc(sizeof *new);
		memset(new, 0, sizeof *new);
		new->name = old_p->name;
		new->any_may_register = old_p->any_may_register;
		new->reginfo = old_p->reginfo;

		mowgli_patricia_add(projectsvs.projects, new->name, new);

		/* This is safe as the list metadata is copied by value;
		 * the actual list comprises nodes of strings (channel namespaces),
		 * which are still valid.
		 *
		 * We do need to restore the reverse mapping as we destroyed it
		 * on unloading due to it having pointers that would now be stale.
		 */
		new->channel_ns = old_p->channel_ns;

		// As above; mark structure only contains integers and char*
		new->marks      = old_p->marks;

		mowgli_node_t *n, *tn;
		MOWGLI_ITER_FOREACH(n, new->channel_ns.head)
		{
			mowgli_patricia_add(projectsvs.projects_by_channelns, n->data, new);
		}

		if (rec->version >= PROJECTNS_MINVER_CONTACT_OBJECT)
		{
			// the list still holds valid objects
			new->contacts = old_p->contacts;

			MOWGLI_ITER_FOREACH(n, new->contacts.head)
			{
				struct project_contact *contact = n->data;
				contact->project = new;
				// the nodes are still in their proper lists
			}
		}
		else
		{
			MOWGLI_ITER_FOREACH_SAFE(n, tn, old_p->contacts.head)
			{
				myuser_t *mu = n->data;

				mowgli_node_delete(n, &old_p->contacts);
				mowgli_node_free(n);

				struct project_contact *contact = smalloc(sizeof *contact);
				contact->project = new;
				contact->mu      = mu;

				mowgli_node_add(contact, &contact->myuser_n,  myuser_get_projects(contact->mu));
				mowgli_node_add(contact, &contact->project_n, &new->contacts);
			}
		}

		if (rec->version >= PROJECTNS_MINVER_CLOAKNS)
		{
			new->cloak_ns = old_p->cloak_ns;

			MOWGLI_ITER_FOREACH(n, new->cloak_ns.head)
			{
				mowgli_patricia_add(projectsvs.projects_by_cloakns, n->data, new);
			}
		}

		if (rec->version >= PROJECTNS_MINVER_CREATION_MD)
		{
			new->creator       = old_p->creator;
			new->creation_time = old_p->creation_time;
		}

		/* If you wish to restore anything else, it will not have been there
		 * in past versions, so you *must* check rec->version to see whether
		 * the data is present or you *will* cause a crash or worse.
		 */
		free(old_p);
	}

	// don't pass a destructor callback; we took care of everything while iterating
	mowgli_patricia_destroy(rec->projects, NULL, NULL);

	/* The comment at the end of the above block applies outside the foreach as well. */
	mowgli_global_storage_free(PERSIST_STORAGE_NAME);
	free(rec);
	// Whew, we're done.

	return true;
}
