/*
 * Copyright (c) 2018-2019 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Core functionality - Data structure management
 */

#include "fn-compat.h"
#include "main.h"

struct project_contact *contact_new(struct projectns * const p, myuser_t * const mu)
{
	mowgli_node_t *n, *tn;
	MOWGLI_ITER_FOREACH(n, p->contacts.head)
	{
		struct project_contact *other = n->data;

		if (other->mu == mu)
			return NULL;
	}

	struct project_contact *contact = smalloc(sizeof *contact);
	contact->project = p;
	contact->mu      = mu;

	mowgli_node_add(contact, &contact->myuser_n,  projectsvs.myuser_get_projects(mu));
	mowgli_node_add(contact, &contact->project_n, &p->contacts);
	return contact;
}

bool contact_destroy(struct projectns * const p, myuser_t * const mu)
{
	mowgli_list_t *mu_projects = projectsvs.myuser_get_projects(mu);
	mowgli_node_t *n, *tn;

	MOWGLI_ITER_FOREACH_SAFE(n, tn, mu_projects->head)
	{
		struct project_contact *contact = n->data;
		if (p == contact->project)
		{
			mowgli_node_delete(&contact->myuser_n,  mu_projects);
			mowgli_node_delete(&contact->project_n, &p->contacts);
			free(contact);
			return true;
		}
	}

	return false;
}

struct projectns *project_new(const char * const name)
{
	struct projectns *project = smalloc(sizeof *project);

	project->name = sstrdup(name);
	project->any_may_register = projectsvs.config.default_open_registration;

	mowgli_patricia_add(projectsvs.projects, name, project);

	return project;
}

struct projectns *project_find(const char * const name)
{
	return mowgli_patricia_retrieve(projectsvs.projects, name);
}

void project_destroy(struct projectns * const p)
{
	mowgli_patricia_delete(projectsvs.projects, p->name);

	mowgli_node_t *n, *tn;

	MOWGLI_ITER_FOREACH_SAFE(n, tn, p->contacts.head)
	{
		struct project_contact *contact = n->data;
		slog(LG_REGISTER, _("PROJECT:CONTACT:LOST: \2%s\2 from \2%s\2"), entity(contact->mu)->name, p->name);
		contact_destroy(p, contact->mu);
	}

	MOWGLI_ITER_FOREACH_SAFE(n, tn, p->channel_ns.head)
	{
		char *ns = n->data;
		mowgli_patricia_delete(projectsvs.projects_by_channelns, ns);

		free(ns);

		mowgli_node_delete(n, &p->channel_ns);
		mowgli_node_free(n);
	}
	MOWGLI_ITER_FOREACH_SAFE(n, tn, p->cloak_ns.head)
	{
		char *ns = n->data;
		mowgli_patricia_delete(projectsvs.projects_by_cloakns, ns);

		free(ns);

		mowgli_node_delete(n, &p->cloak_ns);
		mowgli_node_free(n);
	}
	MOWGLI_ITER_FOREACH_SAFE(n, tn, p->marks.head)
	{
		struct project_mark *mark = n->data;

		free(mark->setter_id);
		free(mark->setter_name);
		free(mark->mark);
		free(mark);

		mowgli_node_delete(n, &p->marks);
		mowgli_node_free(n);
	}
	free(p->name);
	free(p->reginfo);
	strshare_unref(p->creator);
	free(p);
}

static void userdelete_hook(myuser_t *mu)
{
	mowgli_list_t *l = myuser_get_projects(mu);
	mowgli_node_t *n, *tn;

	MOWGLI_ITER_FOREACH_SAFE(n, tn, l->head)
	{
		struct project_contact *contact = n->data;
		mowgli_node_delete(n, l);
		mowgli_node_delete(&contact->project_n, &contact->project->contacts);

		slog(LG_REGISTER, _("PROJECT:CONTACT:LOST: \2%s\2 from \2%s\2"), entity(mu)->name, contact->project->name);

		free(contact);
	}

	mowgli_list_free(l);
}

void init_structures(void)
{
	projectsvs.projects = mowgli_patricia_create(strcasecanon);
	projectsvs.projects_by_channelns = mowgli_patricia_create(irccasecanon);
	projectsvs.projects_by_cloakns = mowgli_patricia_create(strcasecanon);

	hook_add_myuser_delete(userdelete_hook);
}

void deinit_aux_structures(void)
{
	mowgli_patricia_destroy(projectsvs.projects_by_channelns, NULL, NULL);
	mowgli_patricia_destroy(projectsvs.projects_by_cloakns, NULL, NULL);

	hook_del_myuser_delete(userdelete_hook);
}
