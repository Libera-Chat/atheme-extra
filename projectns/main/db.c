/*
 * Copyright (c) 2018-2019 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Core functionality - Database handling
 */

#include "lc-compat.h"
#include "main.h"

#define DB_TYPE_PROJECT           "FNGROUP"
#define DB_TYPE_REGINFO           "FNGRI"
#define DB_TYPE_CONTACT           "FNGC"
#define DB_TYPE_CHANNEL_NAMESPACE "FNCNS"
#define DB_TYPE_CLOAK_NAMESPACE   "FNHNS"
#define DB_TYPE_MARK              "FNGM"

// Reading from the database
static void db_h_project(database_handle_t *db, const char *type)
{
	const char *name     = db_sread_word(db);
	unsigned int any_reg = db_sread_uint(db);

	struct projectns *l = smalloc(sizeof(*l));
	l->name = sstrdup(name);
	l->any_may_register = any_reg;

	mowgli_patricia_add(projectsvs.projects, l->name, l);

	time_t regts;
	if (db_read_time(db, &regts))
		l->creation_time = regts;
	else
		return;

	const char *creator = db_read_word(db);
	if (creator && strcmp(creator, "*") != 0)
		l->creator = strshare_get(creator);
	else
		return;
}

static void db_h_reginfo(database_handle_t *db, const char *type)
{
	const char *name = db_sread_word(db);
	const char *info = db_sread_str(db);

	struct projectns *project = mowgli_patricia_retrieve(projectsvs.projects, name);
	project->reginfo = sstrdup(info);
}

static void db_h_mark(database_handle_t *db, const char *type)
{
	const char *name = db_sread_word(db);
	unsigned int num = db_sread_uint(db);
	time_t time      = db_sread_time(db);

	const char *setter_id   = db_sread_word(db);
	const char *setter_name = db_sread_word(db);

	const char *text = db_sread_str(db);

	struct projectns *project = mowgli_patricia_retrieve(projectsvs.projects, name);
	struct project_mark *mark = smalloc(sizeof *mark);
	mark->number = num;
	mark->time   = time;
	mark->mark   = sstrdup(text);
	mark->setter_id   = sstrdup(setter_id);
	mark->setter_name = sstrdup(setter_name);

	mowgli_node_add(mark, mowgli_node_create(), &project->marks);
}

static void db_h_contact(database_handle_t *db, const char *type)
{
	const char *project_name = db_sread_word(db);
	const char *contact_name = db_sread_word(db);

	struct projectns *project = mowgli_patricia_retrieve(projectsvs.projects, project_name);
	myuser_t *mu = myuser_find(contact_name);

	struct project_contact *contact = smalloc(sizeof *contact);
	contact->project = project;
	contact->mu      = mu;

	mowgli_node_add(contact, &contact->myuser_n,  myuser_get_projects(mu));
	mowgli_node_add(contact, &contact->project_n, &project->contacts);

	unsigned int visible, secondary;

	if (db_read_uint(db, &visible))
		contact->visible = visible;
	else
		return;

	if (db_read_uint(db, &secondary))
		contact->secondary = secondary;
	else
		return;
}

static void db_h_channelns(database_handle_t *db, const char *type)
{
	const char *project_name = db_sread_word(db);
	const char *namespace    = db_sread_word(db);

	struct projectns *project = mowgli_patricia_retrieve(projectsvs.projects, project_name);

	mowgli_patricia_add(projectsvs.projects_by_channelns, namespace, project);
	mowgli_node_add(sstrdup(namespace), mowgli_node_create(), &project->channel_ns);
}

static void db_h_cloakns(database_handle_t *db, const char *type)
{
	const char *project_name = db_sread_word(db);
	const char *namespace    = db_sread_word(db);

	struct projectns *project = mowgli_patricia_retrieve(projectsvs.projects, project_name);

	mowgli_patricia_add(projectsvs.projects_by_cloakns, namespace, project);
	mowgli_node_add(sstrdup(namespace), mowgli_node_create(), &project->cloak_ns);
}

// Writing to the database
static void write_projects_db(database_handle_t *db)
{
	mowgli_patricia_iteration_state_t state;
	struct projectns *project;

	MOWGLI_PATRICIA_FOREACH(project, &state, projectsvs.projects)
	{
		db_start_row(db, DB_TYPE_PROJECT);
		db_write_word(db, project->name);
		db_write_uint(db, project->any_may_register);
		db_write_time(db, project->creation_time);
		db_write_word(db, project->creator);
		db_commit_row(db);

		if (project->reginfo)
		{
			db_start_row(db, DB_TYPE_REGINFO);
			db_write_word(db, project->name);
			db_write_str(db, project->reginfo);
			db_commit_row(db);
		}

		mowgli_node_t *n;
		MOWGLI_ITER_FOREACH(n, project->marks.head)
		{
			struct project_mark *mark = n->data;
			db_start_row(db, DB_TYPE_MARK);
			db_write_word(db, project->name);
			db_write_uint(db, mark->number);
			db_write_time(db, mark->time);
			db_write_word(db, mark->setter_id);
			db_write_word(db, mark->setter_name);
			db_write_str(db, mark->mark);
			db_commit_row(db);
		}

		MOWGLI_ITER_FOREACH(n, project->contacts.head)
		{
			struct project_contact *contact = n->data;
			db_start_row(db, DB_TYPE_CONTACT);
			db_write_word(db, project->name);
			db_write_word(db, ((myentity_t*)contact->mu)->name);
			db_write_uint(db, contact->visible);
			db_write_uint(db, contact->secondary);
			db_commit_row(db);
		}

		MOWGLI_ITER_FOREACH(n, project->channel_ns.head)
		{
			db_start_row(db, DB_TYPE_CHANNEL_NAMESPACE);
			db_write_word(db, project->name);
			db_write_word(db, (char*)n->data);
			db_commit_row(db);
		}

		MOWGLI_ITER_FOREACH(n, project->cloak_ns.head)
		{
			db_start_row(db, DB_TYPE_CLOAK_NAMESPACE);
			db_write_word(db, project->name);
			db_write_word(db, (char*)n->data);
			db_commit_row(db);
		}
	}
}

void init_db (void)
{
	db_register_type_handler(DB_TYPE_PROJECT, db_h_project);
	db_register_type_handler(DB_TYPE_MARK, db_h_mark);
	db_register_type_handler(DB_TYPE_REGINFO, db_h_reginfo);
	db_register_type_handler(DB_TYPE_CONTACT, db_h_contact);
	db_register_type_handler(DB_TYPE_CHANNEL_NAMESPACE, db_h_channelns);
	db_register_type_handler(DB_TYPE_CLOAK_NAMESPACE, db_h_cloakns);

	hook_add_db_write(write_projects_db);
}

void deinit_db (void)
{
	db_unregister_type_handler(DB_TYPE_PROJECT);
	db_unregister_type_handler(DB_TYPE_MARK);
	db_unregister_type_handler(DB_TYPE_REGINFO);
	db_unregister_type_handler(DB_TYPE_CONTACT);
	db_unregister_type_handler(DB_TYPE_CHANNEL_NAMESPACE);
	db_unregister_type_handler(DB_TYPE_CLOAK_NAMESPACE);

	hook_del_db_write(write_projects_db);
}
