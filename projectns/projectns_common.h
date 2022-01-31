/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Common types
 */

#ifndef PROJECTNS_COMMON_H
#define PROJECTNS_COMMON_H

#include "lc-compat.h"
#include "atheme.h"

#define PRIV_PROJECT_ADMIN  "project:admin"
#define PRIV_PROJECT_AUSPEX "project:auspex"

// Arbitrary number that should avoid truncation even with various protocol overhead
#define PROJECTNAMELEN CHANNELLEN

#define PROJECTNS_ABIREV 10U

#define PROJECTNS_MINVER_CLOAKNS 4U
#define PROJECTNS_MINVER_CREATION_MD 9U
#define PROJECTNS_MINVER_CONTACT_OBJECT 10U

struct project_mark {
	time_t time;
	unsigned int number;
	char *mark;
	char *setter_id;
	char *setter_name;
};

struct projectns {
	char *name;
	bool any_may_register;
	char *reginfo;
	mowgli_list_t contacts;
	mowgli_list_t channel_ns;
	mowgli_list_t marks;
	mowgli_list_t cloak_ns;
	time_t creation_time;
	stringref creator;
};

struct project_contact {
	mowgli_node_t project_n, myuser_n;
	myuser_t *mu;
	struct projectns *project;
	bool visible;
	bool secondary;
};

struct projectsvs_conf {
	char *namespace_separators;
	bool default_open_registration;
};

struct projectsvs {
	service_t *me;
	mowgli_patricia_t *projects;
	mowgli_patricia_t *projects_by_channelns;
	mowgli_patricia_t *projects_by_cloakns;
	struct projectsvs_conf config;

	struct projectns *(*project_new)(const char *name);
	struct projectns *(*project_find)(const char *name);
	void (*project_destroy)(struct projectns *p);

	struct project_contact *(*contact_new)(struct projectns * const p, myuser_t * const mu);
	bool (*contact_destroy)(struct projectns * const p, myuser_t * const mu);

	void (*show_marks)(sourceinfo_t *si, struct projectns *p);
	bool (*is_valid_project_name)(const char *name);
	mowgli_list_t *(*myuser_get_projects)(myuser_t *mt);
	struct projectns *(*channame_get_project)(const char *name, char **out_namespace);
};

#endif
