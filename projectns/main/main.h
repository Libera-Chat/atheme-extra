/*
 * Copyright (c) 2018-2019 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Shared header for projectns/main implementation
 */

#ifndef PROJECTNS_MAIN_H
#define PROJECTNS_MAIN_H

#include "lc-compat.h"
#include "../projectns_common.h"

#define MYUSER_PRIVDATA_NAME "freenode:projects"

// main.c
extern unsigned int projectns_abirev;
extern struct projectsvs projectsvs;

// config.c
void init_config(void);
void deinit_config(void);

// db.c
void init_db(void);
void deinit_db(void);

// objects.c
struct project_contact *contact_new(struct projectns * const p, myuser_t * const mu);
bool contact_destroy(struct projectns * const p, myuser_t * const mt);
struct projectns *project_new(const char * const name);
struct projectns *project_find(const char * const name);
void project_destroy(struct projectns * const p);
void init_structures(void);
void deinit_aux_structures(void);

// persist.c
void persist_save_data(void);
bool persist_load_data(module_t *m);

// util.c
bool is_valid_project_name(const char * const name);
struct projectns *channame_get_project(const char * const name, char **out_namespace);
mowgli_list_t *myuser_get_projects(myuser_t *mu);
void show_marks(sourceinfo_t *si, struct projectns *p);

#endif
