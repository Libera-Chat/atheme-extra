/*
 * Copyright (c) 2018-2019 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Core functionality - Module declaration
 */

#include "lc-compat.h"
#include "main.h"

unsigned int projectns_abirev = PROJECTNS_ABIREV;

struct projectsvs projectsvs = {
	.me = NULL,
	.project_new = project_new,
	.project_find = project_find,
	.project_destroy = project_destroy,
	.contact_new = contact_new,
	.contact_destroy = contact_destroy,
	.show_marks = show_marks,
	.is_valid_project_name = is_valid_project_name,
	.myuser_get_projects = myuser_get_projects,
	.channame_get_project = channame_get_project,
};

static void mod_init(module_t *const restrict m)
{
	init_structures();

	if (!persist_load_data(m))
		return;

	if (!projectsvs.me)
		projectsvs.me = service_add("projectserv", NULL);

	init_config();
	init_db();
}

static void mod_deinit(const module_unload_intent_t intent)
{
	persist_save_data();

	deinit_aux_structures();
	deinit_db();
	deinit_config();
}

DECLARE_MODULE_V1
(
	"libera/projectns/main", MODULE_UNLOAD_CAPABILITY_RELOAD_ONLY, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
