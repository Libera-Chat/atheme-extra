/*
 * Originally called cs_successor_freenodestaff,
 * renamed to be more generic and moved to projectns/ due to now only working on registered project channels
 * Copyright (c) 2012 Marien Zwart <marien.zwart@gmail.com>.
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Forces the successor for channels in registered projects to be libera-placeholder-account
 */

#include "fn-compat.h"
#include "atheme.h"
#include "projectns.h"

static char *project_successor;

static void channel_pick_successor_hook(hook_channel_succession_req_t *req)
{
	return_if_fail(req != NULL);
	return_if_fail(req->mc != NULL);

	/* Bail out early if no successor was defined in config or if misconfigured. */
	if (project_successor == NULL || *project_successor == '=')
		return;

	/* Leave double-# channels alone. */
	if (req->mc->name[0] == '#' && req->mc->name[1] == '#')
		return;

	/* Don't override successor of channels not registered to projects. */
	if (!projectsvs->channame_get_project(req->mc->name, NULL))
		return;

	/* If myuser_find_ext returns NULL the normal successor logic is used.
	 * If some other user of this hook picked a successor
	 * we intentionally overrule it.
	 */
	req->mu = myuser_find_ext(project_successor);
}

static void mod_init(module_t *m)
{
	add_dupstr_conf_item("SUCCESSOR", &projectsvs->me->conf_table, 0, &project_successor, NULL);
	hook_add_first_channel_pick_successor(channel_pick_successor_hook);
}

static void mod_deinit(module_unload_intent_t intent)
{
	hook_del_channel_pick_successor(channel_pick_successor_hook);
	del_conf_item("SUCCESSOR", &projectsvs->me->conf_table);
}

DECLARE_MODULE_V1
(
	"freenode/projectns/cs_projectsuccessor", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "Libera Chat <https://libera.chat>"
);
