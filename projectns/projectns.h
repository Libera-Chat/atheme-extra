/*
 * Copyright (c) 2018 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Header for modules accessing projectns/main symbols
 */

#ifndef PROJECTNS_H
#define PROJECTNS_H

#include "lc-compat.h"
#include "atheme.h"
#include "projectns_common.h"

struct projectsvs *projectsvs;

#define MAIN_MODULE "libera/projectns/main"

static inline void projectns_main_symbol_impl(module_t *m)
{
	void **tmp;
	unsigned int *abirev;
	MODULE_TRY_REQUEST_SYMBOL(m, abirev, MAIN_MODULE, "projectns_abirev");
	if (*abirev != PROJECTNS_ABIREV)
	{
		slog(LG_ERROR, "use_projectns_main_symbols(): \2%s\2: projectns ABI revision mismatch (%u != %u), please recompile.", m->name, PROJECTNS_ABIREV, *abirev);
		m->mflags = MODFLAG_FAIL;
		return;
	}

	MODULE_TRY_REQUEST_SYMBOL(m, projectsvs, MAIN_MODULE, "projectsvs");
}

// needed because MODULE_TRY_REQUEST_SYMBOL will "return" on our behalf
static inline bool use_projectns_main_symbols(module_t *m)
{
	projectns_main_symbol_impl(m);
	return m->mflags != MODFLAG_FAIL;
}

#endif
