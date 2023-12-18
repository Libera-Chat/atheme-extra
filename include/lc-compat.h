/*
 * Copyright (c) 2019 Nicole Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Various compatibility features to keep things working with
 * Atheme 7.2 and Atheme 7.3 for now. Can go once we are
 * using 7.3 exclusively.
 */

#ifndef ATHEME_LIBERA_COMPAT_H
#define ATHEME_LIBERA_COMPAT_H

#include <atheme.h>

// Atheme 7.2 used typedefs ending in _t for various structures.
// Such type names are reserved by POSIX and Atheme 7.3 simply
// uses "struct typename" instead of a "typename_t" typedef.
// For now, redeclare the typedef names if we are building
// against 7.3 until we no longer need to support 7.2.
#if CURRENT_ABI_REVISION >= 730000U

#define COMPAT_TYPEDEF(t, tag) typedef t tag tag ## _t;

COMPAT_TYPEDEF(struct, chanacs)
COMPAT_TYPEDEF(struct, channel)
COMPAT_TYPEDEF(enum,   cmd_faultcode)
COMPAT_TYPEDEF(struct, command)
COMPAT_TYPEDEF(struct, database_handle)
COMPAT_TYPEDEF(struct, hook_channel_acl_req)
COMPAT_TYPEDEF(struct, hook_channel_register_check)
COMPAT_TYPEDEF(struct, hook_channel_req)
COMPAT_TYPEDEF(struct, hook_channel_succession_req)
COMPAT_TYPEDEF(struct, hook_user_req)
COMPAT_TYPEDEF(struct, metadata)
COMPAT_TYPEDEF(enum,   module_unload_intent)
COMPAT_TYPEDEF(struct, module)
COMPAT_TYPEDEF(struct, mychan)
COMPAT_TYPEDEF(struct, myentity_iteration_state)
COMPAT_TYPEDEF(struct, myentity)
COMPAT_TYPEDEF(struct, mynick)
COMPAT_TYPEDEF(struct, myuser)
COMPAT_TYPEDEF(struct, service)
COMPAT_TYPEDEF(struct, sourceinfo)
COMPAT_TYPEDEF(struct, user)

#undef COMPAT_TYPEDEF

// A few types were also given better names
typedef struct atheme_object object_t;
typedef struct proto_cmd pcommand_t;

#else // Atheme abirev < 7.3

// A few of our modules require certain include files that were not included by atheme.h
// in 7.2, so make sure to include them if we're not on 7.3
// We can't just blindly include e.g. pmodule.h as it moved to atheme/pmodule.h in 7.3
#define NEED_OLD_COMPAT_INCLUDES

#endif // Atheme abirev check

// MODTYPE_FAIL was renamed to MODFLAG_FAIL;
// this makes sure we don't explode building against
// pre-rename Atheme
#ifndef MODFLAG_FAIL
#define MODFLAG_FAIL MODTYPE_FAIL
#endif

#endif
