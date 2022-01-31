#include "lc-compat.h"
#include "atheme.h"
#ifdef NEED_OLD_COMPAT_INCLUDES
#include "pmodule.h"
#endif

void (*old_encap_handler)(sourceinfo_t *, int, char *[]) = 0;

static void encap_handler(sourceinfo_t *si, int parc, char *parv[])
{
    if (!irccasecmp(parv[1], "SASLFAIL"))
    {
	if (parc < 6) return;
	slog(LG_CMD_REQUEST, "SASL login failure by %s from %s(%s)", parv[2], parv[5], parv[6]);
    }
    if (old_encap_handler)
	old_encap_handler(si, parc, parv);
}

static void mod_init(module_t *m)
{
    pcommand_t *old_encap = pcommand_find("ENCAP");
    if (old_encap) old_encap_handler = old_encap->handler;
    pcommand_delete("ENCAP");
    pcommand_add("ENCAP", encap_handler, 2, MSRC_USER | MSRC_SERVER);
}

static void mod_deinit(module_unload_intent_t intentvoid)
{
    pcommand_delete("ENCAP");
    if (old_encap_handler) pcommand_add("ENCAP", old_encap_handler, 2, MSRC_USER | MSRC_SERVER);
}

DECLARE_MODULE_V1 (
	"libera/log_sasl_fail", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "libera chat <https://libera.chat>"
);
