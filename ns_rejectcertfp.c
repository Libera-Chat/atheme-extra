/*
 * Rejects certificate fingerprint additions unless they appear
 * to be hexadecimal SHA2-512 hashes.
 */

#include "atheme.h"

#define NETCERTFPLEN 128U

static void
rejectcertfp_user_certfp_add(struct hook_user_certfp *const restrict req)
{
	return_if_fail(req != NULL);
	return_if_fail(req->si != NULL);

	if (! req->certfp[0])
		// Another hook already rejected the fingerprint
		return;

	/* Strip colons as colon-separated hexadecimal bytes (2 characters)
	 * is the default output format of some tools like openssl-x509(1)
	 */
	(void) replace(req->certfp, sizeof req->certfp, ":", "");

	if (strlen(req->certfp) != NETCERTFPLEN)
		goto invalid;

	for (size_t i = 0; i < NETCERTFPLEN; i++)
		if (! isxdigit((unsigned char) req->certfp[i]))
			goto invalid;

	return;

invalid:
	(void) memset(req->certfp, 0x00, sizeof req->certfp);
	(void) command_fail(req->si, fault_badparams, _("Fingerprints on this network must be SHA2-512 digests "
	                                                "consisting of %u hexadecimal characters"), NETCERTFPLEN);
}

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "nickserv/cert");

	(void) hook_add_user_certfp_add(&rejectcertfp_user_certfp_add);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	(void) hook_del_user_certfp_add(&rejectcertfp_user_certfp_add);
}

SIMPLE_DECLARE_MODULE_V1("freenode/ns_rejectcertfp", MODULE_UNLOAD_CAPABILITY_OK)
