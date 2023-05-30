// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2023, Linaro Limited */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <string.h>
#include <util.h>

#include <ta_tls_client.h>
#include <tee_ta_api.h>
#include <trace.h>

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
				    TEE_Param pParams[4],
				    void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	(void)pSessionContext;

	switch (nCommandID) {
#ifdef CFG_TA_MBEDTLS
	case TA_TLS_CLIENT_CMD_CONNECT_SVR:
		return ta_entry_mbedtls_connect_svr(nParamTypes, pParams);
	case TA_CRYPT_CMD_MBEDTLS_CHECK_CERT:
		return ta_entry_mbedtls_check_cert(nParamTypes, pParams);
	case TA_CRYPT_CMD_MBEDTLS_SIGN_CERT:
		return ta_entry_mbedtls_sign_cert(nParamTypes, pParams);
#endif

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

