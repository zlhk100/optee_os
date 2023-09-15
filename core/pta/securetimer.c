// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023, Linaro Limited
 */

#include <kernel/pseudo_ta.h>
#include <kernel/tee_time.h>
#include <kernel/time_source.h>
#include <pta_stimer.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>

#define PTA_NAME "securetimer.pta"

static TEE_Result pta_set_stime(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result ret = TEE_SUCCESS;
	/* combined to provide ms resolution potentially */
	TEE_Time utc_ts = { 0 };

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	utc_ts.seconds = params[0].value.a;
	utc_ts.millis  = params[0].value.b;

	if (_time_source.set_offset)
		ret = _time_source.set_offset(&utc_ts);
	else
		ret = TEE_ERROR_NOT_SUPPORTED;

	return ret;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = ts_get_calling_session();

	/* Check that we're called from a user TA */
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_CMD_SET_STIME:
		return pta_set_stime(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_STIMER_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
