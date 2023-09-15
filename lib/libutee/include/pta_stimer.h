/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, Linaro
 */
#ifndef __PTA_STIMER_H
#define __PTA_STIMER_H

#include <tee_api_types.h>

#define PTA_STIMER_UUID { 0xd5515274, 0x5415, 0x41fa, \ 
		{ 0x8f, 0x07, 0x8d, 0x2a, 0x33, 0x4d, 0x2d, 0xf3} }

#define PTA_STIMER_INFO_VERSION		0x1

/*
 * PTA_CMD_SET_STIME - Set time from Remote Timer Server
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_SET_STIME		0x2

#endif /* __PTA_STIMER_H */
