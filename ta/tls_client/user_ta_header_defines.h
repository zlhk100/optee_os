/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2018, Linaro Limited */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_tls_client.h>

#define TA_UUID TA_TLS_CLIENT_UUID

#define TA_FLAGS		(TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE		(32 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#define TA_DESCRIPTION          "TLS Client trusted application"

#endif /* USER_TA_HEADER_DEFINES_H */
