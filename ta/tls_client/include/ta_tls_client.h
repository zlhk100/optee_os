/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2023, Linaro Limited */

#ifndef __TA_TLS_CLIENT_H
#define __TA_TLS_CLIENT_H

/* This UUID is generated with the ITU-T UUID generator at
   http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_TLS_CLIENT_UUID { 0x03e24561, 0x9c29, 0x464f, \
                      { 0x94, 0x7b, 0x07, 0xbb, 0xe3, 0xa4, 0x30, 0x6e } }

/*
 * Create a secure connection over TCP socket
 *
 * [in]     params[0].value.a	ipVersion
 * [in]     params[0].value.b	server port
 * [in]     params[1].memref	server address
 * [out]    params[2].memref	handle
 * [out]    params[3].value.a	protocol error
 */
#define TA_TLS_CLIENT_CMD_CONNECT_SVR  0

/*
 * Opens a UDP socket
 *
 * [in]     params[0].value.a	ipVersion
 * [in]     params[0].value.b	server port
 * [in]     params[1].memref	server address
 * [out]    params[2].memref	handle
 * [out]    params[3].value.a	protocol error
 */
#define TA_TLS_CLIENT_CMD_UDP_OPEN	1

/*
 * Closes a socket
 *
 * [in]     params[0].memref	handle
 */
#define TA_TLS_CLIENT_CMD_CLOSE	2

/*
 * Send data on socket
 *
 * [in]     params[0].memref	handle
 * [in]     params[1].memref	data
 * [in]     params[2].value.a	timeout
 * [out]    params[2].value.b	sent bytes
 */
#define TA_TLS_CLIENT_CMD_SEND	3

/*
 * Receive data on socket
 *
 * [in]     params[0].memref	handle
 * [out]    params[1].memref	data
 * [in]     params[2].value.a	timeout
 */
#define TA_TLS_CLIENT_CMD_RECV	4

/*
 * Retrieve protocol error from socket
 *
 * [in]     params[0].memref	handle
 * [out]    params[1].value.a	error code
 */
#define TA_TLS_CLIENT_CMD_ERROR	5

/*
 * Ioctl on socket
 *
 * [in]     params[0].memref	handle
 * [in/out] params[1].memref	data
 * [in]     params[2].value.a	command code
 */
#define TA_TLS_CLIENT_CMD_IOCTL	6

#define TA_CRYPT_CMD_MBEDTLS_CHECK_CERT 43
#define TA_CRYPT_CMD_MBEDTLS_SIGN_CERT  44

#endif /*__TA_TLS_CLIENT_H*/

