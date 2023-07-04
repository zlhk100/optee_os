// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2023, Linaro Limited */

#include <stdlib.h>
//#include <string.h>
//#include <stdio.h>
//#include <stdint.h>

#include <tee_internal_api.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>
#include <trace.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
// #include "common.h"

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif

static struct sock_handle {
	TEE_iSocketHandle ctx;
	TEE_iSocket *socket;
} g_sock_handle;

/*
 * Initialize a context
 */
void mbedtls_net_init( mbedtls_net_context *ctx __unused)
{
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx __unused, const char *host,
                         const char *port, int proto __unused)
{
    int ret = 0;
    struct sock_handle h = { };
    TEE_tcpSocket_Setup setup = { };
    TEE_Result res;
    uint32_t err;
    char *endptr = NULL;

#if 0
typedef struct TEE_tcpSocket_Setup_s {
	TEE_ipSocket_ipVersion ipVersion;
	char *server_addr;
	uint16_t server_port;
} TEE_tcpSocket_Setup;

TEE_Result (*open)(TEE_iSocketHandle *ctx, void *setup,
			   uint32_t *protocolError);
unsigned long strtoul (const char *s, char **ptr, int base);
#endif

    setup.ipVersion = TEE_IP_VERSION_DC;
    setup.server_port = strtoul(port, &endptr, 10);
    setup.server_addr = (char *)host; 

    h.socket = TEE_tcpSocket;
    res = h.socket->open(&h.ctx, &setup, &err);
    if (res != TEE_SUCCESS) {
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }
    g_sock_handle = h; // cache the handle for later use.   

    return( ret );
}

void mbedtls_net_usleep( unsigned long usec __unused )
{
    // TODO
}

/*
 * Read at most 'len' characters
 */
int mbedtls_net_recv( void *ctx __unused, unsigned char *buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    TEE_Result res = TEE_SUCCESS;
    uint32_t length = len; /* I/O, input buffer size and output actually received data from isocket */

#if 0
TEE_Result (*recv)(TEE_iSocketHandle ctx, void *buf, uint32_t *length,
			   uint32_t timeout);
#endif

    res = g_sock_handle.socket->recv(g_sock_handle.ctx, buf, &length, 0 /* timeout ms*/);

    if( res != TEE_SUCCESS )
    {
        ret = MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return( ret );
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout( void *ctx __unused, unsigned char *buf,
                              size_t len, uint32_t timeout )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    TEE_Result res = TEE_SUCCESS;
    uint32_t length = len; /* I/O, input buffer size and output actually received data from isocket */

    res = g_sock_handle.socket->recv(g_sock_handle.ctx, buf, &length, timeout);
    if( res != TEE_SUCCESS )
    {
        ret = MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return( ret );
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx __unused, const unsigned char *buf, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    TEE_Result res = TEE_SUCCESS;
    uint32_t length = len; /* I/O, input buffer size and output actually sent data from isocket */
#if 0
TEE_Result (*send)(TEE_iSocketHandle ctx, const void *buf,
		    uint32_t *length, uint32_t timeout);
#endif
    
    res = g_sock_handle.socket->send(g_sock_handle.ctx, buf, &length, 0);
    if( res != TEE_SUCCESS )
    {
        ret = MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return( ret );
}

void mbedtls_net_close( mbedtls_net_context *ctx __unused)
{
    g_sock_handle.socket->close(g_sock_handle.ctx);
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx __unused)
{
    g_sock_handle.socket->close(g_sock_handle.ctx);
}
