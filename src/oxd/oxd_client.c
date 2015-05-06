/* Copyright (C) 2007-2015 Gluu ()
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so. subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIBILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHERS DEALINGS IN THE SOFTWARE.
 */

#include "oxd_client.h"

#define BUFSIZE 	8192

ngx_int_t 
oxd_discovery(
				ngx_http_request_t 	*r,
				ngx_str_t 			*hostname,
				ngx_int_t 			portnum,
				ngx_str_t 			*discovery_url,
				u_char 				*result ) {
	ngx_socket_t 	s;

	u_char 	request[BUFSIZE] = {0, };
	u_char 	response[BUFSIZE] = {0, };

	if( ( discovery_url->data == NULL ) 
		|| ( discovery_url->len == 0 ) 
		|| ( hostname == NULL ) 
		|| ( portnum < 0 ) ) {
		return NGX_ERROR;
	}

	if( do_connect( r, &s, hostname, portnum ) != NGX_OK ) {
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "do_connect function failed" );
		return NGX_ERROR;
	}																																																																																																																																																																																																																																																																																												

	ngx_sprintf( request, "    {\"command\":\"discovery\",\"params\":{\"discovery_url\":\"https://%s/.well-known/openid-configuration\"}}", discovery_url->data );
	ngx_sprintf( &request[0], "%04lu", ngx_strlen( request ) - 4 );
	request[4] = '{';

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "discovery request string: <%s>", request );

	if( s == ( ngx_socket_t ) - 1 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno, ngx_socket_n " failed in oxd_discovery function" );
		return NGX_ERROR;
	}

	if( do_client_task( r, s, request, response ) != NGX_OK ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "do_client_task function failed." );
		return NGX_ERROR;
	}

	if( ngx_strncmp( &response[4], "{\"status\":\"ok\"", 14 ) != 0 )
		return NGX_ERROR;

	response[ ngx_strlen(response) - 1 ] = 0;
	result = ngx_pcalloc( r->pool, sizeof( u_char *) );
	ngx_memcpy( result, &response[26], ngx_strlen( &response[26] ) );
	result[ ngx_strlen( &response[26] ) ] = 0;

	return NGX_OK;
}

/*
 * connect to the remote host
 */
ngx_int_t
do_connect( 
			ngx_http_request_t 	*r,
			ngx_socket_t 		*s,
			ngx_str_t 			*host,
			ngx_int_t 			port ) {

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, 
									"entering do_connect function <hostname: %s, port:%d>\n", 
									host->data,
									port );
	ngx_socket_t 		fd;
	struct sockaddr_in 	sin;
//		struct hostent 		*h;

/*	sin = ngx_pcalloc( r->pool, sizeof( struct sockaddr_in ) );

	if( sin == NULL ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " failed sockaddr_in structure" );
		return NGX_ERROR;
	}*/

	if( host->data == NULL || host->len == 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " Missing host address" );
		return NGX_ERROR;
	}

	struct 	hostent *server;
	server = gethostbyname( (const char *)host->data );

	if( server == NULL ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "gethostbyname failed" );
		return NGX_ERROR;
	}

	bzero( (char *)&sin, sizeof( sin ) );
	bcopy( (char *)server->h_addr, (char *)&sin.sin_addr.s_addr, server->h_length );
	sin.sin_family = AF_INET;
//	sin.sin_addr.s_addr = ngx_inet_addr( host->data, host->len );
	sin.sin_port = htons( atoi( "8099" ) );

	fd = ngx_socket( sin.sin_family, SOCK_STREAM, 0 );

	if( fd == ( ngx_socket_t ) - 1 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno, ngx_socket_n " failed" );
		return NGX_ERROR;
	}

	if( 0 /*ngx_nonblocking( fd ) == -1 */) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno, ngx_nonblocking_n " failed" );
		return NGX_ERROR;
	}

	if( connect( fd, ( struct sockaddr *)&sin, sizeof( sin )) < 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,  "connect() failed" );
		return NGX_ERROR;
	}

	if( 0/*ngx_blocking( fd ) == -1 */) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno, ngx_blocking_n " failed" );
		return NGX_ERROR;
	}

	s = ( ngx_socket_t * )&fd;

	if( *s == ( ngx_socket_t ) - 1 )
		return NGX_ERROR;

	return NGX_OK;
}

ngx_int_t 
do_client_task(
				ngx_http_request_t 	*r,
				ngx_socket_t 		s, 
				u_char	 			*req_str,
				u_char 				*resp_str ) {
	ngx_int_t 	n;
	u_char 		*req = req_str;
	u_char 		*resp = resp_str;
	size_t 		len = ngx_strlen( req );

	ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "do_client_task->request: %s", req );
	ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "do_client_task->request string length: %d", len );

	if( send( s, req, len, 0 ) < 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "failed sending a discovery request." );
		close( s );
		return NGX_ERROR;
	}

	len = BUFSIZE;

	n = recv( ( int )s, resp, len, 0 );
	resp[n] = 0;

	close( s );

	return NGX_OK;
}