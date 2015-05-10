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

#define MAX_BUF_SIZE 	8192


/*
 * connect to the remote host
 */
ngx_int_t
do_connect( 
			ngx_http_request_t 	*r,
			ngx_str_t 			*hostinfo ) {

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, 
									"entering do_connect function <hostinfo: %s>\n", 
									hostinfo->data );
	int 				fd;
	struct sockaddr_in 	sin;
	struct 	hostent 	*server;
	u_char 				*h_info = NULL;
	u_char 				*hostname = ngx_palloc( r->pool, sizeof(u_char *) );
	u_char 				*port = ngx_palloc( r->pool, sizeof(u_char *) );


	if( hostinfo->data == NULL || hostinfo->len == 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " Missing hostinfo" );
		return NGX_ERROR;
	}

	h_info = ngx_pstrdup( r->pool, hostinfo );

	if( h_info == NULL ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " Invalid hostinfo" );
		return NGX_ERROR;
	}

	u_char *p = (u_char *)ngx_strchr( h_info, ':');
	if( p == NULL ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " Invalid hostinfo parameter struct" );
		return NGX_ERROR;		
	}

	port = p + 1;												
	strncpy( (char *)hostname, (char *)h_info, ( p - h_info ) );

	if( hostname == NULL || port == NULL ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " Invalid hostname or port number" );
		return NGX_ERROR;
	}
	ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, " hostinfo %s:%s", hostname, port );
	server = gethostbyname( (const char *)hostname );

	if( server == NULL ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "gethostbyname failed" );
		return NGX_ERROR;
	}

	bzero( (char *)&sin, sizeof( sin ) );
	bcopy( (char *)server->h_addr, (char *)&sin.sin_addr.s_addr, server->h_length );
	sin.sin_family = AF_INET;
	sin.sin_port = htons( atoi( (char *) port) );

	fd = socket( sin.sin_family, SOCK_STREAM, 0 );

	if( fd < 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno, ngx_socket_n " failed" );
		return NGX_ERROR;
	}

	if( connect( fd, ( struct sockaddr *)&sin, sizeof( sin )) < 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_socket_errno,  "connect() failed" );
		return NGX_ERROR;
	}

	return fd;
}

ngx_int_t 
do_client_task(
				ngx_http_request_t 	*r,
				int 		 		socket, 
				u_char	 			*req_str,
				u_char 				*resp_str ) {
	ngx_int_t 	n;
	u_char 		*req = req_str;
	u_char 		*resp = resp_str;
	size_t 		len = ngx_strlen( req );

	ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "do_client_task->request: %s", req );
	ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "do_client_task->request string length: %d", len );

	n = write( socket, (char *)req, len );
	if( n < 0 ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "failed sending a discovery request." );
		close( socket );
		return NGX_ERROR;
	}

	n = read( socket, (char *)resp, MAX_BUF_SIZE );
	if ( n < 0 ){
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "failed reading a discovery request." );
		close( socket );
		return NGX_ERROR;
	}
	resp[n] = '\0';

	close( socket );

	return NGX_OK;
}

u_char * 
oxd_discovery(
				ngx_http_request_t 	*r,
				ngx_str_t 			*hostinfo,
				ngx_str_t 			*discovery_url ) {

	u_char 	*result = { 0, };
	int  	socketfd;

	u_char 	request[MAX_BUF_SIZE] = {0, };
	u_char 	response[MAX_BUF_SIZE] = {0, };

	if( ( discovery_url->data == NULL ) 
		|| ( discovery_url->len == 0 ) 
		|| ( hostinfo->data == NULL )
		|| ( hostinfo->len == 0 ) ) {
		return NULL;
	}

	socketfd = do_connect( r, hostinfo );
	if(  socketfd == NGX_ERROR ) {
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "do_connect function failed" );
		return NULL;
	}																																																																																																																																																																																																																																																																																												

	ngx_sprintf( request, "    {\"command\":\"discovery\",\"params\":{\"discovery_url\":\"https://%s/.well-known/openid-configuration\"}}", discovery_url->data );
	ngx_sprintf( &request[0], "%04lu", ngx_strlen( request ) - 4 );
	request[4] = '{';

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "discovery request string: <%s>", request );

	if( do_client_task( r, socketfd, request, response ) != NGX_OK ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, 0, "do_client_task function failed." );
		return NULL;
	}

//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "discovery request string: <%s>", response );

	if( ngx_strncmp( &response[4], "{\"status\":\"ok\"", 14 ) != 0 )
		return NULL;

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "discovery response status OK! size[%d]", ngx_strlen( response ) );

//																																																response + ngx_strlen( response ) - 1 = '\0';
	result = (u_char *)ngx_palloc( r->pool, sizeof( u_char ) *  MAX_BUF_SIZE );
	ngx_memcpy( result, response + 26, ngx_strlen( response ) - 26 + 1 );

//	ngx_memcpy( result, &response[26], ngx_strlen( &response[26] ) );
//	result[ ngx_strlen( &response[26] ) ] = '\0';
//	result = response + 27;
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "discovery request string: <%s>", *result );

	return result;
}

/*
ngx_int_t
oxd_register_client(
			ngx_http_request_t	*r;
			ngx_str_t 			*hostname,
			ngx_int_t 			portnum,
			ngx_str_t 			*discovery_url,
			ngx_str_t			*redirect_url,
			ngx_str_t 			*logout_redirect_url,
			ngx_str_t			*client_name,
			u_char 				*result ) {
	
	ngx_socket_t 	s;

	u_char 	request[BUFSIZE] = {0, };
	u_char 	response[BUFSIZE] = {0, };

	if( ( discovery_url->data == NULL ) 
		|| ( discovery_url->len == 0 ) 
		|| ( hostname->data == NULL ) 
		|| ( hostname->len == NULL ) 
		|| ( portnum < 0 ) 
		|| ( redirect_url->data == NULL ) 
		|| ( redirect_url->len == 0 )
		|| ( logout_redirect_url->data == NULL ) 
		|| ( logout_redirect_url->len == 0 )
		|| ( client_name->data == NULL ) 
		|| ( client_name->len == 0 )) {
		return NGX_ERROR;
	}

	if( do_connect( r, &s, hostname, portnum ) != NGX_OK ) {
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0,  "do_connect function failed" );
		return NGX_ERROR;
	}

	ngx_sprintf( request, "    {\"command\":\"register_client\",\"params\":{\"discovery_url\":\"https://%s/.well-known/openid-configuration\",\"redirect_url\":\"%s")

}*/