/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Gluu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 **/

#include <libmemcached/memcached.h>

#include "ngx_http_gluu_ox_module.h"

/*
static 
memcached_server_st 	*servers = NULL;
*/
static 
memcached_st 		*memc;


#define UNTIL 	3600


ngx_int_t
ngx_gluu_ox_memcached_init( 
					ngx_str_t 	cfg_host,
					ngx_int_t  	cfg_port ) {

	int 	port;
	const char 	*host;

	memcached_return 	rc;

	memc = memcached_create( NULL );

	/* Connection settings */
	memcached_behavior_set( memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1 );
	memcached_behavior_set( memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 1 );

	host = cfg_host.len == 0 ? "localhost" : (char *)cfg_host.data;
	port = cfg_port == 0 ? 11211 : cfg_port;

/*
	servers = memcached_server_list_append( memc, host, port, &rc );
	rc = memcached_server_push( memc, servers );
*/
	rc = memcached_server_add( memc, host, port );

	if( rc == MEMCACHED_SUCCESS )
		return NGX_OK;
	else
		return NGX_ERROR;
}

ngx_int_t
ngx_gluu_ox_memcached_set(
					const char 	*key,
					const char 	*value ) {
	memcached_return 	rc;

	rc = memcached_set( memc, key, strlen( key ), value, strlen( value ), ( time_t )UNTIL, ( uint32_t )0 );

	if( rc == MEMCACHED_SUCCESS )
		return NGX_OK;
	else
		return NGX_ERROR;
}

ngx_int_t
ngx_gluu_ox_memcached_set_timeout( 
					const char 		*key,
					const char 		*value,
					unsigned int 	timeout ) {
	memcached_return 	rc;

	rc = memcached_set( memc, key, strlen( key ), value, strlen( value ), ( time_t )timeout, ( uint32_t )0 );

	if( rc == MEMCACHED_SUCCESS )
		return NGX_OK;
	else
		return NGX_ERROR;
}

char *
ngx_gluu_ox_memcached_get(
					const char *key ) {
	memcached_return 	rc;
	char 		*result;
	size_t 		len;
	uint32_t	flag;

	result = memcached_get( memc, key, strlen( key ), &len, &flag, &rc );

	if( rc == MEMCACHED_SUCCESS )
		return result;
	else
		return NULL;
}

ngx_int_t
ngx_gluu_ox_memcached_delete(
					const char 	*key ) {
	memcached_return 	rc;

	rc = memcached_delete( memc, key, strlen( key ), ( time_t )100 );

	if( rc == MEMCACHED_SUCCESS )
		return NGX_OK;
	else
		return NGX_ERROR;
}

void
ngx_http_memcached_destroy( void ) {
	memcached_free( memc );
}

