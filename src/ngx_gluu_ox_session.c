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

#include "ngx_gluu_ox_session.h"

ngx_int_t
ox_session_load(
				ngx_http_request_t 			*r,
				ngx_gluu_ox_loc_conf_t		*loc_conf,
				ngx_params_t 				*params,
				ngx_int_t					login_status,
				ngx_int_t 					authn_type )
{
	switch ( authn_type )
	{
	case TRUSTED_RP_CONNECT:
		{
			return oidc_session_load( r, loc_conf, params, login_status );
		}
	case TRUSTED_RP_UMA:
		{
			return uma_session_load( r, loc_conf, params, login_status );
		}
	}

	return NGX_DECLINED;
}

/**
 * Loading the session for openid-connect
 **/

ngx_int_t
oidc_session_load(
				ngx_http_request_t 		*r,
				ngx_gluu_ox_loc_conf_t	*loc_conf,
				ngx_params_t 			*params,
				ngx_int_t				login_status )
{
//	u_char 	*session_id = NULL;
//	u_char	*session_value = NULL;

	if( loc_conf->cookie_name.data != NULL )
		return NGX_OK;
	return NGX_ERROR;
}

/**
 * Loading the session for UMA
 **/
ngx_int_t
uma_session_load(
				ngx_http_request_t 		*r,
				ngx_gluu_ox_loc_conf_t	*loc_conf,
				ngx_params_t 			*params,
				ngx_int_t				login_status )
{	
	return NGX_OK;
}

/*
static ngx_int_t
get_session_info(
				ngx_http_request_t 		*r,
				u_char 		*cookie_name,
				u_char 		**session_key,
				u_char 		**session_value )
{
	ngx_table_elt_t		*cookie;

	if( ngx_http_process_cookie( r, cookie ) == NGX_ERROR )
		return NGX_ERROR;

	

}
*/

ngx_int_t
ngx_http_process_cookie(
					ngx_http_request_t 		*r,
					ngx_table_elt_t			*h )
{
	ngx_table_elt_t		**cookie;
	ngx_array_t 		*headers;

	headers = (ngx_array_t *)&r->headers_in.cookies;

	if( headers->elts == NULL ) {
		if( ngx_array_init( headers, r->pool, 1, sizeof( ngx_table_elt_t * ) ) != NGX_OK )
			return NGX_ERROR;
	}

	cookie = ngx_array_push( headers );

	if( cookie ) {
		*cookie = h;
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, " Success ngx_http_process_cookie function.\n" );
		return NGX_OK;
	}

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, " Fail ngx_http_process_cookie function. \n" );

	return NGX_ERROR;
}

