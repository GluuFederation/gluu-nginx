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

#ifndef __NGX_GLUU_OX_SESSION_H__
#define __NGX_GLUU_OX_SESSION_H__

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_http.h>
 #include <ngx_inet.h>
 #include <nginx.h>

 #include "ngx_gluu_ox_config.h"
 #include "ngx_http_gluu_ox_module.h"
 #include "ngx_gluu_ox_utils.h"

ngx_int_t
ox_session_load(
				ngx_http_request_t 			*r,
				ngx_gluu_ox_loc_conf_t		*loc_conf,
				ngx_params_t 				*params,
				ngx_int_t					login_status,
				ngx_int_t 					authn_type );
/**
 * Loading the session for openid-connect
 **/
ngx_int_t
oidc_session_load(
				ngx_http_request_t 		*r,
				ngx_gluu_ox_loc_conf_t	*loc_conf,
				ngx_params_t 			*params,
				ngx_int_t				login_status );

/**
 * Loading the session for UMA
 **/
ngx_int_t
uma_session_load(
				ngx_http_request_t 		*r,
				ngx_gluu_ox_loc_conf_t	*loc_conf,
				ngx_params_t 			*params,
				ngx_int_t				login_status );

ngx_int_t
ngx_http_process_cookie(
					ngx_http_request_t 		*r,
					ngx_table_elt_t			*h );
/**
 * If exist or put in session id string, getting session id from cookie, 
 * return if no exist a cookie with given name
 **/
/*static ngx_int_t
get_session_info(
				ngx_http_request_t 		*r,
				char 					*cookie_name,
				char 					*session_key,
				char 					*session_value );
*/
#endif