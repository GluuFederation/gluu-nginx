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

 #ifndef _NGX_HTTP_GLUU_OX_MODULE_
 #define _NGX_HTTP_GLUU_OX_MODULE_

 #include <ngx_config.h>
 #include <ngx_core.h>
 #include <ngx_http.h>
 #include <ngx_inet.h>
 #include <nginx.h>

 #include "ngx_gluu_ox_utils.h"


/* authentication mode */
#define TRUSTED_RP_NONE		0
#define TRUSTED_RP_CONNECT	1
#define TRUSTED_RP_UMA		2
//#define	TRUSTED_RP_SAML		3

/* flags for send_headers */
enum {
	SETNONE	= -1,
	SETOFF	= 0,
	SETON = 1
};

/* return values for predefined URL */
enum {
	NONE_PREDEFINED,
	ADMIN_PREDEFINED,
	LOGIN_PREDEFINED,
	LOGOUT_PREDEFINED
};

/* UMA config variables */
 typedef struct {
 	ngx_str_t	host;
 	ngx_str_t	scope[5];
 }ngx_gluu_uma_host_config;

typedef struct {
// 	ngx_http_complex_value_t	realm;
// 	ngx_http_complex_value_t	user_file;
 	ngx_str_t	authn_type;
 	ngx_str_t	cookie_path;
 	ngx_str_t	app_dest_url;
 	ngx_str_t	client_credits_path;
 	ngx_flag_t	send_headers;

 	/* Only valid if authn_type is SAML method(Optional) */
// 	ngx_str_t	SAML_redirect_url;

 	/* oxd configuration */
 	ngx_str_t	oxd_host;
 	ngx_int_t	oxd_port;

 	/* memcached*/
 	ngx_str_t	memcached_host;
 	ngx_int_t	memcached_port;

 	/* OpenID connect */
 	ngx_str_t	openid_provider;

 	/* Scope is a concatenated list of requested permissions */
 	ngx_str_t	openid_scope;
 	/* RedirectUri is used to correlate the response. It is reflected back to the site.*/
 	ngx_str_t	openid_client_redirect_uris;

 	/* Human readabile name to be registered with the Authorization Server for this website. If in doubt, use the URL for the protected folder. */
 	ngx_str_t	openid_client_name;
 	ngx_str_t	openid_request_acr;
 	ngx_str_t	opneid_response_type;

 	/* UMA */
 	ngx_str_t	uma_authorization_server;
 	ngx_str_t	uma_resource_name;
 	ngx_str_t	uma_get_scope;
 	ngx_str_t	uma_put_scope;
 	ngx_str_t	uma_post_scope;
 	ngx_str_t	uma_delete_scope;

 	/* Logout */
 	ngx_str_t	app_post_logout_url;
 	ngx_str_t	app_post_logout_redirect_url;
 	ngx_str_t	ox_logout_url;

 	ngx_str_t	admin_url;
 	ngx_str_t	uma_rs_host;
	ngx_gluu_uma_host_config	uma_am_host[3];
	ngx_str_t	uma_sent_user_claims;
	ngx_str_t	cookied_name;
	ngx_int_t	cookie_lifespan;
 }ngx_gluu_ox_loc_conf_t;


#include "ngx_gluu_ox_config.h"

#endif