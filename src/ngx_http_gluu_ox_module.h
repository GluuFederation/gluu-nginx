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
	ngx_str_t	url;
	ngx_int_t 	refresh_internal;
	ngx_int_t	ssl_validate_server;
}ngx_gluu_ox_oidc_jwks_uri_t;

typedef struct {
	u_char 	*metadata_url;
	u_char 	*issuer;
	u_char 	*authorization_endpoint_url;
	u_char 	*token_endpoint_url;
	u_char 	*token_endpoint_auth;
	u_char 	*token_endpoint_params;
	u_char 	*userinfo_endpoint_url;
	u_char 	*registration_endpoint_url;
	u_char 	*check_session_iframe;
	u_char 	*end_session_endpoint;
	u_char 	*jwks_uri;
	u_char 	*client_id;
	u_char 	*client_secret;

	ngx_int_t 	ssl_validate_server;
	u_char 	*client_name;
	u_char 	*client_contract;
	u_char 	*registration_token;
	u_char 	*registration_endpoint_json;
	u_char 	*scope;
	u_char 	*response_type;
	u_char 	*response_mode;
	ngx_int_t	jwks_refresh_interval;
	ngx_int_t	idtoken_iat_slack;
	u_char 	*auth_request_param;
	ngx_int_t 	session_max_duration;

	u_char 	*client_jwks_uri;
	u_char 	*id_token_signed_response_alg;
	u_char 	*id_token_encrypted_response_alg;
	u_char 	*id_token_encrypted_response_enc;
	u_char 	*userinfo_signed_response_alg;
	u_char 	*userinfo_encrypted_response_alg;
	u_char 	*userinfo_encrypted_response_enc;
}ngx_gluu_ox_oidc_provider_t;

typedef struct {
 	ngx_str_t 		authn_type;

	/* RedirectUri is used to correlate the response. It is reflected back to the site.*/
 	ngx_str_t 		redirect_uris;
// 	ngx_str_t	cookie_path;
	/* indicates whether this is a derived config, merged from a base one */
	ngx_uint_t 		merged;

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
// 	ngx_str_t	openid_provider;
 	ngx_gluu_ox_oidc_provider_t		openid_provider;

 	/* Scope is a concatenated list of requested permissions */
 	ngx_str_t	openid_scope;

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
	ngx_str_t	cookie_name;
	ngx_int_t	cookie_lifespan;
 }ngx_gluu_ox_loc_conf_t;
/*
typedef struct {
	u_char 			*cookie_path;
	u_char 			*cookie;
	u_char 			*authn_header;
	ngx_int_t 		return401;
	ngx_array_t		*pass_cookies;
}
*/

typedef struct {
	ngx_pool_t 						*pool;		/* pool to be used for this session */
    ngx_str_t                       name;
    time_t                          expires_time;
    ngx_str_t                       domain;
    ngx_str_t                       path;
    ngx_http_complex_value_t        *value;
} ngx_http_cookie_loc_conf_t;




ngx_int_t
ox_utils_html_send_error( 
					ngx_http_request_t 	*r, 
					char 				*error, 
					char 				*description, 
					ngx_int_t 			status_code );

ngx_int_t 
ox_utils_html_send( 
				ngx_http_request_t 	*r,
				u_char 				*title,
				u_char 				*html_header,
				u_char 				*on_load,
				u_char 				*html_body,
				ngx_int_t 			status_code );

ngx_int_t 
ox_utils_http_send( 
				ngx_http_request_t 	*r,
				u_char				*msg,
				u_char 				*content_type,
				ngx_int_t 			success_rvalue );

/* see if the currently accessed path matches a path from a defined URL */
ngx_int_t
oidc_util_request_matchs_url(
						ngx_http_request_t 	*r,
						ngx_str_t			url );

ngx_int_t
ngx_gluu_ox_parse_url( 
				ngx_http_request_t *r,
				ngx_str_t 	*uri,
				ngx_str_t 	*args );

ngx_int_t 
utils_request_has_parameter( 
						ngx_http_request_t 	*r,
						const char 			*param );

ngx_int_t
ngx_gluu_ox_oidc_handle_redirect_uri_request (
							ngx_http_request_t 		*r,
							ngx_gluu_ox_loc_conf_t 	*s_cfg
							/*session_rec *session */);

ngx_int_t
ngx_gluu_ox_oidc_proto_is_redirect_authorization_response(
			 						ngx_http_request_t 			*r,
			 						ngx_gluu_ox_loc_conf_t 		*s_cfg );

#endif