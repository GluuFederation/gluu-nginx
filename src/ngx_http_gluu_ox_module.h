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

#include "cache/cache.h"
#include "ngx_gluu_ox_config.h"

#include <jansson.h>

#define  OPENSSL_THREAD_DEFINES

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>

#include <curl/curl.h>

//#ifdef (OPENSSL_VERSION_NUMBER < 0x01000000)
//#define OPENSSL_NO_THREADID
//#endif


/* UMA config variables */
 typedef struct {
 	ngx_str_t	host;
 	ngx_str_t	scope[5];
 }ox_uma_host_config;

typedef struct {
	ngx_str_t	url;
	ngx_int_t 	refresh_internal;
	ngx_int_t	ssl_validate_server;
}ox_jwks_uri_t;

typedef struct {
	ngx_str_t 	metadata_url;
	ngx_str_t 	issuer;
	ngx_str_t 	authorization_endpoint_url;
	ngx_str_t 	token_endpoint_url;
	ngx_str_t 	token_endpoint_auth;
	ngx_str_t 	token_endpoint_params;
	ngx_str_t 	userinfo_endpoint_url;
	ngx_str_t 	registration_endpoint_url;
	ngx_str_t 	check_session_iframe;
	ngx_str_t 	end_session_endpoint;
	ngx_str_t 	jwks_uri;
	ngx_str_t 	client_id;
	ngx_str_t 	client_secret;

	/* the next ones function as global default settings too */
	ngx_int_t 	ssl_validate_server;
	ngx_str_t 	client_name;
	ngx_str_t 	client_contact;
	ngx_str_t 	registration_token;
	ngx_str_t 	registration_endpoint_json;
	ngx_str_t 	scope;
	ngx_str_t 	response_type;
	ngx_str_t 	response_mode;
	ngx_int_t	jwks_refresh_interval;
	ngx_int_t	idtoken_iat_slack;
	ngx_str_t 	auth_request_params;
	ngx_int_t 	session_max_duration;

	ngx_str_t 	client_jwks_uri;
	ngx_str_t 	id_token_signed_response_alg;
	ngx_str_t 	id_token_encrypted_response_alg;
	ngx_str_t 	id_token_encrypted_response_enc;
	ngx_str_t 	userinfo_signed_response_alg;
	ngx_str_t 	userinfo_encrypted_response_alg;
	ngx_str_t 	userinfo_encrypted_response_enc;
}ox_provider_t;

typedef struct {
	ngx_str_t 		claim_name;
	ngx_str_t 		reg_exp;
}ox_remote_user_claim_t;

typedef struct {
	ngx_int_t 		ssl_validate_server;
	ngx_str_t 		client_id;
	ngx_str_t 		client_secret;
	ngx_str_t 		introspection_endpoint_url;
	ngx_str_t 		introspection_endpoint_method;
	ngx_str_t 		introspection_endpoint_params;
	ngx_str_t 		introspection_endpoint_auth;
	ngx_str_t 		introspection_token_param_name;
	ngx_str_t 		introspection_token_expiry_claim_name;
	ngx_str_t 		introspection_token_expiry_claim_format;
	ngx_int_t 		introspection_token_expiry_claim_required;
	ox_remote_user_claim_t 	remote_user_claim;
	ngx_hash_t 		*verify_shared_keys;
	ngx_str_t 		verify_jwks_uri;
	ngx_hash_t 		*verify_public_keys;
}ox_oauth_t;

typedef struct {
	/* indicates whether this is a derived config, merged from a base one */
	ngx_uint_t 		merged;
	/* external OP discovery page */
 	ngx_str_t 		discover_url;
	/* RedirectUri is used to correlate the response. It is reflected back to the site.*/
 	ngx_str_t 		redirect_uri;
 	/* (optional) default URL for third-party initiated SSO */
 	ngx_str_t 		default_sso_url;
 	/* (optional) default URL to go to after logout */
 	ngx_str_t 		default_slo_url;

 	/* public keys in JWK format, used by parters for encrypting JWTs sent to us */
 	ngx_hash_t 		*public_keys;
 	/* private keys in JWK format used for decrypting encrypted JWTs sent to us */
 	ngx_hash_t 		*private_keys;
 	/* a pointer to the (single) provider that we connect to */
 	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there. */
 	ox_provider_t 	provider;
 	/* a pointer to the oAuth server settings */
 	ox_oauth_t 		oauth;

 	/* directory that holds the provider & client metadata files */
 	ngx_str_t 		metadata_dir;
 	/* type of session management/storage */
 	ngx_int_t 		session_type;

 	/* pointer to cache functions */
 	//ox_cache_t 		*cache;
 	//void 				*cache_cfg;
 	/* cache_type = file: directory that holds the cache files (if not set, we`ll try and use an OS defined one like "/tmp") */
 	ngx_str_t 		cache_file_dir;
 	/* cache_type = file: clean interval */
 	ngx_int_t 		cache_file_clean_interval;
 	/* cache_type = memcache: list of memcache host/port servers to use */
 	ngx_str_t 		cache_memcache_servers;
 	/* cache_type = shm: size of the shared memory segment (cq. max number of cached entries) */
 	ngx_int_t 		cache_shm_size_max;
 	/* cache_type = shm: maximum size in bytes of a cache entry */
 	ngx_int_t 		cache_shm_entry_size_max;

#ifdef USE_LIBHIREDIS
 	/* cache_type = redis: Redis host/port server to use */
 	ngx_str_t 		cache_redis_server;
#endif

 	/* tell the module to strip any ngx_gluu_ox releated headers that already have been set by the user-agent, normally required for secure operation */
 	ngx_int_t 		scrub_request_headers;
 	ngx_int_t 		http_timeout_long;
 	ngx_int_t 		http_timeout_short;
 	ngx_int_t 		state_timeout;
 	ngx_int_t 		session_inactivity_timeout;

 	ngx_str_t 		cookie_domain;
 	ngx_str_t 		claim_delimiter;
 	ngx_str_t 		claim_prefix;
 	ox_remote_user_claim_t 		remote_user_claim;
 	ngx_int_t 		pass_idtoken_as;
 	ngx_int_t 		cookie_http_only;

 	ngx_str_t 		outgoing_proxy;
 	ngx_str_t 		crypto_passphrase;

 	EVP_CIPHER_CTX 	*encrypt_ctx;
 	EVP_CIPHER_CTX 	*decrypt_ctx;
 }ox_cfg;

typedef struct {
	ngx_str_t 		*cookie_path;
	ngx_str_t 		cookie;
	ngx_str_t 		authn_header;
	ngx_int_t 		return401;
	ngx_array_t 	*pass_cookies;
} ox_dir_cfg;

typedef struct {
	ngx_pool_t 						*pool;		/* pool to be used for this session */
    ngx_str_t                       name;
    time_t                          expires;
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

u_char *
ngx_gluu_ox_get_request_url( ngx_http_request_t *r );

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
							ox_cfg 	*s_cfg
							/*session_rec *session */);

ngx_int_t
ngx_gluu_ox_oidc_proto_is_redirect_authorization_response(
			 						ngx_http_request_t 			*r,
			 						ox_cfg 		*s_cfg );
/* Memcached module */
ngx_int_t
ngx_gluu_ox_memcache_init( 
					ngx_str_t 	cfg_host,
					ngx_int_t  	cfg_port );

ngx_int_t
ngx_gluu_ox_memcached_set(
					const char 	*key,
					const char 	*value );

ngx_int_t
ngx_gluu_ox_memcached_set_timeout( 
					const char 		*key,
					const char 		*value,
					unsigned int 	timeout );
char *
ngx_gluu_ox_memcached_get(
					const char *key );

ngx_int_t
ngx_gluu_ox_memcached_delete(
					const char 	*key );

void
ngx_http_memcached_destroy( void );

typedef struct {
	ngx_str_t 		session_id;
	ngx_str_t 		username;
	ngx_str_t 		path;
	ngx_str_t 		identify;
	time_t 			expiry;
}oidc_session_t;



/**
 * restore the state that was maintained between authorization request 
 * and response in an encrypted cookie
 **/
ngx_int_t
ngx_gluu_ox_oidc_restore_proto_state(
							ngx_http_request_t 		*r,
							ox_cfg 	*s_cfg,
							u_char 					*state,
							json_t 					**proto_state );

u_char *
ngx_gluu_ox_oidc_get_state_cookie_name(
					ngx_http_request_t 	*r,
					u_char 				*state );

/**
 * set a cookie in the HTTP response headers
 **/
void
ngx_gluu_ox_oidc_util_set_cookie(
						ngx_http_request_t 	*r,
						ox_cfg 		*s_conf,
						ngx_str_t 			*cookie_name,
						ngx_str_t 			*cookie_value,
						time_t 				expires );

#endif