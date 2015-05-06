/** Copyright (C) 2007-2015 Gluu ()
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
 **/

#include "ngx_http_gluu_ox_module.h"

static char*
ngx_http_gluu_ox_module_init( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );

static void* 
ngx_http_gluu_ox_create_loc_config(ngx_conf_t *cf)
{
	ox_cfg *loc_conf = ngx_palloc(cf->pool, sizeof(ox_cfg));
	if ( loc_conf == NULL )
		return NGX_CONF_ERROR;

	loc_conf->merged = NGX_CONF_UNSET_UINT;
	loc_conf->public_keys = NGX_CONF_UNSET_PTR;
	loc_conf->private_keys = NGX_CONF_UNSET_PTR;
	loc_conf->provider.ssl_validate_server = NGX_CONF_UNSET;
	loc_conf->provider.jwks_refresh_interval = NGX_CONF_UNSET;
	loc_conf->provider.idtoken_iat_slack = NGX_CONF_UNSET;
	loc_conf->provider.session_max_duration = NGX_CONF_UNSET;
	loc_conf->provider.oxd_port = NGX_CONF_UNSET_UINT;
	loc_conf->oauth.ssl_validate_server = NGX_CONF_UNSET;
	loc_conf->oauth.introspection_token_expiry_claim_required = NGX_CONF_UNSET;
	loc_conf->oauth.verify_public_keys = NGX_CONF_UNSET_PTR;
	loc_conf->oauth.verify_shared_keys = NGX_CONF_UNSET_PTR;
	loc_conf->cache_file_clean_interval = NGX_CONF_UNSET;
	loc_conf->cache_shm_size_max = NGX_CONF_UNSET;
	loc_conf->cache_shm_entry_size_max = NGX_CONF_UNSET;
	loc_conf->session_type = NGX_CONF_UNSET;
	loc_conf->http_timeout_long = NGX_CONF_UNSET;
	loc_conf->http_timeout_short = NGX_CONF_UNSET;
	loc_conf->state_timeout = NGX_CONF_UNSET;
	loc_conf->session_inactivity_timeout = NGX_CONF_UNSET;
	loc_conf->pass_idtoken_as = NGX_CONF_UNSET;
	loc_conf->cookie_http_only = NGX_CONF_UNSET;
	loc_conf->scrub_request_headers = NGX_CONF_UNSET;

	ngx_conf_log_error( NGX_LOG_EMERG, cf, 0, "return to create loc config" );

	return loc_conf;
}

static char*
ngx_http_gluu_ox_merge_loc_config( ngx_conf_t *cf, void *parent, void *child )
{
	ox_cfg 		*prev = parent;
	ox_cfg		*conf = child;

	conf->merged = 1;
	ngx_conf_merge_str_value( conf->redirect_uri, prev->redirect_uri, "" );
	ngx_conf_merge_str_value( conf->discover_url, prev->discover_url, "" );
	ngx_conf_merge_str_value( conf->default_sso_url, prev->default_sso_url, "" );
	ngx_conf_merge_str_value( conf->default_slo_url, prev->default_slo_url, "" );
	ngx_conf_merge_ptr_value( conf->public_keys, prev->public_keys, NULL );
	ngx_conf_merge_ptr_value( conf->private_keys, prev->private_keys, NULL );

	ngx_conf_merge_str_value( conf->provider.metadata_url, prev->provider.metadata_url, "" );
	ngx_conf_merge_str_value( conf->provider.issuer, prev->provider.issuer, "" );
	ngx_conf_merge_str_value( conf->provider.authorization_endpoint_url, prev->provider.authorization_endpoint_url, "" );
	ngx_conf_merge_str_value( conf->provider.token_endpoint_url, prev->provider.token_endpoint_url, "" );
	ngx_conf_merge_str_value( conf->provider.token_endpoint_auth, prev->provider.token_endpoint_auth, "" );
	ngx_conf_merge_str_value( conf->provider.token_endpoint_params, prev->provider.token_endpoint_params, "" );
	ngx_conf_merge_str_value( conf->provider.userinfo_endpoint_url, prev->provider.userinfo_endpoint_url, "" );
	ngx_conf_merge_str_value( conf->provider.client_id, prev->provider.client_id, "" );
	ngx_conf_merge_str_value( conf->provider.client_secret, prev->provider.client_secret, "" );
	ngx_conf_merge_str_value( conf->provider.registration_endpoint_url, prev->provider.registration_endpoint_url, "" );
	ngx_conf_merge_str_value( conf->provider.registration_endpoint_json, prev->provider.registration_endpoint_json, "" );
	ngx_conf_merge_str_value( conf->provider.check_session_iframe, prev->provider.check_session_iframe, "" );
	ngx_conf_merge_str_value( conf->provider.end_session_endpoint, prev->provider.end_session_endpoint, "" );
	ngx_conf_merge_str_value( conf->provider.jwks_uri, prev->provider.jwks_uri, "" );

	ngx_conf_merge_value( conf->provider.ssl_validate_server, prev->provider.ssl_validate_server, OX_DEFAULT_SSL_VALIDATE_SERVER );
	ngx_conf_merge_str_value( conf->provider.client_name, prev->provider.client_name, OX_DEFAULT_CLIENT_NAME );
	ngx_conf_merge_str_value( conf->provider.client_contact, prev->provider.client_contact, "" );
	ngx_conf_merge_str_value( conf->provider.registration_token, prev->provider.registration_token, "" );
	ngx_conf_merge_str_value( conf->provider.scope, prev->provider.scope, OX_DEFAULT_SCOPE );
	ngx_conf_merge_str_value( conf->provider.response_type, prev->provider.response_type, OX_DEFAULT_RESPONSE_TYPE );
	ngx_conf_merge_str_value( conf->provider.response_mode, prev->provider.response_mode, "" );
	ngx_conf_merge_value( conf->provider.jwks_refresh_interval, prev->provider.jwks_refresh_interval, OX_DEFAULT_JWKS_REFRESH_INTERVAL );
	ngx_conf_merge_value( conf->provider.idtoken_iat_slack, prev->provider.idtoken_iat_slack, OX_DEFAULT_IDTOKEN_IAT_SLACK );
	ngx_conf_merge_value( conf->provider.session_max_duration, prev->provider.session_max_duration, OX_DEFAULT_SESSION_MAX_DURATION );
	ngx_conf_merge_str_value( conf->provider.auth_request_params, prev->provider.auth_request_params, "" );

	ngx_conf_merge_str_value( conf->provider.client_jwks_uri, prev->provider.client_jwks_uri, "" );
	ngx_conf_merge_str_value( conf->provider.id_token_signed_response_alg, prev->provider.id_token_signed_response_alg, "" );
	ngx_conf_merge_str_value( conf->provider.id_token_encrypted_response_alg, prev->provider.id_token_encrypted_response_alg, "" );
	ngx_conf_merge_str_value( conf->provider.id_token_encrypted_response_enc, prev->provider.id_token_encrypted_response_enc, "" );
	ngx_conf_merge_str_value( conf->provider.userinfo_signed_response_alg, prev->provider.userinfo_signed_response_alg, "" );
	ngx_conf_merge_str_value( conf->provider.userinfo_encrypted_response_alg, prev->provider.userinfo_encrypted_response_alg, "" );
	ngx_conf_merge_str_value( conf->provider.userinfo_encrypted_response_enc, prev->provider.userinfo_encrypted_response_enc, "" );
	ngx_conf_merge_str_value( conf->provider.oxd_hostname, prev->provider.oxd_hostname, "" );
	ngx_conf_merge_value( conf->provider.oxd_port, prev->provider.oxd_port, 0 );
	ngx_conf_merge_str_value( conf->provider.logout_url, prev->provider.logout_url, "" );

	ngx_conf_merge_value( conf->oauth.ssl_validate_server, prev->oauth.ssl_validate_server, OX_DEFAULT_SSL_VALIDATE_SERVER );
	ngx_conf_merge_str_value( conf->oauth.client_id, prev->oauth.client_id, "" );
	ngx_conf_merge_str_value( conf->oauth.client_secret, prev->oauth.client_secret, "" );
	ngx_conf_merge_str_value( conf->oauth.introspection_endpoint_url, prev->oauth.introspection_endpoint_url, "" );
	ngx_conf_merge_str_value( conf->oauth.introspection_endpoint_method, prev->oauth.introspection_endpoint_method, OX_DEFAULT_OAUTH_ENDPOINT_METHOD );
	ngx_conf_merge_str_value( conf->oauth.introspection_endpoint_params, prev->oauth.introspection_endpoint_params, "" );
	ngx_conf_merge_str_value( conf->oauth.introspection_endpoint_auth, prev->oauth.introspection_endpoint_auth, "" );
	ngx_conf_merge_str_value( conf->oauth.introspection_token_param_name, prev->oauth.introspection_token_param_name, "" );

	ngx_conf_merge_str_value( conf->oauth.introspection_token_expiry_claim_name, prev->oauth.introspection_token_expiry_claim_name, OX_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME );
	ngx_conf_merge_str_value( conf->oauth.introspection_token_expiry_claim_format, prev->oauth.introspection_token_expiry_claim_format, OX_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT );
	ngx_conf_merge_value( conf->oauth.introspection_token_expiry_claim_required, prev->oauth.introspection_token_expiry_claim_required, OX_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED );

	ngx_conf_merge_str_value( conf->oauth.remote_user_claim.claim_name, prev->oauth.remote_user_claim.claim_name, OX_DEFAULT_OAUTH_CLAIM_REMOTE_USER );
	ngx_conf_merge_str_value( conf->oauth.remote_user_claim.reg_exp, prev->oauth.remote_user_claim.reg_exp, "" );

	ngx_conf_merge_str_value( conf->oauth.verify_jwks_uri, prev->oauth.verify_jwks_uri, "" );
	ngx_conf_merge_ptr_value( conf->oauth.verify_public_keys, prev->oauth.verify_public_keys, NULL );
	ngx_conf_merge_ptr_value( conf->oauth.verify_shared_keys, prev->oauth.verify_shared_keys, NULL );

/*
	loc_conf->cache = &ox_cache_memcache;
	loc_conf->cache_cfg = NULL;
*/
	ngx_conf_merge_str_value( conf->cache_file_dir, prev->cache_file_dir, "" );
	ngx_conf_merge_value( conf->cache_file_clean_interval, prev->cache_file_clean_interval, OX_DEFAULT_CACHE_FILE_CLEAN_INTERVAL );
	ngx_conf_merge_str_value( conf->cache_memcache_servers, prev->cache_memcache_servers, "" );
	ngx_conf_merge_value( conf->cache_shm_size_max, prev->cache_shm_size_max, OX_DEFAULT_CACHE_SHM_SIZE );
	ngx_conf_merge_value( conf->cache_shm_entry_size_max, prev->cache_shm_entry_size_max, OX_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX );

#ifdef USE_LIBHIREDIS
	ngx_conf_merge_str_value( conf->cache_redis_server, prev->cache_redis_server, "" );
#endif

	ngx_conf_merge_str_value( conf->metadata_dir, prev->metadata_dir, "" );
	ngx_conf_merge_value( conf->session_type, prev->session_type, OX_DEFAULT_SESSION_TYPE );

	ngx_conf_merge_value( conf->http_timeout_long, prev->http_timeout_long, OX_DEFAULT_HTTP_TIMEOUT_LONG );
	ngx_conf_merge_value( conf->http_timeout_short, prev->http_timeout_short, OX_DEFAULT_HTTP_TIMEOUT_SHORT );
	ngx_conf_merge_value( conf->state_timeout, prev->state_timeout, OX_DEFAULT_STATE_TIMEOUT );
	ngx_conf_merge_value( conf->session_inactivity_timeout, prev->session_inactivity_timeout, OX_DEFAULT_SESSION_INACTIVITY_TIMEOUT );

	ngx_conf_merge_str_value( conf->cookie_domain, prev->cookie_domain, "" );
	ngx_conf_merge_str_value( conf->claim_delimiter, prev->claim_delimiter, OX_DEFAULT_CLAIM_DELIMITER );
	ngx_conf_merge_str_value( conf->claim_prefix, prev->claim_prefix, OX_DEFAULT_CLAIM_PREFIX );
	ngx_conf_merge_str_value( conf->remote_user_claim.claim_name, prev->remote_user_claim.claim_name, OX_DEFAULT_CLAIM_REMOTE_USER );
	ngx_conf_merge_str_value( conf->remote_user_claim.reg_exp, prev->remote_user_claim.reg_exp, "" );
	ngx_conf_merge_value( conf->pass_idtoken_as, prev->pass_idtoken_as, OX_PASS_IDTOKEN_AS_CLAIMS );
	ngx_conf_merge_value( conf->cookie_http_only, prev->cookie_http_only, OX_DEFAULT_COOKIE_HTTPONLY );

	ngx_conf_merge_str_value( conf->outgoing_proxy, prev->outgoing_proxy, "" );
	ngx_conf_merge_str_value( conf->crypto_passphrase, prev->crypto_passphrase, "" );

	ngx_conf_merge_value( conf->scrub_request_headers, prev->scrub_request_headers, OX_DEFAULT_SCRUB_REQUEST_HEADERS );

	return NGX_CONF_OK;
}
/*
 * This module context has hooks, here we have a hook 
 * for creating location configuration.
 */
static ngx_http_module_t ngx_http_gluu_ox_module_ctx = {
	NULL, /* preconfiguration */
	NULL, /* postconfiguration */
	NULL, /* create main configuration */
	NULL, /* init main configuration */
	NULL, /* create server configuration */
	NULL, /* merge server configuration */
	ngx_http_gluu_ox_create_loc_config, /* create location configuration */
	ngx_http_gluu_ox_merge_loc_config /* merge location configuration */
};

static
ngx_command_t ngx_http_gluu_ox_commands[] = {
	{ ngx_string("Gluu_OX"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
	  ngx_http_gluu_ox_module_init,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

	{ ngx_string("OXCDiscoverURL"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ox_cfg, discover_url),
	  NULL },

	{ ngx_string("OXRedirectURI"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ox_cfg, redirect_uri),
	  NULL },

	{ ngx_string("OXMetadataURI"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ox_cfg, provider.metadata_url),
	  NULL },

  	{ ngx_string("OXProviderIssuer"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ox_cfg, provider.issuer),
	  NULL },

  	{ ngx_string("OXOxdHostName"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ox_cfg, provider.oxd_hostname),
	  NULL },

	{ ngx_string("OXOxdPortNum"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ox_cfg, provider.oxd_port),
	  NULL },
	ngx_null_command
};


static ngx_int_t
ngx_http_ox_init_module( ngx_cycle_t *cycle ) {
	curl_global_init( CURL_GLOBAL_ALL );
	return NGX_OK;
}

static void
ngx_http_ox_exit_module( ngx_cycle_t *cycle ) {
	curl_global_cleanup();
}

/*
 * The module which binds the context and commands
 */
ngx_module_t ngx_http_gluu_ox_module = {
	NGX_MODULE_V1,
 	&ngx_http_gluu_ox_module_ctx, 	/* module context */
 	ngx_http_gluu_ox_commands,		/* module directives */
 	NGX_HTTP_MODULE,				/* module type */
 	NULL,							/* init master */
 	ngx_http_ox_init_module, 		/* init module */
 	NULL, 							/* init process */
 	NULL, 							/* init thread */
 	NULL,							/* exit thread */
 	NULL, 							/* exit process */
 	&ngx_http_ox_exit_module,		/* exit master */
 	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_gluu_ox_module_handler( ngx_http_request_t	*r )
{
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "request_line: %s\n", r->request_line.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "uri 		 : %s\n", r->uri.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "args 		 : %s\n", r->args.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "exten 		 : %s\n", r->exten.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "unparsed_uri: %s\n", r->unparsed_uri.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "content-type: %s\n", r->headers_in.chunked );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "schema_start: %s\n", r->schema_start );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "schema_end: %s\n", r->schema_end );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "header_start: %s\n", r->header_start );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "header_end: %s\n", r->header_end );

	if( r->main->internal ) {
		return NGX_DECLINED;
	}
	
	r->main->internal = 1;

	/* Getting module configuration struct info */
	ox_cfg *conf = (ox_cfg *)ngx_http_get_module_loc_conf( r, ngx_http_gluu_ox_module );

	if( conf == NULL )
		return NGX_ERROR;

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, 
									"oxd<issuer: %s, hostname: %s, port:%d>\n", 
									conf->provider.issuer.data,
									conf->provider.oxd_hostname.data,
									conf->provider.oxd_port );

	u_char *result = NULL;
	if( oxd_discovery( r, &conf->provider.oxd_hostname, conf->provider.oxd_port, &conf->provider.issuer, result ) != NGX_OK ) {
		return ox_utils_html_send_error( 
								r,
								"oxd_discovery",
								"failed",
								NGX_HTTP_UNAUTHORIZED );
	}

	return ox_utils_html_send_error( 
						r,
						"oxd_discovery",
						(char *) result,
						NGX_HTTP_UNAUTHORIZED );

	if( ngx_ox_is_discovery_response( r, conf ) == NGX_OK ) {
		/* this is response from the OP discovery page */
///		return ox_handle_discovery_response( r, conf );
	}
	/* test */
	if( conf->metadata_dir.data != NULL )
		return ox_discovery( r, conf );

	if( r->headers_in.server.len > 0)
		return ox_utils_html_send_error( 
								r, 
								(char *)r->headers_in.server.data,
								(char *)ngx_gluu_ox_get_request_url(r) == NULL ? "NULL" : (char *)ngx_gluu_ox_get_request_url(r),
								NGX_HTTP_UNAUTHORIZED );

	return ox_utils_html_send_error( 
								r,
								"ngx_http_gluu_ox_module_handler",
								"this is main request",
								NGX_HTTP_UNAUTHORIZED );
}


static char*
ngx_http_gluu_ox_module_init( ngx_conf_t *cf, ngx_command_t *cmd, void *conf )
{
	ngx_http_core_loc_conf_t 	*clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_gluu_ox_module_handler;

	return NGX_CONF_OK;
}

/*
 * find out whether the request is a response from an IDP discovery page
 */
ngx_int_t
ngx_ox_is_discovery_response (
						ngx_http_request_t	 	*r,
						ox_cfg 					*cfg ) {
	/*
	 * prereq : this is a call to the configured redirect_uri, now see if:
	 * the OX_DISC_OP_PARAM is present
	 */

	return ox_utils_request_has_parameter( r, OX_DISC_OP_PARAM );
}

/*
 * handle a response from an IDP discovery page and/or handle third-party initiated SSO
 */
ngx_int_t
ox_handle_discovery_response(
						ngx_http_request_t 	*r,
						ox_cfg 				*c ) {

	ngx_str_t issuer, target_linked_uri, login_hint, auth_request_params;
	if( ngx_http_arg( r, (u_char *)OX_DISC_OP_PARAM, sizeof( OX_DISC_OP_PARAM ) - 1, &issuer) != NGX_OK ) {
		return ox_utils_html_send_error( 
								r,
								"ngx_gluu_ox",
								"Wherever you came from, it sent you here with the wrong parameters...",
								NGX_HTTP_INTERNAL_SERVER_ERROR );
	}

	if( ngx_http_arg( r, (u_char *)OX_DISC_RT_PARAM, sizeof( OX_DISC_RT_PARAM ) - 1, &target_linked_uri) != NGX_OK ) {
		if( c->default_sso_url.data == NULL ) {
			return ox_utils_html_send_error( 
								r,
								"ngx_gluu_ox",
								"SSO to this module without specifying a \"\" parameter is not possible because OXDefaultURL is not set.",
								NGX_HTTP_INTERNAL_SERVER_ERROR );

		}

		target_linked_uri = c->default_sso_url;
	}

	if( ngx_http_arg( r, (u_char *)OX_DISC_LH_PARAM, sizeof( OX_DISC_LH_PARAM ) - 1, &login_hint) != NGX_OK ) {
	}

	if( ngx_http_arg( r, (u_char *)OX_DISC_AR_PARAM, sizeof( OX_DISC_AR_PARAM ) - 1, &auth_request_params) != NGX_OK ) {
	}

	/* find out if the user entered an account name or selected an OP manually */
	if( ngx_strstr( issuer.data, (u_char *)"@") != NULL ) {
		if( login_hint.data == NULL ) {
			login_hint.data = ngx_pstrdup( r->pool, &issuer );
			login_hint.len = ngx_strlen( login_hint.data );
		}

		/* got an account name as input, perform OP discovery with that */

	}

	return ox_utils_html_send_error( 
								r,
								"ox_handle_discovery_response",
								"Not not_found",
								NGX_HTTP_UNAUTHORIZED );
}

ngx_int_t
ngx_gluu_ox_oidc_handle_redirect_uri_request (
							ngx_http_request_t 		*r,
							ox_cfg 	*s_cfg
							/*session_rec *session */)
{
	if ( 1/*ngx_gluu_ox_oidc_proto_is_redirect_authorization_response( r, s_cfg ) == NGX_OK*/ ){
		return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"authoriozation response success",
								NGX_HTTP_UNAUTHORIZED );
	} else {
		return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"authoriozation response failed",
								NGX_HTTP_UNAUTHORIZED );
	}
}

u_char *
ngx_gluu_ox_oidc_get_state_cookie_name(
					ngx_http_request_t 	*r,
					u_char 				*state ) {
	u_char 	*ret = NULL;
//	ngx_sprintf( ret, "%s%s", OIDC_STATE_COOKIE_PREFIX, state );

	return ret;
}

/*
 * authenticate the user to the selected OP, if the OP is not selected yet perform discovery first
 */
/*static ngx_int_t
ox_authenticate_user(
		ngx_http_request_t 	*r,
		ox_cfg 				*c,
		ox_provider_t 		*provider,
		ngx_str_t 			*original_url,
		ngx_str_t 			*login_hint,
		ngx_str_t 			*id_token_hint,
		u_char 				*prompt,
		ngx_str_t 			auth_request_params ) {
	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "==============> entering ox_authenticate_user\n" );

	if( provider == NULL ) {*/
		/* TODO: should we use an explicit redirect to the discovery endpoint ( maybe a "discovery" param to the redirect_uri )?*/
/*		if( c->metadata_dir.data != NULL )
			return ox_discovery( r, c );
		if( ox_provider_static_config( r, c, &provider ) == NGX_ERROR )
			return NGX_HTTPINTERNAL_SERVER_ERROR;

	}
	
	return NGX_OK;

}*/

/*
 * present the user with an OP selection screen
 */
ngx_int_t
ox_discovery(
		ngx_http_request_t 		*r,
		ox_cfg 					*c ) {
	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "entering ox_discovery\n" );

	ngx_array_t 	arr;
	ngx_str_t 		url;
	u_char *current_url = ngx_gluu_ox_get_request_url( r );

	if( current_url == NULL )
		return NGX_DECLINED;

	if( c->discover_url.data != NULL ) {
		/* yes, assemble the parameters for external discovery */
		
		u_char *cl = ngx_palloc( r->pool, sizeof(u_char *) );
		u_char *rl = ngx_palloc( r->pool, sizeof(u_char *) );

		ngx_escape_uri( cl, current_url, ngx_strlen( current_url ), NGX_ESCAPE_URI );
		ngx_escape_uri( rl, c->redirect_uri.data, c->redirect_uri.len, NGX_ESCAPE_URI );

		ngx_sprintf( url.data, "%s%s%s=%s&%s=%s", 
							c->discover_url.data,
							ngx_strchr( c->discover_url.data, '?') != NULL ? "&" : "?",
							OX_DISC_RT_PARAM, cl,
							OX_DISC_CB_PARAM, rl );
		url.len = ngx_strlen( url.data );

		/* log what we`re about to do */
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "redirecting to external discovery page: %s\n", url );

		r->headers_out.location->hash = 1;
		ngx_str_set( &r->headers_out.location->key, "Location" );
		r->headers_out.location->value = url;

		return NGX_HTTP_MOVED_TEMPORARILY;
	}

	/* get a list of all providers configured in the metadata directory */
	ox_metadata_list( r, c, &arr );
	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "current url : %s\n", current_url );

	return NGX_OK;
}

/*
 * return the static provider configuration, i.e. from a metadata URL or configuration primitives
 */
/*static ngx_int_t
ox_provider_static_config(
				ngx_http_request_t 	*r,
				ox_cfg 				*c,
				ox_provider_t 		**provider ) {

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "entering ox_provider_static_config\n" );

	json_t 		*j_provider = NULL;
	u_char 		*s_json = NULL;*/

	/* see if we should configure a static provider based on external (cached) metadata */
/*	if( ( c->metadata_dir.data != NULL ) || ( c->provider.metadata_url.data == NULL ) ) {
		*provider = &c->provider;
		return NGX_OK;
	}*/

	/*********************************************/
	/* get a provider memcached in cache server  */
	/* feature */
	/*********************************************/

/*	if( s_json == NULL ) {
		if( ox_metadata_provider_retrieve( r, c, NULL, c->provider.metadata_url.data, &j_provider, &s_json ) != NGX_OK ) {
			ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "could not retrieve metadata from url: %s\n", c->provider.metadata_url.data );

			return NGX_ERROR;
		}
	}
	
}*/