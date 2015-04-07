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

#include "ngx_http_gluu_ox_module.h"

#ifdef DEBUG 
 	#define D if(1)
#else
 	#define D if(0)
#endif


static char*
ngx_http_gluu_ox_module_init( ngx_conf_t *cf, ngx_command_t *cmd, void *conf );

static ngx_int_t
check_authn_type( ngx_gluu_ox_loc_conf_t *s_cfg );

static char*
check_configs( ngx_gluu_ox_loc_conf_t *s_cfg, ngx_int_t authn_type_value);

/*
 * Checking if uri is a predefined with one defined in Nginx configuration.
 */
static ngx_int_t
check_predefined_url( ngx_http_request_t *r, ngx_gluu_ox_loc_conf_t *s_cfg );

/*static char* ngx_http_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	//ngx_gluu_ox_loc_conf_t *gluu_conf = conf;

	ngx_str_t 	*value;

	value = cf->args->elts;

	if( ngx_strcasecmp(value[1].data, (u_char*)"Connect") == 0)
		ngx_conf_log_error( NGX_LOG_EMERG, cf, 0, "authn_type success" );
	else
		ngx_conf_log_error( NGX_LOG_EMERG, cf, 0, "authn_type failed" );

	return NGX_CONF_OK;
}
*/
static void* 
ngx_http_gluu_ox_create_loc_config(ngx_conf_t *cf)
{
	D fprintf( stderr, "enter ngx_http_gluu_ox_create_loc_config\n" );

	ngx_gluu_ox_loc_conf_t *loc_conf;

	loc_conf = ngx_palloc(cf->pool, sizeof(ngx_gluu_ox_loc_conf_t));
	if ( loc_conf == NULL )
		return NGX_CONF_ERROR;

	loc_conf->send_headers = NGX_CONF_UNSET;
	
	loc_conf->oxd_port = NGX_CONF_UNSET;

	loc_conf->memcached_port = NGX_CONF_UNSET;

	ngx_memzero(&loc_conf->uma_am_host, sizeof(ngx_gluu_uma_host_config));

	ngx_str_set(&loc_conf->uma_sent_user_claims, "givenName+issuingIDP+mail+uid");
	ngx_str_set(&loc_conf->cookied_name, "ox_session_id");
	loc_conf->cookie_lifespan = 0;

	ngx_conf_log_error( NGX_LOG_EMERG, cf, 0, "return to create loc config" );

	return loc_conf;
}

static char*
ngx_http_gluu_ox_merge_loc_config( ngx_conf_t *cf, void *parent, void *child )
{
	ngx_gluu_ox_loc_conf_t 	*prev = parent;
	ngx_gluu_ox_loc_conf_t		*conf = child;

	ngx_conf_merge_str_value( conf->cookie_path, prev->cookie_path, "" );

	D fprintf( stderr, "this is ngx_http_gluu_ox_merge_loc_config" );

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

	{ ngx_string("Gluu_ox"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
	  ngx_http_gluu_ox_module_init,
	  0,
	  0,
	  NULL },

	{ ngx_string("authn_type"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, authn_type),
	  NULL },

	{ ngx_string("cookie_path"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, cookie_path),
	  NULL },

	{ ngx_string("app_dest_url"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, app_dest_url),
	  NULL },

	{ ngx_string("client_credits_path"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, client_credits_path),
	  NULL },

	{ ngx_string("send_headers"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, send_headers),
	  NULL },

	{ ngx_string("oxd_host_addr"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, oxd_host),
	  NULL },

	{ ngx_string("oxd_port_num"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, oxd_port),
	  NULL },

	{ ngx_string("memcached_host_addr"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, memcached_host),
	  NULL },

	{ ngx_string("memcached_port_num"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, memcached_port),
	  NULL },

  	{ ngx_string("openid_provider"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, openid_provider),
	  NULL },

	{ ngx_string("openid_client_redirect_uris"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, openid_client_redirect_uris),
	  NULL },

	{ ngx_string("openid_requested_scope"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, openid_scope),
	  NULL },

	{ ngx_string("openid_client_name"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, openid_client_name),
	  NULL },

	{ ngx_string("openid_requested_acr"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, openid_request_acr),
	  NULL },

	{ ngx_string("openid_response_type"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, opneid_response_type),
	  NULL },

	{ ngx_string("uma_authorization_server"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, uma_authorization_server),
	  NULL },

	{ ngx_string("uma_resource_name"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, uma_resource_name),
	  NULL },

	{ ngx_string("uma_get_scope"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, uma_get_scope),
	  NULL },

	{ ngx_string("uma_put_scope"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, uma_put_scope),
	  NULL },

	{ ngx_string("uma_post_scope"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, uma_post_scope),
	  NULL },

	{ ngx_string("uma_delete_scope"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, uma_delete_scope),
	  NULL },

	{ ngx_string("app_post_logout_url"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, app_post_logout_url),
	  NULL },

	{ ngx_string("app_post_logout_redirect_url"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, app_post_logout_redirect_url),
	  NULL },

	{ ngx_string("ox_logout_url"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, ox_logout_url),
	  NULL },

	  ngx_null_command
};

/*
 * The module which binds the context and commands
 */
ngx_module_t ngx_http_gluu_ox_module = {
	NGX_MODULE_V1,
 	&ngx_http_gluu_ox_module_ctx, 	/* module context */
 	ngx_http_gluu_ox_commands,		/* module directives */
 	NGX_HTTP_MODULE,				/* module type */
 	NULL,							/* init master */
 	NULL, 							/* init module */
 	NULL, 							/* init process */
 	NULL, 							/* init thread */
 	NULL,							/* exit thread */
 	NULL, 							/* exit process */
 	NULL, 							/* exit master */
 	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_gluu_ox_module_handler( ngx_http_request_t* r )
{
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "request_line: %s\n", r->request_line.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "uri 		 : %s\n", r->uri.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "args 		 : %s\n", r->args.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "exten 		 : %s\n", r->exten.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "unparsed_uri: %s\n", r->unparsed_uri.data );

	/* gluu ox module location configuration */
	ngx_gluu_ox_loc_conf_t	*ox_loc_conf;
	
	/* Getting module configuration struct info */
	ox_loc_conf = (ngx_gluu_ox_loc_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_gluu_ox_module);

	/* Return Value */
	ngx_int_t 	ret;

	/* Setting the flag value whether login or logout.
	 * if is 1, session is already logged in,
	 * if is 0, session is logged out.
	 */
	ngx_int_t 	login = 0;

/*	if( ( ox_loc_conf->realm == NULL ) || ( ox_loc_conf->user_file.value.data == NULL || )
		return NGX_DECLINED;

	if( ngx_http_complex_value( ox_loc_conf, ox_loc_conf->realm, &realm ) != NGX_OK )
		return NGX_DECLINED;
 
	if( ngx_strcmp( realm.data, "Gluu_ox" ) != 0 )
		return NGX_DECLINED; */

	if( ngx_strcasecmp(ox_loc_conf->cookie_path.data, (u_char*)"/protected" ) != 0 )
	{
		return ox_util_html_send_error(
									r, 
									"ngx_http_gluu_ox_module", 
									"invaild cookie_path config in ox parameters, Please check ox configuration in Nginx config file!",
									NGX_HTTP_UNAUTHORIZED );
	}

	ngx_int_t authn_type = check_authn_type(ox_loc_conf);
	
	if( authn_type == NGX_ERROR )
	{
		return ox_util_html_send_error(
									r, 
									"ngx_http_gluu_ox_module", 
									"invaild authn_type config in ox parameters, Please check ox configuration in Nginx config file!",
									NGX_HTTP_UNAUTHORIZED );
	}

	if( check_configs( ox_loc_conf, authn_type ) == NGX_CONF_ERROR)
	{
		return ox_util_html_send_error(
									r, 
									"ngx_http_gluu_ox_module", 
									"Invaild ox parameters, Please check ox configuration in Nginx config file!",
									NGX_HTTP_UNAUTHORIZED );
	}

	/* memcached area (unused)*/

	/* if aceess, redirect, ok */
	ret = check_predefined_url( r, ox_loc_conf );
	switch( ret )
	{
	case NONE_PREDEFINED:
		break;
	case LOGIN_PREDEFINED:
		{
			login = 1;
			break;
		}
	case LOGOUT_PREDEFINED:
		{
			login = 0;
			break;
		}
	}

	
	/* Parsing the get/post params */
	
	if( login == 1)
	{

	}

	return NGX_OK;

}

static char*
ngx_http_gluu_ox_module_init( ngx_conf_t *cf, ngx_command_t *cmd, void *conf )
{
	ngx_http_core_loc_conf_t *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_gluu_ox_module_handler;

	return NGX_CONF_OK;
}

static ngx_int_t
check_authn_type( ngx_gluu_ox_loc_conf_t *s_cfg )
{
	if( ngx_strcmp( s_cfg->authn_type.data, "" ) == 0 )
	{
		return NGX_ERROR;
	}	
	else
	{
		if( ngx_strcmp( s_cfg->authn_type.data, "openid-connect" ) == 0 )
			return TRUSTED_RP_CONNECT;
		else
			return NGX_ERROR;
	}
}

static char*
check_configs( ngx_gluu_ox_loc_conf_t *s_cfg, ngx_int_t authn_type_value)
{
	/* checking typical directives in ox location configuration. */
	if ( ngx_strcmp( s_cfg->authn_type.data, "" ) == 0 ||
		 ngx_strcmp( s_cfg->cookie_path.data, "" ) == 0 ||
		 s_cfg->send_headers == SETNONE ||
		 ngx_strcmp( s_cfg->openid_provider.data, "" ) == 0 ||
		 ngx_strcmp( s_cfg->openid_client_redirect_uris.data, "" ) == 0||
		 ngx_strcmp( s_cfg->opneid_response_type.data, "" ) == 0)
		return NGX_CONF_ERROR;

	/* checking configs for each mode. */
	switch ( authn_type_value )
	{
	case TRUSTED_RP_CONNECT:
		{
			if( ngx_strcmp( s_cfg->opneid_response_type.data, "" ) == 0 )
				return NGX_CONF_ERROR;

			return NGX_CONF_OK;
		}
	case TRUSTED_RP_UMA:
		{
			if( ngx_strcmp( s_cfg->uma_authorization_server.data, "" ) == 0 ||
				ngx_strcmp( s_cfg->uma_resource_name.data, "" ) == 0 ||
				ngx_strcmp( s_cfg->uma_rs_host.data, "" ) == 0 ||
				ngx_strcmp( s_cfg->uma_am_host[0].host.data, "" ) == 0 ||
				ngx_strcmp( s_cfg->uma_am_host[0].scope[0].data, "" ) == 0 )
				return NGX_CONF_ERROR;

			return NGX_CONF_OK;
		}
	default:
		return NGX_CONF_ERROR;
	}
}

/*
 * Checking if uri is a predefined with one defined in Nginx configuration.
 */
static ngx_int_t
check_predefined_url( ngx_http_request_t *r, ngx_gluu_ox_loc_conf_t *s_cfg )
{
	ngx_str_t 	path;
	ngx_uint_t	flag;	
	/* Checking admin page */
	/* Unused */

	ngx_str_null(&path);
	flag = NGX_HTTP_LOG_UNSAFE;

	if( ngx_strcmp(s_cfg->openid_client_redirect_uris.data, "") != 0 )
	{
		if( ngx_http_parse_unsafe_uri( r, &s_cfg->openid_client_redirect_uris, &path, &flag ) == NGX_OK )
		{
			if( ngx_strcmp( path.data, "" ) != 0 )
			{
				if(ngx_strcmp( r->uri.data, path.data ) == 0 )
					return  ADMIN_PREDEFINED;
			}
		}
	}

	if(ngx_strcmp(s_cfg->ox_logout_url.data, "") == 0)
	{
		if( ngx_http_parse_unsafe_uri( r, &s_cfg->ox_logout_url, &path, &flag ) == NGX_OK )
		{
			if( ngx_strcmp( path.data, "" ) != 0 )
			{
				if( ngx_strcmp( r->uri.data, path.data ) == 0 )
					return  LOGOUT_PREDEFINED;
			}
		}
	}

	return NONE_PREDEFINED;
}
