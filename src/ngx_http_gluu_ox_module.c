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

static ngx_conf_post_handler_pt 
ngx_http_gluu_ox_module_init_p = (ngx_conf_post_handler_pt)ngx_http_gluu_ox_module_init;

static void* 
ngx_http_gluu_ox_create_loc_config(ngx_conf_t *cf)
{
	ngx_gluu_ox_loc_conf_t *loc_conf;

	loc_conf = ngx_palloc(cf->pool, sizeof(ngx_gluu_ox_loc_conf_t));
	if ( loc_conf == NULL )
		return NGX_CONF_ERROR;

	ngx_conf_log_error( NGX_LOG_EMERG, cf, 0, "return to create loc config" );

	return loc_conf;
}

static char*
ngx_http_gluu_ox_merge_loc_config( ngx_conf_t *cf, void *parent, void *child )
{
//	ngx_gluu_ox_loc_conf_t 	*prev = parent;
//	ngx_gluu_ox_loc_conf_t		*conf = child;

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

	{ ngx_string("authn_type"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, authn_type),
	  &ngx_http_gluu_ox_module_init_p },

	  { ngx_string("redirect_uris"),
	  NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_gluu_ox_loc_conf_t, redirect_uris),
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
ngx_http_gluu_ox_module_handler( ngx_http_request_t	*r )
{
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "request_line: %s\n", r->request_line.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "uri 		 : %s\n", r->uri.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "args 		 : %s\n", r->args.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "exten 		 : %s\n", r->exten.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "unparsed_uri: %s\n", r->unparsed_uri.data );
//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "content-type: %s\n", r->headers_in.chunked );

	/* Getting module configuration struct info */
	ngx_gluu_ox_loc_conf_t *ox_loc_conf = (ngx_gluu_ox_loc_conf_t *)ngx_http_get_module_loc_conf( r, ngx_http_gluu_ox_module );

	if( ngx_strcmp( ox_loc_conf->authn_type.data, (u_char *)"openid-connect") != 0 )
		return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"Invalid authn_type directive in nginx configuration file!",
								NGX_HTTP_UNAUTHORIZED );

	/* see if the initial request is to the redirect URI; this handles potential logout too */
	if( ngx_strcmp( ox_loc_conf->redirect_uris.data, "") == 0 )
			return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"Invalid redirect_uris directive in nginx configuration file!",
								NGX_HTTP_UNAUTHORIZED );

	if( oidc_util_request_matchs_url( r, ox_loc_conf->redirect_uris ) == NGX_OK )
	{	
		if ( ngx_gluu_ox_oidc_proto_is_redirect_authorization_response( r, ox_loc_conf ) == NGX_OK )
			return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"authoriozation response success",
								NGX_HTTP_UNAUTHORIZED );
		else
			return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"authoriozation response failed",
								NGX_HTTP_UNAUTHORIZED );
	}
	else
	{
		return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"No match",
								NGX_HTTP_UNAUTHORIZED );
	}

/*	if( oidc_util_request_matchs_url( r, ox_loc_conf->redirect_uris ) == NGX_ERROR )
	{

	}
	else
	{
		return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"Match!",
								NGX_HTTP_OK );

	}*/
/*	return ox_utils_html_send_error( 
								r, 
								"ngx_http_gluu_ox_module_handler",
								"All configuration OKAY!",
								NGX_HTTP_OK );*/
	//return NGX_OK;
}


static char*
ngx_http_gluu_ox_module_init( ngx_conf_t *cf, ngx_command_t *cmd, void *conf )
{
	ngx_http_core_loc_conf_t *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_gluu_ox_module_handler;

	return NGX_CONF_OK;
}

ngx_int_t
ngx_gluu_ox_oidc_handle_redirect_uri_request (
							ngx_http_request_t 		*r,
							ngx_gluu_ox_loc_conf_t 	*s_cfg
							/*session_rec *session */)
{
	return NGX_OK;
}