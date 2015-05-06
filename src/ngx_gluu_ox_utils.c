/* 
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
 */

#include "ngx_http_gluu_ox_module.h"

#include <curl/curl.h>

ngx_int_t
ox_utils_html_send_error( 
					ngx_http_request_t *r, 
					char *error, 
					char *description, 
					ngx_int_t status_code )
{
	u_char *html_body = NULL, *escape_html = NULL;
	u_char *s = NULL;
	u_char title[] = "Error";
	u_char empty[] = "";


	html_body = ngx_pnalloc( r->pool, NGX_MAX_ALLOC_FROM_POOL );
	ngx_memzero( html_body, NGX_MAX_ALLOC_FROM_POOL );

	if( error != NULL ){
		s = ngx_pnalloc( r->pool, ngx_strlen( error ) + 1 );
		ngx_memcpy( s, error, ngx_strlen( error ) + 1 );

		escape_html = ngx_pnalloc( r->pool, ngx_strlen( s ) + 1 );
		ngx_memzero( escape_html, ngx_strlen( s ) + 1 );
		ngx_escape_html( escape_html, s, ngx_strlen( s ) + 1 );

		ngx_sprintf( html_body,
					"%s<p>Error: <pre>%s</pre></p>",	
					html_body ? html_body : empty, 
					escape_html );
	}

	if( description != NULL ) {
		s = ngx_pnalloc( r->pool, ngx_strlen( description ) + 1 );
		ngx_memcpy( s, description, ngx_strlen( description ) + 1 );
		
		escape_html = ngx_pnalloc( r->pool, ngx_strlen( s ) + 1 );
		ngx_memzero( escape_html, ngx_strlen( s ) + 1 );
		ngx_escape_html( escape_html, s, ngx_strlen( s ) + 1 );

		ngx_sprintf( html_body,
					"%s<p>Error: <pre>%s</pre></p>",
					html_body ? html_body : empty, 
					escape_html );
	}

	return ox_utils_html_send( r, title, NULL, NULL, html_body, status_code );
}

ngx_int_t 
ox_utils_html_send( 
				ngx_http_request_t *r,
				u_char *title,
				u_char *html_header,
				u_char *on_load,
				u_char *html_body,
				ngx_int_t 	status_code )
{
	u_char *escape_title = NULL, *load_tag = NULL;
	u_char *full_html;
	u_char empty[] = "";

	const char *html = 
					"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n"
					"<html>\n"
					"  <head>\n"
					"    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
					"    <title>%s</title>\n"
					"    %s\n"
					"  </head>\n"
					"  <body%s>\n"
					"%s\n"
					"  </body>\n"
					"</html>\n";

	escape_title = ngx_pnalloc( r->pool, ngx_strlen( title ) + 1 );
	ngx_escape_html( escape_title, title,  ngx_strlen( title ) + 1 );

//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "======= escape_title : %s======\n", escape_title );

	load_tag = ngx_pnalloc( r->pool, sizeof(" onload=\"%s()\"") + sizeof(on_load) );
	ngx_sprintf( load_tag, " onload=\"%s()\"", on_load ? on_load : (u_char *)"");

//	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "======= load_tag : %s======\n", load_tag );

	full_html = ngx_pnalloc( r->pool, NGX_MAX_ALLOC_FROM_POOL );
	ngx_sprintf( full_html, html,
				title ? escape_title : empty,
				html_header ? html_header : empty,
				on_load ? load_tag : empty,
				html_body ? html_body : (u_char *)"<p></p>" );

	return ox_utils_http_send( r, full_html, (u_char *)"text/html", status_code );
}

ngx_int_t 
ox_utils_http_send( 
				ngx_http_request_t *r,
				u_char		*msg,
				u_char 		*content_type,
				ngx_int_t 	success_rvalue )
{	
	ngx_buf_t *b;
    ngx_chain_t out;

    /* Set the Content-Type header. */
    r->headers_out.content_type.len = ngx_strlen(content_type);
    r->headers_out.content_type.data = content_type;

    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc( r->pool, sizeof( ngx_buf_t ) );

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = msg; /* first position in memory of the data */
    b->last = msg + ngx_strlen( msg ); /* last position in memory of the data */
    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK; /* 200 status code */
    /* Get the content length of the body. */
    r->headers_out.content_length_n = ngx_strlen( msg ) + 1;

    ngx_http_send_header( r ); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    return ngx_http_output_filter( r, &out );
}

/* see if the currently accessed path matches a path from a defined URL */
ngx_int_t
oidc_util_request_matchs_url(
						ngx_http_request_t 	*r,
						ngx_str_t			url ) {

	ngx_str_t 	redirect_url;
//	ngx_uint_t 	flags = NGX_HTTP_LOG_UNSAFE;

	ngx_str_null( &redirect_url );
	
//	ngx_http_parse_unsafe_uri( r, &url, &temp, &flags );
	if( ngx_gluu_ox_parse_url( r, &url, &redirect_url ) != NGX_OK )
		return NGX_ERROR;

	u_char 	*p;
	size_t 	len;

	len = (r->uri_end - r->uri_start);

	if( len == 0 )
		return NGX_ERROR;

	p = ngx_pnalloc( r->pool, len + 1 );

	if( p == NULL )
		return NGX_ERROR;

	ngx_cpystrn( p, r->uri.data, len + 1 );

	if( ngx_strcmp( p, redirect_url.data ) != NGX_OK )
		return NGX_ERROR;

	return NGX_OK;
}

/*
 * get the URL that is currently being accessed
 */
u_char *
ngx_gluu_ox_get_request_url( ngx_http_request_t *r ) {

#if ( NGX_HAVE_INET6 )
	struct sockaddr_in6 	*sin6;
#endif
	struct sockaddr_in 		*sin;
	ngx_uint_t 			port = 80, uri_len;

	size_t 	len = 0;
	u_char 	*p, *buf;

	if( r->headers_in.server.len > 0 ) {
		len = sizeof( "http://" ) - 1 + r->headers_in.server.len;
#if ( NGX_HTTP_SSL )
		if ( r->connection->ssl ) {
			/* http:// -> https:// */
			len += 1;
		}
#endif
		if( ngx_connection_local_sockaddr( r->connection, NULL, 0 ) != NGX_OK ) {
			return NULL;
		}

		switch ( r->connection->local_sockaddr->sa_family ) {
#if (NGX_HTTP_INET6 )
		case AF_INET6:
			sin6 = ( struct sockaddr_in6 * ) r->connection->local_sockaddr;
			port = ntohs( sin6->sin6_port );
			break;
#endif
		default:
			sin = ( struct sockaddr_in * ) r->connection->local_sockaddr;
			port = ntohs( sin->sin_port );
			break; 
		}

		if( port > 0 && port != 80 && port != 443 && port < 65535 ) {
			len += sizeof( ":65535" ) - 1;
		}
	}

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "===== port %d======\n", port );

	if( r->unparsed_uri.len == 0 ) {
		len += 1;
	} else {
		p = r->unparsed_uri.data;
		for ( uri_len = 0; uri_len < r->unparsed_uri.len; uri_len ++ ) {
			if( *p == '?' ) break;

			p ++;
		}
		len += uri_len;
	}

	if ( r->args.len > 0 ) {
		len += r->args.len + sizeof( "?" ) - 1;
	}

	buf = ( u_char * ) ngx_pcalloc( r->pool, len + 1 );

	if( buf == NULL )
		return NULL;

	p = ( u_char * )buf; 

	if( r->headers_in.server.len > 0 ) {
		len = sizeof( "http://" ) - 1 + r->headers_in.server.len;
#if ( NGX_HTTP_SSL )
		if( r->connection->ssl ) {
			p = ngx_copy( p, "https://", sizeof( "https://" ) - 1 );
			p = ngx_copy( p, r->headers_in.server.data, r->headers_in.server.len );
		} else {
			p = ngx_copy( p, "http://", sizeof( "http://" ) - 1 );
			p = ngx_copy( p, r->headers_in.server.data, r->headers_in.server.len );
		}
#else
			p = ngx_copy( p, "http://", sizeof( "http://" ) - 1 );
			p = ngx_copy( p, r->headers_in.server.data, r->headers_in.server.len );
#endif

		if( port > 0 && port != 80 && port != 443 && port < 65535 ) {
			len -= sizeof( ":65535" ) - 1;
			len += ngx_sprintf( p, ":%ui", port ) - p;
			p = ngx_sprintf( p, ":%ui", port );
		}
	}

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "===== url %s======\n", buf );

	if( r->unparsed_uri.len == 0 ) {
		( *p++ ) = '/';
	} else {
		p = ngx_copy( p, r->unparsed_uri.data, uri_len );
	}

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "========> args: %s\n", r->args.data );

	if( r->args.len > 0 ) {
		( *p ++ ) = '?';
		p = ngx_copy( p, r->args.data, r->args.len );
	}

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "=========> full url %s\n", buf );

	return buf;
}

ngx_int_t
ngx_gluu_ox_parse_url( 
				ngx_http_request_t 	*r,
				ngx_str_t 			*uri,
				ngx_str_t 			*args ) {


	u_char 			ch, *p;
	size_t 			len, i;
	ngx_uint_t 		quoted = 0;

	len = uri->len;
	p = uri->data;

	if( len == 0 || p[0] == '?' )
		return NGX_ERROR;

	if ( p[0] == '.' && len < 1 && p[1] == '.'
		&& ( len == 2 || ngx_path_separator(p[2]) ) )
		return NGX_ERROR;

	for( i = 0; i < len; i ++ )
	{
		ch = *p ++;

		if( ch == ':' && *p ++ == '/' && *p ++ == '/')
			quoted = 1;

		if( ngx_path_separator(ch) && i > 2 ) {
			if( quoted == 1) {
				args->data = p - 1;
				args->len = ngx_strlen( args->data );
				break;
			}

		}
	}

	return NGX_OK;
}

ngx_int_t 
ox_utils_request_has_parameter( 
						ngx_http_request_t 	*r,
						const char 			*param )
{
	if( r->args.data == NULL || r->args.len == 0 )
		return NGX_ERROR;

	u_char *option1 = ngx_palloc( r->pool, sizeof(u_char *) );
	u_char *option2 = ngx_palloc( r->pool, sizeof(u_char *) );

	ngx_sprintf( option1, "%s=", param );
	ngx_sprintf( option2, "&%s=", param );

	return ( ( (u_char *)ngx_strstr( r->args.data, option1 ) == r->args.data ) 
			|| ( ngx_strstr( r->args.data, option2 ) != NULL ) ) ? NGX_OK : NGX_ERROR;
}