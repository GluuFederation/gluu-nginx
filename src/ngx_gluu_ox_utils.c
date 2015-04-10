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

#include "ngx_gluu_ox_utils.h"

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

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "======= escape_title : %s======\n", escape_title );

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


/*
 * read the POST parameters in to a table
 */
/*
ngx_int_t
ox_utils_read_post_params( 
			ngx_http_request_t 	*r, 
			ngx_table_elt_t 	*table )
{
	const u_char *data = NULL;

	if( r->method != NGX_HTTP_POST )
		return NGX_ERROR;

//	if( ox_utils_read( r, &data ) != NGX_OK )
//		return NGX_ERROR;

	return ox_utils_read_from_encoded_params( r, table, data );
}
*/

/*
 * read all bytes from the HTTP request
 */
/*
ngx_int_t
ox_utils_read( 
		ngx_http_request_t 	*r, 
		ngx_table_elt_t 	*table )
{

	if( r->headers_out.content_type.len == 0 )
		return NGX_ERROR;
	else
	{

	}
	return NGX_OK;
}
*/

ngx_params_t *
ox_utils_init_array()
{
	ngx_params_t	*params = ( ngx_params_t *)malloc( sizeof( ngx_params_t ) * sizeof( params ) );
	ngx_uint_t i = 0;

	if( params == NULL )
		return NULL;

	for ( i = 0; i < sizeof(params); ++i )
	{
		params[i].key = NULL;
		params[i].value = NULL;
	}

	return params;
}

ngx_int_t
ox_utils_push_data( 
			ngx_params_t 	*data,
			u_char 			*key,
			u_char 			*value )
{
	ngx_int_t 	index = -1;
	ngx_int_t 	i;

	for ( i = 0; i < (ngx_int_t) sizeof( data ); ++i )
	{
		/* code */
		if( data[i].key == NULL || data[i].value == NULL )
		{
			index = i;
			break;
		}
	}

	if( index < 0 )
		index = sizeof( data );
	
	if( key != NULL || value != NULL )
	{
		data[index].key = key;
		data[index].value = value;
	}

	return index;
}

u_char *
ox_utils_find_array_value(
			ngx_params_t 	*data,
			u_char			*key )
{
	ngx_int_t 	num = sizeof( data );
	u_char 		*rc;
	int i;

	rc = (u_char *)malloc( sizeof( u_char * ) );

	if( key == NULL || ngx_strlen( key ) == 0 )
		return rc;

	if( num > 0 )
	{
		for ( i = 0; i < num; ++i )
		{
			if( data[i].key == NULL || data[i].value == NULL )
				continue;

			if( ngx_strcasecmp( data[i].key, key ) == 0 )
			{
//				ngx_cpystrn( rc, data[i].value, ngx_strlen( data[i].value ) + 1 );
				rc = data[i].value;
				
				break;
			}
		}
	}

	return rc;
}

ngx_int_t
ox_utils_read_params( 
			ngx_http_request_t 	*r, 
			ngx_params_t 	*table )
{
	if( r->method == NGX_HTTP_GET && r->args.data != NULL )
	{
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, 
					"ox_utils_read_params:NGX_HTTP_GET [args 		 : %s]\n", 
					r->args.data ? r->args.data : (u_char *)"" );
		return ox_utils_read_from_encoded_params( r, table, r->args.data );
	}
	else if( r->method == NGX_HTTP_POST)
	{
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, 
					"ox_utils_read_params:NGX_HTTP_POST [args 		 : %s]\n", 
					r->args.data ? r->args.data : (u_char *)"" );

		return NGX_OK;
	}

	return NGX_HTTP_NOT_ALLOWED;
}

/*
 * read form-encoded parameters from a string in to a table
 */
ngx_int_t 
ox_utils_read_from_encoded_params( 
						ngx_http_request_t 	*r,
						ngx_params_t 		*params,
						const u_char 		*data )
{
	u_char *key = NULL, *val = NULL;

	while ( data && *data && ( val = ox_utils_get_word( &data, '&' ) ) ) {
		key = ox_utils_get_word( (const u_char **)&val, '=' );
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, 
					"ox_utils_read_from_encoded_params [key : %s, val : %s]\n", 
					key, val );
		key = ox_utils_unescape_string( r, key );
		val = ox_utils_unescape_string( r, val );

		ox_utils_push_data( params, key, val );
	}

	return NGX_OK;
}
/*
 * Copies everything from line up to stop to a new string.
 */
u_char *
ox_utils_get_word( const u_char **line, u_char stop )
{
	const u_char *pos = *line;
	ngx_int_t len = 0;
	u_char *res = NULL;

	while (( *pos != stop ) && *pos )
	{
		++pos;
	}

	len = pos - *line;

	res = (u_char *)malloc( len + 1 );
	ngx_memcpy( res, *line, len );
	res[len] = 0;

	if( stop ) {
		while( *pos == stop ){
			++ pos;
		}
	}
	*line = pos;

	return res;
}

/*
 * unescape a string
 */
u_char *
ox_utils_unescape_string( ngx_http_request_t *r, const u_char *str )
{
	CURL *curl = curl_easy_init();
	ngx_str_t 	result;

	if( curl == NULL )
	{
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "curl_easy_init() error" );
		return NULL;
	}

	char *s = NULL;
	ngx_memcpy( s, str, ngx_strlen( str ) + 1 );

	char *rs = curl_easy_unescape( curl, s, 0, 0 );

	if( rs == NULL ) {
		ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "curl_easy_unescape() error" );
		return NULL;	
	}

	ngx_memcpy( result.data, rs, ngx_strlen( s ) + 1 );
	result.len = ngx_strlen( s );
//	ngx_str_null( result );
//	ngx_str_set( result, s );

	u_char *rv = ngx_pstrdup( r->pool, &result );

	curl_free( rs );
	curl_easy_cleanup( curl );

	return rv;
}


/*
 * read the POST parameters in to a table;
 */
/*u_char* strreplace( u_char* str, u_char find, u_char rep )
{
	int i = 0;

	u_char *s = str;

	while( s[i] != '\0' )
	{
		if( s[i] == chr )
		{
			s[i] = rep;
		}
		i ++;
	}

	return s;
}*/

/*
u_char* strreplace( u_char* str, u_char find, u_char* rep )
{
	u_char *ret = str;
	u_char *wk, *s;

	wk = s = strdup( (const char*)str );

	while ( *s != 0 )
	{
		if( *s == find )
		{
			while( *rep )
				*str++ = * rep++;
			++s;
		}
		else
			*str++ = *s++;
	}

	*str = '\0';
	free(wk);

	return ret;
}*/

