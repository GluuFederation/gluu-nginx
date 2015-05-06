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

#define NGX_HTTP_AUTOINDEX_PREALLOCATE 50


ngx_int_t
ngx_http_autoindex_error( 
				ngx_http_request_t 	*r,
				ngx_dir_t 			*dir,
				ngx_str_t 			*name );

/*
 * get a list of configured OX providers based on the entries 
 * in the provider metadata directory
 */
ngx_int_t
ox_metadata_list( 
	ngx_http_request_t 		*r,
	ox_cfg 					*c,
	ngx_array_t 			*list ) {

	ngx_dir_t 		dir;
	ngx_err_t 		err;
	ngx_uint_t 		level;
	ngx_int_t 		rc;

	u_char 			*filename;//, *last;
	size_t 			allocated;

	ngx_log_error( NGX_LOG_NOTICE, r->connection->log, 0, "========> entering ox_metadata_list function" );

	/* open the metadata directory */
	if( ngx_open_dir( &c->metadata_dir, &dir ) == NGX_ERROR ) {
		err = ngx_errno;

		if( err == NGX_ENOENT
			|| err == NGX_ENOTDIR
			|| err == NGX_ENAMETOOLONG ) {
			level = NGX_LOG_ERR;
			rc = NGX_HTTP_NOT_FOUND;
		} else if ( err == NGX_EACCES ){
			level = NGX_LOG_ERR;
			rc = NGX_HTTP_FORBIDDEN;
		} else {
			level = NGX_LOG_CRIT;
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_log_error( level, r->connection->log, err, 
										ngx_open_dir_n " \"%s\" failed", c->metadata_dir.data );

		return rc;
	}

	/* allocate some space in the array that will hold the list of providers */
	if( ngx_array_init(list, r->pool, 5, sizeof( ngx_str_t )) != NGX_OK ) {
		return NGX_ERROR;
	}

	/* BTW: we could estimate the number in the array based on # directory enties... */

	filename = c->metadata_dir.data;
	filename[c->metadata_dir.len] = '/';

	/* loop over the entries in the provider metadata directory */
	for( ;; ) {
		ngx_set_errno( 0 );

		if( ngx_read_dir( &dir ) == NGX_ERROR ) {
			err = ngx_errno;

			if( err != NGX_ENOMOREFILES ) {
				ngx_log_error( NGX_LOG_NOTICE, r->connection->log, err, 
										ngx_read_dir_n " \"%V\" failed", &c->metadata_dir.data );
				return ngx_http_autoindex_error( r, &dir, &c->metadata_dir );
			}

			break;
		}

		allocated = c->metadata_dir.len;

		if( ngx_de_name( &dir )[0] == '.')
			continue;

		if( !dir.valid_info ) {
			/* 1 byte for '/' and 1 byte for terminating '\0' */

			if( c->metadata_dir.len + 1 + ngx_de_namelen( &dir ) + 1 > allocated ) {
				allocated = c->metadata_dir.len + 1 + ngx_de_namelen( &dir ) + 1
												+ NGX_HTTP_AUTOINDEX_PREALLOCATE;

				filename = ngx_pnalloc( r->pool, allocated );

				if( filename == NULL ) {
					return ngx_http_autoindex_error( r, &dir, &c->metadata_dir );
				}

//				last = ngx_cpystrn( filename, c->metadata_dir.data, c->metadata_dir.len + 1 );
//				*last ++ = '/';
			}

//			ngx_cpystrn( last, ngx_de_name( &dir ), ngx_de_namelen( &dir ) + 1 );
		}
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_autoindex_error( 
				ngx_http_request_t 	*r,
				ngx_dir_t 			*dir,
				ngx_str_t 			*name ) {
	if( ngx_close_dir( dir ) == NGX_ERROR ) {
		ngx_log_error( NGX_LOG_ALERT, r->connection->log, ngx_errno, 
									ngx_close_dir_n " \"%V\"failed", name );
	}

	return r->header_sent ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * use OpenID Connect Discovery to get metadata for the specified issuer
 */
ngx_int_t
ox_metadata_provider_retrieve(
				ngx_http_request_t 	*r,
				ox_cfg				*c,
				u_char 				*issuer,
				u_char	 			*url,
				json_t 				**j_metadata,
				u_char 				**response) {

	
	return NGX_OK;
}