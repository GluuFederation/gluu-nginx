#ifndef __NGX_GLUU_OX_UTILS_H__
#define __NGX_GLUU_OX_UTILS_H__

#include <stdio.h>

#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t
ox_util_html_send_error( 
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

/*
 * read the POST parameters in to a array
 */
ngx_int_t
ox_utils_read_post_params( 
			ngx_http_request_t 	*r, 
			ngx_table_elt_t 	*table );

/*
 * read form-encoded parameters from a string in to a array
 */
ngx_int_t 
ox_util_read_from_encoded_params( 
						ngx_http_request_t 	*r,
						ngx_table_elt_t 	*table,
						const u_char 		*data );

/*
 * Copies everything from line up to stop to a new string.
 */
u_char *
ox_utils_get_word( const u_char **line, u_char stop );

u_char *
ox_utils_unescape_string( ngx_http_request_t *r, const u_char *str );

//u_char* strreplace( u_char* str, u_char find, u_char rep );
u_char* strreplace( u_char* s, u_char find, u_char* rep );

#endif