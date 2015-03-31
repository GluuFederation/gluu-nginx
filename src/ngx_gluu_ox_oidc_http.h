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


#ifndef __NGX_GLUU_OX_OIDC_HTTP_H__
#define __NGX_GLUU_OX_OIDC_HTTP_H__

#include <stdio.h>

#include "ngx_gluu_ox_oidc_utils.h"

/* Send response message (text/html) into the client.
 * On success, send either the value of 
 * a parameter success_rvalue or OK by default.
 */

ngx_int_t http_send_string( ngx_http_requests_t *r, u_char *s, nginx_int_t success_rvalue = OK );

/* Send location header to a reserved location */
ngx_int_t send_from_post( ngx_http_requests_t *r, u_char *location );
ngx_int_t http_redirect( ngx_http_requests_t *r, u_char *location );

/* Show redirect page */
ngx_int_t show_html_redirect_page( ngx_http_requests_t *r, u_char *src_location );

/* show login page with given message string */
ngx_int_t show_html_error_message( ngx_http_requests_t *r, u_char *name, u_char *msg );

/* Get a session id from cookie, if exist, put in session_id string,
 * return if no cookie, with a given name.
 */
 void get_session_id( ngx_http_requests_t *h, u_char *cookie_name, u_char *session_key, u_char **session_value );

/* Get the base location of url ( everything up to the last '/' ) */
u_char *base_dir( u_char *path );

/* Return a url without the query string */
char *get_queryless_url( char *url);

/*... ... ...*/

/* Get requests parameters whether POST or GET */
void get_request_params( ngx_http_requests_t *r, struct params_t &params );

/* Decoding url from a string */
ngx_str_t* decoding_uri( ngx_str_t* uri );

#endif