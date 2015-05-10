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

#ifndef _OXD_CLIENT_H
#define _OXD_CLIENT_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_inet.h>
#include <nginx.h>

u_char * 
oxd_discovery(
				ngx_http_request_t 	*r,
				ngx_str_t 			*hostinfo,
				ngx_str_t 			*discovery_url );

/*
 * connect to the remote host
 */
ngx_int_t
do_connect( 
			ngx_http_request_t 	*r,
			ngx_str_t 			*hostinfo );

/*
 * Send a request as a oxd protocol
 * Write the received response to the standard output until the EOF
 */
ngx_int_t 
do_client_task(
				ngx_http_request_t 	*r,
				int 		 		socket, 
				u_char	 			*req_str,
				u_char 				*resp_str );
#endif