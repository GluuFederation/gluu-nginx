/**
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
 **/

#include "ngx_http_gluu_ox_module.h"


ngx_int_t
ngx_gluu_ox_oidc_proto_is_redirect_authorization_response(
			 						ngx_http_request_t 			*r,
			 						ngx_gluu_ox_loc_conf_t 		*s_cfg )
{
	/* 
 	 * prereq: this is a call to the configured redirect_uri; 
 	 * see if it is a GET with stat and id_token or code parameters 
 	 */

 	 return ( ( r->method == NGX_HTTP_GET ) 
 	 			&& utils_request_has_parameter( r, "state" )
 	 			&& ( utils_request_has_parameter( r, "id_token" )
 	 						|| utils_request_has_parameter( r, "code" ) ) );


}