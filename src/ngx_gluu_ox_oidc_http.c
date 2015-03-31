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

#include "ngx_gluu_ox_oidc_http.h"

ngx_str_t* 
decoding_uri( ngx_str_t* uri )
{
	u_char *dst = {0, };
	u_char *s = {0, };
	u_char *src = {0, };

	ngx_copy( s, uri->data, uri->len);

	/* replacing '+' with '%20' */
	src = strreplace( s, '+', '%20');

	uri->data = dst;

	ngx_unescape_uri(&dst, &src, uri->len, 0);

	uri->len = dst - uri->data;

	return uri;
}

/*parse_query_string( u_char* str )
{
	if( str == NULL )
		return NULL;

	
}*/

ngx_int_t
show_html_error_message( ngx_http_request_t *r, u_char* name, u_char* msg )
{
	
	return NGX_OK;
}



