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

/*
 * return the supported flows
 */
ngx_array_t *
ox_proto_supported_flows( ngx_pool_t *pool ) {
	ngx_array_t 	*result = ngx_array_create( pool, 6, sizeof( const char * ));

	*(const char **) ngx_array_push( result ) = "code";
	*(const char **) ngx_array_push( result ) = "id_token";
	*(const char **) ngx_array_push( result ) = "id_token token";
	*(const char **) ngx_array_push( result ) = "code id_token";
	*(const char **) ngx_array_push( result ) = "code token";
	*(const char **) ngx_array_push( result ) = "code id_token token";

	return result;
}
