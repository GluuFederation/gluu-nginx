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

#include "ngx_gluu_ox_oidc_utils.h"

u_char* strreplace( u_char* str, u_char find, u_char rep )
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
}

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
}

