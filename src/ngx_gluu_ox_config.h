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

#ifndef __NGX_HTTP_GLUU_MODULE_CONFIG_H__
#define __NGX_HTTP_GLUU_MODULE_CONFIG_H__

/* key for storing the claims in the session context */
#define OX_CLAIMS_SESSION_KEY "claims"
/* key for storing the id_token in the session context */
#define OX_IDTOKEN_CLAIMS_SESSION_KEY "id_token_claims"
/* key for storing the raw id_token in the session context */
#define OX_IDTOKEN_SESSION_KEY "id_token"
/* key for storing the access_token in the session context */
#define OX_ACCESSTOKEN_SESSION_KEY "access_token"
/* key for storing the access_token expiry in the session context */
#define OX_ACCESSTOKEN_EXPIRES_SESSION_KEY "access_token_expires"
/* key for storing the refresh_token in the session context */
#define OX_REFRESHTOKEN_SESSION_KEY "refresh_token"
/* key for storing maximum session duration in the session context */
#define OX_SESSION_EXPIRES_SESSION_KEY "session_expires"

/* key for storing the session_state in the session context */
#define OX_SESSION_STATE_SESSION_KEY "session_state"
/* key for storing the issuer in the session context */
#define OX_ISSUER_SESSION_KEY "issuer"
/* key for storing the client_id in the session context */
#define OX_CLIENTID_SESSION_KEY "client_id"
/* key for storing the check_session_iframe in the session context */
#define OX_CHECK_IFRAME_SESSION_KEY "check_session_iframe"
/* key for storing the end_session_endpoint in the session context */
#define OX_LOGOUT_ENDPOINT_SESSION_KEY "end_session_endpoint"

/* parameter name of the callback URL in the discovery response */
#define OX_DISC_CB_PARAM "ox_callback"
/* parameter name of the OP provider selection in the discovery response */
#define OX_DISC_OP_PARAM "iss"
/* parameter name of the original URL in the discovery response */
#define OX_DISC_RT_PARAM "target_link_uri"
/* parameter name of login hint in the discovery response */
#define OX_DISC_LH_PARAM "login_hint"
/* parameter name of parameters that need to be passed in the authentication request */
#define OX_DISC_AR_PARAM "auth_request_params"

/* value that indicates to use server-side cache based session tracking */
#define OX_SESSION_TYPE_22_SERVER_CACHE 0
/* value that indicates to use client cookie based session tracking */
#define OX_SESSION_TYPE_22_CLIENT_COOKIE 1

/* pass id_token as individual claims in headers (default) */
#define OX_PASS_IDTOKEN_AS_CLAIMS     1
/* pass id_token payload as JSON object in header*/
#define OX_PASS_IDTOKEN_AS_PAYLOAD    2
/* pass id_token in compact serialized format in header*/
#define OX_PASS_IDTOKEN_AS_SERIALIZED 4

/* prefix of the cookie that binds the state in the authorization request/response to the browser */
#define OXStateCookiePrefix  "ngx_auth_ox_state_"

/* default prefix for information passed in HTTP headers */
#define OX_DEFAULT_HEADER_PREFIX "OX_"

/* the (global) key for the mod_auth_ox related state that is stored in the request userdata context */
#define OX_USERDATA_KEY "ngx__auth_ox_state"

/* input filter hook name */
#define OX_UTIL_HTTP_SENDSTRING "OX_UTIL_HTTP_SENDSTRING"

/* the name of the keyword that follows the Require primitive to indicate claims-based authorization */
#define OX_REQUIRE_NAME "claim"

/* defines for how long provider metadata will be cached */
#define OX_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT 86400

/* define the parameter value for the "logout" request that indicates a GET-style logout call from the OP */
#define OX_GET_STYLE_LOGOUT_PARAM_VALUE "get"

/* cache sections */
#define OX_CACHE_SECTION_JTI "jti"
#define OX_CACHE_SECTION_SESSION "session"
#define OX_CACHE_SECTION_NONCE "nonce"
#define OX_CACHE_SECTION_JWKS "jwks"
#define OX_CACHE_SECTION_ACCESS_TOKEN "access_token"
#define OX_CACHE_SECTION_PROVIDER "provider"





/* validate SSL server certificates by default */
#define OX_DEFAULT_SSL_VALIDATE_SERVER 1
/* default scope requested from the OP */
#define OX_DEFAULT_SCOPE "openid"
/* default claim delimiter for multi-valued claims passed in a HTTP header */
#define OX_DEFAULT_CLAIM_DELIMITER ","
/* default prefix for claim names being passed in HTTP headers */
#define OX_DEFAULT_CLAIM_PREFIX "OX_CLAIM_"
/* default name for the claim that will contain the REMOTE_USER value for OpenID Connect protected paths */
#define OX_DEFAULT_CLAIM_REMOTE_USER "sub@"
/* default name for the claim that will contain the REMOTE_USER value for OAuth 2.0 protected paths */
#define OX_DEFAULT_OAUTH_CLAIM_REMOTE_USER "sub"
/* default name of the session cookie */
#define OX_DEFAULT_COOKIE "ngx_gluu_ox_session"
/* default for the HTTP header name in which the remote user name is passed */
#define OX_DEFAULT_AUTHN_HEADER NULL
/* scrub HTTP headers by default unless overridden (and insecure) */
#define OX_DEFAULT_SCRUB_REQUEST_HEADERS 1
/* default client_name the client uses for dynamic client registration */
#define OX_DEFAULT_CLIENT_NAME "OpenID Connect Nginx Module (ngx_gluu_ox)"
/* timeouts in seconds for HTTP calls that may take a long time */
#define OX_DEFAULT_HTTP_TIMEOUT_LONG  60
/* timeouts in seconds for HTTP calls that should take a short time (registry/discovery related) */
#define OX_DEFAULT_HTTP_TIMEOUT_SHORT  5
/* default session storage type */
#define OX_DEFAULT_SESSION_TYPE OX_SESSION_TYPE_22_SERVER_CACHE
/* timeout in seconds after which state expires */
#define OX_DEFAULT_STATE_TIMEOUT 300
/* default session inactivity timeout */
#define OX_DEFAULT_SESSION_INACTIVITY_TIMEOUT 300
/* default session max duration */
#define OX_DEFAULT_SESSION_MAX_DURATION 3600 * 8
/* default OpenID Connect authorization response type */
#define OX_DEFAULT_RESPONSE_TYPE "code"
/* default duration in seconds after which retrieved JWS should be refreshed */
#define OX_DEFAULT_JWKS_REFRESH_INTERVAL 3600
/* default max cache size for shm */
#define OX_DEFAULT_CACHE_SHM_SIZE 500
/* default max cache entry size for shm: # value + # key + # overhead */
#define OX_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 16384 + 512 + 17
/* minimum size of a cache entry */
#define OX_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX 8192 + 512 + 17
/* for issued-at timestamp (iat) checking */
#define OX_DEFAULT_IDTOKEN_IAT_SLACK 600
/* for file-based caching: clean interval in seconds */
#define OX_DEFAULT_CACHE_FILE_CLEAN_INTERVAL 60
/* set httponly flag on cookies */
#define OX_DEFAULT_COOKIE_HTTPONLY 1
/* default cookie path */
#define OX_DEFAULT_COOKIE_PATH "/"
/* default OAuth 2.0 introspection token parameter name */
#define OX_DEFAULT_OAUTH_TOKEN_PARAM_NAME "token"
/* default OAuth 2.0 introspection call HTTP method */
#define OX_DEFAULT_OAUTH_ENDPOINT_METHOD "POST"
/* default OAuth 2.0 non-spec compliant introspection expiry claim name */
#define OX_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME "expires_in"
/* default OAuth 2.0 non-spec compliant introspection expiry claim format */
#define OX_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT "relative"
/* default OAuth 2.0 non-spec compliant introspection expiry claim required */
#define OX_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED 1






#endif