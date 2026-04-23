#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_auth_set_proxy_authenticate(ngx_http_request_t *r)
{
	static ngx_str_t realm = ngx_string("Basic realm=\"proxy\"");

	r->headers_out.proxy_authenticate = ngx_list_push(&r->headers_out.headers);
	if (r->headers_out.proxy_authenticate == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.proxy_authenticate->hash = 1;
	r->headers_out.proxy_authenticate->next = NULL;
	ngx_str_set(&r->headers_out.proxy_authenticate->key, "Proxy-Authenticate");
	r->headers_out.proxy_authenticate->value = realm;

	return NGX_HTTP_PROXY_AUTH_REQUIRED;
}

ngx_int_t
tunnel_auth_access_denied(ngx_http_request_t *r,
						  ngx_http_tunnel_srv_conf_t *tscf)
{
	if (tscf->probe_resistance) {
		ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		h->hash = 1;
		h->next = NULL;
		ngx_str_set(&h->key, "Allow");
		ngx_str_set(&h->value, "GET, POST, HEAD, OPTIONS");

		return NGX_HTTP_NOT_ALLOWED;
	}

	return tunnel_auth_set_proxy_authenticate(r);
}

ngx_int_t
tunnel_auth_check(ngx_http_request_t *r, ngx_http_tunnel_srv_conf_t *tscf)
{
	size_t len;
	ngx_str_t auth;
	ngx_str_t decoded;
	ngx_str_t encoded;
	ngx_table_elt_t *header;
	u_char *colon;

	if (tscf->auth_username.len == 0 && tscf->auth_password.len == 0) {
		return NGX_OK;
	}

	header = r->headers_in.proxy_authorization;
	if (header == NULL) {
		return tunnel_auth_access_denied(r, tscf);
	}

	encoded = header->value;

	if (encoded.len < sizeof("Basic ") - 1 ||
		ngx_strncasecmp(encoded.data, (u_char *)"Basic ",
						sizeof("Basic ") - 1) != 0) {
		return tunnel_auth_access_denied(r, tscf);
	}

	encoded.len -= sizeof("Basic ") - 1;
	encoded.data += sizeof("Basic ") - 1;

	while (encoded.len != 0 && encoded.data[0] == ' ') {
		encoded.len--;
		encoded.data++;
	}

	if (encoded.len == 0) {
		return tunnel_auth_access_denied(r, tscf);
	}

	decoded.len = ngx_base64_decoded_length(encoded.len);
	decoded.data = ngx_pnalloc(r->pool, decoded.len + 1);
	if (decoded.data == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_decode_base64(&decoded, &encoded) != NGX_OK) {
		return tunnel_auth_access_denied(r, tscf);
	}

	decoded.data[decoded.len] = '\0';
	colon = ngx_strlchr(decoded.data, decoded.data + decoded.len, ':');
	if (colon == NULL || colon == decoded.data ||
		colon == decoded.data + decoded.len) {
		return tunnel_auth_access_denied(r, tscf);
	}

	auth.data = decoded.data;
	auth.len = colon - decoded.data;

	if (auth.len != tscf->auth_username.len ||
		ngx_strncmp(auth.data, tscf->auth_username.data, auth.len) != 0) {
		return tunnel_auth_access_denied(r, tscf);
	}

	colon++;
	len = (decoded.data + decoded.len) - colon;

	if (len != tscf->auth_password.len ||
		ngx_strncmp(colon, tscf->auth_password.data, len) != 0) {
		return tunnel_auth_access_denied(r, tscf);
	}

	return NGX_OK;
}
