#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_MIN 30
#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_MAX 62

static ngx_int_t ngx_http_tunnel_padding_enabled(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_padding_present(ngx_http_request_t *r);
static ngx_int_t
ngx_http_tunnel_padding_generate_response_value(ngx_http_request_t *r,
												ngx_str_t *value);

ngx_int_t
ngx_http_tunnel_padding_negotiate(ngx_http_request_t *r,
								  ngx_http_tunnel_ctx_t *ctx)
{
	if (ngx_http_tunnel_padding_enabled(r) != NGX_OK) {
		ctx->padding_negotiated = 0;
		ctx->padding_response_ready = 0;
		return NGX_OK;
	}

	if (ngx_http_tunnel_padding_present(r) != NGX_OK) {
		ctx->padding_negotiated = 0;
		ctx->padding_response_ready = 0;
		return NGX_OK;
	}

	if (ngx_http_tunnel_padding_generate_response_value(
			r, &ctx->padding_response_value) != NGX_OK) {
		return NGX_ERROR;
	}

	ctx->padding_negotiated = 1;
	ctx->padding_response_ready = 1;

	return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_padding_add_response_header(ngx_http_request_t *r,
											ngx_http_tunnel_ctx_t *ctx)
{
	ngx_table_elt_t *h;

	if (ngx_http_tunnel_padding_enabled(r) != NGX_OK) {
		return NGX_OK;
	}

	if (ctx == NULL || !ctx->padding_negotiated) {
		return NGX_OK;
	}

	if (!ctx->padding_response_ready) {
		return NGX_ERROR;
	}

	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	h->hash = 1;
	h->next = NULL;
	ngx_str_set(&h->key, "padding");
	h->value = ctx->padding_response_value;

	return NGX_OK;
}

static ngx_int_t
ngx_http_tunnel_padding_enabled(ngx_http_request_t *r)
{
	ngx_http_tunnel_srv_conf_t *tscf;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (!tscf->padding || !ngx_http_tunnel_stream_downstream(r)) {
		return NGX_DECLINED;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_tunnel_padding_present(ngx_http_request_t *r)
{
	ngx_list_part_t *part;
	ngx_table_elt_t *header;
	ngx_uint_t i;

	part = &r->headers_in.headers.part;
	header = part->elts;

	for (i = 0;; i++) {
		u_char *key;

		if (i >= part->nelts) {
			if (part->next == NULL) {
				return NGX_DECLINED;
			}

			part = part->next;
			header = part->elts;
			i = 0;
		}

		key = (header[i].lowcase_key != NULL) ? header[i].lowcase_key
											  : header[i].key.data;

		if (header[i].key.len == sizeof("padding") - 1 &&
			ngx_strncasecmp(key, (u_char *)"padding", sizeof("padding") - 1) ==
				0) {
			return NGX_OK;
		}
	}
}

static ngx_int_t
ngx_http_tunnel_padding_generate_response_value(ngx_http_request_t *r,
												ngx_str_t *value)
{
	static u_char alphabet[] = "!#$%&'*+-.^_`|~";
	size_t alphabet_len;
	ngx_uint_t i;
	ngx_uint_t len;

	alphabet_len = sizeof(alphabet) - 1;
	len = NGX_HTTP_TUNNEL_PADDING_RESPONSE_MIN +
		  (ngx_random() % (NGX_HTTP_TUNNEL_PADDING_RESPONSE_MAX -
						   NGX_HTTP_TUNNEL_PADDING_RESPONSE_MIN + 1));

	value->data = ngx_pnalloc(r->pool, len);
	if (value->data == NULL) {
		return NGX_ERROR;
	}

	value->len = len;

	for (i = 0; i < len; i++) {
		value->data[i] = alphabet[ngx_random() % alphabet_len];
	}

	return NGX_OK;
}
