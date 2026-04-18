#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_MIN 30
#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_MAX 62
#define NGX_HTTP_TUNNEL_FIRST_PADDINGS 8
#define NGX_HTTP_TUNNEL_MAX_PADDING_SIZE 255

#define NGX_HTTP_TUNNEL_PADDING_READ_HEADER 0
#define NGX_HTTP_TUNNEL_PADDING_READ_PAYLOAD 1
#define NGX_HTTP_TUNNEL_PADDING_READ_DISCARD 2

static ngx_int_t ngx_http_tunnel_padding_enabled(ngx_http_request_t *r);
static ngx_int_t
ngx_http_tunnel_padding_relay_active(ngx_http_tunnel_ctx_t *ctx);
static ngx_int_t ngx_http_tunnel_padding_present(ngx_http_request_t *r);
static ngx_int_t
ngx_http_tunnel_padding_generate_response_value(ngx_http_request_t *r,
												ngx_str_t *value);
static ngx_chain_t *ngx_http_tunnel_padding_next_chain(ngx_http_request_t *r,
													   ngx_chain_t **chain);
static void
ngx_http_tunnel_padding_complete_downstream_frame(ngx_http_tunnel_ctx_t *ctx,
												  ngx_uint_t *activity);
static ngx_int_t
ngx_http_tunnel_padding_build_output_frame(ngx_http_tunnel_ctx_t *ctx);

ngx_int_t
ngx_http_tunnel_padding_negotiate(ngx_http_request_t *r,
								  ngx_http_tunnel_ctx_t *ctx)
{
	ngx_http_tunnel_srv_conf_t *tscf;
	size_t size;

	ctx->padding_negotiated = 0;
	ctx->padding_response_ready = 0;

	if (ngx_http_tunnel_padding_enabled(r) != NGX_OK) {
		return NGX_OK;
	}

	if (ngx_http_tunnel_padding_present(r) != NGX_OK) {
		return NGX_OK;
	}

	if (ngx_http_tunnel_padding_generate_response_value(
			r, &ctx->padding_response_value) != NGX_OK) {
		return NGX_ERROR;
	}

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);
	size = ngx_min(tscf->buffer_size, (size_t)65535) + 3 +
		   NGX_HTTP_TUNNEL_MAX_PADDING_SIZE;

	ctx->padding_buffer = ngx_create_temp_buf(r->pool, size);
	if (ctx->padding_buffer == NULL) {
		return NGX_ERROR;
	}

	ctx->padding_negotiated = 1;
	ctx->padding_response_ready = 1;
	ctx->padding_read_state = NGX_HTTP_TUNNEL_PADDING_READ_HEADER;

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

ngx_int_t
ngx_http_tunnel_padding_fill_upstream_buffer(ngx_http_tunnel_ctx_t *ctx,
											 ngx_uint_t *activity)
{
	size_t capacity;
	size_t n;
	ngx_buf_t *dst;
	ngx_buf_t *src;
	ngx_chain_t *cl;
	ngx_http_request_t *r;

	r = ctx->request;
	dst = ctx->client_buffer;
	capacity = dst->end - dst->start;

	if (ctx->downstream_padding_count >= NGX_HTTP_TUNNEL_FIRST_PADDINGS) {
		return NGX_DECLINED;
	}

	if (dst->pos == dst->last) {
		dst->pos = dst->start;
		dst->last = dst->start;
	}

	for (;;) {
		cl = ngx_http_tunnel_padding_next_chain(r, &ctx->downstream_chain);
		if (cl == NULL) {
			if (ctx->downstream_eof &&
				(ctx->padding_read_state !=
					 NGX_HTTP_TUNNEL_PADDING_READ_HEADER ||
				 ctx->padding_read_header_size != 0 ||
				 ctx->padding_payload_rest != 0 ||
				 ctx->padding_discard_rest != 0)) {
				return NGX_HTTP_BAD_REQUEST;
			}

			break;
		}

		src = cl->buf;

		switch (ctx->padding_read_state) {

		case NGX_HTTP_TUNNEL_PADDING_READ_HEADER:
			n = ngx_min((size_t)ngx_buf_size(src),
						sizeof(ctx->padding_read_header) -
							ctx->padding_read_header_size);

			ngx_memcpy(ctx->padding_read_header + ctx->padding_read_header_size,
					   src->pos, n);
			src->pos += n;
			ctx->padding_read_header_size += n;

			if (ctx->padding_read_header_size !=
				sizeof(ctx->padding_read_header)) {
				continue;
			}

			ctx->padding_payload_rest =
				((size_t)ctx->padding_read_header[0] << 8) |
				ctx->padding_read_header[1];
			ctx->padding_discard_rest = ctx->padding_read_header[2];

			if (ctx->padding_payload_rest > capacity) {
				return NGX_HTTP_BAD_REQUEST;
			}

			ctx->padding_read_header_size = 0;

			if (ctx->padding_payload_rest != 0) {
				ctx->padding_read_state = NGX_HTTP_TUNNEL_PADDING_READ_PAYLOAD;
				continue;
			}

			if (ctx->padding_discard_rest != 0) {
				ctx->padding_read_state = NGX_HTTP_TUNNEL_PADDING_READ_DISCARD;
				continue;
			}

			ngx_http_tunnel_padding_complete_downstream_frame(ctx, activity);
			continue;

		case NGX_HTTP_TUNNEL_PADDING_READ_PAYLOAD:
			if (dst->last == dst->end) {
				return NGX_OK;
			}

			n = ngx_min((size_t)ngx_buf_size(src), ctx->padding_payload_rest);
			n = ngx_min(n, (size_t)(dst->end - dst->last));

			dst->last = ngx_cpymem(dst->last, src->pos, n);
			src->pos += n;
			ctx->padding_payload_rest -= n;

			if (ctx->padding_payload_rest != 0) {
				if (dst->last == dst->end) {
					return NGX_OK;
				}

				continue;
			}

			if (ctx->padding_discard_rest != 0) {
				ctx->padding_read_state = NGX_HTTP_TUNNEL_PADDING_READ_DISCARD;
				continue;
			}

			ngx_http_tunnel_padding_complete_downstream_frame(ctx, activity);
			continue;

		case NGX_HTTP_TUNNEL_PADDING_READ_DISCARD:
			n = ngx_min((size_t)ngx_buf_size(src), ctx->padding_discard_rest);
			src->pos += n;
			ctx->padding_discard_rest -= n;

			if (ctx->padding_discard_rest == 0) {
				ngx_http_tunnel_padding_complete_downstream_frame(ctx,
																  activity);
			}

			continue;
		}
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_padding_send_downstream(ngx_http_tunnel_ctx_t *ctx,
										ngx_uint_t *activity)
{
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_connection_t *c;
	ngx_http_request_t *r;

	r = ctx->request;
	c = r->connection;
	b = ctx->padding_buffer;

	if (ctx->upstream_padding_count >= NGX_HTTP_TUNNEL_FIRST_PADDINGS) {
		return NGX_DECLINED;
	}

	if ((b == NULL || (b->pos == b->last && !ctx->padding_output_active)) &&
		ctx->upstream_buffer->pos != ctx->upstream_buffer->last) {
		if (ngx_http_tunnel_padding_build_output_frame(ctx) != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	if ((b == NULL || b->pos == b->last) && r->out == NULL && !r->buffered &&
		!c->buffered) {
		return NGX_OK;
	}

	if (r->out != NULL || r->buffered || c->buffered) {
		rc = ngx_http_output_filter(r, NULL);
	} else {
		out.buf = b;
		out.next = NULL;

		b->flush = 1;
		rc = ngx_http_output_filter(r, &out);
		b->flush = 0;
	}

	if (rc == NGX_ERROR) {
		return NGX_DONE;
	}

	if (b != NULL && b->pos == b->last && r->out == NULL && !r->buffered &&
		!c->buffered) {
		b->pos = b->start;
		b->last = b->start;

		if (ctx->padding_output_active) {
			ctx->padding_output_active = 0;
			ctx->upstream_padding_count++;
			*activity = 1;
		}
	}

	if (rc == NGX_OK || rc == NGX_AGAIN) {
		*activity = 1;
		return NGX_OK;
	}

	return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
ngx_http_tunnel_padding_relay_active(ngx_http_tunnel_ctx_t *ctx)
{
	if (ctx == NULL || !ctx->padding_negotiated) {
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
	u_char *key;

	part = &r->headers_in.headers.part;
	header = part->elts;

	for (i = 0;; i++) {
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

static ngx_chain_t *
ngx_http_tunnel_padding_next_chain(ngx_http_request_t *r, ngx_chain_t **chain)
{
	ngx_chain_t *cl;

	for (;;) {
		cl = *chain;
		if (cl == NULL) {
			return NULL;
		}

		if (ngx_buf_size(cl->buf) != 0) {
			return cl;
		}

		*chain = cl->next;
		ngx_free_chain(r->pool, cl);
	}
}

static void
ngx_http_tunnel_padding_complete_downstream_frame(ngx_http_tunnel_ctx_t *ctx,
												  ngx_uint_t *activity)
{
	ctx->padding_read_state = NGX_HTTP_TUNNEL_PADDING_READ_HEADER;
	ctx->padding_payload_rest = 0;
	ctx->padding_discard_rest = 0;
	ctx->downstream_padding_count++;
	*activity = 1;
}

static ngx_int_t
ngx_http_tunnel_padding_build_output_frame(ngx_http_tunnel_ctx_t *ctx)
{
	size_t padding_size;
	size_t payload_size;
	ngx_buf_t *dst;
	ngx_buf_t *src;

	if (ngx_http_tunnel_padding_relay_active(ctx) != NGX_OK ||
		ctx->upstream_padding_count >= NGX_HTTP_TUNNEL_FIRST_PADDINGS) {
		return NGX_DECLINED;
	}

	src = ctx->upstream_buffer;
	if (src->pos == src->last) {
		return NGX_OK;
	}

	dst = ctx->padding_buffer;
	dst->pos = dst->start;
	dst->last = dst->start;

	payload_size = ngx_min((size_t)(src->last - src->pos), (size_t)65535);
	padding_size = ngx_random() % (NGX_HTTP_TUNNEL_MAX_PADDING_SIZE + 1);

	*dst->last++ = (u_char)(payload_size >> 8);
	*dst->last++ = (u_char)payload_size;
	*dst->last++ = (u_char)padding_size;
	dst->last = ngx_cpymem(dst->last, src->pos, payload_size);
	ngx_memzero(dst->last, padding_size);
	dst->last += padding_size;

	src->pos += payload_size;
	if (src->pos == src->last) {
		src->pos = src->start;
		src->last = src->start;
	}

	ctx->padding_output_active = 1;

	return NGX_OK;
}
