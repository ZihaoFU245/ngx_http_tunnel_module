#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_MIN 30
#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_MAX 62
#define NGX_HTTP_TUNNEL_MAX_PADDING_SIZE 255
#define NGX_HTTP_TUNNEL_FNV1A_OFFSET_BASIS 14695981039346656037ULL
#define NGX_HTTP_TUNNEL_FNV1A_PRIME 1099511628211ULL
#define NGX_HTTP_TUNNEL_PADDING_RESPONSE_RETRY_MAX 5
#define NGX_HTTP_TUNNEL_RST_STREAM_DATA_MIN 48
#define NGX_HTTP_TUNNEL_RST_STREAM_DATA_MAX 72

#define NGX_HTTP_TUNNEL_PADDING_READ_HEADER 0
#define NGX_HTTP_TUNNEL_PADDING_READ_PAYLOAD 1
#define NGX_HTTP_TUNNEL_PADDING_READ_DISCARD 2

static ngx_int_t is_padding_enabled(ngx_http_request_t *r);
static ngx_int_t is_padding_present(ngx_http_request_t *r);
static ngx_int_t padding_generate_response_value(ngx_http_request_t *r,
												 tunnel_padding_ctx_t *padding,
												 ngx_str_t *value);
static ngx_chain_t *padding_next_chain(ngx_http_request_t *r,
									   ngx_chain_t **chain);
static void padding_complete_downstream_frame(ngx_http_tunnel_ctx_t *ctx,
											  ngx_uint_t *activity);
static ngx_int_t padding_build_output_frame(ngx_http_tunnel_ctx_t *ctx);
static ngx_int_t padding_queue_h2_rst_stream_data(ngx_http_request_t *r);
static ngx_int_t padding_h2_send_rst_stream_precheck(ngx_http_request_t *r);
static ngx_int_t
padding_h2_rst_stream_data_handler(ngx_http_v2_connection_t *h2c,
								   ngx_http_v2_out_frame_t *frame);

ngx_int_t
tunnel_padding_needed(ngx_http_request_t *r)
{
	if (is_padding_enabled(r) != NGX_OK) {
		return NGX_DECLINED;
	}

	if (is_padding_present(r) != NGX_OK) {
		return NGX_DECLINED;
	}

	return NGX_OK;
}

size_t
tunnel_padding_buffer_size(ngx_http_request_t *r)
{
	ngx_http_tunnel_srv_conf_t *tscf;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	return ngx_min(tscf->buffer_size, (size_t)65535) + 3 +
		   NGX_HTTP_TUNNEL_MAX_PADDING_SIZE;
}

ngx_int_t
tunnel_padding_negotiate(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx)
{
	tunnel_padding_ctx_t *padding;

	if (tunnel_padding_needed(r) != NGX_OK) {
		return NGX_OK;
	}

	if (ctx == NULL || ctx->padding == NULL || ctx->padding->buffer == NULL) {
		return NGX_ERROR;
	}

	padding = ctx->padding;

	if (padding_generate_response_value(r, padding, &padding->response_value) !=
		NGX_OK) {
		return NGX_ERROR;
	}

	padding->response_ready = 1;
	padding->read_state = NGX_HTTP_TUNNEL_PADDING_READ_HEADER;

	return NGX_OK;
}

ngx_int_t
tunnel_padding_add_response_header(ngx_http_request_t *r,
								   ngx_http_tunnel_ctx_t *ctx)
{
	ngx_table_elt_t *h;
	tunnel_padding_ctx_t *padding;

	if (is_padding_enabled(r) != NGX_OK) {
		return NGX_OK;
	}

	if (ctx == NULL || ctx->padding == NULL) {
		return NGX_OK;
	}

	padding = ctx->padding;

	if (!padding->response_ready) {
		return NGX_ERROR;
	}

	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	h->hash = 1;
	h->next = NULL;
	ngx_str_set(&h->key, "padding");
	h->value = padding->response_value;

	return NGX_OK;
}

void
tunnel_padding_h2_prepend_rst_stream_data(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_http_request_t *r;

	if (tunnel_padding_active(ctx) == NGX_DECLINED) {
		return;
	}

	r = ctx->request;

	if (r->http_version != NGX_HTTP_VERSION_20 || r->stream == NULL ||
		!ctx->connected ||
		padding_h2_send_rst_stream_precheck(r) != NGX_OK) {
		return;
	}

	(void)padding_queue_h2_rst_stream_data(r);
}

ngx_int_t
tunnel_padding_send_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
	tunnel_padding_ctx_t *padding;
	size_t n;
	ngx_buf_t *dst;
	ngx_buf_t *src;
	ngx_chain_t *cl;
	ngx_http_request_t *r;

	if (tunnel_padding_active(ctx) != NGX_OK) {
		return NGX_DECLINED;
	}

	padding = ctx->padding;
	if (padding->downstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
		return NGX_DECLINED;
	}

	r = ctx->request;
	dst = ctx->client_buffer;

	for (;;) {
		cl = padding_next_chain(r, &ctx->downstream_chain);
		if (cl == NULL) {
			if (ctx->downstream_eof &&
				(padding->read_state != NGX_HTTP_TUNNEL_PADDING_READ_HEADER ||
				 padding->read_header_size != 0 || padding->payload_rest != 0 ||
				 padding->discard_rest != 0)) {
				return NGX_HTTP_BAD_REQUEST;
			}

			break;
		}

		src = cl->buf;

		switch (padding->read_state) {

		case NGX_HTTP_TUNNEL_PADDING_READ_HEADER:
			n = ngx_min((size_t)ngx_buf_size(src),
						sizeof(padding->read_header) -
							padding->read_header_size);

			ngx_memcpy(padding->read_header + padding->read_header_size,
					   src->pos, n);
			src->pos += n;
			padding->read_header_size += n;

			if (padding->read_header_size != sizeof(padding->read_header)) {
				continue;
			}

			padding->payload_rest = ((size_t)padding->read_header[0] << 8) |
									padding->read_header[1];
			padding->discard_rest = padding->read_header[2];

			padding->read_header_size = 0;

			if (padding->payload_rest != 0) {
				padding->read_state = NGX_HTTP_TUNNEL_PADDING_READ_PAYLOAD;
				continue;
			}

			if (padding->discard_rest != 0) {
				padding->read_state = NGX_HTTP_TUNNEL_PADDING_READ_DISCARD;
				continue;
			}

			padding_complete_downstream_frame(ctx, activity);
			continue;

		case NGX_HTTP_TUNNEL_PADDING_READ_PAYLOAD:
			if (dst->last == dst->end) {
				return NGX_OK;
			}

			n = ngx_min((size_t)ngx_buf_size(src), padding->payload_rest);
			n = ngx_min(n, (size_t)(dst->end - dst->last));

			if (n == 0) {
				return NGX_OK;
			}

			dst->last = ngx_cpymem(dst->last, src->pos, n);
			src->pos += n;
			padding->payload_rest -= n;
			*activity = 1;
			tunnel_utils_free_consumed_chain(r, &ctx->downstream_chain, NULL);

			if (padding->payload_rest != 0) {
				return NGX_OK;
			}

			if (padding->discard_rest != 0) {
				padding->read_state = NGX_HTTP_TUNNEL_PADDING_READ_DISCARD;
				continue;
			}

			padding_complete_downstream_frame(ctx, activity);
			continue;

		case NGX_HTTP_TUNNEL_PADDING_READ_DISCARD:
			n = ngx_min((size_t)ngx_buf_size(src), padding->discard_rest);
			src->pos += n;
			padding->discard_rest -= n;
			*activity = 1;
			tunnel_utils_free_consumed_chain(r, &ctx->downstream_chain, NULL);

			if (padding->discard_rest == 0) {
				padding_complete_downstream_frame(ctx, activity);
			}

			continue;
		}
	}

	return NGX_OK;
}

ngx_int_t
tunnel_padding_send_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
	tunnel_padding_ctx_t *padding;
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t out;
	ngx_connection_t *c;
	ngx_http_request_t *r;

	if (tunnel_padding_active(ctx) != NGX_OK) {
		return NGX_DECLINED;
	}

	padding = ctx->padding;
	if (padding->upstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
		return NGX_DECLINED;
	}

	r = ctx->request;
	c = r->connection;
	b = padding->buffer;

	if ((b == NULL || (b->pos == b->last && !padding->output_active)) &&
		ctx->upstream_buffer->pos != ctx->upstream_buffer->last) {
		rc = padding_build_output_frame(ctx);
		if (rc == NGX_DECLINED) {
			return NGX_DECLINED;
		}

		if (rc != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		b = padding->buffer;
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

		if (padding->output_active) {
			padding->output_active = 0;
			padding->upstream_count++;
			*activity = 1;
		}
	}

	if (rc == NGX_OK || rc == NGX_AGAIN) {
		return NGX_OK;
	}

	return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

static ngx_int_t
is_padding_enabled(ngx_http_request_t *r)
{
	ngx_http_tunnel_srv_conf_t *tscf;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	/* Only let HTTP2/3 support padding */
	if (!tscf->padding || !tunnel_relay_is_stream_downstream(r)) {
		return NGX_DECLINED;
	}

	return NGX_OK;
}

static ngx_int_t
is_padding_present(ngx_http_request_t *r)
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
padding_generate_response_value(ngx_http_request_t *r,
								tunnel_padding_ctx_t *padding,
								ngx_str_t *value)
{
	static u_char alphabet[] = "!#$%&'*+-.^_`|~";
	size_t alphabet_len;
	ngx_uint_t attempt;
	uint64_t hash;
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

	for (attempt = 0; attempt < NGX_HTTP_TUNNEL_PADDING_RESPONSE_RETRY_MAX;
		 attempt++) {
		hash = NGX_HTTP_TUNNEL_FNV1A_OFFSET_BASIS;

		for (i = 0; i < len; i++) {
			value->data[i] = alphabet[ngx_random() % alphabet_len];
			hash ^= value->data[i];
			hash *= NGX_HTTP_TUNNEL_FNV1A_PRIME;
		}

		if (hash != padding->previous_header_hash) {
			padding->previous_header_hash = hash;
			return NGX_OK;
		}
	}

	for (i = 0; i < alphabet_len; i++) {
		if (value->data[0] == alphabet[i]) {
			value->data[0] = alphabet[(i + 1) % alphabet_len];
			break;
		}
	}

	hash = NGX_HTTP_TUNNEL_FNV1A_OFFSET_BASIS;
	for (i = 0; i < len; i++) {
		hash ^= value->data[i];
		hash *= NGX_HTTP_TUNNEL_FNV1A_PRIME;
	}

	padding->previous_header_hash = hash;

	return NGX_OK;
}

static ngx_chain_t *
padding_next_chain(ngx_http_request_t *r, ngx_chain_t **chain)
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
padding_complete_downstream_frame(ngx_http_tunnel_ctx_t *ctx,
								  ngx_uint_t *activity)
{
	tunnel_padding_ctx_t *padding;

	padding = ctx->padding;
	padding->read_state = NGX_HTTP_TUNNEL_PADDING_READ_HEADER;
	padding->payload_rest = 0;
	padding->discard_rest = 0;
	padding->downstream_count++;
	*activity = 1;
}

static ngx_int_t
padding_build_output_frame(ngx_http_tunnel_ctx_t *ctx)
{
	tunnel_padding_ctx_t *padding;
	size_t padding_size;
	size_t payload_size;
	ngx_buf_t *dst;
	ngx_buf_t *src;

	if (tunnel_padding_active(ctx) != NGX_OK) {
		return NGX_DECLINED;
	}

	padding = ctx->padding;
	if (padding->upstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
		return NGX_DECLINED;
	}

	src = ctx->upstream_buffer;
	if (src->pos == src->last) {
		return NGX_OK;
	}

	dst = padding->buffer;
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

	padding->output_active = 1;

	return NGX_OK;
}

static ngx_int_t
padding_queue_h2_rst_stream_data(ngx_http_request_t *r)
{
	u_char *p;
	size_t frame_size;
	size_t total_size;
	ngx_buf_t *b;
	ngx_chain_t *cl;
	ngx_http_v2_stream_t *stream;
	ngx_http_v2_connection_t *h2c;
	ngx_http_v2_out_frame_t *frame;

	stream = r->stream;
	h2c = stream->connection;

	if (stream->out_closed || stream->rst_sent || h2c->connection->error) {
		return NGX_DECLINED;
	}

	total_size = NGX_HTTP_TUNNEL_RST_STREAM_DATA_MIN +
				 (ngx_random() % (NGX_HTTP_TUNNEL_RST_STREAM_DATA_MAX -
								  NGX_HTTP_TUNNEL_RST_STREAM_DATA_MIN + 1));
	frame_size = total_size - NGX_HTTP_V2_FRAME_HEADER_SIZE;

	if (frame_size < 2 || frame_size - 1 > 255) {
		return NGX_DECLINED;
	}

	if (h2c->send_window < frame_size ||
		stream->send_window < (ssize_t)frame_size) {
		return NGX_DECLINED;
	}

	frame = ngx_pcalloc(r->pool, sizeof(ngx_http_v2_out_frame_t));
	if (frame == NULL) {
		return NGX_ERROR;
	}

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	b = ngx_create_temp_buf(r->pool, total_size);
	if (b == NULL) {
		return NGX_ERROR;
	}

	b->tag = (ngx_buf_tag_t)&ngx_http_v2_module;
	b->memory = 1;
	b->flush = 1;
	b->last_buf = 1;

	p = b->last;
	p = ngx_http_v2_write_len_and_type(p, frame_size, NGX_HTTP_V2_DATA_FRAME);
	*p++ = NGX_HTTP_V2_END_STREAM_FLAG | NGX_HTTP_V2_PADDED_FLAG;
	p = ngx_http_v2_write_sid(p, stream->node->id);
	*p++ = (u_char)(frame_size - 1);
	ngx_memzero(p, frame_size - 1);
	p += frame_size - 1;
	b->last = p;

	cl->buf = b;
	cl->next = NULL;

	frame->first = cl;
	frame->last = cl;
	frame->handler = padding_h2_rst_stream_data_handler;
	frame->stream = stream;
	frame->length = frame_size;
	frame->blocked = 0;
	frame->fin = 1;

	ngx_http_v2_queue_frame(h2c, frame);
	h2c->send_window -= frame_size;
	stream->send_window -= frame_size;
	stream->queued++;
	r->connection->buffered |= NGX_HTTP_V2_BUFFERED;
	r->connection->write->active = 1;
	r->connection->write->ready = 0;

	if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
padding_h2_send_rst_stream_precheck(ngx_http_request_t *r)
{
	ngx_http_v2_stream_t *stream;
	ngx_http_v2_connection_t *h2c;

	stream = r->stream;
	h2c = stream->connection;

	if (stream->rst_sent || h2c->connection->error) {
		return NGX_DECLINED;
	}

	if (!stream->out_closed) {
		return NGX_OK;
	}

	return NGX_DECLINED;
}

static ngx_int_t
padding_h2_rst_stream_data_handler(ngx_http_v2_connection_t *h2c,
								   ngx_http_v2_out_frame_t *frame)
{
	ngx_connection_t *fc;
	ngx_event_t *wev;
	ngx_chain_t *cl;
	ngx_http_request_t *r;
	ngx_http_v2_stream_t *stream;

	if (frame->first->buf->pos != frame->first->buf->last) {
		return NGX_AGAIN;
	}

	stream = frame->stream;
	r = stream->request;
	cl = frame->first;

	r->connection->sent += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
	r->header_size += NGX_HTTP_V2_FRAME_HEADER_SIZE;
	h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
	h2c->payload_bytes += frame->length;

	if (frame->fin) {
		stream->out_closed = 1;
	}

	ngx_free_chain(r->pool, cl);

	frame->next = stream->free_frames;
	stream->free_frames = frame;
	stream->queued--;

	fc = r->connection;
	if (stream->queued == 0 && !h2c->connection->buffered) {
		fc->buffered &= ~NGX_HTTP_V2_BUFFERED;
	}

	if (!stream->waiting && !stream->blocked) {
		wev = fc->write;
		wev->active = 0;
		wev->ready = 1;

		if (fc->error || !wev->delayed) {
			ngx_post_event(wev, &ngx_posted_events);
		}
	}

	return NGX_OK;
}
