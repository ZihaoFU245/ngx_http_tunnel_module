#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_STREAM_MAX_ITERATIONS 16

static void ngx_http_tunnel_request_body_post_handler(ngx_http_request_t *r);
static ngx_inline void ngx_http_tunnel_stream_clear_timer(ngx_event_t *ev);
static void ngx_http_tunnel_stream_update_idle_timer(ngx_event_t *ev,
													 ngx_msec_t timeout);
static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_padding_drained(ngx_http_tunnel_ctx_t *ctx);
static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_output_idle(ngx_http_request_t *r, ngx_connection_t *c);
static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_recv_upstream_precheck(ngx_http_tunnel_ctx_t *ctx);
static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_recv_downstream_precheck(ngx_http_tunnel_ctx_t *ctx);
static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_local_work_pending(ngx_http_tunnel_ctx_t *ctx);
static ngx_int_t
ngx_http_tunnel_send_stream_downstream(ngx_http_tunnel_ctx_t *ctx,
									   ngx_uint_t *activity);
static ngx_int_t
ngx_http_tunnel_recv_stream_downstream(ngx_http_tunnel_ctx_t *ctx,
									   ngx_uint_t *activity);
static ngx_int_t
ngx_http_tunnel_fill_stream_upstream_buffer(ngx_http_tunnel_ctx_t *ctx,
											ngx_uint_t *activity);
static ngx_int_t
ngx_http_tunnel_send_stream_upstream(ngx_http_tunnel_ctx_t *ctx,
									 ngx_uint_t *activity);

ngx_int_t
ngx_http_tunnel_init_request_body(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_int_t rc;
	ngx_http_request_t *r;

	r = ctx->request;

	if (!ngx_http_tunnel_stream_downstream(r) || ctx->request_body_started) {
		return NGX_OK;
	}

	r->request_body_no_buffering = 1;

	rc = ngx_http_read_client_request_body(
		r, ngx_http_tunnel_request_body_post_handler);
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	ctx->request_body_started = 1;

	return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_process_stream(ngx_http_tunnel_ctx_t *ctx)
{
	ssize_t n;
	size_t size;
	ngx_int_t rc;
	ngx_uint_t activity;
	ngx_uint_t budget_exhausted;
	ngx_uint_t flags;
	ngx_uint_t i;
	ngx_uint_t loop_activity;
	ngx_uint_t upload_drained;
	ngx_uint_t download_drained;
	ngx_buf_t *b;
	ngx_msec_t idle_timeout;
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;
	ngx_http_core_loc_conf_t *clcf;
	ngx_http_tunnel_srv_conf_t *tscf;

	r = ctx->request;
	u = r->upstream;
	c = r->connection;
	pc = u->peer.connection;

	if (ctx->finalized) {
		return NGX_OK;
	}

	if (pc == NULL) {
		return NGX_DONE;
	}

	if (c->read->timedout || c->write->timedout || pc->read->timedout ||
		pc->write->timedout) {
		ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
					  "tunnel idle timeout");
		return NGX_DONE;
	}

	activity = 0;
	budget_exhausted = 1;

	for (i = 0; i < NGX_HTTP_TUNNEL_STREAM_MAX_ITERATIONS; i++) {
		loop_activity = 0;

		if (ngx_http_tunnel_stream_recv_downstream_precheck(ctx)) {
			rc = ngx_http_tunnel_recv_stream_downstream(ctx, &loop_activity);
			if (rc != NGX_OK) {
				return rc;
			}
		}

		rc = ngx_http_tunnel_fill_stream_upstream_buffer(ctx, &loop_activity);
		if (rc != NGX_OK) {
			return rc;
		}

		if (ctx->client_buffer->pos != ctx->client_buffer->last) {
			rc = ngx_http_tunnel_send_stream_upstream(ctx, &loop_activity);
			if (rc != NGX_OK) {
				return rc;
			}
		}

		rc = ngx_http_tunnel_send_stream_downstream(ctx, &loop_activity);
		if (rc != NGX_OK) {
			return rc;
		}

		if (loop_activity) {
			activity = 1;
		}

		if (ngx_http_tunnel_stream_recv_upstream_precheck(ctx)) {
			b = ctx->upstream_buffer;
			size = b->end - b->last;

			if (size != 0) {
				n = pc->recv(pc, b->last, size);

				if (n == NGX_AGAIN || n == 0) {
					if (n == 0) {
						pc->read->eof = 1;
					}
				} else if (n > 0) {
					b->last += n;
					loop_activity = 1;
					activity = 1;
					continue;
				} else if (n == NGX_ERROR) {
					pc->read->eof = 1;
					pc->read->error = 1;
					(void)ngx_connection_error(pc, ngx_socket_errno,
											   "tunnel upstream recv() failed");
				}
			}
		}

		if (!loop_activity) {
			budget_exhausted = 0;
			break;
		}
	}

	if (i != NGX_HTTP_TUNNEL_STREAM_MAX_ITERATIONS) {
		budget_exhausted = 0;
	}

	upload_drained = (ctx->client_buffer->pos == ctx->client_buffer->last &&
					  ctx->downstream_chain == NULL);

	download_drained =
		(ctx->upstream_buffer->pos == ctx->upstream_buffer->last &&
		 ngx_http_tunnel_stream_padding_drained(ctx) &&
		 ngx_http_tunnel_stream_output_idle(r, c));

	if (pc->read->eof && upload_drained && download_drained) {
		return NGX_DONE;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);
	idle_timeout = tscf->idle_timeout;

	if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT
													  : NGX_OK) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	flags = c->read->eof ? NGX_CLOSE_EVENT : NGX_OK;

	if (ngx_handle_read_event(c->read, flags) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (activity) {
		ngx_http_tunnel_stream_clear_timer(pc->read);
		ngx_http_tunnel_stream_clear_timer(pc->write);
		ngx_http_tunnel_stream_clear_timer(c->read);
		ngx_http_tunnel_stream_clear_timer(c->write);

		ngx_http_tunnel_stream_update_idle_timer(pc->write, idle_timeout);
		ngx_http_tunnel_stream_update_idle_timer(pc->read, idle_timeout);
		ngx_http_tunnel_stream_update_idle_timer(c->write, idle_timeout);
		ngx_http_tunnel_stream_update_idle_timer(c->read, idle_timeout);
	}

	if (budget_exhausted && ngx_http_tunnel_stream_local_work_pending(ctx)) {
		ngx_post_event(c->write, &ngx_posted_events);
	}

	return NGX_OK;
}

static ngx_inline void
ngx_http_tunnel_stream_clear_timer(ngx_event_t *ev)
{
	if (ev->timer_set) {
		ngx_del_timer(ev);
	}
}

static void
ngx_http_tunnel_stream_update_idle_timer(ngx_event_t *ev, ngx_msec_t timeout)
{
	if (ev->active && !ev->ready) {
		ngx_add_timer(ev, timeout);
		return;
	}

	ngx_http_tunnel_stream_clear_timer(ev);
}

static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_padding_drained(ngx_http_tunnel_ctx_t *ctx)
{
	return ctx->padding == NULL ||
		   ctx->padding->buffer->pos == ctx->padding->buffer->last;
}

static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_output_idle(ngx_http_request_t *r, ngx_connection_t *c)
{
	return r->out == NULL && !r->buffered && !c->buffered;
}

static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_recv_upstream_precheck(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	c = r->connection;
	pc = r->upstream->peer.connection;

	if (pc == NULL || !pc->read->ready) {
		return 0;
	}

	if (ctx->upstream_buffer->pos != ctx->upstream_buffer->last) {
		return 0;
	}

	if (!ngx_http_tunnel_stream_padding_drained(ctx)) {
		return 0;
	}

	return ngx_http_tunnel_stream_output_idle(r, c);
}

static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_recv_downstream_precheck(ngx_http_tunnel_ctx_t *ctx)
{
	return ctx->client_buffer->pos == ctx->client_buffer->last &&
		   ctx->downstream_chain == NULL && !ctx->downstream_eof;
}

static ngx_inline ngx_uint_t
ngx_http_tunnel_stream_local_work_pending(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_http_request_t *r;

	r = ctx->request;
	c = r->connection;

	if (ctx->client_buffer->pos != ctx->client_buffer->last ||
		ctx->downstream_chain != NULL ||
		ctx->upstream_buffer->pos != ctx->upstream_buffer->last) {
		return 1;
	}

	if (!ngx_http_tunnel_stream_padding_drained(ctx) ||
		!ngx_http_tunnel_stream_output_idle(r, c)) {
		return 1;
	}

	if (ngx_http_tunnel_stream_recv_downstream_precheck(ctx) ||
		ngx_http_tunnel_stream_recv_upstream_precheck(ctx)) {
		return 1;
	}

	return 0;
}

static void
ngx_http_tunnel_request_body_post_handler(ngx_http_request_t *r)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);

	if (ctx != NULL && !ctx->request_body_ref_released) {
		ctx->request_body_ref_released = 1;

		/*
		 * The tunnel already holds its own async reference from the content
		 * handler, so release the extra reference acquired by
		 * ngx_http_read_client_request_body().
		 */
		r->main->count--;
	}

	return;
}

static ngx_int_t
ngx_http_tunnel_send_stream_downstream(ngx_http_tunnel_ctx_t *ctx,
									   ngx_uint_t *activity)
{
	ngx_int_t rc;
	ngx_buf_t *b;
	u_char *before_pos;
	off_t before_sent;
	ngx_chain_t *before_out;
	ngx_uint_t before_c_buffered;
	ngx_uint_t before_r_buffered;
	ngx_chain_t out;
	ngx_connection_t *c;
	ngx_http_request_t *r;

	r = ctx->request;
	c = r->connection;
	b = ctx->upstream_buffer;

	if (ngx_http_tunnel_padding_active(ctx) == NGX_OK) {
		rc = ngx_http_tunnel_padding_send_downstream(ctx, activity);
		if (rc != NGX_DECLINED) {
			return rc;
		}
	}

	if (b->pos == b->last && r->out == NULL && !r->buffered && !c->buffered) {
		return NGX_OK;
	}

	before_pos = b->pos;
	before_sent = c->sent;
	before_out = r->out;
	before_r_buffered = r->buffered;
	before_c_buffered = c->buffered;

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

	if (b->pos == b->last && r->out == NULL && !r->buffered && !c->buffered) {
		b->pos = b->start;
		b->last = b->start;
	}

	if (rc == NGX_OK || rc == NGX_AGAIN) {
		if (c->sent != before_sent || b->pos != before_pos ||
			before_out != r->out || (before_r_buffered && !r->buffered) ||
			(before_c_buffered && !c->buffered)) {
			*activity = 1;
		}

		return NGX_OK;
	}

	return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

static ngx_int_t
ngx_http_tunnel_recv_stream_downstream(ngx_http_tunnel_ctx_t *ctx,
									   ngx_uint_t *activity)
{
	ngx_int_t rc;
	ngx_http_request_t *r;

	r = ctx->request;

	if (!ctx->request_body_started || !r->reading_body) {
		if (r->request_body != NULL && r->request_body->bufs != NULL) {
			ctx->downstream_chain = r->request_body->bufs;
			r->request_body->bufs = NULL;
			*activity = 1;
		} else if (ctx->request_body_started) {
			ctx->downstream_eof = 1;
		}

		return NGX_OK;
	}

	rc = ngx_http_read_unbuffered_request_body(r);
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	if (r->request_body != NULL && r->request_body->bufs != NULL) {
		ctx->downstream_chain = r->request_body->bufs;
		r->request_body->bufs = NULL;
		*activity = 1;
	} else if (rc == NGX_OK && !r->reading_body) {
		ctx->downstream_eof = 1;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_tunnel_fill_stream_upstream_buffer(ngx_http_tunnel_ctx_t *ctx,
											ngx_uint_t *activity)
{
	ngx_int_t rc;
	size_t n;
	ngx_chain_t *free;
	ngx_chain_t *next;
	ngx_buf_t *dst;
	ngx_buf_t *src;
	ngx_chain_t *cl;
	ngx_http_request_t *r;

	r = ctx->request;
	dst = ctx->client_buffer;
	free = NULL;

	if (ngx_http_tunnel_padding_active(ctx) == NGX_OK) {
		rc = ngx_http_tunnel_padding_fill_upstream_buffer(ctx, activity);
		if (rc != NGX_DECLINED) {
			return rc;
		}
	}

	if (dst->pos == dst->last) {
		dst->pos = dst->start;
		dst->last = dst->start;
	}

	while (dst->last < dst->end) {
		if (ctx->downstream_chain == NULL) {
			break;
		}

		cl = ctx->downstream_chain;
		src = cl->buf;
		n = ngx_buf_size(src);

		if (n == 0) {
			ctx->downstream_chain = cl->next;
			cl->next = free;
			free = cl;
			continue;
		}

		if (n > (size_t)(dst->end - dst->last)) {
			n = dst->end - dst->last;
		}

		dst->last = ngx_cpymem(dst->last, src->pos, n);
		src->pos += n;
		*activity = 1;

		if (ngx_buf_size(src) == 0) {
			ctx->downstream_chain = cl->next;
			cl->next = free;
			free = cl;
		}
	}

	while (free != NULL) {
		next = free->next;
		ngx_free_chain(r->pool, free);
		free = next;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_tunnel_send_stream_upstream(ngx_http_tunnel_ctx_t *ctx,
									 ngx_uint_t *activity)
{
	ssize_t n;
	size_t size;
	ngx_buf_t *b;
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	pc = r->upstream->peer.connection;
	b = ctx->client_buffer;

	while (b->pos != b->last && pc->write->ready) {
		size = b->last - b->pos;

		n = pc->send(pc, b->pos, size);

		if (n == NGX_ERROR) {
			return NGX_DONE;
		}

		if (n == NGX_AGAIN) {
			break;
		}

		if (n > 0) {
			b->pos += n;
			*activity = 1;

			if (b->pos == b->last) {
				b->pos = b->start;
				b->last = b->start;
			}
		}
	}

	return NGX_OK;
}
