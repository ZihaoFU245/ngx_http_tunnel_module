#include "ngx_http_tunnel_module.h"

/* Bound relay work per callback to keep nginx event loop responsive. */
#define NGX_HTTP_RELAY_MAX_ITERATIONS 64
#define RELAY_CHECK_PERIOD 8

static void request_body_post_handler(ngx_http_request_t *r);
static ngx_int_t recv_downstream(ngx_http_tunnel_ctx_t *ctx,
								 ngx_uint_t *activity);
static ngx_int_t send_upstream(ngx_http_tunnel_ctx_t *ctx,
							   ngx_uint_t *activity);
static ngx_int_t send_downstream(ngx_http_tunnel_ctx_t *ctx,
								 ngx_uint_t *activity);
static ngx_int_t recv_upstream(ngx_http_tunnel_ctx_t *ctx,
							   ngx_uint_t *activity);
static ngx_int_t send_client_buffer(ngx_http_tunnel_ctx_t *ctx,
									ngx_uint_t *activity);
static ngx_inline ngx_uint_t
recv_downstream_precheck(ngx_http_tunnel_ctx_t *ctx);
static ngx_inline ngx_uint_t recv_upstream_precheck(ngx_http_tunnel_ctx_t *ctx);
static ngx_inline ngx_uint_t padding_drained(ngx_http_tunnel_ctx_t *ctx);
static ngx_inline ngx_uint_t output_idle(ngx_http_request_t *r,
										 ngx_connection_t *c);
static ngx_inline ngx_uint_t is_relay_finished(ngx_http_tunnel_ctx_t *ctx,
											   ngx_http_request_t *r,
											   ngx_connection_t *c,
											   ngx_connection_t *pc,
											   ngx_uint_t *upload_drained);


ngx_int_t
tunnel_relay_v2_init_request_body(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_int_t rc;
	ngx_http_request_t *r;

	r = ctx->request;

	if (!tunnel_relay_is_stream_downstream(r) || ctx->request_body_started) {
		return NGX_OK;
	}

	r->request_body_no_buffering = 1;
	ctx->request_body_started = 1;
	ctx->request_body_ref_acquired = 1;

	rc = ngx_http_read_client_request_body(r, request_body_post_handler);
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		ctx->request_body_ref_acquired = 0;
		return rc;
	}

	return NGX_OK;
}

ngx_int_t
tunnel_relay_v2_process(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_int_t rc;
	ngx_uint_t i;
	ngx_uint_t flags;
	ngx_uint_t activity;
	ngx_uint_t loop_activity;
	ngx_uint_t upload_drained;
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

	for (i = 0; i < NGX_HTTP_RELAY_MAX_ITERATIONS; i++) {
		loop_activity = 0;

		if ((i % RELAY_CHECK_PERIOD) == 0 &&
			(ngx_terminate || ngx_quit || ngx_exiting)) {
			return NGX_DONE;
		}

		if (recv_downstream_precheck(ctx)) {
			rc = recv_downstream(ctx, &loop_activity);
			if (rc != NGX_OK) {
				return rc;
			}
		}

		if (ctx->downstream_chain != NULL ||
			ctx->client_buffer->pos != ctx->client_buffer->last ||
			(tunnel_padding_active(ctx) == NGX_OK &&
			 ctx->padding->downstream_count <
				 NGX_HTTP_TUNNEL_K_FIRST_PADDINGS)) {
			rc = send_upstream(ctx, &loop_activity);
			if (rc != NGX_OK) {
				return rc;
			}
		}

		rc = send_downstream(ctx, &loop_activity);
		if (rc != NGX_OK) {
			return rc;
		}

		if (recv_upstream_precheck(ctx)) {
			rc = recv_upstream(ctx, &loop_activity);
			if (rc != NGX_OK) {
				return rc;
			}
		}

		if (loop_activity) {
			activity = 1;
		}

		if (is_relay_finished(ctx, r, c, pc, &upload_drained)) {
			return NGX_DONE;
		}

		if (!loop_activity) {
			break;
		}
	}

	if (is_relay_finished(ctx, r, c, pc, &upload_drained)) {
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
		tunnel_utils_clear_timer(pc->read);
		tunnel_utils_clear_timer(pc->write);
		tunnel_utils_clear_timer(c->read);
		tunnel_utils_clear_timer(c->write);

		tunnel_utils_update_idle_timer(pc->write, idle_timeout);
		tunnel_utils_update_idle_timer(pc->read, idle_timeout);
		tunnel_utils_update_idle_timer(c->write, idle_timeout);
		tunnel_utils_update_idle_timer(c->read, idle_timeout);

		/*
		 * Any forward progress invalidates a pending self-post: a real
		 * event drove us this time, so allow a fresh nudge if we stall
		 * again.
		 */
		ctx->stall_wakeup_posted = 0;
	}

	/*
	 * Defensive wakeup: if the upload side is fully drained but the client
	 * body is still streaming, re-queue our downstream read handler on the
	 * next event-loop tick. On H3 in particular, a request-body arrival
	 * can get dispatched through nginx paths that do not reach
	 * r->read_event_handler, leaving this pump starved until the idle
	 * timer fires. Posting once per idle transition (guarded by
	 * stall_wakeup_posted) avoids busy-spinning inside
	 * ngx_event_process_posted while still forcing a re-check.
	 */
	if (!ctx->stall_wakeup_posted && upload_drained && r->reading_body &&
		!ctx->downstream_eof && !pc->read->eof) {
		tunnel_relay_post_downstream_read(ctx);
		ctx->stall_wakeup_posted = 1;
	}

	return NGX_OK;
}

static void
request_body_post_handler(ngx_http_request_t *r)
{
	return;
}

static ngx_int_t
recv_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
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
			tunnel_utils_release_request_body_ref(ctx);
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
		tunnel_utils_release_request_body_ref(ctx);
	}

	return NGX_OK;
}

static ngx_int_t
send_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_http_request_t *r;

	r = ctx->request;
	b = ctx->client_buffer;

	tunnel_utils_free_consumed_chain(r, &ctx->downstream_chain, NULL);

	if (b->pos != b->last) {
		return send_client_buffer(ctx, activity);
	}

	b->pos = b->start;
	b->last = b->start;

	if (tunnel_padding_active(ctx) == NGX_OK &&
		ctx->padding->downstream_count < NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
		rc = tunnel_padding_send_upstream(ctx, activity);
		if (rc != NGX_DECLINED) {
			return rc;
		}

		if (b->pos != b->last) {
			return send_client_buffer(ctx, activity);
		}
	}

	if (ctx->downstream_chain == NULL || b->last == b->end) {
		return NGX_OK;
	}

	if (tunnel_utils_copy_chain_to_buffer(r, &ctx->downstream_chain, b,
										  (size_t)-1)) {
		*activity = 1;
	}

	if (b->pos != b->last) {
		return send_client_buffer(ctx, activity);
	}

	return NGX_OK;
}

static ngx_int_t
send_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
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

	if (tunnel_padding_active(ctx) == NGX_OK) {
		rc = tunnel_padding_send_downstream(ctx, activity);
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
recv_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
	ssize_t n;
	size_t size;
	ngx_buf_t *b;
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	pc = r->upstream->peer.connection;
	b = ctx->upstream_buffer;
	size = b->end - b->last;

	if (size == 0) {
		return NGX_OK;
	}

	n = pc->recv(pc, b->last, size);

	if (n == NGX_AGAIN) {
		return NGX_OK;
	}

	if (n == 0) {
		pc->read->eof = 1;
		pc->read->ready = 0;
		return NGX_OK;
	}

	if (n > 0) {
		b->last += n;
		*activity = 1;
		return NGX_OK;
	}

	pc->read->eof = 1;
	pc->read->error = 1;
	pc->read->ready = 0;

	return NGX_OK;
}

static ngx_int_t
send_client_buffer(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
	ssize_t n;
	size_t size;
	ngx_buf_t *b;
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	pc = r->upstream->peer.connection;
	b = ctx->client_buffer;

	if (!pc->write->ready) {
		return NGX_OK;
	}

	size = b->last - b->pos;
	if (size == 0) {
		return NGX_OK;
	}

	n = pc->send(pc, b->pos, size);
	if (n == NGX_ERROR) {
		return NGX_DONE;
	}

	if (n > 0) {
		b->pos += n;
		*activity = 1;

		if (b->pos == b->last) {
			b->pos = b->start;
			b->last = b->start;
			tunnel_utils_free_consumed_chain(r, &ctx->downstream_chain, NULL);
		}
	}

	return NGX_OK;
}

static ngx_inline ngx_uint_t
recv_downstream_precheck(ngx_http_tunnel_ctx_t *ctx)
{
	return ctx->downstream_chain == NULL && !ctx->downstream_eof;
}

static ngx_inline ngx_uint_t
recv_upstream_precheck(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	pc = r->upstream->peer.connection;

	if (pc == NULL || !pc->read->ready) {
		return 0;
	}

	if (ctx->upstream_buffer->pos != ctx->upstream_buffer->last) {
		return 0;
	}

	if (!padding_drained(ctx)) {
		return 0;
	}

	/*
	 * Historically this also required output_idle (r->out == NULL &&
	 * !r->buffered && !c->buffered). That gate starved H3 download: QUIC
	 * keeps c->buffered set while frames sit in its internal queue, so the
	 * precheck could never pass and no further upstream bytes were pulled.
	 *
	 * Dropping the output_idle condition is safe because upstream_buffer
	 * reuse is already guarded: the send path only rewinds the buffer when
	 * r->out == NULL && !r->buffered && !c->buffered (see
	 * send_downstream below), so the filter cannot still reference bytes
	 * past b->last. Bytes written by this recv land at b->last..b->end,
	 * which the filter has not observed.
	 */
	return 1;
}

static ngx_inline ngx_uint_t
padding_drained(ngx_http_tunnel_ctx_t *ctx)
{
	return ctx->padding == NULL ||
		   ctx->padding->buffer->pos == ctx->padding->buffer->last;
}

static ngx_inline ngx_uint_t
output_idle(ngx_http_request_t *r, ngx_connection_t *c)
{
	return r->out == NULL && !r->buffered && !c->buffered;
}

static ngx_inline ngx_uint_t
is_relay_finished(ngx_http_tunnel_ctx_t *ctx, ngx_http_request_t *r,
				  ngx_connection_t *c, ngx_connection_t *pc,
				  ngx_uint_t *upload_drained)
{
	ngx_uint_t download_drained;

	*upload_drained = (ctx->downstream_chain == NULL &&
					   ctx->client_buffer->pos == ctx->client_buffer->last);

	download_drained =
		(ctx->upstream_buffer->pos == ctx->upstream_buffer->last &&
		 padding_drained(ctx) && output_idle(r, c));

	return ((pc->read->eof || ctx->downstream_eof) && *upload_drained &&
			download_drained);
}

