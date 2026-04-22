#include "ngx_http_tunnel_module.h"

static void tunnel_relay_cancel_downstream_read(ngx_http_tunnel_ctx_t *ctx);
static void tunnel_relay_finalize_on_error(ngx_http_request_t *r,
	ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc);

ngx_int_t
tunnel_relay_start(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_http_cleanup_t *cln;
	ngx_int_t rc;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;
	ngx_http_core_loc_conf_t *clcf;
	ngx_http_tunnel_srv_conf_t *tscf;

	r = ctx->request;
	u = r->upstream;
	c = r->connection;
	pc = u->peer.connection;

	tunnel_utils_clear_timer(pc->read);
	tunnel_utils_clear_timer(pc->write);

	r->keepalive = 0;
	c->log->action = "tunneling connection";

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (clcf->tcp_nodelay) {
		if (ngx_tcp_nodelay(pc) != NGX_OK) {
			return NGX_ERROR;
		}
	}

	rc = tunnel_relay_v2_init_request_body(ctx);
	if (rc != NGX_OK) {
		return rc;
	}

	if (tunnel_relay_send_connected(r) != NGX_OK) {
		return NGX_ERROR;
	}

	pc->read->handler = tunnel_relay_upstream_read_handler;
	pc->write->handler = tunnel_relay_upstream_write_handler;
	r->read_event_handler = tunnel_relay_downstream_read_handler;
	r->write_event_handler = tunnel_relay_downstream_write_handler;
	pc->data = ctx;

	if (!ctx->cleanup_added) {
		cln = ngx_http_cleanup_add(r, 0);
		if (cln == NULL) {
			return NGX_ERROR;
		}

		cln->handler = tunnel_relay_cleanup;
		cln->data = ctx;
		ctx->cleanup_added = 1;
	}

	ctx->connected = 1;

	tunnel_utils_update_idle_timer(pc->write, tscf->idle_timeout);
	tunnel_utils_update_idle_timer(pc->read, tscf->idle_timeout);
	tunnel_utils_update_idle_timer(c->write, tscf->idle_timeout);
	tunnel_utils_update_idle_timer(c->read, tscf->idle_timeout);

	if (pc->read->ready) {
		tunnel_relay_post_downstream_read(ctx);
		tunnel_relay_process(ctx, 1, 1);
		return NGX_OK;
	}

	tunnel_relay_process(ctx, 0, 1);

	return NGX_OK;
}

ngx_int_t
tunnel_relay_send_connected(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = -1;
	r->headers_out.content_length = NULL;
	ngx_str_set(&r->headers_out.status_line, "200 Connection Established");
	ngx_str_null(&r->headers_out.content_type);

	if (tunnel_padding_add_response_header(r, ctx) != NGX_OK) {
		return NGX_ERROR;
	}

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
		return NGX_ERROR;
	}

	/*
	 * CONNECT sends only headers plus an initial flush before switching to raw
	 * tunnel relay, so nginx's normal last-buffer path never marks the response
	 * as sent. HTTP/3 cleanup treats that as an aborted stream and resets it.
	 */
	r->response_sent = 1;

	return NGX_OK;
}

void
tunnel_relay_downstream_read_handler(ngx_http_request_t *r)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx == NULL) {
		tunnel_relay_finalize_on_error(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	ctx->downstream_read_posted = 0;
	tunnel_relay_process(ctx, 0, 0);
}

void
tunnel_relay_downstream_write_handler(ngx_http_request_t *r)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx == NULL) {
		tunnel_relay_finalize_on_error(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	tunnel_relay_process(ctx, 1, 1);
}

void
tunnel_relay_upstream_read_handler(ngx_event_t *ev)
{
	ngx_connection_t *c;
	ngx_http_tunnel_ctx_t *ctx;

	c = ev->data;
	ctx = c->data;

	tunnel_relay_process(ctx, 1, 0);
}

void
tunnel_relay_upstream_write_handler(ngx_event_t *ev)
{
	ngx_connection_t *c;
	ngx_http_tunnel_ctx_t *ctx;

	c = ev->data;
	ctx = c->data;

	tunnel_relay_process(ctx, 0, 1);
}

void
tunnel_relay_process(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t from_upstream,
						ngx_uint_t do_write)
{
	ngx_int_t rc;

	(void)from_upstream;
	(void)do_write;

	/*
	 * HTTP/3 uses the same stream-body abstraction as HTTP/2 here:
	 * request-body chains for upload and the HTTP output filter for
	 * download. Protocol-specific differences stay below nginx core.
	 */
	rc = tunnel_relay_v2_process(ctx);

	if (rc == NGX_DONE) {
		tunnel_relay_finalize(ctx, NGX_OK);
		return;
	}

	if (rc != NGX_OK) {
		tunnel_relay_finalize(ctx, rc);
	}
}

void
tunnel_relay_post_downstream_read(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_event_t *rev;

	rev = ctx->request->connection->read;

	if (rev->posted) {
		return;
	}

	ngx_post_event(rev, &ngx_posted_events);
	ctx->downstream_read_posted = 1;
}

static void
tunnel_relay_finalize_on_error(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx,
	ngx_int_t rc)
{
	/*
	 * Error finalization path for when module context might not be available.
	 * If ctx is provided, route through normal finalize; otherwise, attempt
	 * to detect and release request body ref that may have been acquired but
	 * not yet released due to early error.
	 */
	if (ctx != NULL) {
		tunnel_relay_finalize(ctx, rc);
		return;
	}

	/*
	 * ctx is NULL: check if request body ref might have been acquired
	 * (e.g., before module took full ownership). If reading_body was set,
	 * ngx_http_read_client_request_body likely incremented count.
	 * Try to balance it before finalize.
	 */
	if (r->reading_body || r->request_body != NULL) {
		if (r->main->count > 1) {
			r->main->count--;
		}
	}

	ngx_http_finalize_request(r, rc);
}

void
tunnel_relay_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
{
	ngx_http_request_t *r;

	if (ctx->finalized) {
		return;
	}

	ctx->finalized = 1;
	r = ctx->request;

	/*
	 * Release the reference acquired by ngx_http_read_client_request_body().
	 * Without this, any tunnel exit that isn't a natural client-body EOF
	 * (upstream close, timeout, relay error) leaves r->main->count above
	 * zero, so ngx_http_free_request() never runs and the request pool
	 * (tunnel buffers, padding buffer, ctx) is held until the H2/H3
	 * transport connection itself closes.
	 */
	tunnel_utils_release_request_body_ref(ctx);

	if (rc == NGX_OK && r->connection->quic) {
		/*
		 * A cleanly finished CONNECT tunnel should close only the request
		 * stream. If the read side is left open, nginx treats the stream as
		 * aborted and sends CANCEL_STREAM during close, which can escalate to
		 * closing the whole HTTP/3 connection when that send fails.
		 */
		r->connection->read->eof = 1;
	}

	tunnel_padding_h2_prepend_rst_stream_data(ctx);

	tunnel_relay_close(ctx);

	ngx_http_finalize_request(r, rc);
}

void
tunnel_relay_cleanup(void *data)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = data;
	if (ctx->finalized) {
		return;
	}

	ctx->finalized = 1;

	/*
	 * Cleanup handler called during request free. tunnel_relay_close will
	 * properly release request body ref and close tunnel. This ensures
	 * r->main->count reaches 0 cleanly even if tunnel_relay_finalize wasn't
	 * called (e.g., request aborted mid-tunnel).
	 */
	tunnel_relay_close(ctx);
}

void
tunnel_relay_close(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;

	r = ctx->request;
	c = r->connection;
	u = r->upstream;

	tunnel_relay_cancel_downstream_read(ctx);
	tunnel_utils_release_request_body_ref(ctx);

	tunnel_utils_clear_timer(c->read);
	tunnel_utils_clear_timer(c->write);

	if (u == NULL) {
		return;
	}

	/*
	 * The stream relay finalizes the HTTP request itself after taking over
	 * from upstream.  Disarm nginx upstream cleanup so request cleanup does
	 * not re-enter upstream finalization on an already closed tunnel.
	 */
	if (u->cleanup) {
		*u->cleanup = NULL;
		u->cleanup = NULL;
	}

	if (u->resolved && u->resolved->ctx) {
		ngx_resolve_name_done(u->resolved->ctx);
		u->resolved->ctx = NULL;
	}

	if (u->peer.free && u->peer.sockaddr) {
		u->peer.free(&u->peer, u->peer.data, 0);
		u->peer.sockaddr = NULL;
	}

	pc = u->peer.connection;
	if (pc != NULL) {
		tunnel_utils_clear_timer(pc->read);
		tunnel_utils_clear_timer(pc->write);

		ngx_close_connection(pc);
		u->peer.connection = NULL;
	}

}

static void
tunnel_relay_cancel_downstream_read(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_event_t *rev;

	rev = ctx->request->connection->read;

	/*
	 * The stream relay can self-post c->read as a wakeup. Remove only the
	 * event posted by this module before closing: after the request is freed,
	 * a stale relay wakeup would fire on a dead stream and re-enter request
	 * finalization.
	 */
	if (ctx->downstream_read_posted && rev->posted) {
		ngx_delete_posted_event(rev);
	}

	ctx->downstream_read_posted = 0;
	ctx->stall_wakeup_posted = 0;
}
