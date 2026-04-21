#include "ngx_http_tunnel_module.h"

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

	ctx->connected = 1;
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

	tunnel_utils_update_idle_timer(pc->write, tscf->idle_timeout);
	tunnel_utils_update_idle_timer(pc->read, tscf->idle_timeout);
	tunnel_utils_update_idle_timer(c->write, tscf->idle_timeout);
	tunnel_utils_update_idle_timer(c->read, tscf->idle_timeout);

	if (pc->read->ready) {
		ngx_post_event(c->read, &ngx_posted_events);
		tunnel_relay_process(ctx, 1, 1);
		return NGX_OK;
	}

	tunnel_relay_process(ctx, 0, 1);

	return NGX_OK;
}

ngx_int_t
tunnel_relay_is_stream_downstream(ngx_http_request_t *r)
{
	return r->http_version == NGX_HTTP_VERSION_20 ||
		   r->http_version == NGX_HTTP_VERSION_30;
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
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	tunnel_relay_process(ctx, 0, 0);
}

void
tunnel_relay_downstream_write_handler(ngx_http_request_t *r)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
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
tunnel_relay_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
{
	ngx_http_request_t *r;

	if (ctx->finalized) {
		return;
	}

	ctx->finalized = 1;
	r = ctx->request;

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

	tunnel_relay_close(ctx);
}

void
tunnel_relay_close(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	c = r->connection;

	tunnel_utils_clear_timer(c->read);
	tunnel_utils_clear_timer(c->write);

	pc = (r->upstream != NULL) ? r->upstream->peer.connection : NULL;
	if (pc != NULL) {
		tunnel_utils_clear_timer(pc->read);
		tunnel_utils_clear_timer(pc->write);

		ngx_close_connection(pc);
		r->upstream->peer.connection = NULL;
	}

}
