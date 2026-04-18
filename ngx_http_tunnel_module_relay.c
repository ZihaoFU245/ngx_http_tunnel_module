#include "ngx_http_tunnel_module.h"

static ngx_int_t ngx_http_tunnel_process_raw(ngx_http_tunnel_ctx_t *ctx,
											 ngx_uint_t from_upstream,
											 ngx_uint_t do_write);
static void ngx_http_tunnel_clear_timer(ngx_event_t *ev);
static void ngx_http_tunnel_update_idle_timer(ngx_event_t *ev,
											  ngx_msec_t timeout);
static void ngx_http_tunnel_close(ngx_http_tunnel_ctx_t *ctx);

ngx_int_t
ngx_http_tunnel_start(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_int_t rc;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;
	ngx_http_core_loc_conf_t *clcf;

	r = ctx->request;
	u = r->upstream;
	c = r->connection;
	pc = u->peer.connection;

	ngx_http_tunnel_clear_timer(pc->read);
	ngx_http_tunnel_clear_timer(pc->write);

	ctx->waiting_connect = 0;
	ctx->connected = 1;
	r->keepalive = 0;
	c->log->action = "tunneling connection";

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	if (clcf->tcp_nodelay) {
		if (ngx_tcp_nodelay(pc) != NGX_OK) {
			return NGX_ERROR;
		}

		if (!ngx_http_tunnel_stream_downstream(r) &&
			ngx_tcp_nodelay(c) != NGX_OK) {
			return NGX_ERROR;
		}
	}

	rc = ngx_http_tunnel_init_request_body(ctx);
	if (rc != NGX_OK) {
		return rc;
	}

	if (ngx_http_tunnel_send_connected(r) != NGX_OK) {
		return NGX_ERROR;
	}

	pc->read->handler = ngx_http_tunnel_upstream_read_handler;
	pc->write->handler = ngx_http_tunnel_upstream_write_handler;
	r->read_event_handler = ngx_http_tunnel_downstream_read_handler;
	r->write_event_handler = ngx_http_tunnel_downstream_write_handler;

	if (pc->read->ready) {
		ngx_post_event(c->read, &ngx_posted_events);
		ngx_http_tunnel_process(ctx, 1, 1);
		return NGX_OK;
	}

	ngx_http_tunnel_process(ctx, 0, 1);

	return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_send_connected(ngx_http_request_t *r)
{
	ngx_int_t rc;

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = -1;
	r->headers_out.content_length = NULL;
	ngx_str_set(&r->headers_out.status_line, "200 Connection Established");
	ngx_str_null(&r->headers_out.content_type);

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

void
ngx_http_tunnel_downstream_read_handler(ngx_http_request_t *r)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	ngx_http_tunnel_process(ctx, 0, 0);
}

void
ngx_http_tunnel_downstream_write_handler(ngx_http_request_t *r)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx == NULL) {
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	ngx_http_tunnel_process(ctx, 1, 1);
}

void
ngx_http_tunnel_upstream_read_handler(ngx_event_t *ev)
{
	ngx_connection_t *c;
	ngx_http_tunnel_ctx_t *ctx;

	c = ev->data;
	ctx = c->data;

	ngx_http_tunnel_process(ctx, 1, 0);
}

void
ngx_http_tunnel_upstream_write_handler(ngx_event_t *ev)
{
	ngx_connection_t *c;
	ngx_http_tunnel_ctx_t *ctx;

	c = ev->data;
	ctx = c->data;

	ngx_http_tunnel_process(ctx, 0, 1);
}

void
ngx_http_tunnel_process(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t from_upstream,
						ngx_uint_t do_write)
{
	ngx_int_t rc;

	if (ngx_http_tunnel_stream_downstream(ctx->request)) {
		rc = ngx_http_tunnel_process_stream(ctx);
	} else {
		rc = ngx_http_tunnel_process_raw(ctx, from_upstream, do_write);
	}

	if (rc == NGX_DONE) {
		ngx_http_tunnel_finalize(ctx, NGX_OK);
		return;
	}

	if (rc != NGX_OK) {
		ngx_http_tunnel_finalize(ctx, rc);
	}
}

static ngx_int_t
ngx_http_tunnel_process_raw(ngx_http_tunnel_ctx_t *ctx,
							ngx_uint_t from_upstream, ngx_uint_t do_write)
{
	size_t size;
	ssize_t n;
	ngx_uint_t buffers_drained;
	ngx_buf_t *b;
	ngx_msec_t idle_timeout;
	ngx_uint_t flags;
	ngx_uint_t activity;
	ngx_connection_t *c, *dst, *pc, *src;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;
	ngx_http_core_loc_conf_t *clcf;
	ngx_http_tunnel_srv_conf_t *tscf;

	r = ctx->request;
	u = r->upstream;
	c = r->connection;
	pc = u->peer.connection;

	if (ctx->finalized || pc == NULL) {
		return NGX_DONE;
	}

	if (c->read->timedout || c->write->timedout || pc->read->timedout ||
		pc->write->timedout) {
		ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
					  "tunnel idle timeout");
		return NGX_DONE;
	}

	activity = 0;

	if (from_upstream) {
		src = pc;
		dst = c;
		b = ctx->upstream_buffer;
	} else {
		src = c;
		dst = pc;
		b = ctx->client_buffer;
	}

	for (;;) {
		if (do_write) {
			size = b->last - b->pos;

			if (size != 0 && dst->write->ready) {
				n = dst->send(dst, b->pos, size);

				if (n == NGX_ERROR) {
					return NGX_DONE;
				}

				if (n > 0) {
					b->pos += n;
					activity = 1;

					if (b->pos == b->last) {
						b->pos = b->start;
						b->last = b->start;
					}
				}
			}
		}

		size = b->end - b->last;

		if (size != 0 && src->read->ready) {
			n = src->recv(src, b->last, size);

			if (n == NGX_AGAIN || n == NGX_OK) {
				if (n == NGX_OK) {
					src->read->eof = 1;
				}

				break;
			}

			if (n > 0) {
				b->last += n;
				do_write = 1;
				activity = 1;
				continue;
			}

			if (n == NGX_ERROR) {
				src->read->eof = 1;
				src->read->error = 1;
				(void)ngx_connection_error(src, ngx_socket_errno,
									  from_upstream
										  ? "tunnel upstream recv() failed"
										  : "tunnel downstream recv() failed");
			}
		}

		break;
	}

	buffers_drained =
		(ctx->upstream_buffer->pos == ctx->upstream_buffer->last &&
		 ctx->client_buffer->pos == ctx->client_buffer->last);

	if ((pc->read->eof || c->read->eof) && buffers_drained) {
		return NGX_DONE;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);
	idle_timeout = tscf->idle_timeout;

	if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT : 0) !=
		NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	flags = c->read->eof ? NGX_CLOSE_EVENT : 0;

	if (ngx_handle_read_event(c->read, flags) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (activity) {
		ngx_http_tunnel_clear_timer(pc->read);
		ngx_http_tunnel_clear_timer(pc->write);
		ngx_http_tunnel_clear_timer(c->read);
		ngx_http_tunnel_clear_timer(c->write);

		ngx_http_tunnel_update_idle_timer(pc->write, idle_timeout);
		ngx_http_tunnel_update_idle_timer(pc->read, idle_timeout);
		ngx_http_tunnel_update_idle_timer(c->write, idle_timeout);
		ngx_http_tunnel_update_idle_timer(c->read, idle_timeout);
	}

	return NGX_OK;
}

void
ngx_http_tunnel_release_peer(ngx_http_request_t *r, ngx_uint_t state)
{
	ngx_http_upstream_t *u;

	u = r->upstream;

	if (u == NULL || u->peer.free == NULL || u->peer.sockaddr == NULL) {
		return;
	}

	u->peer.free(&u->peer, u->peer.data, state);
	u->peer.sockaddr = NULL;
	u->peer.connection = NULL;
}

void
ngx_http_tunnel_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
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
		r->reading_body = 0;
	}

	if (ctx->resolving && ctx->resolver_ctx != NULL) {
		ngx_resolve_name_done(ctx->resolver_ctx);
		ctx->resolver_ctx = NULL;
		ctx->resolving = 0;
	}

	ngx_http_tunnel_close(ctx);

	ngx_http_finalize_request(r, rc);
}

void
ngx_http_tunnel_cleanup(void *data)
{
	ngx_http_tunnel_ctx_t *ctx;

	ctx = data;
	if (ctx->finalized) {
		return;
	}

	ctx->finalized = 1;

	if (ctx->resolving && ctx->resolver_ctx != NULL) {
		ngx_resolve_name_done(ctx->resolver_ctx);
		ctx->resolver_ctx = NULL;
		ctx->resolving = 0;
	}

	ngx_http_tunnel_close(ctx);
}

ngx_int_t
ngx_http_tunnel_test_connect(ngx_connection_t *c)
{
	int err;
	socklen_t len;

#if (NGX_HAVE_KQUEUE)

	if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
		if (c->write->pending_eof || c->read->pending_eof) {
			err =
				c->write->pending_eof ? c->write->kq_errno : c->read->kq_errno;
			(void)ngx_connection_error(
				c, err, "kevent() reported that connect() failed");
			return NGX_ERROR;
		}
	} else
#endif
	{
		err = 0;
		len = sizeof(int);

		if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) == -1) {
			err = ngx_socket_errno;
		}

		if (err != 0) {
			(void)ngx_connection_error(c, err, "connect() failed");
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static void
ngx_http_tunnel_clear_timer(ngx_event_t *ev)
{
	if (ev->timer_set) {
		ngx_del_timer(ev);
	}
}

static void
ngx_http_tunnel_update_idle_timer(ngx_event_t *ev, ngx_msec_t timeout)
{
	if (ev->active && !ev->ready) {
		ngx_add_timer(ev, timeout);
		return;
	}

	ngx_http_tunnel_clear_timer(ev);
}

static void
ngx_http_tunnel_close(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_connection_t *c;
	ngx_connection_t *pc;
	ngx_http_request_t *r;

	r = ctx->request;
	c = r->connection;

	ngx_http_tunnel_clear_timer(c->read);
	ngx_http_tunnel_clear_timer(c->write);

	pc = (r->upstream != NULL) ? r->upstream->peer.connection : NULL;
	if (pc != NULL) {
		ngx_http_tunnel_clear_timer(pc->read);
		ngx_http_tunnel_clear_timer(pc->write);

		ngx_close_connection(pc);
		r->upstream->peer.connection = NULL;
	}

	if (ctx->peer_acquired) {
		ngx_http_tunnel_release_peer(r, 0);
		ctx->peer_acquired = 0;
	}
}
