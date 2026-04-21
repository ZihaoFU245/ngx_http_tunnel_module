#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_relay_v1_process(ngx_http_tunnel_ctx_t *ctx,
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

	if (ngx_handle_read_event(pc->read,
		pc->read->eof ? NGX_CLOSE_EVENT : 0) != NGX_OK) {
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
		tunnel_utils_clear_timer(pc->read);
		tunnel_utils_clear_timer(pc->write);
		tunnel_utils_clear_timer(c->read);
		tunnel_utils_clear_timer(c->write);

		tunnel_utils_update_idle_timer(pc->write, idle_timeout);
		tunnel_utils_update_idle_timer(pc->read, idle_timeout);
		tunnel_utils_update_idle_timer(c->write, idle_timeout);
		tunnel_utils_update_idle_timer(c->read, idle_timeout);
	}

	return NGX_OK;
}
