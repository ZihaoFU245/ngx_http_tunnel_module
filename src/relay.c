/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Bidirectional byte relay for client and upstream.
 */

#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_RELAY_MAX_ITERATIONS 64
#define RELAY_CHECK_PERIOD 8

static void                  request_body_post_handler(ngx_http_request_t *r);
static ngx_int_t             recv_downstream(ngx_http_tunnel_ctx_t *ctx,
                                             ngx_uint_t            *activity);
static ngx_int_t             send_upstream(ngx_http_tunnel_ctx_t *ctx,
                                           ngx_uint_t            *activity);
static ngx_int_t             recv_upstream(ngx_http_tunnel_ctx_t *ctx,
                                           ngx_uint_t            *activity);
static ngx_int_t             send_downstream(ngx_http_tunnel_ctx_t *ctx,
                                             ngx_uint_t            *activity);
static ngx_int_t             close_upstream_write(ngx_http_tunnel_ctx_t *ctx,
                                                  ngx_uint_t             upload_drained);
static ngx_inline ngx_uint_t downstream_output_idle(ngx_http_request_t *r,
                                                    ngx_connection_t   *c);
static ngx_inline ngx_uint_t is_relay_finished(ngx_http_tunnel_ctx_t *ctx,
                                               ngx_http_request_t    *r,
                                               ngx_connection_t      *c,
                                               ngx_connection_t      *pc,
                                               ngx_uint_t *upload_drained);

ngx_int_t
tunnel_relay_start(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_connection_t           *c;
    ngx_connection_t           *pc;
    ngx_http_cleanup_t         *cln;
    ngx_int_t                   rc;
    ngx_http_request_t         *r;
    ngx_http_upstream_t        *u;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_tunnel_srv_conf_t *tscf;

    r = ctx->request;
    u = r->upstream;
    c = r->connection;
    pc = u->peer.connection;

    if (pc == NULL) {
        return NGX_ERROR;
    }

    tunnel_utils_clear_timer(pc->read);
    tunnel_utils_clear_timer(pc->write);

    r->keepalive = 0;
    c->log->action = "tunneling connection";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

    if (clcf->tcp_nodelay) {
        if (r->http_version == NGX_HTTP_VERSION_20 &&
            ngx_tcp_nodelay(c) != NGX_OK) {
            return NGX_ERROR;
        }

        if (u->peer.type != SOCK_DGRAM && ngx_tcp_nodelay(pc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    rc = tunnel_relay_init_request_body(ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    if (tunnel_relay_send_connected(r, 1) != NGX_OK) {
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
    }

    tunnel_relay_process(ctx);

    return NGX_OK;
}

ngx_int_t
tunnel_relay_send_connected(ngx_http_request_t *r, ngx_uint_t allow_padding)
{
    ngx_int_t              rc;
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = -1;
    r->headers_out.content_length = NULL;
    ngx_str_set(&r->headers_out.status_line, "200 Connection Established");
    ngx_str_null(&r->headers_out.content_type);

    if (allow_padding &&
        tunnel_padding_add_response_header(r, ctx->padding) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->response_sent = 1;

    return NGX_OK;
}

ngx_int_t
tunnel_relay_init_request_body(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t           rc;
    ngx_http_request_t *r;

    r = ctx->request;

    if (!tunnel_relay_is_stream_downstream(r)) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->http_version == NGX_HTTP_VERSION_20 && r->stream &&
        r->stream->in_closed) {
        ctx->downstream_eof = 1;
        return NGX_OK;
    }
#endif

    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, request_body_post_handler);
    return (rc >= NGX_HTTP_SPECIAL_RESPONSE) ? rc : NGX_OK;
}

void
tunnel_relay_downstream_read_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    tunnel_relay_process(ctx);
}

void
tunnel_relay_downstream_write_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    tunnel_relay_process(ctx);
}

void
tunnel_relay_upstream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    tunnel_relay_process(ctx);
}

void
tunnel_relay_upstream_write_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    tunnel_relay_process(ctx);
}

void
tunnel_relay_process(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i, flags, activity, loop_activity;
    ngx_uint_t                  upload_drained;
    ngx_msec_t                  idle_timeout;
    ngx_connection_t           *c, *pc;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_request_t         *r;
    ngx_http_tunnel_srv_conf_t *tscf;

    if (ctx == NULL || ctx->finalized) {
        return;
    }

    r = ctx->request;
    c = r->connection;
    pc = r->upstream->peer.connection;

    if (pc == NULL) {
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    if (c->read->timedout || c->write->timedout || pc->read->timedout ||
        pc->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "tunnel idle timeout");
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    activity = 0;

    for (i = 0; i < NGX_HTTP_RELAY_MAX_ITERATIONS; i++) {
        loop_activity = 0;

        if ((i % RELAY_CHECK_PERIOD) == 0 &&
            (ngx_terminate || ngx_quit || ngx_exiting)) {
            tunnel_relay_finalize(ctx, NGX_OK);
            return;
        }

        rc = recv_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = send_upstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = recv_upstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = send_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        if (loop_activity) {
            activity = 1;
        }

        if (is_relay_finished(ctx, r, c, pc, &upload_drained)) {
            tunnel_relay_finalize(ctx, NGX_OK);
            return;
        }

        rc = close_upstream_write(ctx, upload_drained);
        if (rc != NGX_OK) {
            goto failed;
        }

        if (!loop_activity) {
            break;
        }
    }

    if (is_relay_finished(ctx, r, c, pc, &upload_drained)) {
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    rc = close_upstream_write(ctx, upload_drained);
    if (rc != NGX_OK) {
        goto failed;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);
    idle_timeout = tscf->idle_timeout;

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK ||
        ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT
                                                      : NGX_OK) != NGX_OK ||
        ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    flags = c->read->eof ? NGX_CLOSE_EVENT : NGX_OK;
    if (ngx_handle_read_event(c->read, flags) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
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
        ctx->read_again_event_posted = 0;
    }

    if (!ctx->read_again_event_posted && upload_drained && r->reading_body &&
        !ctx->downstream_eof && !pc->read->eof) {
        tunnel_relay_post_downstream_read(ctx);
    }

    return;

failed:
    tunnel_relay_finalize(ctx, rc == NGX_DONE ? NGX_OK : rc);
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
    ctx->read_again_event_posted = 1;
}

void
tunnel_relay_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
{
    ngx_connection_t    *c;
    ngx_connection_t    *pc;
    ngx_event_t         *rev;
    ngx_http_request_t  *r;
    ngx_http_upstream_t *u;

    if (ctx == NULL || ctx->finalized) {
        return;
    }

    ctx->finalized = 1;
    r = ctx->request;
    c = r->connection;
    u = r->upstream;

    rev = c->read;
    if (ctx->read_again_event_posted && rev->posted) {
        ngx_delete_posted_event(rev);
    }

    ctx->read_again_event_posted = 0;

    if (ctx->content_handler_ref) {
        ctx->content_handler_ref = 0;
        if (r->main->count > 1) {
            r->main->count--;
        }
    }

    if (tunnel_relay_is_stream_downstream(r)) {
        r->connection->read->eof = 1;
    }

#if (NGX_HTTP_V2)
    tunnel_padding_h2_prepend_rst_stream_data(ctx);
#endif

    if (rc == NGX_OK && tunnel_relay_is_stream_downstream(r) &&
        r->header_sent &&
        (r->http_version != NGX_HTTP_VERSION_20 ||
         tunnel_padding_active(ctx->padding) != NGX_OK)) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    tunnel_utils_clear_timer(c->read);
    tunnel_utils_clear_timer(c->write);

    if (u != NULL) {
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

            /*
             * ngx_close_connection(pc) does not destroy the peer pool; this
             * relay owns it after taking over upstream, so destroy it here.
             */
            if (pc->pool) {
                ngx_destroy_pool(pc->pool);
            }

            ngx_close_connection(pc);
            u->peer.connection = NULL;
        }
    }

    if (r->header_sent && rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        rc = NGX_ERROR;
    }

    ngx_http_finalize_request(r, rc);
}

void
tunnel_relay_cleanup(void *data)
{
    tunnel_relay_finalize(data, NGX_DONE);
}

static void
request_body_post_handler(ngx_http_request_t *r)
{
    if (r->main->count > 1) {
        r->main->count--;
    }

    return;
}

static ngx_int_t
recv_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    ngx_http_request_t *r;

    r = ctx->request;

    if (ctx->downstream_eof) {
        return NGX_OK;
    }

    if (!r->reading_body) {
        if (r->request_body != NULL && r->request_body->bufs != NULL) {
            if (tunnel_utils_append_chain(&ctx->downstream_in,
                                          r->request_body->bufs)) {
                ctx->downstream_eof = 1;
            }

            r->request_body->bufs = NULL;
            *activity = 1;
        } else {
            ctx->downstream_eof = 1;
        }

        return NGX_OK;
    }

    rc = ngx_http_read_unbuffered_request_body(r);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (r->request_body != NULL && r->request_body->bufs != NULL) {
        if (tunnel_utils_append_chain(&ctx->downstream_in,
                                      r->request_body->bufs)) {
            ctx->downstream_eof = 1;
        }

        r->request_body->bufs = NULL;
        *activity = 1;
    } else if (rc == NGX_OK && !r->reading_body) {
        ctx->downstream_eof = 1;
    }

    return NGX_OK;
}

static ngx_int_t
send_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t             n;
    size_t              size;
    ngx_buf_t          *b;
    ngx_chain_t        *cl;
    ngx_connection_t   *pc;
    ngx_http_request_t *r;
    ngx_int_t           rc;

    r = ctx->request;
    pc = r->upstream->peer.connection;

    tunnel_utils_free_consumed_chain(ctx, &ctx->downstream_in, NULL);
    tunnel_utils_free_consumed_chain(ctx, &ctx->upstream_out, NULL);

    rc = NGX_DECLINED;

    if (ctx->downstream_in != NULL) {
        if (ctx->downstream_filter != NULL) {
            /* Call custom filter for padding or capsule */
            rc = ctx->downstream_filter(ctx, activity);
            if (rc == NGX_AGAIN && ctx->upstream_out == NULL) {
                    return NGX_OK;
            }

            if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }
        }
    }

    if (ctx->upstream_out != NULL) {
        cl = ctx->upstream_out;
    } else if (ctx->downstream_filter == NULL || rc == NGX_DECLINED) {
        cl = ctx->downstream_in;
    } else {
        cl = NULL;
    }

    if (!pc->write->ready || cl == NULL) {
        return NGX_OK;
    }

    b = cl->buf;
    size = b->last - b->pos;
    n = pc->send(pc, b->pos, size);

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    if (n == NGX_ERROR) {
        return NGX_DONE;
    }

    if (r->upstream->peer.type == SOCK_DGRAM && n != (ssize_t)size) {
        pc->write->error = 1;
        return NGX_DONE;
    }

    if (n > 0) {
        b->pos += n;
        *activity = 1;

        if (b->pos == b->last) {
            if (ctx->upstream_out != NULL) {
                tunnel_utils_free_consumed_chain(ctx, &ctx->upstream_out,
                                                 NULL);
            } else {
                tunnel_utils_free_consumed_chain(ctx, &ctx->downstream_in,
                                                 NULL);
            }
        }
    }

    return NGX_OK;
}

static ngx_int_t
recv_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t                     n;
    ngx_int_t                   rc;
    size_t                      size;
    ngx_buf_t                  *b;
    ngx_chain_t                *cl;
    ngx_connection_t           *pc;
    ngx_http_request_t         *r;
    ngx_http_tunnel_srv_conf_t *tscf;

    r = ctx->request;
    pc = r->upstream->peer.connection;
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

    if (pc == NULL || !pc->read->ready) {
        return NGX_OK;
    }

    size = tscf->buffer_size;
    rc = tunnel_utils_alloc_chain_buf(ctx, &cl, size);
    if (rc == NGX_AGAIN) {
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = cl->buf;

    n = pc->recv(pc, b->last, size);

    if (n == NGX_AGAIN) {
        tunnel_utils_free_consumed_chain(ctx, &cl, NULL);
        return NGX_OK;
    }

    if (n == 0) {
        tunnel_utils_free_consumed_chain(ctx, &cl, NULL);
        if (r->upstream->peer.type == SOCK_DGRAM) {
            return NGX_OK;
        }

        pc->read->eof = 1;
        pc->read->ready = 0;
        return NGX_OK;
    }

    if (n < 0) {
        tunnel_utils_free_consumed_chain(ctx, &cl, NULL);
        pc->read->eof = 1;
        pc->read->error = 1;
        pc->read->ready = 0;
        return NGX_DONE;
    }

    b->last += n;
    tunnel_utils_append_chain(&ctx->upstream_in, cl);

    *activity = 1;

    return NGX_OK;
}

static ngx_int_t
send_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    ngx_buf_t          *b;
    u_char             *before_pos;
    off_t               before_sent;
    ngx_chain_t        *before_out;
    ngx_uint_t          before_c_buffered;
    ngx_uint_t          before_r_buffered;
    ngx_chain_t        *cl;
    ngx_connection_t   *c;
    ngx_http_request_t *r;

    r = ctx->request;
    c = r->connection;

    tunnel_utils_free_consumed_chain(ctx, &ctx->upstream_in, NULL);
    tunnel_utils_free_consumed_chain(ctx, &ctx->downstream_out, NULL);

    rc = NGX_DECLINED;

    if (ctx->upstream_in != NULL) {
        if (ctx->upstream_filter != NULL) {
            /* Call custom filter to do encode operation */
            rc = ctx->upstream_filter(ctx, activity);
            if (rc == NGX_AGAIN && ctx->downstream_out == NULL) {
                    return NGX_OK;
            }

            if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }
        }
    }

    if (ctx->downstream_out != NULL) {
        cl = ctx->downstream_out;
    } else if (ctx->upstream_filter == NULL || rc == NGX_DECLINED) {
        cl = ctx->upstream_in;
    } else {
        cl = NULL;
    }

    if (cl == NULL && downstream_output_idle(r, c)) {
        return NGX_OK;
    }

    b = (cl == NULL) ? NULL : cl->buf;
    before_pos = (b == NULL) ? NULL : b->pos;
    before_sent = c->sent;
    before_out = r->out;
    before_r_buffered = r->buffered;
    before_c_buffered = c->buffered;

    if (!downstream_output_idle(r, c)) {
        rc = ngx_http_output_filter(r, NULL);
    } else {
        for (; cl != NULL; cl = cl->next) {
            cl->buf->flush = 1;
        }
        cl = (ctx->downstream_out != NULL) ? ctx->downstream_out
                                           : ctx->upstream_in;
        rc = ngx_http_output_filter(r, cl);
        for (; cl != NULL; cl = cl->next) {
            cl->buf->flush = 0;
        }
    }

    if (rc == NGX_ERROR) {
        return NGX_DONE;
    }

    if (downstream_output_idle(r, c)) {
        tunnel_utils_free_consumed_chain(ctx, &ctx->downstream_out, NULL);
        tunnel_utils_free_consumed_chain(ctx, &ctx->upstream_in, NULL);
    }

    if (rc == NGX_OK || rc == NGX_AGAIN) {
        if (c->sent != before_sent || (b != NULL && b->pos != before_pos) ||
            before_out != r->out || (before_r_buffered && !r->buffered) ||
            (before_c_buffered && !c->buffered)) {
            *activity = 1;
        }

        return NGX_OK;
    }

    return NGX_DONE;
}

static ngx_int_t
close_upstream_write(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t upload_drained)
{
    ngx_connection_t   *pc;
    ngx_http_request_t *r;

    if (!ctx->downstream_eof || !upload_drained || ctx->upstream_write_closed) {
        return NGX_OK;
    }

    r = ctx->request;
    pc = r->upstream->peer.connection;
    if (pc == NULL || pc->write->error) {
        return NGX_OK;
    }

    if (ngx_shutdown_socket(pc->fd, NGX_WRITE_SHUTDOWN) == -1) {
        if (ngx_socket_errno == NGX_ENOTCONN ||
            ngx_socket_errno == NGX_ECONNRESET) {
            ctx->upstream_write_closed = 1;
            pc->write->ready = 0;
            return NGX_OK;
        }

        ngx_connection_error(pc, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->upstream_write_closed = 1;
    pc->write->ready = 0;

    return NGX_OK;
}

static ngx_inline ngx_uint_t
downstream_output_idle(ngx_http_request_t *r, ngx_connection_t *c)
{
    return r->out == NULL && !r->buffered && !c->buffered;
}

static ngx_inline ngx_uint_t
is_relay_finished(ngx_http_tunnel_ctx_t *ctx, ngx_http_request_t *r,
                  ngx_connection_t *c, ngx_connection_t *pc,
                  ngx_uint_t *upload_drained)
{
    ngx_uint_t download_drained;

    *upload_drained = (ctx->downstream_in == NULL && ctx->upstream_out == NULL);

    download_drained =
        (ctx->upstream_in == NULL && ctx->downstream_out == NULL &&
         downstream_output_idle(r, c));

    return (pc->read->eof && *upload_drained && download_drained);
}
