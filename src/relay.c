
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Bidirectional byte relay for client and upstream.
 */

#include "ngx_http_tunnel_module.h"

#define downstream_output_idle(r)                                              \
    ((r)->out == NULL && !(r)->buffered && !(r)->connection->buffered)

#define tunnel_upload_drained(ctx)                                             \
    ((ctx)->downstream_in == NULL && (ctx)->flush_size == 0 &&                 \
     !(ctx)->downstream_empty_datagram)

#define swap_buffers(ctx)                                                      \
    do {                                                                       \
        ngx_buf_t *b;                                                          \
                                                                               \
        b = (ctx)->buffers[SEND_BUF];                                          \
        (ctx)->buffers[SEND_BUF] = (ctx)->buffers[RECV_BUF];                   \
        (ctx)->buffers[RECV_BUF] = b;                                          \
    } while (0)

static void      request_body_post_handler(ngx_http_request_t *r);
static ngx_int_t recv_downstream(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_uint_t            *activity);
static ngx_int_t send_upstream(ngx_http_tunnel_ctx_t *ctx,
                               ngx_uint_t            *activity);
static ngx_int_t recv_upstream(ngx_http_tunnel_ctx_t *ctx,
                               ngx_uint_t            *activity);
static ngx_int_t send_downstream(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_uint_t            *activity);
static ngx_int_t close_upstream_write(ngx_http_tunnel_ctx_t *ctx);
static void process_relay(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t from_upstream,
                          ngx_uint_t do_write);

ngx_int_t
tunnel_relay_start(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_connection_t           *c;
    ngx_connection_t           *pc;
    ngx_http_cleanup_t         *cln;
    ngx_int_t                   rc;
    ngx_uint_t                  datagram;
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

    datagram = (pc->type == SOCK_DGRAM);

    if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }

    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    r->keepalive = 0;
    c->log->action =
        datagram ? "tunneling UDP capsules" : "tunneling connection";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

    if (clcf->tcp_nodelay || tscf->tcp_nodelay) {
        if (r->http_version == NGX_HTTP_VERSION_20 &&
            ngx_tcp_nodelay(c) != NGX_OK) {
            return NGX_ERROR;
        }

        if (!datagram && ngx_tcp_nodelay(pc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    rc = tunnel_relay_init_request_body(ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    pc->read->handler = tunnel_relay_upstream_read_handler;
    pc->write->handler = tunnel_relay_upstream_write_handler;
    r->read_event_handler = tunnel_relay_downstream_read_handler;
    r->write_event_handler = tunnel_relay_downstream_write_handler;
    pc->data = ctx;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = tunnel_relay_cleanup;
    cln->data = ctx;

    ngx_add_timer(pc->write, tscf->idle_timeout);
    ngx_add_timer(pc->read, tscf->idle_timeout);
    ngx_add_timer(c->write, tscf->idle_timeout);
    ngx_add_timer(c->read, tscf->idle_timeout);

    process_relay(ctx, 1, 1);

    if (!ctx->finalized) {
        process_relay(ctx, 0, 0);
    }

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

    if (r->stream && r->stream->in_closed) {
        ctx->downstream_eof = 1;
        return NGX_OK;
    }

    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, request_body_post_handler);
    return (rc >= NGX_HTTP_SPECIAL_RESPONSE) ? rc : NGX_OK;
}

void
tunnel_relay_downstream_read_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    process_relay(ctx, 0, 0);
}

void
tunnel_relay_downstream_write_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    process_relay(ctx, 1, 1);
}

void
tunnel_relay_upstream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    process_relay(ctx, 1, 0);
}

void
tunnel_relay_upstream_write_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    process_relay(ctx, 0, 1);
}

static void
process_relay(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t from_upstream,
              ngx_uint_t do_write)
{
    ngx_int_t                   rc;
    ngx_uint_t                  flags, activity, datagram, loop_activity;
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

    datagram = (pc->type == SOCK_DGRAM);

    if (c->read->timedout || c->write->timedout || pc->read->timedout ||
        pc->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "tunnel idle timeout");
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    activity = 0;

    for (;;) {
        loop_activity = 0;

        if (ngx_terminate || ngx_quit || ngx_exiting) {
            tunnel_relay_finalize(ctx, NGX_OK);
            return;
        }

        if (do_write) {
            if (from_upstream) {
                rc = send_downstream(ctx, &loop_activity);
            } else {
                rc = send_upstream(ctx, &loop_activity);
            }

            if (rc != NGX_OK) {
                goto failed;
            }
        }

        if (from_upstream) {
            rc = recv_upstream(ctx, &loop_activity);
        } else {
            rc = recv_downstream(ctx, &loop_activity);
        }

        if (rc != NGX_OK) {
            goto failed;
        }

        if (loop_activity) {
            activity = 1;
            do_write = 1;
            continue;
        }

        break;
    }

    if (datagram &&
        /* void */
        (c->read->eof || c->write->error || pc->read->error ||
         pc->write->error)) {
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    if (!datagram &&
        /* peer read EOF */
        pc->read->eof &&
        /* upload drained */
        tunnel_upload_drained(ctx) &&
        /* download drained */
        ctx->buffers[SEND_BUF]->pos == ctx->buffers[SEND_BUF]->last &&
        ctx->buffers[RECV_BUF]->pos == ctx->buffers[RECV_BUF]->last &&
        downstream_output_idle(r)) {
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    /*
     * Half-close the upstream write side once the client has finished
     * sending and all buffered data has been flushed.  The three guards
     * inside close_upstream_write make this call a cheap no-op on every
     * invocation except the one where conditions are first met.
     */
    if (!datagram) {
        rc = close_upstream_write(ctx);
        if (rc != NGX_OK) {
            goto failed;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);
    idle_timeout = tscf->idle_timeout;

    if (from_upstream) {
        if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

        flags = pc->read->eof ? NGX_CLOSE_EVENT : NGX_OK;
        if (ngx_handle_read_event(pc->read, flags) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

    } else {
        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

        flags = c->read->eof ? NGX_CLOSE_EVENT : NGX_OK;
        if (ngx_handle_read_event(c->read, flags) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }
    }

    if (activity) {
        ngx_add_timer(pc->write, idle_timeout);
        ngx_add_timer(pc->read, idle_timeout);
        ngx_add_timer(c->write, idle_timeout);
        ngx_add_timer(c->read, idle_timeout);
    }

    return;

failed:
    tunnel_relay_finalize(ctx, rc == NGX_DONE ? NGX_OK : rc);
}

void
tunnel_relay_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
{
    ngx_connection_t    *c;
    ngx_connection_t    *pc;
    ngx_http_request_t  *r;
    ngx_http_upstream_t *u;

    if (ctx == NULL || ctx->finalized) {
        return;
    }

    ctx->finalized = 1;
    r = ctx->request;
    c = r->connection;
    u = r->upstream;

    if (ctx->content_handler_ref) {
        ctx->content_handler_ref = 0;
        if (r->main->count > 1) {
            r->main->count--;
        }
    }

    if (tunnel_relay_is_stream_downstream(r)) {
        r->connection->read->eof = 1;
    }

    tunnel_padding_h2_prepend_rst_stream_data(ctx);

    if (rc == NGX_OK && tunnel_relay_is_stream_downstream(r) &&
        r->header_sent &&
        (r->http_version != NGX_HTTP_VERSION_20 ||
         tunnel_padding_active(ctx->padding) != NGX_OK)) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

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
            if (pc->read->timer_set) {
                ngx_del_timer(pc->read);
            }

            if (pc->write->timer_set) {
                ngx_del_timer(pc->write);
            }

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
    ngx_chain_t        *cl;
    ngx_http_request_t *r;

    r = ctx->request;

    if (ctx->downstream_eof) {
        return NGX_OK;
    }

    if (ctx->downstream_in != NULL && ctx->downstream_filter == NULL) {
        return NGX_OK;
    }

    if (!r->reading_body) {
        if (r->request_body != NULL && r->request_body->bufs != NULL) {
            if (ctx->downstream_in == NULL) {
                ctx->downstream_in = r->request_body->bufs;
            } else {
                cl = ctx->downstream_in;
                while (cl->next) {
                    cl = cl->next;
                }
                cl->next = r->request_body->bufs;
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
        if (ctx->downstream_in == NULL) {
            ctx->downstream_in = r->request_body->bufs;
        } else {
            cl = ctx->downstream_in;
            while (cl->next) {
                cl = cl->next;
            }
            cl->next = r->request_body->bufs;
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
    off_t               before_sent;
    off_t               sent;
    ngx_buf_t           empty;
    ngx_chain_t        *cl, *out;
    ngx_chain_t         empty_chain;
    ngx_connection_t   *pc;
    ngx_http_request_t *r;
    ngx_int_t           rc;

    r = ctx->request;
    pc = r->upstream->peer.connection;

    tunnel_utils_free_consumed_chain(r, &ctx->downstream_in, NULL);

    if (ctx->flush_size != 0 && ctx->downstream_filter == NULL) {
        ctx->flush_size = 0;
    }

    /*
     * A non-zero flush_size means a previous filter-selected payload has not
     * finished sending yet.
     */
    if (!ctx->downstream_empty_datagram && ctx->flush_size == 0 &&
        ctx->downstream_filter != NULL) {
        rc = ctx->downstream_filter(ctx, activity);
        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }
        if (rc != NGX_OK) {
            return rc;
        }

        /*
         * When flush_size is 0, it is owned by filter, this check prevent
         * leaks.
         */
        if (ctx->downstream_filter != NULL && ctx->flush_size == 0 &&
            !ctx->downstream_empty_datagram) {
            return NGX_OK;
        }
    }

    if (ctx->downstream_empty_datagram) {
        if (!pc->write->ready) {
            return NGX_OK;
        }

        ngx_memzero(&empty, sizeof(ngx_buf_t));
        empty.flush = 1;

        empty_chain.buf = &empty;
        empty_chain.next = NULL;

        out = pc->send_chain(pc, &empty_chain, 0);
        if (out == NGX_CHAIN_ERROR) {
            pc->write->error = 1;
            return NGX_DONE;
        }

        if (out != NULL) {
            return NGX_OK;
        }

        ctx->downstream_empty_datagram = 0;
        *activity = 1;

        return NGX_OK;
    }

    if (ctx->downstream_in == NULL && ctx->flush_size != 0 &&
        ctx->downstream_eof) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ctx->downstream_in == NULL || !pc->write->ready) {
        return NGX_OK;
    }

    cl = ctx->downstream_in;
    before_sent = pc->sent;

    /*
     * Stream send_chain honors the byte limit directly.  UDP send_chain uses
     * buf->flush as the datagram boundary; capsule filter sets that boundary
     * when it publishes a non-zero flush_size.
     */
    out = pc->send_chain(pc, cl, (off_t)ctx->flush_size);

    if (out == NGX_CHAIN_ERROR) {
        pc->write->error = 1;
        return NGX_DONE;
    }

    sent = pc->sent - before_sent;
    if (ctx->flush_size != 0 && sent != 0) {
        ctx->flush_size -= (size_t)sent;
    }

    ctx->downstream_in = out;

    if (sent != 0 || out != cl) {
        *activity = 1;
    }

    return NGX_OK;
}

static ngx_int_t
recv_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t             n;
    size_t              size;
    ngx_buf_t          *b;
    ngx_connection_t   *pc;
    ngx_http_request_t *r;

    r = ctx->request;
    pc = r->upstream->peer.connection;
    b = ctx->buffers[RECV_BUF];

    if (pc == NULL || !pc->read->ready || ctx->upstream_empty_datagram ||
        b->last == b->end) {
        return NGX_OK;
    }

    if (pc->type == SOCK_DGRAM && b->pos != b->last) {
        return NGX_OK;
    }

    size = b->end - b->last;

    if (ctx->buffer_tail_reserve != 0) {
        if (size <= ctx->buffer_tail_reserve) {
            return NGX_OK;
        }

        size -= ctx->buffer_tail_reserve;
    }

    if (size == 0) {
        return NGX_OK;
    }

    n = pc->recv(pc, b->last, size);

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    if (n == 0) {
        if (pc->type == SOCK_DGRAM) {
            ctx->upstream_empty_datagram = 1;
            *activity = 1;
            return NGX_OK;
        }

        pc->read->eof = 1;
        pc->read->ready = 0;
        return NGX_OK;
    }

    if (n < 0) {
        pc->read->eof = 1;
        pc->read->error = 1;
        pc->read->ready = 0;
        return NGX_DONE;
    }

    b->last += n;
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
    ngx_chain_t         out;
    ngx_chain_t        *chain;
    ngx_connection_t   *c;
    ngx_http_request_t *r;

    r = ctx->request;
    c = r->connection;
    b = ctx->buffers[SEND_BUF];

    if (b->pos == b->last && downstream_output_idle(r)) {
        b->pos = b->start;
        b->last = b->start;

        if (ctx->buffers[RECV_BUF]->pos != ctx->buffers[RECV_BUF]->last) {
            swap_buffers(ctx);
            b = ctx->buffers[SEND_BUF];
            *activity = 1;
        }
    }

    if (b->pos == b->last && !ctx->upstream_empty_datagram &&
        downstream_output_idle(r)) {
        return NGX_OK;
    }

    before_pos = b->pos;
    before_sent = c->sent;
    before_out = r->out;
    before_r_buffered = r->buffered;
    before_c_buffered = c->buffered;

    if (!downstream_output_idle(r)) {
        rc = ngx_http_output_filter(r, NULL);
    } else {
        out.buf = b;
        out.next = NULL;
        chain = &out;

        /*
         * Call upstream filters, upstream filters are used to
         * transform data for padding / capsules.
         * Data is read directly into the send buffer, so we reserve
         * a 32 bytes field for storing additional headers.
         * downstream_out->buf must never be mutated. It always
         * points to the 32 bytes fixed buffer.
         */
        if (ctx->upstream_filter != NULL) {
            rc = ctx->upstream_filter(ctx, activity);
            if (rc == NGX_AGAIN || rc == NGX_DONE) {
                return NGX_OK;
            }
            if (rc == NGX_OK) {
                chain = &ctx->downstream_out;
                if (!ctx->upstream_empty_datagram) {
                    ctx->downstream_out.next = &out;
                }
            } else if (rc != NGX_DECLINED) {
                return rc;
            }
        }

        if (ctx->upstream_empty_datagram) {
            ctx->downstream_out.buf->flush = 1;
        } else {
            b->flush = 1;
        }

        rc = ngx_http_output_filter(r, chain);
        b->flush = 0;
        ctx->upstream_empty_datagram = 0;

        if (chain == &ctx->downstream_out) {
            ctx->downstream_out.buf->flush = 0;
            ctx->downstream_out.next = NULL;
        }
    }

    if (rc == NGX_ERROR) {
        return NGX_DONE;
    }

    if (b->pos == b->last && downstream_output_idle(r)) {
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

    return NGX_DONE;
}

static ngx_int_t
close_upstream_write(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_connection_t   *pc;
    ngx_http_request_t *r;

    if (!ctx->downstream_eof || !tunnel_upload_drained(ctx) ||
        ctx->upstream_write_closed) {
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
