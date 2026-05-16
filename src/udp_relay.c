
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * CONNECT-UDP capsule/datagram relay.
 */

#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_UDP_RELAY_MAX_ITERATIONS 64
#define UDP_RELAY_CHECK_PERIOD 8
#define UDP_CAPSULE_HEADER_RESERVE 10

static void      udp_downstream_read_handler(ngx_http_request_t *r);
static void      udp_downstream_write_handler(ngx_http_request_t *r);
static void      udp_upstream_read_handler(ngx_event_t *ev);
static void      udp_upstream_write_handler(ngx_event_t *ev);
static void      udp_relay_process(ngx_http_tunnel_ctx_t *ctx);
static void      udp_append_downstream_chain(ngx_http_tunnel_ctx_t *ctx,
                                             ngx_chain_t           *in);
static ngx_int_t udp_recv_downstream(ngx_http_tunnel_ctx_t *ctx,
                                     ngx_uint_t            *activity);
static ngx_int_t udp_decode_downstream(ngx_http_tunnel_ctx_t *ctx,
                                       ngx_uint_t            *activity);
static ngx_int_t udp_send_upstream(ngx_http_tunnel_ctx_t *ctx,
                                   ngx_uint_t            *activity);
static ngx_int_t udp_recv_upstream(ngx_http_tunnel_ctx_t *ctx,
                                   ngx_uint_t            *activity);
static ngx_int_t udp_send_downstream(ngx_http_tunnel_ctx_t *ctx,
                                     ngx_uint_t            *activity);
static ngx_inline ngx_uint_t udp_output_idle(ngx_http_request_t *r,
                                             ngx_connection_t   *c);
static void udp_relay_finalize_on_error(ngx_http_request_t    *r,
                                        ngx_http_tunnel_ctx_t *ctx,
                                        ngx_int_t              rc);

ngx_int_t
tunnel_udp_relay_start(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t                   rc;
    ngx_connection_t           *c, *pc;
    ngx_http_cleanup_t         *cln;
    ngx_http_request_t         *r;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_tunnel_srv_conf_t *tscf;
    ngx_http_upstream_t        *u;

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
    c->log->action = "tunneling UDP capsules";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->tcp_nodelay && r->http_version == NGX_HTTP_VERSION_20 &&
        ngx_tcp_nodelay(c) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = tunnel_relay_init_request_body(ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    if (tunnel_relay_send_connected(r, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    pc->read->handler = udp_upstream_read_handler;
    pc->write->handler = udp_upstream_write_handler;
    r->read_event_handler = udp_downstream_read_handler;
    r->write_event_handler = udp_downstream_write_handler;
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

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);
    tunnel_utils_update_idle_timer(pc->write, tscf->idle_timeout);
    tunnel_utils_update_idle_timer(pc->read, tscf->idle_timeout);
    tunnel_utils_update_idle_timer(c->write, tscf->idle_timeout);
    tunnel_utils_update_idle_timer(c->read, tscf->idle_timeout);

    udp_relay_process(ctx);

    return NGX_OK;
}

static void
udp_downstream_read_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);
    if (ctx == NULL) {
        udp_relay_finalize_on_error(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    udp_relay_process(ctx);
}

static void
udp_downstream_write_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);
    if (ctx == NULL) {
        udp_relay_finalize_on_error(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    udp_relay_process(ctx);
}

static void
udp_upstream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    udp_relay_process(ctx);
}

static void
udp_upstream_write_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    udp_relay_process(ctx);
}

static void
udp_relay_process(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i, flags, activity, loop_activity;
    ngx_msec_t                  idle_timeout;
    ngx_connection_t           *c, *pc;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_request_t         *r;
    ngx_http_tunnel_srv_conf_t *tscf;

    if (ctx == NULL || ctx->finalized) {
        return;
    }

    r = ctx->request;
    pc = r->upstream->peer.connection;
    c = r->connection;

    if (pc == NULL) {
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    if (c->read->timedout || c->write->timedout || pc->read->timedout ||
        pc->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "tunnel UDP idle timeout");
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    activity = 0;
    rc = NGX_OK;

    for (i = 0; i < NGX_HTTP_UDP_RELAY_MAX_ITERATIONS; i++) {
        loop_activity = 0;

        if ((i % UDP_RELAY_CHECK_PERIOD) == 0 &&
            (ngx_terminate || ngx_quit || ngx_exiting)) {
            rc = NGX_DONE;
            goto done;
        }

        rc = udp_recv_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = udp_decode_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = udp_send_upstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = udp_send_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = udp_recv_upstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = udp_send_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        if (loop_activity) {
            activity = 1;
            continue;
        }

        break;
    }

    if (c->read->eof || c->write->error || pc->read->error ||
        pc->write->error) {
        rc = NGX_DONE;
        goto done;
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

    if (!ctx->read_again_event_posted &&
        ctx->client_buffer->pos == ctx->client_buffer->last &&
        ctx->upstream_buffer->pos == ctx->upstream_buffer->last &&
        r->reading_body && !ctx->downstream_eof && !pc->read->eof) {
        tunnel_relay_post_downstream_read(ctx);
    }

    return;

done:
    tunnel_relay_finalize(ctx, NGX_OK);
    return;

failed:
    tunnel_relay_finalize(ctx, rc);
}

static void
udp_append_downstream_chain(ngx_http_tunnel_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_chain_t **ll;

    if (in == NULL) {
        return;
    }

    ll = &ctx->downstream_chain;
    while (*ll != NULL) {
        ll = &(*ll)->next;
    }

    *ll = in;
}

static ngx_int_t
udp_recv_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    ngx_http_request_t *r;

    r = ctx->request;

    if (ctx->downstream_chain != NULL || ctx->downstream_eof) {
        return NGX_OK;
    }

    if (!r->reading_body) {
        if (r->request_body != NULL && r->request_body->bufs != NULL) {
            udp_append_downstream_chain(ctx, r->request_body->bufs);
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
        udp_append_downstream_chain(ctx, r->request_body->bufs);
        r->request_body->bufs = NULL;
        *activity = 1;
    } else if (rc == NGX_OK && !r->reading_body) {
        ctx->downstream_eof = 1;
    }

    return NGX_OK;
}

static ngx_int_t
udp_decode_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    ngx_buf_t          *dst;
    ngx_http_request_t *r;

    if (ctx->downstream_chain == NULL) {
        return NGX_OK;
    }

    dst = ctx->upstream_buffer;
    r = ctx->request;

    if (dst->pos != dst->last) {
        return NGX_OK;
    }

    dst->pos = dst->start;
    dst->last = dst->start;

    rc = tunnel_capsule_decode_datagram(&ctx->downstream_chain, dst);
    if (rc == NGX_AGAIN) {
        if (ctx->downstream_eof) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "CONNECT-UDP request ended with incomplete capsule");
            return NGX_HTTP_BAD_REQUEST;
        }

        return NGX_OK;
    }

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "CONNECT-UDP received invalid datagram capsule");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tunnel_utils_free_consumed_chain(r, &ctx->downstream_chain, NULL);
    *activity = 1;

    return NGX_OK;
}

static ngx_int_t
udp_send_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t             n;
    size_t              size;
    ngx_buf_t          *b;
    ngx_connection_t   *pc;
    ngx_http_request_t *r;

    r = ctx->request;
    pc = r->upstream->peer.connection;
    b = ctx->upstream_buffer;

    if (!pc->write->ready || b->pos == b->last) {
        return NGX_OK;
    }

    size = b->last - b->pos;
    n = pc->send(pc, b->pos, size);

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    if (n == NGX_ERROR || n != (ssize_t)size) {
        pc->write->error = 1;
        return NGX_DONE;
    }

    b->pos = b->start;
    b->last = b->start;
    *activity = 1;

    return NGX_OK;
}

static ngx_int_t
udp_recv_upstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t             n;
    size_t              size;
    ngx_buf_t          *b;
    ngx_buf_t           payload;
    ngx_connection_t   *pc;
    ngx_http_request_t *r;
    tunnel_capsule_t    capsule;

    r = ctx->request;
    pc = r->upstream->peer.connection;
    b = ctx->client_buffer;

    if (!pc->read->ready || b->pos != b->last) {
        return NGX_OK;
    }

    if (!udp_output_idle(r, r->connection)) {
        return NGX_OK;
    }

    if ((size_t)(b->end - b->start) <= UDP_CAPSULE_HEADER_RESERVE) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = b->start;
    b->last = b->pos;
    size = b->end - b->last - UDP_CAPSULE_HEADER_RESERVE;

    n = pc->recv(pc, b->last, size);
    if (n == NGX_AGAIN) {
        b->pos = b->start;
        b->last = b->start;
        return NGX_OK;
    }

    if (n < 0) {
        pc->read->error = 1;
        return NGX_DONE;
    }

    if (n == 0) {
        b->pos = b->start;
        b->last = b->start;
        return NGX_OK;
    }

    b->last += n;

    ngx_memzero(&payload, sizeof(ngx_buf_t));
    payload.pos = b->pos;
    payload.last = b->last;
    payload.start = b->pos;
    payload.end = b->last;
    payload.memory = 1;

    capsule.type = CAPSULE_DATAGRAM;
    capsule.len =
        tunnel_capsule_varint_size(CAPSULE_DATAGRAM_CONTEXT_ID) + (size_t)n;
    capsule.payload = &payload;

    if (tunnel_capsule_encode_datagram(&capsule, b) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *activity = 1;

    return NGX_OK;
}

static ngx_int_t
udp_send_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    off_t               before_sent;
    u_char             *before_pos;
    ngx_buf_t          *b;
    ngx_chain_t         out, *before_out;
    ngx_connection_t   *c;
    ngx_http_request_t *r;
    ngx_uint_t          before_c_buffered, before_r_buffered;

    r = ctx->request;
    c = r->connection;
    b = ctx->client_buffer;

    if (b->pos == b->last && udp_output_idle(r, c)) {
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

    if (b->pos == b->last && udp_output_idle(r, c)) {
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

static ngx_inline ngx_uint_t
udp_output_idle(ngx_http_request_t *r, ngx_connection_t *c)
{
    return r->out == NULL && !r->buffered && !c->buffered;
}

static void
udp_relay_finalize_on_error(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx,
                            ngx_int_t rc)
{
    if (ctx != NULL) {
        tunnel_relay_finalize(ctx, rc);
        return;
    }

    if (r->reading_body || r->request_body != NULL) {
        if (r->main->count > 1) {
            r->main->count--;
        }
    }

    ngx_http_finalize_request(r, rc);
}
