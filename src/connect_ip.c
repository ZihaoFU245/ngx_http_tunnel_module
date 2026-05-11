/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * CONNECT-IP capsule/datagram relay over a user-provided TUN fd.
 */

#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_CONNECT_IP_MAX_ITERATIONS 64
#define CONNECT_IP_CHECK_PERIOD 8
#define CONNECT_IP_CAPSULE_HEADER_RESERVE 10

static void      connect_ip_downstream_read_handler(ngx_http_request_t *r);
static void      connect_ip_downstream_write_handler(ngx_http_request_t *r);
static void      connect_ip_tun_read_handler(ngx_event_t *ev);
static void      connect_ip_tun_write_handler(ngx_event_t *ev);
static void      connect_ip_process(ngx_http_tunnel_ctx_t *ctx);
static ngx_int_t connect_ip_recv_downstream(ngx_http_tunnel_ctx_t *ctx,
                                            ngx_uint_t            *activity);
static ngx_int_t connect_ip_decode_downstream(ngx_http_tunnel_ctx_t *ctx,
                                              ngx_uint_t            *activity);
static ngx_int_t connect_ip_send_tun(ngx_http_tunnel_ctx_t *ctx,
                                     ngx_uint_t            *activity);
static ngx_int_t connect_ip_recv_tun(ngx_http_tunnel_ctx_t *ctx,
                                     ngx_uint_t            *activity);
static ngx_int_t connect_ip_send_downstream(ngx_http_tunnel_ctx_t *ctx,
                                            ngx_uint_t            *activity);
static ngx_inline ngx_uint_t connect_ip_output_idle(ngx_http_request_t *r,
                                                    ngx_connection_t   *c);
static void connect_ip_finalize_on_error(ngx_http_request_t    *r,
                                         ngx_http_tunnel_ctx_t *ctx,
                                         ngx_int_t              rc);

ngx_int_t
tunnel_connect_ip_is_request(ngx_http_request_t *r)
{
    static ngx_str_t connect_ip = ngx_string("connect-ip");

    if (r->connect_protocol.len != connect_ip.len ||
        ngx_strncmp(r->connect_protocol.data, connect_ip.data,
                    connect_ip.len) != 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

ngx_int_t
tunnel_connect_ip_start(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx)
{
    ngx_str_t                    path;
    tunnel_tun_t                *tun;
    ngx_connection_t            *tc, *c;
    ngx_int_t                    rc;
    ngx_table_elt_t             *h;
    ngx_http_cleanup_t          *cln;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_tunnel_loc_conf_t  *tlcf;
    ngx_http_tunnel_srv_conf_t  *tscf;

    c = r->connection;
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (ngx_http_complex_value(r, tlcf->connect_ip_tun_path, &path) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (path.len == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "tunnel_connect_ip_tun_path evaluated to empty path");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tun = ngx_pcalloc(r->pool, sizeof(tunnel_tun_t));
    if (tun == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tun->fd = NGX_INVALID_FILE;

    if (tunnel_tun_open(r, &path, tun) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tc = ngx_get_connection(tun->fd, c->log);
    if (tc == NULL) {
        tunnel_tun_close(c->log, tun);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * The fd is now owned by the nginx connection.  Prevent cleanup from
     * closing it twice through tunnel_tun_close().
     */
    tun->fd = NGX_INVALID_FILE;

    tc->data = ctx;
    tc->read->handler = connect_ip_tun_read_handler;
    tc->write->handler = connect_ip_tun_write_handler;
    tc->read->log = c->log;
    tc->write->log = c->log;
    tc->log = c->log;
    ctx->tun_connection = tc;

    r->main->count++;
    ctx->content_handler_ref = 1;

    r->keepalive = 0;
    c->log->action = "tunneling IP capsules";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->tcp_nodelay && r->http_version == NGX_HTTP_VERSION_20 &&
        ngx_tcp_nodelay(c) != NGX_OK) {
        tunnel_relay_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    rc = tunnel_relay_init_request_body(ctx);
    if (rc != NGX_OK) {
        tunnel_relay_finalize(ctx, rc);
        return NGX_DONE;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        tunnel_relay_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Capsule-Protocol");
    ngx_str_set(&h->value, "?1");

    if (tunnel_relay_send_connected(r, 0) != NGX_OK) {
        tunnel_relay_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    r->read_event_handler = connect_ip_downstream_read_handler;
    r->write_event_handler = connect_ip_downstream_write_handler;

    if (!ctx->cleanup_added) {
        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            tunnel_relay_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }

        cln->handler = tunnel_relay_cleanup;
        cln->data = ctx;
        ctx->cleanup_added = 1;
    }

    ctx->connected = 1;

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);
    tunnel_utils_update_idle_timer(tc->write, tscf->idle_timeout);
    tunnel_utils_update_idle_timer(tc->read, tscf->idle_timeout);
    tunnel_utils_update_idle_timer(c->write, tscf->idle_timeout);
    tunnel_utils_update_idle_timer(c->read, tscf->idle_timeout);

    connect_ip_process(ctx);

    return NGX_DONE;
}

static void
connect_ip_downstream_read_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL) {
        connect_ip_finalize_on_error(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    connect_ip_process(ctx);
}

static void
connect_ip_downstream_write_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL) {
        connect_ip_finalize_on_error(r, NULL, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    connect_ip_process(ctx);
}

static void
connect_ip_tun_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    connect_ip_process(ctx);
}

static void
connect_ip_tun_write_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    connect_ip_process(ctx);
}

static void
connect_ip_process(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i, flags, activity, loop_activity;
    ngx_msec_t                  idle_timeout;
    ngx_connection_t           *c, *tc;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_request_t         *r;
    ngx_http_tunnel_srv_conf_t *tscf;

    if (ctx == NULL || ctx->finalized) {
        return;
    }

    r = ctx->request;
    c = r->connection;
    tc = ctx->tun_connection;

    if (tc == NULL) {
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    if (c->read->timedout || c->write->timedout || tc->read->timedout ||
        tc->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "tunnel connect-ip idle timeout");
        tunnel_relay_finalize(ctx, NGX_OK);
        return;
    }

    activity = 0;
    rc = NGX_OK;

    for (i = 0; i < NGX_HTTP_CONNECT_IP_MAX_ITERATIONS; i++) {
        loop_activity = 0;

        if ((i % CONNECT_IP_CHECK_PERIOD) == 0 &&
            (ngx_terminate || ngx_quit || ngx_exiting)) {
            rc = NGX_DONE;
            goto done;
        }

        rc = connect_ip_recv_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = connect_ip_decode_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = connect_ip_send_tun(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = connect_ip_send_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = connect_ip_recv_tun(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        rc = connect_ip_send_downstream(ctx, &loop_activity);
        if (rc != NGX_OK) {
            goto failed;
        }

        if (loop_activity) {
            activity = 1;
            continue;
        }

        break;
    }

    if (c->read->eof || c->write->error || tc->read->error ||
        tc->write->error) {
        rc = NGX_DONE;
        goto done;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);
    idle_timeout = tscf->idle_timeout;

    if (ngx_handle_write_event(tc->write, 0) != NGX_OK ||
        ngx_handle_read_event(tc->read, tc->read->eof ? NGX_CLOSE_EVENT
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
        tunnel_utils_clear_timer(tc->read);
        tunnel_utils_clear_timer(tc->write);
        tunnel_utils_clear_timer(c->read);
        tunnel_utils_clear_timer(c->write);

        tunnel_utils_update_idle_timer(tc->write, idle_timeout);
        tunnel_utils_update_idle_timer(tc->read, idle_timeout);
        tunnel_utils_update_idle_timer(c->write, idle_timeout);
        tunnel_utils_update_idle_timer(c->read, idle_timeout);
        ctx->read_again_event_posted = 0;
    }

    if (!ctx->read_again_event_posted &&
        ctx->client_buffer->pos == ctx->client_buffer->last &&
        ctx->upstream_buffer->pos == ctx->upstream_buffer->last &&
        r->reading_body && !ctx->downstream_eof && !tc->read->eof) {
        tunnel_relay_post_downstream_read(ctx);
    }

    return;

done:
    tunnel_relay_finalize(ctx, NGX_OK);
    return;

failed:
    tunnel_relay_finalize(ctx, rc);
}

static ngx_int_t
connect_ip_recv_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    ngx_http_request_t *r;

    r = ctx->request;

    if (ctx->downstream_chain != NULL || ctx->downstream_eof) {
        return NGX_OK;
    }

    if (!r->reading_body) {
        if (r->request_body != NULL && r->request_body->bufs != NULL) {
            ctx->downstream_chain = r->request_body->bufs;
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
        ctx->downstream_chain = r->request_body->bufs;
        r->request_body->bufs = NULL;
        *activity = 1;
    } else if (rc == NGX_OK && !r->reading_body) {
        ctx->downstream_eof = 1;
    }

    return NGX_OK;
}

static ngx_int_t
connect_ip_decode_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
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
                          "CONNECT-IP request ended with incomplete capsule");
            return NGX_HTTP_BAD_REQUEST;
        }

        return NGX_OK;
    }

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "CONNECT-IP received invalid datagram capsule");
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
connect_ip_send_tun(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t       n;
    ngx_buf_t    *b;
    tunnel_tun_t  tun;

    b = ctx->upstream_buffer;

    if (!ctx->tun_connection->write->ready || b->pos == b->last) {
        return NGX_OK;
    }

    tun.fd = ctx->tun_connection->fd;
    ngx_str_set(&tun.path, "connect-ip tun");

    n = tunnel_tun_send(&tun, b, ctx->request->connection->log);
    if (n == NGX_AGAIN) {
        ctx->tun_connection->write->ready = 0;
        return NGX_OK;
    }

    if (n == NGX_ERROR) {
        ctx->tun_connection->write->error = 1;
        return NGX_DONE;
    }

    if (n > 0) {
        *activity = 1;
    }

    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
    }

    return NGX_OK;
}

static ngx_int_t
connect_ip_recv_tun(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ssize_t          n;
    size_t           size;
    ngx_buf_t       *b;
    ngx_buf_t        payload;
    tunnel_tun_t     tun;
    tunnel_capsule_t capsule;

    b = ctx->client_buffer;

    if (!ctx->tun_connection->read->ready || b->pos != b->last) {
        return NGX_OK;
    }

    if (!connect_ip_output_idle(ctx->request, ctx->request->connection)) {
        return NGX_OK;
    }

    if ((size_t)(b->end - b->start) <= CONNECT_IP_CAPSULE_HEADER_RESERVE) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = b->start;
    b->last = b->start + CONNECT_IP_CAPSULE_HEADER_RESERVE;
    size = b->end - b->last;

    tun.fd = ctx->tun_connection->fd;
    ngx_str_set(&tun.path, "connect-ip tun");

    n = tunnel_tun_read(&tun, b, ctx->request->connection->log);
    if (n == NGX_AGAIN) {
        b->pos = b->start;
        b->last = b->start;
        ctx->tun_connection->read->ready = 0;
        return NGX_OK;
    }

    if (n < 0) {
        b->pos = b->start;
        b->last = b->start;
        ctx->tun_connection->read->error = 1;
        return NGX_DONE;
    }

    if (n == 0 || (size_t)n > size) {
        b->pos = b->start;
        b->last = b->start;
        return NGX_OK;
    }

    ngx_memzero(&payload, sizeof(ngx_buf_t));
    payload.pos = b->start + CONNECT_IP_CAPSULE_HEADER_RESERVE;
    payload.last = b->last;
    payload.start = payload.pos;
    payload.end = payload.last;
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
connect_ip_send_downstream(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
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

    if (b->pos == b->last && connect_ip_output_idle(r, c)) {
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

    if (b->pos == b->last && connect_ip_output_idle(r, c)) {
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
connect_ip_output_idle(ngx_http_request_t *r, ngx_connection_t *c)
{
    return r->out == NULL && !r->buffered && !c->buffered;
}

static void
connect_ip_finalize_on_error(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx,
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

char *
tunnel_connect_ip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_loc_conf_t *tlcf = conf;

    if (tlcf->connect_ip != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    tlcf->connect_ip = 1;

    return NGX_CONF_OK;
}
