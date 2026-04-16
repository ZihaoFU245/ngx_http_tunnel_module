#include "ngx_http_tunnel_module.h"

static void ngx_http_tunnel_request_body_post_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_send_stream_downstream(
    ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity);
static ngx_int_t ngx_http_tunnel_recv_stream_downstream(
    ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity);
static ngx_int_t ngx_http_tunnel_send_stream_upstream(
    ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity);

ngx_int_t
ngx_http_tunnel_stream_downstream(ngx_http_request_t *r)
{
    return r->http_version == NGX_HTTP_VERSION_20 ||
           r->http_version == NGX_HTTP_VERSION_30;
}

ngx_int_t
ngx_http_tunnel_init_request_body(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t rc;
    ngx_http_request_t *r;

    r = ctx->request;

    if (!ngx_http_tunnel_stream_downstream(r) || ctx->request_body_started)
    {
        return NGX_OK;
    }

    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(
        r, ngx_http_tunnel_request_body_post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
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
    ngx_uint_t flags;
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

    if (ctx->finalized || pc == NULL)
    {
        return NGX_OK;
    }

    if (c->read->timedout || c->write->timedout || pc->read->timedout ||
        pc->write->timedout)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "tunnel idle timeout");
        return NGX_DONE;
    }

    activity = 0;

    for (;;)
    {
        if (ctx->downstream_chain != NULL)
        {
            rc = ngx_http_tunnel_send_stream_upstream(ctx, &activity);
            if (rc != NGX_OK)
            {
                return rc;
            }
        }

        rc = ngx_http_tunnel_send_stream_downstream(ctx, &activity);
        if (rc != NGX_OK)
        {
            return rc;
        }

        if (ctx->downstream_chain == NULL && !ctx->downstream_eof)
        {
            rc = ngx_http_tunnel_recv_stream_downstream(ctx, &activity);
            if (rc != NGX_OK)
            {
                return rc;
            }

            if (ctx->downstream_chain != NULL)
            {
                continue;
            }
        }

        if (ctx->upstream_buffer->pos == ctx->upstream_buffer->last &&
            r->out == NULL && !r->buffered && !c->buffered && pc->read->ready)
        {
            b = ctx->upstream_buffer;
            size = b->end - b->last;

            if (size != 0)
            {
                n = pc->recv(pc, b->last, size);

                if (n == NGX_AGAIN || n == 0)
                {
                    if (n == 0)
                    {
                        pc->read->eof = 1;
                    }
                }
                else if (n > 0)
                {
                    b->last += n;
                    activity = 1;
                    continue;
                }
                else
                {
                    pc->read->eof = 1;
                }
            }
        }

        break;
    }

    if ((pc->read->eof && ctx->upstream_buffer->pos == ctx->upstream_buffer->last && r->out == NULL && !r->buffered && !c->buffered) || (ctx->downstream_eof && pc->read->eof &&
                                                                                                                                         ctx->downstream_chain == NULL))
    {
        return NGX_DONE;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);
    idle_timeout = tscf->idle_timeout;

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT : NGX_OK) !=
        NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    flags = c->read->eof ? NGX_CLOSE_EVENT : NGX_OK;

    if (ngx_handle_read_event(c->read, flags) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (activity)
    {
        if (pc->read->timer_set)
        {
            ngx_del_timer(pc->read);
        }

        if (pc->write->timer_set)
        {
            ngx_del_timer(pc->write);
        }

        if (c->read->timer_set)
        {
            ngx_del_timer(c->read);
        }

        if (c->write->timer_set)
        {
            ngx_del_timer(c->write);
        }

        if (pc->write->active && !pc->write->ready)
        {
            ngx_add_timer(pc->write, idle_timeout);
        }

        if (pc->read->active && !pc->read->ready)
        {
            ngx_add_timer(pc->read, idle_timeout);
        }

        if (c->write->active && !c->write->ready)
        {
            ngx_add_timer(c->write, idle_timeout);
        }

        if (c->read->active && !c->read->ready)
        {
            ngx_add_timer(c->read, idle_timeout);
        }
    }

    return NGX_OK;
}

static void
ngx_http_tunnel_request_body_post_handler(ngx_http_request_t *r)
{
    return;
}

static ngx_int_t
ngx_http_tunnel_send_stream_downstream(ngx_http_tunnel_ctx_t *ctx,
                                       ngx_uint_t *activity)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_connection_t *c;
    ngx_http_request_t *r;

    r = ctx->request;
    c = r->connection;
    b = ctx->upstream_buffer;

    if (b->pos == b->last && r->out == NULL && !r->buffered && !c->buffered)
    {
        return NGX_OK;
    }

    if (r->out != NULL || r->buffered || c->buffered)
    {
        rc = ngx_http_output_filter(r, NULL);
    }
    else
    {
        out.buf = b;
        out.next = NULL;

        b->flush = 1;
        rc = ngx_http_output_filter(r, &out);
        b->flush = 0;
    }

    if (rc == NGX_ERROR)
    {
        return NGX_DONE;
    }

    if (b->pos == b->last && r->out == NULL && !r->buffered && !c->buffered)
    {
        b->pos = b->start;
        b->last = b->start;
    }

    if (rc == NGX_OK || rc == NGX_AGAIN)
    {
        *activity = 1;
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

    if (!ctx->request_body_started || !r->reading_body)
    {
        if (r->request_body != NULL && r->request_body->bufs != NULL)
        {
            ctx->downstream_chain = r->request_body->bufs;
            r->request_body->bufs = NULL;
            *activity = 1;
        }
        else if (ctx->request_body_started)
        {
            ctx->downstream_eof = 1;
        }

        return NGX_OK;
    }

    rc = ngx_http_read_unbuffered_request_body(r);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        return rc;
    }

    if (r->request_body != NULL && r->request_body->bufs != NULL)
    {
        ctx->downstream_chain = r->request_body->bufs;
        r->request_body->bufs = NULL;
        *activity = 1;
    }
    else if (rc == NGX_OK && !r->reading_body)
    {
        ctx->downstream_eof = 1;
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
    ngx_chain_t *cl;
    ngx_connection_t *pc;
    ngx_http_request_t *r;

    r = ctx->request;
    pc = r->upstream->peer.connection;

    while (ctx->downstream_chain != NULL && pc->write->ready)
    {
        cl = ctx->downstream_chain;
        b = cl->buf;
        size = ngx_buf_size(b);

        if (size == 0)
        {
            ctx->downstream_chain = cl->next;
            ngx_free_chain(r->pool, cl);
            continue;
        }

        n = pc->send(pc, b->pos, size);

        if (n == NGX_ERROR)
        {
            return NGX_DONE;
        }

        if (n == NGX_AGAIN)
        {
            break;
        }

        if (n > 0)
        {
            b->pos += n;
            *activity = 1;

            if (ngx_buf_size(b) == 0)
            {
                ctx->downstream_chain = cl->next;
                ngx_free_chain(r->pool, cl);
            }
        }
    }

    return NGX_OK;
}
