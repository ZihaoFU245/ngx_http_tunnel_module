#include "ngx_http_tunnel_module.h"

ngx_int_t
ngx_http_tunnel_start(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_connection_t *c;
    ngx_connection_t *pc;
    ngx_http_request_t *r;
    ngx_http_upstream_t *u;
    ngx_http_core_loc_conf_t *clcf;

    r = ctx->request;
    u = r->upstream;
    c = r->connection;
    pc = u->peer.connection;

    if (pc->write->timer_set)
    {
        ngx_del_timer(pc->write);
    }

    ctx->waiting_connect = 0;
    ctx->connected = 1;
    r->keepalive = 0;
    c->log->action = "tunneling connection";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->tcp_nodelay)
    {
        if (ngx_tcp_nodelay(c) != NGX_OK || ngx_tcp_nodelay(pc) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_http_tunnel_send_connected(r) != NGX_OK)
    {
        return NGX_ERROR;
    }

    pc->read->handler = ngx_http_tunnel_upstream_read_handler;
    pc->write->handler = ngx_http_tunnel_upstream_write_handler;
    r->read_event_handler = ngx_http_tunnel_downstream_read_handler;
    r->write_event_handler = ngx_http_tunnel_downstream_write_handler;

    if (pc->read->ready)
    {
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
    r->headers_out.content_length_n = 0;
    ngx_str_set(&r->headers_out.status_line, "200 Connection Established");
    ngx_str_null(&r->headers_out.content_type);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

void ngx_http_tunnel_downstream_read_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_tunnel_process(ctx, 0, 0);
}

void ngx_http_tunnel_downstream_write_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_tunnel_process(ctx, 1, 1);
}

void ngx_http_tunnel_upstream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_http_tunnel_process(ctx, 1, 0);
}

void ngx_http_tunnel_upstream_write_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_http_tunnel_process(ctx, 0, 1);
}

void ngx_http_tunnel_process(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t from_upstream,
                             ngx_uint_t do_write)
{
    size_t size;
    ssize_t n;
    ngx_buf_t *b;
    ngx_uint_t flags;
    ngx_connection_t *c, *dst, *pc, *src;
    ngx_http_request_t *r;
    ngx_http_upstream_t *u;
    ngx_http_core_loc_conf_t *clcf;

    r = ctx->request;
    u = r->upstream;
    c = r->connection;
    pc = u->peer.connection;

    if (ctx->finalized || pc == NULL)
    {
        return;
    }

    if (from_upstream)
    {
        src = pc;
        dst = c;
        b = ctx->upstream_buffer;
    }
    else
    {
        src = c;
        dst = pc;
        b = ctx->client_buffer;
    }

    for (;;)
    {
        if (do_write)
        {
            size = b->last - b->pos;

            if (size != 0 && dst->write->ready)
            {
                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR)
                {
                    ngx_http_tunnel_finalize(ctx, 0);
                    return;
                }

                if (n > 0)
                {
                    b->pos += n;

                    if (b->pos == b->last)
                    {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size != 0 && src->read->ready)
        {
            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0)
            {
                if (n == 0)
                {
                    src->read->eof = 1;
                }

                break;
            }

            if (n > 0)
            {
                b->last += n;
                do_write = 1;
                continue;
            }

            src->read->eof = 1;
        }

        break;
    }

    if ((pc->read->eof && ctx->upstream_buffer->pos == ctx->upstream_buffer->last) || (c->read->eof && ctx->client_buffer->pos == ctx->client_buffer->last) || (c->read->eof && pc->read->eof))
    {
        ngx_http_tunnel_finalize(ctx, 0);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT : 0) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    flags = c->read->eof ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(c->read, flags) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

void ngx_http_tunnel_release_peer(ngx_http_request_t *r, ngx_uint_t state)
{
    ngx_http_upstream_t *u;

    u = r->upstream;

    if (u == NULL || u->peer.free == NULL || u->peer.sockaddr == NULL)
    {
        return;
    }

    u->peer.free(&u->peer, u->peer.data, state);
    u->peer.sockaddr = NULL;
    u->peer.connection = NULL;
}

void ngx_http_tunnel_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
{
    ngx_connection_t *pc;
    ngx_http_request_t *r;

    if (ctx->finalized)
    {
        return;
    }

    ctx->finalized = 1;
    r = ctx->request;

    if (ctx->resolving && ctx->resolver_ctx != NULL)
    {
        ngx_resolve_name_done(ctx->resolver_ctx);
        ctx->resolver_ctx = NULL;
        ctx->resolving = 0;
    }

    pc = (r->upstream != NULL) ? r->upstream->peer.connection : NULL;
    if (pc != NULL)
    {
        if (pc->read->timer_set)
        {
            ngx_del_timer(pc->read);
        }

        if (pc->write->timer_set)
        {
            ngx_del_timer(pc->write);
        }

        ngx_close_connection(pc);
        r->upstream->peer.connection = NULL;
    }

    if (ctx->peer_acquired)
    {
        ngx_http_tunnel_release_peer(r, 0);
        ctx->peer_acquired = 0;
    }

    ngx_http_finalize_request(r, rc);
}

void ngx_http_tunnel_cleanup(void *data)
{
    ngx_connection_t *pc;
    ngx_http_request_t *r;
    ngx_http_tunnel_ctx_t *ctx;

    ctx = data;
    if (ctx->finalized)
    {
        return;
    }

    ctx->finalized = 1;
    r = ctx->request;

    if (ctx->resolving && ctx->resolver_ctx != NULL)
    {
        ngx_resolve_name_done(ctx->resolver_ctx);
        ctx->resolver_ctx = NULL;
        ctx->resolving = 0;
    }

    pc = (r->upstream != NULL) ? r->upstream->peer.connection : NULL;
    if (pc != NULL)
    {
        if (pc->read->timer_set)
        {
            ngx_del_timer(pc->read);
        }

        if (pc->write->timer_set)
        {
            ngx_del_timer(pc->write);
        }

        ngx_close_connection(pc);
        r->upstream->peer.connection = NULL;
    }

    if (ctx->peer_acquired)
    {
        ngx_http_tunnel_release_peer(r, 0);
        ctx->peer_acquired = 0;
    }
}

ngx_int_t
ngx_http_tunnel_test_connect(ngx_connection_t *c)
{
    int err;
    socklen_t len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)
    {
        if (c->write->pending_eof || c->read->pending_eof)
        {
            err = c->write->pending_eof ? c->write->kq_errno : c->read->kq_errno;
            (void)ngx_connection_error(c, err,
                                       "kevent() reported that connect() failed");
            return NGX_ERROR;
        }
    }
    else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) == -1)
        {
            err = ngx_socket_errno;
        }

        if (err != 0)
        {
            (void)ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
