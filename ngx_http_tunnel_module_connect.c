#include "ngx_http_tunnel_module.h"

ngx_int_t
ngx_http_tunnel_init_upstream_peer(ngx_http_request_t *r,
                                   ngx_http_tunnel_ctx_t *ctx)
{
    if (ngx_http_upstream_create(r) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (ctx->resolved == NULL)
    {
        return NGX_ERROR;
    }

    r->upstream->resolved = ctx->resolved;

    return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_parse_target(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx)
{
    ngx_url_t url;
    ngx_str_t authority;
    ngx_http_upstream_resolved_t *resolved;

    if (r->http_version == NGX_HTTP_VERSION_11)
    {
        if (r->host_start == NULL || r->host_end == NULL)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        authority.data = r->host_start;
        authority.len = r->host_end - r->host_start;
    }
    else if (r->http_version == NGX_HTTP_VERSION_20 ||
             r->http_version == NGX_HTTP_VERSION_30)
    {
        if (r->headers_in.server.len == 0)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        authority = r->headers_in.server;
    }
    else
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = authority;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (url.no_port)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    resolved = ctx->resolved;
    resolved->host = url.host;
    resolved->port = url.port;
    resolved->no_port = 0;

    if (url.naddrs == 1)
    {
        resolved->sockaddr = url.addrs[0].sockaddr;
        resolved->socklen = url.addrs[0].socklen;
        resolved->name = url.addrs[0].name;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_connect_next(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_http_request_t *r;
    ngx_http_tunnel_srv_conf_t *tscf;
    ngx_http_upstream_t *u;

    r = ctx->request;
    u = r->upstream;
    c = r->connection;
    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

    rc = ngx_event_connect_peer(&u->peer);

    if (rc == NGX_DECLINED)
    {
        ngx_http_tunnel_release_peer(r, NGX_PEER_FAILED);
        ctx->peer_acquired = 0;

        if (u->peer.tries)
        {
            return ngx_http_tunnel_connect_next(ctx);
        }

        return NGX_ERROR;
    }

    if (rc == NGX_ERROR)
    {
        ngx_http_tunnel_release_peer(r, NGX_PEER_FAILED);
        ctx->peer_acquired = 0;
        return NGX_ERROR;
    }

    if (rc == NGX_BUSY)
    {
        return NGX_ERROR;
    }

    ctx->peer_acquired = 1;

    u->peer.connection->data = ctx;
    u->peer.connection->pool = r->pool;
    u->peer.connection->log = c->log;
    u->peer.connection->read->log = c->log;
    u->peer.connection->write->log = c->log;

    if (rc == NGX_AGAIN)
    {
        ctx->waiting_connect = 1;
        u->peer.connection->read->handler = ngx_http_tunnel_connect_handler;
        u->peer.connection->write->handler = ngx_http_tunnel_connect_handler;
        ngx_add_timer(u->peer.connection->write, tscf->connect_timeout);
        return NGX_OK;
    }

    return ngx_http_tunnel_start(ctx);
}

void ngx_http_tunnel_resolve_handler(ngx_resolver_ctx_t *resolver_ctx)
{
    ngx_int_t rc;
    ngx_http_request_t *r;
    ngx_http_tunnel_ctx_t *ctx;
    ngx_http_upstream_resolved_t *resolved;

    ctx = resolver_ctx->data;
    r = ctx->request;
    resolved = ctx->resolved;

    ctx->resolving = 0;
    ctx->resolver_ctx = NULL;

    if (ctx->finalized)
    {
        ngx_resolve_name_done(resolver_ctx);
        return;
    }

    if (resolver_ctx->state || resolver_ctx->naddrs == 0)
    {
        ngx_resolve_name_done(resolver_ctx);
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    resolved->naddrs = resolver_ctx->naddrs;
    resolved->addrs = resolver_ctx->addrs;

    if (ngx_http_upstream_create_round_robin_peer(r, resolved) != NGX_OK)
    {
        ngx_resolve_name_done(resolver_ctx);
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(resolver_ctx);

    rc = ngx_http_tunnel_connect_next(ctx);
    if (rc != NGX_OK)
    {
        ngx_http_tunnel_finalize(
            ctx, rc >= NGX_HTTP_SPECIAL_RESPONSE ? rc : NGX_HTTP_BAD_GATEWAY);
    }
}

void ngx_http_tunnel_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_int_t rc;
    ngx_http_request_t *r;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;
    r = ctx->request;

    if (ev->timedout)
    {
        ngx_close_connection(c);
        r->upstream->peer.connection = NULL;
        ctx->waiting_connect = 0;
        ngx_http_tunnel_release_peer(r, NGX_PEER_FAILED);
        ctx->peer_acquired = 0;

        if (r->upstream->peer.tries && ngx_http_tunnel_connect_next(ctx) == NGX_OK)
        {
            return;
        }

        ngx_http_tunnel_finalize(ctx, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (ngx_http_tunnel_test_connect(c) != NGX_OK)
    {
        if (c->write->timer_set)
        {
            ngx_del_timer(c->write);
        }

        ngx_close_connection(c);
        r->upstream->peer.connection = NULL;
        ctx->waiting_connect = 0;
        ngx_http_tunnel_release_peer(r, NGX_PEER_FAILED);
        ctx->peer_acquired = 0;

        if (r->upstream->peer.tries && ngx_http_tunnel_connect_next(ctx) == NGX_OK)
        {
            return;
        }

        ngx_http_tunnel_finalize(ctx, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    rc = ngx_http_tunnel_start(ctx);
    if (rc != NGX_OK)
    {
        ngx_http_tunnel_finalize(
            ctx,
            rc >= NGX_HTTP_SPECIAL_RESPONSE ? rc
                                            : NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}
