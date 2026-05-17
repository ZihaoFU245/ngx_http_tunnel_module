
/*
 * Copyright(c) 2026 ZihaoFU245
 */

#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_SMALL_BUF_SIZE 256
#define NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE 4096

static tunnel_extended_connect_regex_t tunnel_extended_connect_regexes[] = {
	{
		ngx_string("^/.well-known/masque/udp/([^/?#]+)/([0-9]{1,5})/(?:[?#].*)?$"),
		NULL,
		1,
		2
	},
	{
		ngx_string("(?:^|[?&])h=([^&#]+)(?:&[^#]*)*&p=([0-9]{1,5})(?:[&#]|$)"),
		NULL,
		1,
		2
	},
	{
		ngx_string("(?:^|[?&])p=([0-9]{1,5})(?:&[^#]*)*&h=([^&#]+)(?:[&#]|$)"),
		NULL,
		2,
		1
	},
	{
		ngx_string("(?:^|[?&])target_host=([^&#]+)(?:&[^#]*)*&target_port=([0-9]{1,5})(?:[&#]|$)"),
		NULL,
		1,
		2
	},
	{
		ngx_string("(?:^|[?&])target_port=([0-9]{1,5})(?:&[^#]*)*&target_host=([^&#]+)(?:[&#]|$)"),
		NULL,
		2,
		1
	}
};

static ngx_chain_t *utils_get_free_buf(ngx_http_tunnel_ctx_t *ctx,
                                       size_t size);
static size_t      utils_alloc_size(size_t size);
static ngx_uint_t  utils_buf_match(size_t capacity, size_t size);
static void        utils_reset_temp_buf(ngx_buf_t *b);
static ngx_uint_t  utils_cache_free_buf(ngx_http_tunnel_ctx_t *ctx,
                                        ngx_chain_t *cl, size_t size);
static void        utils_reclaim_free_bufs(ngx_http_tunnel_ctx_t *ctx,
                                           size_t need);

ngx_int_t
tunnel_utils_init_extended_connect(ngx_conf_t *cf)
{
    u_char              errstr[NGX_MAX_CONF_ERRSTR];
    ngx_uint_t          i;
    ngx_regex_compile_t rc;

    for (i = 0; i < sizeof(tunnel_extended_connect_regexes) /
                        sizeof(tunnel_extended_connect_regexes[0]);
         i++) {
        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = tunnel_extended_connect_regexes[i].pattern;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "failed to compile tunnel extended CONNECT "
                               "regex \"%V\": %V",
                               &rc.pattern, &rc.err);
            return NGX_ERROR;
        }

        tunnel_extended_connect_regexes[i].regex = rc.regex;
    }

    return NGX_OK;
}

ngx_int_t
tunnel_util_parse_extended_connect(ngx_http_request_t *r, ngx_str_t *params,
                                   ngx_http_upstream_resolved_t *resolved)
{
    int                              captures[9];
    ngx_int_t                        rc, port;
    ngx_uint_t                       i;
    ngx_str_t                        host;
    tunnel_extended_connect_regex_t *re;

    if (params == NULL || resolved == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid extended CONNECT parser argument");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * params is generated from tunnel_udp_path, which defaults to
     * $request_uri.  An empty value means the configured complex value did
     * not produce a target string, not that the client sent an unparsable
     * target.
     */
    if (params->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tunnel_udp_path evaluated to empty extended CONNECT "
                      "target");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < sizeof(tunnel_extended_connect_regexes) /
                        sizeof(tunnel_extended_connect_regexes[0]);
         i++) {
        re = &tunnel_extended_connect_regexes[i];

        rc = ngx_regex_exec(re->regex, params, captures, 9);
        if (rc == NGX_REGEX_NO_MATCHED) {
            continue;
        }

        if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          ngx_regex_exec_n " failed: %i on \"%V\"", rc, params);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        host.data = params->data + captures[re->host_capture * 2];
        host.len =
            captures[re->host_capture * 2 + 1] - captures[re->host_capture * 2];

        if (host.len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent extended CONNECT target without host");
            return NGX_HTTP_BAD_REQUEST;
        }

        port = ngx_atoi(params->data + captures[re->port_capture * 2],
                        captures[re->port_capture * 2 + 1] -
                            captures[re->port_capture * 2]);

        if (port < 1 || port > 65535) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid extended CONNECT target port");
            return NGX_HTTP_BAD_REQUEST;
        }

        resolved->host = host;
        resolved->port = (in_port_t)port;
        resolved->no_port = 0;

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent invalid extended CONNECT target \"%V\"", params);

    return NGX_HTTP_BAD_REQUEST;
}

ngx_http_tunnel_protocol_t
tunnel_utils_match_protocol(ngx_http_request_t *r)
{
    if (tunnel_udp_is_request(r) == NGX_OK) {
        return CONNECT_UDP;
    }

    /* Other matching will go here */

    return UNKNOWN_PROTOCOL;
}

void
tunnel_utils_clear_timer(ngx_event_t *ev)
{
    if (ev->timer_set) {
        ngx_del_timer(ev);
    }
}

void
tunnel_utils_update_idle_timer(ngx_event_t *ev, ngx_msec_t timeout)
{
    if (ev->active) {
        ngx_add_timer(ev, timeout);
        return;
    }

    tunnel_utils_clear_timer(ev);
}

void
tunnel_utils_free_consumed_chain(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_chain_t **chain, ngx_chain_t *limit)
{
    size_t              size;
    ngx_buf_t          *b;
    ngx_chain_t        *cl;
    ngx_http_request_t *r;

    r = ctx->request;

    while (*chain != limit && *chain != NULL &&
           ngx_buf_size((*chain)->buf) == 0) {
        cl = *chain;
        b = cl->buf;
        *chain = cl->next;

        if (b->tag != (ngx_buf_tag_t)&ngx_http_tunnel_connect_module) {
            ngx_free_chain(r->pool, cl);
            continue;
        }

        size = (size_t)(b->end - b->start);
        ctx->buffered = (ctx->buffered > size) ? ctx->buffered - size : 0;
        utils_reset_temp_buf(b);

        if (utils_cache_free_buf(ctx, cl, size)) {
            continue;
        }

        (void)ngx_pfree(r->pool, b->start);
        ngx_free_chain(r->pool, cl);
    }
}

ngx_int_t
tunnel_utils_alloc_chain_buf(ngx_http_tunnel_ctx_t *ctx, ngx_chain_t **cl,
                             size_t size)
{
    size_t              alloc_size;
    ngx_buf_t          *b;
    ngx_http_request_t *r;

    if (size == 0) {
        return NGX_AGAIN;
    }

    *cl = utils_get_free_buf(ctx, size);
    if (*cl != NULL) {
        return NGX_OK;
    }

    alloc_size = utils_alloc_size(size);
    utils_reclaim_free_bufs(ctx, alloc_size);

    if (ctx->buffered + ctx->free_buffered >= ctx->buffer_limit ||
        alloc_size > ctx->buffer_limit - ctx->buffered - ctx->free_buffered) {
        return NGX_AGAIN;
    }

    r = ctx->request;

    *cl = ngx_alloc_chain_link(r->pool);
    if (*cl == NULL) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, alloc_size);
    if (b == NULL) {
        ngx_free_chain(r->pool, *cl);
        return NGX_ERROR;
    }

    b->tag = (ngx_buf_tag_t)&ngx_http_tunnel_connect_module;
    (*cl)->buf = b;
    (*cl)->next = NULL;
    ctx->buffered += alloc_size;

    return NGX_OK;
}

ngx_uint_t
tunnel_utils_append_chain(ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_uint_t   last_buf;
    ngx_chain_t *cl, **ll;

    if (in == NULL) {
        return 0;
    }

    ll = chain;
    while (*ll != NULL) {
        ll = &(*ll)->next;
    }

    *ll = in;

    last_buf = 0;
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            last_buf = 1;
        }
    }

    return last_buf;
}

ngx_inline ngx_uint_t
tunnel_utils_chain_have(ngx_chain_t *chain, u_char *pos, size_t len)
{
    size_t n;

    while (len != 0) {
        if (chain == NULL) {
            return 0;
        }

        if (pos == NULL || pos == chain->buf->last) {
            chain = chain->next;
            pos = chain == NULL ? NULL : chain->buf->pos;
            continue;
        }

        n = chain->buf->last - pos;
        if (n >= len) {
            return 1;
        }

        len -= n;
        chain = chain->next;
        pos = chain == NULL ? NULL : chain->buf->pos;
    }

    return 1;
}

static ngx_chain_t *
utils_get_free_buf(ngx_http_tunnel_ctx_t *ctx, size_t size)
{
    size_t       capacity;
    ngx_buf_t  *b;
    ngx_chain_t *cl, **ll;

    for (ll = &ctx->free_chain; *ll != NULL; ll = &(*ll)->next) {
        cl = *ll;
        b = cl->buf;
        capacity = (size_t)(b->end - b->start);

        if (!utils_buf_match(capacity, size)) {
            continue;
        }

        *ll = cl->next;
        cl->next = NULL;
        ctx->free_buffered -= capacity;
        ctx->buffered += capacity;
        utils_reset_temp_buf(b);
        return cl;
    }

    return NULL;
}

static ngx_uint_t
utils_buf_match(size_t capacity, size_t size)
{
    if (size <= NGX_HTTP_TUNNEL_SMALL_BUF_SIZE) {
        return capacity >= size && capacity <= NGX_HTTP_TUNNEL_SMALL_BUF_SIZE;
    }

    if (size <= NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE) {
        return capacity >= size &&
               capacity <= NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE;
    }

    return capacity >= size;
}

static size_t
utils_alloc_size(size_t size)
{
    if (size <= NGX_HTTP_TUNNEL_SMALL_BUF_SIZE) {
        return NGX_HTTP_TUNNEL_SMALL_BUF_SIZE;
    }

    if (size <= NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE) {
        return NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE;
    }

    return size;
}

static void
utils_reset_temp_buf(ngx_buf_t *b)
{
    u_char *start, *end;

    start = b->start;
    end = b->end;

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->pos = start;
    b->last = start;
    b->start = start;
    b->end = end;
    b->temporary = 1;
    b->tag = (ngx_buf_tag_t)&ngx_http_tunnel_connect_module;
}

static ngx_uint_t
utils_cache_free_buf(ngx_http_tunnel_ctx_t *ctx, ngx_chain_t *cl, size_t size)
{
    if (ctx->buffered + ctx->free_buffered >= ctx->buffer_limit ||
        size > ctx->buffer_limit - ctx->buffered - ctx->free_buffered) {
        return 0;
    }

    ctx->free_buffered += size;
    cl->next = ctx->free_chain;
    ctx->free_chain = cl;

    return 1;
}

static void
utils_reclaim_free_bufs(ngx_http_tunnel_ctx_t *ctx, size_t need)
{
    size_t              size;
    ngx_buf_t          *b;
    ngx_chain_t        *cl;
    ngx_http_request_t *r;

    r = ctx->request;

    while (ctx->free_chain != NULL &&
           ctx->buffered + ctx->free_buffered + need > ctx->buffer_limit) {
        cl = ctx->free_chain;
        ctx->free_chain = cl->next;
        cl->next = NULL;

        b = cl->buf;
        size = (size_t)(b->end - b->start);
        ctx->free_buffered = (ctx->free_buffered > size)
                                 ? ctx->free_buffered - size
                                 : 0;

        (void) ngx_pfree(r->pool, b->start);
        ngx_free_chain(r->pool, cl);
    }
}
