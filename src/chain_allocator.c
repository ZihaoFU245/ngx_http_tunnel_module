
/*
 * Copyright(c) 2026 ZihaoFU245
 */

#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_SMALL_BUF_SIZE 256
#define NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE 4096

typedef enum {
    TUNNEL_CHAIN_BUF_SMALL = 0,
    TUNNEL_CHAIN_BUF_MEDIUM,
    TUNNEL_CHAIN_BUF_LARGE,
    TUNNEL_CHAIN_BUF_COUNT
} tunnel_chain_buf_class_e;

struct tunnel_chain_allocator_s {
    ngx_chain_t *free[TUNNEL_CHAIN_BUF_COUNT];
};

static tunnel_chain_allocator_t *
chain_allocator_get(ngx_http_tunnel_ctx_t *ctx);
static ngx_chain_t *
chain_allocator_get_free_buf(ngx_http_tunnel_ctx_t    *ctx,
                             tunnel_chain_allocator_t *alloc, size_t size);
static void chain_allocator_put_free_buf(tunnel_chain_allocator_t *alloc,
                                         ngx_chain_t              *cl);
static ngx_chain_t **chain_allocator_free_list(tunnel_chain_allocator_t *alloc,
                                               size_t                    size);
static size_t        chain_allocator_alloc_size(size_t size);
static tunnel_chain_buf_class_e chain_allocator_buf_class(size_t size);
static void                     chain_allocator_reset_temp_buf(ngx_buf_t *b);

void
tunnel_utils_free_consumed_chain(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_chain_t **chain, ngx_chain_t *limit)
{
    ngx_buf_t                *b;
    tunnel_chain_allocator_t *alloc;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r;

    r = ctx->request;

    while (*chain != limit && *chain != NULL &&
           ngx_buf_size((*chain)->buf) == 0) {
        cl = *chain;
        b = cl->buf;
        *chain = cl->next;

        if (b->tag == (ngx_buf_tag_t)&ngx_http_tunnel_connect_module) {
            ctx->buffered = (ctx->buffered > (size_t)(b->end - b->start))
                                ? ctx->buffered - (size_t)(b->end - b->start)
                                : 0;

            chain_allocator_reset_temp_buf(b);

            alloc = ctx->chain_allocator;
            if (alloc == NULL) {
                ngx_free_chain(r->pool, cl);
                continue;
            }

            chain_allocator_put_free_buf(alloc, cl);
            continue;
        }

        ngx_free_chain(r->pool, cl);
    }
}

ngx_int_t
tunnel_utils_alloc_chain_buf(ngx_http_tunnel_ctx_t *ctx, ngx_chain_t **cl,
                             size_t size)
{
    ngx_buf_t                *b;
    tunnel_chain_allocator_t *alloc;
    ngx_http_request_t       *r;
    size_t                    alloc_size;

    if (size == 0) {
        return NGX_AGAIN;
    }

    alloc = chain_allocator_get(ctx);
    if (alloc == NULL) {
        return NGX_ERROR;
    }

    *cl = chain_allocator_get_free_buf(ctx, alloc, size);
    if (*cl != NULL) {
        ctx->buffered += (size_t)((*cl)->buf->end - (*cl)->buf->start);
        return NGX_OK;
    }

    alloc_size = chain_allocator_alloc_size(size);

    if (ctx->buffered >= ctx->buffer_limit ||
        alloc_size > ctx->buffer_limit - ctx->buffered) {
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

static tunnel_chain_allocator_t *
chain_allocator_get(ngx_http_tunnel_ctx_t *ctx)
{
    if (ctx->chain_allocator != NULL) {
        return ctx->chain_allocator;
    }

    ctx->chain_allocator =
        ngx_pcalloc(ctx->request->pool, sizeof(tunnel_chain_allocator_t));

    return ctx->chain_allocator;
}

static ngx_chain_t *
chain_allocator_get_free_buf(ngx_http_tunnel_ctx_t    *ctx,
                             tunnel_chain_allocator_t *alloc, size_t size)
{
    ngx_buf_t   *b;
    ngx_chain_t *cl, **ll;
    size_t       capacity;

    ll = chain_allocator_free_list(alloc, size);

    while (*ll != NULL) {
        cl = *ll;
        b = cl->buf;
        capacity = (size_t)(b->end - b->start);

        if (ctx->buffered < ctx->buffer_limit && capacity >= size &&
            capacity <= ctx->buffer_limit - ctx->buffered) {
            *ll = cl->next;
            cl->next = NULL;
            chain_allocator_reset_temp_buf(b);
            return cl;
        }

        ll = &cl->next;
    }

    return NULL;
}

static void
chain_allocator_put_free_buf(tunnel_chain_allocator_t *alloc, ngx_chain_t *cl)
{
    ngx_chain_t **free;

    free = chain_allocator_free_list(alloc,
                                     (size_t)(cl->buf->end - cl->buf->start));

    cl->next = *free;
    *free = cl;
}

static ngx_chain_t **
chain_allocator_free_list(tunnel_chain_allocator_t *alloc, size_t size)
{
    return &alloc->free[chain_allocator_buf_class(size)];
}

static size_t
chain_allocator_alloc_size(size_t size)
{
    switch (chain_allocator_buf_class(size)) {

    case TUNNEL_CHAIN_BUF_SMALL:
        return NGX_HTTP_TUNNEL_SMALL_BUF_SIZE;

    case TUNNEL_CHAIN_BUF_MEDIUM:
        return NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE;

    case TUNNEL_CHAIN_BUF_LARGE:
    default:
        return size;
    }
}

static tunnel_chain_buf_class_e
chain_allocator_buf_class(size_t size)
{
    if (size <= NGX_HTTP_TUNNEL_SMALL_BUF_SIZE) {
        return TUNNEL_CHAIN_BUF_SMALL;
    }

    if (size <= NGX_HTTP_TUNNEL_MEDIUM_BUF_SIZE) {
        return TUNNEL_CHAIN_BUF_MEDIUM;
    }

    return TUNNEL_CHAIN_BUF_LARGE;
}

static void
chain_allocator_reset_temp_buf(ngx_buf_t *b)
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
