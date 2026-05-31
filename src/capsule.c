
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Reusable capsule protocol implementation
 * for connect udp mainly.
 */

#include "ngx_http_tunnel_module.h"

#define capsule_reset(capsule)                                                 \
    ((capsule)->capsule_len = 0, (capsule)->payload_size = 0,                  \
     (capsule)->read_state = CAPSULE_READ_TYPE)

static ngx_int_t capsule_encode_varint(u_char **pos, u_char *last,
                                       uint64_t value);
static ngx_int_t capsule_read_varint(ngx_http_tunnel_ctx_t *ctx,
                                     uint64_t *value, size_t *encoded);
static ngx_int_t capsule_prepare_datagram(ngx_http_tunnel_ctx_t *ctx,
                                          size_t payload_size);
static ngx_int_t capsule_chain_read_varint(ngx_chain_t **chain, u_char **pos,
                                           uint64_t *value, size_t *encoded);
static void capsule_chain_advance(ngx_chain_t **chain, u_char **pos, size_t n);
static ngx_int_t capsule_is_protocol_header(ngx_table_elt_t *header);

enum {
    CAPSULE_READ_TYPE = 0,
    CAPSULE_READ_LENGTH,
    CAPSULE_READ_CONTEXT,
    CAPSULE_READ_PAYLOAD
};

ngx_int_t
tunnel_capsule_is_header_present(ngx_http_request_t *r)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t       found, i;
    size_t           match_len;

    match_len = sizeof("?1") - 1;
    found = 0;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                return found == 1 ? NGX_OK : NGX_DECLINED;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (capsule_is_protocol_header(&header[i]) != NGX_OK) {
            continue;
        }

        if (header[i].value.len != match_len ||
            ngx_strncmp(header[i].value.data, "?1", match_len) != 0) {
            return NGX_DECLINED;
        }

        found++;
        if (found > 1) {
            return NGX_DECLINED;
        }
    }
}

/*
 * QUIC varint, valid return values are
 * {1, 2, 4, 8}
 * 0 represent an error.
 */
static size_t
tunnel_capsule_varint_size(uint64_t value)
{
    if (value <= 0x3f) {
        return 1;
    }

    if (value <= 0x3fff) {
        return 2;
    }

    if (value <= 0x3fffffff) {
        return 4;
    }

    if (value <= 0x3fffffffffffffff) {
        return 8;
    }

    return 0;
}

ngx_int_t
tunnel_capsule_downstream_filter(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_uint_t            *activity)
{
    size_t                encoded;
    ngx_int_t             rc;
    ngx_http_request_t   *r;
    uint64_t              value;
    tunnel_capsule_ctx_t *capsule;

    r = ctx->request;
    capsule = ctx->capsule;

    if (capsule == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (;;) {
        switch (capsule->read_state) {

        case CAPSULE_READ_TYPE:
            if (capsule_read_varint(ctx, &value, NULL) != NGX_OK) {
                goto incomplete;
            }

            if (value != CAPSULE_DATAGRAM) {
                goto invalid;
            }

            capsule->read_state = CAPSULE_READ_LENGTH;
            *activity = 1;
            continue;

        case CAPSULE_READ_LENGTH:
            if (capsule_read_varint(ctx, &capsule->capsule_len, NULL) !=
                NGX_OK) {
                goto incomplete;
            }

            if (capsule->capsule_len > NGX_HTTP_TUNNEL_MAX_DATAGRAM_CAPSULE) {
                goto invalid;
            }

            capsule->read_state = CAPSULE_READ_CONTEXT;
            *activity = 1;
            continue;

        case CAPSULE_READ_CONTEXT:
            if (capsule_read_varint(ctx, &value, &encoded) != NGX_OK) {
                goto incomplete;
            }

            if (value != CAPSULE_DATAGRAM_CONTEXT_ID ||
                capsule->capsule_len < encoded) {
                goto invalid;
            }

            capsule->payload_size = capsule->capsule_len - encoded;
            capsule->read_state = CAPSULE_READ_PAYLOAD;
            *activity = 1;

            if (capsule->payload_size == 0) {
                ctx->downstream_empty_datagram = 1;
                capsule_reset(capsule);
                return NGX_OK;
            }

            continue;

        case CAPSULE_READ_PAYLOAD:
            if (ctx->downstream_in == NULL) {
                goto incomplete;
            }

            rc = capsule_prepare_datagram(ctx, (size_t)capsule->payload_size);
            if (rc == NGX_AGAIN) {
                goto incomplete;
            }
            if (rc != NGX_OK) {
                return rc;
            }

            ctx->flush_size = (size_t)capsule->payload_size;
            capsule_reset(capsule);
            *activity = 1;
            return NGX_OK;

        default:
            return NGX_HTTP_BAD_REQUEST;
        }
    }

incomplete:
    if (ctx->downstream_eof && (capsule->read_state != CAPSULE_READ_TYPE ||
                                ctx->downstream_in != NULL)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "CONNECT-UDP request ended with incomplete capsule");
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_AGAIN;

invalid:
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "CONNECT-UDP received invalid datagram capsule");
    return NGX_HTTP_BAD_REQUEST;
}

ngx_int_t
tunnel_capsule_upstream_filter(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t           rc;
    u_char             *p;
    size_t              capsule_len, context_len, header_len, payload_len;
    ngx_buf_t          *b, *hb;

    b = ctx->buffer;

    payload_len = (size_t)(b->last - b->pos);
    if (payload_len == 0 && !ctx->upstream_empty_datagram) {
        return NGX_AGAIN;
    }

    context_len = tunnel_capsule_varint_size(CAPSULE_DATAGRAM_CONTEXT_ID);
    capsule_len = context_len + payload_len;
    header_len = tunnel_capsule_varint_size(CAPSULE_DATAGRAM) +
                 tunnel_capsule_varint_size(capsule_len) + context_len;

    if (context_len == 0 || tunnel_capsule_varint_size(capsule_len) == 0 ||
        header_len > HEADER_RESERVE_BYTES) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hb = ctx->downstream_out.buf;

    rc = downstream_prepare_addition_header(hb, header_len);
    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = hb->last;

    if (capsule_encode_varint(&p, hb->end, CAPSULE_DATAGRAM) != NGX_OK ||
        capsule_encode_varint(&p, hb->end, capsule_len) != NGX_OK ||
        capsule_encode_varint(&p, hb->end, CAPSULE_DATAGRAM_CONTEXT_ID) !=
            NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hb->last = p;

    return NGX_OK;
}

static ngx_int_t
capsule_prepare_datagram(ngx_http_tunnel_ctx_t *ctx, size_t payload_size)
{
    size_t              remaining;
    size_t              size;
    u_char             *split;
    ngx_buf_t          *b;
    ngx_buf_t          *tail;
    ngx_chain_t        *cl;
    ngx_chain_t        *next;
    ngx_http_request_t *r;

    r = ctx->request;
    remaining = payload_size;

    for (cl = ctx->downstream_in; cl != NULL; cl = cl->next) {
        b = cl->buf;
        size = ngx_buf_size(b);

        if (size == 0) {
            continue;
        }

        if (remaining > size) {
            remaining -= size;
            continue;
        }

        /*
         * UDP send_chain forms one datagram up to a flush buffer.  When the
         * capsule payload ends inside a buffer, split the tail into the next
         * chain link so relay does not need to rediscover this boundary.
         */
        if (remaining < size) {
            next = ngx_alloc_chain_link(r->pool);
            if (next == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            tail = ngx_calloc_buf(r->pool);
            if (tail == NULL) {
                ngx_free_chain(r->pool, next);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            split = b->pos + remaining;
            *tail = *b;
            tail->pos = split;
            tail->flush = 0;

            next->buf = tail;
            next->next = cl->next;
            cl->next = next;

            b->last = split;
            b->last_buf = 0;
            b->last_in_chain = 0;
        }

        b->flush = 1;
        return NGX_OK;
    }

    return NGX_AGAIN;
}

/*
 * Capsule encoder
 *
 * @param pos `&dst->last` point to the last byte of valid buffer
 * @param last `dst->end` end of buffer
 * @param The length of the QUIC varint
 *
 * Eg. (&dst->last, dst->end, capsule->type)
 */
static ngx_int_t
capsule_encode_varint(u_char **pos, u_char *last, uint64_t value)
{
    u_char  *p;
    size_t   len;
    uint64_t n;

    len = tunnel_capsule_varint_size(value);
    if (len == 0 || pos == NULL || *pos == NULL ||
        (size_t)(last - *pos) < len) {
        return NGX_ERROR;
    }

    p = *pos;
    n = value;

    switch (len) {
    case 1:
        p[0] = (u_char)n;
        break;

    case 2:
        p[0] = (u_char)(0x40 | (n >> 8));
        p[1] = (u_char)n;
        break;

    case 4:
        p[0] = (u_char)(0x80 | (n >> 24));
        p[1] = (u_char)(n >> 16);
        p[2] = (u_char)(n >> 8);
        p[3] = (u_char)n;
        break;

    case 8:
        p[0] = (u_char)(0xc0 | (n >> 56));
        p[1] = (u_char)(n >> 48);
        p[2] = (u_char)(n >> 40);
        p[3] = (u_char)(n >> 32);
        p[4] = (u_char)(n >> 24);
        p[5] = (u_char)(n >> 16);
        p[6] = (u_char)(n >> 8);
        p[7] = (u_char)n;
        break;
    }

    *pos = p + len;

    return NGX_OK;
}

static ngx_int_t
capsule_read_varint(ngx_http_tunnel_ctx_t *ctx, uint64_t *value,
                    size_t *encoded)
{
    ngx_int_t    rc;
    u_char      *p;
    size_t       n;
    ngx_chain_t *cl;

    if (ctx->downstream_in == NULL) {
        return NGX_AGAIN;
    }

    cl = ctx->downstream_in;
    p = cl->buf->pos;

    rc = capsule_chain_read_varint(&cl, &p, value, &n);
    if (rc != NGX_OK) {
        return rc;
    }

    cl = ctx->downstream_in;
    p = cl->buf->pos;
    capsule_chain_advance(&cl, &p, n);
    ctx->downstream_in = cl;
    tunnel_utils_free_consumed_chain(ctx->request, &ctx->downstream_in, NULL);

    if (encoded != NULL) {
        *encoded = n;
    }

    return NGX_OK;
}

static ngx_int_t
capsule_chain_read_varint(ngx_chain_t **chain, u_char **pos, uint64_t *value,
                          size_t *encoded)
{
    u_char       byte;
    size_t       len;
    ngx_uint_t   prefix, i;
    ngx_chain_t *cl;
    u_char      *p;
    uint64_t     n;

    if (chain == NULL || pos == NULL || value == NULL) {
        return NGX_ERROR;
    }

    cl = *chain;
    p = *pos;

    for (;;) {
        if (cl == NULL) {
            return NGX_AGAIN;
        }

        if (p == NULL || p == cl->buf->last) {
            cl = cl->next;
            p = cl == NULL ? NULL : cl->buf->pos;
            continue;
        }

        break;
    }

    byte = *p++;
    prefix = byte >> 6;
    len = (size_t)1 << prefix;
    n = byte & 0x3f;

    for (i = 1; i < len; i++) {
        for (;;) {
            if (cl == NULL) {
                return NGX_AGAIN;
            }

            if (p == cl->buf->last) {
                cl = cl->next;
                p = cl == NULL ? NULL : cl->buf->pos;
                continue;
            }

            break;
        }

        n = (n << 8) | *p++;
    }

    *chain = cl;
    *pos = p;
    *value = n;

    if (encoded != NULL) {
        *encoded = len;
    }

    return NGX_OK;
}

static void
capsule_chain_advance(ngx_chain_t **chain, u_char **pos, size_t n)
{
    size_t       size;
    ngx_chain_t *cl;
    u_char      *p;

    cl = *chain;
    p = *pos;

    while (n != 0 && cl != NULL) {
        if (p == NULL || p == cl->buf->last) {
            cl = cl->next;
            p = cl == NULL ? NULL : cl->buf->pos;
            continue;
        }

        size = ngx_min(n, (size_t)(cl->buf->last - p));
        p += size;
        cl->buf->pos = p;
        n -= size;
    }

    while (cl != NULL && (p == NULL || p == cl->buf->last)) {
        cl = cl->next;
        p = cl == NULL ? NULL : cl->buf->pos;
    }

    *chain = cl;
    *pos = p;
}

static ngx_int_t
capsule_is_protocol_header(ngx_table_elt_t *header)
{
    u_char *key;

    key =
        (header->lowcase_key != NULL) ? header->lowcase_key : header->key.data;

    if (header->key.len == sizeof("capsule-protocol") - 1 &&
        ngx_strncasecmp(key, (u_char *)"capsule-protocol",
                        sizeof("capsule-protocol") - 1) == 0) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}
