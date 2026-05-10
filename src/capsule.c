
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Reusable capsule protocol implementation
 * for connect udp mainly.
 */

#include "ngx_http_tunnel_module.h"

static ngx_int_t capsule_decode_varint(u_char **pos, u_char *last,
                                       uint64_t *value);
static ngx_int_t capsule_encode_varint(u_char **pos, u_char *last,
                                       uint64_t value);
static ngx_int_t capsule_chain_read_varint(ngx_chain_t **chain, u_char **pos,
                                           uint64_t *value, size_t *encoded);
static ngx_int_t capsule_chain_peek(ngx_chain_t *chain, u_char *pos,
                                    u_char *value);
static ngx_int_t capsule_chain_have(ngx_chain_t *chain, u_char *pos,
                                    uint64_t len);
static void capsule_chain_advance(ngx_chain_t **chain, u_char **pos, size_t n);
static void capsule_chain_copy(ngx_chain_t **chain, u_char **pos,
                               ngx_buf_t *dst, size_t n);
static ngx_int_t capsule_is_protocol_header(ngx_table_elt_t *header);

ngx_int_t
tunnel_capsule_is_header_present(ngx_http_request_t *r)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t       found, i;

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

        if (header[i].value.len != sizeof("?1") - 1 ||
            ngx_strncmp(header[i].value.data, "?1", sizeof("?1") - 1) != 0) {
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
size_t
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
tunnel_capsule_decode(ngx_buf_t *src, tunnel_capsule_t *capsule)
{
    u_char  *p, *payload;
    uint64_t type, len;

    if (src == NULL || capsule == NULL || capsule->payload == NULL) {
        return NGX_ERROR;
    }

    p = src->pos;

    if (capsule_decode_varint(&p, src->last, &type) != NGX_OK) {
        return NGX_AGAIN;
    }

    if (capsule_decode_varint(&p, src->last, &len) != NGX_OK) {
        return NGX_AGAIN;
    }

    if (len > (uint64_t)(src->last - p)) {
        return NGX_AGAIN;
    }

    payload = p;
    p += (size_t)len;

    capsule->payload->pos = payload;
    capsule->payload->last = p;
    capsule->payload->start = payload;
    capsule->payload->end = p;
    capsule->payload->memory = 1;

    capsule->type = type;
    capsule->len = len;

    src->pos = p;

    return NGX_OK;
}

ngx_int_t
tunnel_capsule_encode(ngx_buf_t *dst, tunnel_capsule_t *capsule)
{
    u_char *p;
    size_t  payload_len;

    if (dst == NULL || capsule == NULL || capsule->payload == NULL) {
        return NGX_ERROR;
    }

    payload_len = ngx_buf_size(capsule->payload);

    if ((uint64_t)payload_len != capsule->len) {
        return NGX_ERROR;
    }

    /* Check if varint is not out of range */
    if (tunnel_capsule_varint_size(capsule->type) == 0 ||
        tunnel_capsule_varint_size(capsule->len) == 0) {
        return NGX_ERROR;
    }

    /* Check if enough buffer has enough space */
    if ((size_t)(dst->end - dst->last) <
        tunnel_capsule_varint_size(capsule->type) +
            tunnel_capsule_varint_size(capsule->len) + payload_len) {
        return NGX_AGAIN;
    }

    p = dst->last;

    if (capsule_encode_varint(&p, dst->end, capsule->type) != NGX_OK ||
        capsule_encode_varint(&p, dst->end, capsule->len) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(p, capsule->payload->pos, payload_len);
    dst->last = p;

    return NGX_OK;
}

/*
 * Decode one CONNECT-UDP DATAGRAM capsule from src chain into dst.
 *
 * *src points to HTTP DATA bytes containing capsule frames.  dst->last points
 * to the write position for the decoded UDP payload.
 *
 * On NGX_OK, *src and its buffer cursors are advanced past the capsule and
 * dst->last is advanced past the copied UDP payload.  dst->pos is unchanged.
 * On NGX_AGAIN, NGX_DECLINED, or NGX_ERROR, src and dst cursors are unchanged.
 */
ngx_int_t
tunnel_capsule_decode_datagram(ngx_chain_t **src, ngx_buf_t *dst)
{
    u_char      *p, context_first;
    size_t       context_len, header_len, len_len, payload_len, type_len;
    ngx_chain_t *cl, *commit;
    uint64_t     type, capsule_len, context_id;

    if (src == NULL || dst == NULL) {
        return NGX_ERROR;
    }

    cl = *src;
    if (cl == NULL) {
        return NGX_AGAIN;
    }

    p = cl->buf->pos;

    if (capsule_chain_read_varint(&cl, &p, &type, &type_len) != NGX_OK) {
        return NGX_AGAIN;
    }

    if (capsule_chain_read_varint(&cl, &p, &capsule_len, &len_len) != NGX_OK) {
        return NGX_AGAIN;
    }

    if (capsule_chain_have(cl, p, capsule_len) != NGX_OK) {
        return NGX_AGAIN;
    }

    if (type != CAPSULE_DATAGRAM) {
        return NGX_DECLINED;
    }

    if (capsule_chain_peek(cl, p, &context_first) != NGX_OK) {
        return NGX_DECLINED;
    }

    context_len = (size_t)1 << (context_first >> 6);
    if (capsule_len < context_len) {
        return NGX_DECLINED;
    }

    if (capsule_chain_read_varint(&cl, &p, &context_id, &context_len) !=
        NGX_OK) {
        return NGX_DECLINED;
    }

    if (context_id != CAPSULE_DATAGRAM_CONTEXT_ID) {
        return NGX_DECLINED;
    }

    if (capsule_len < context_len) {
        return NGX_DECLINED;
    }

    payload_len = (size_t)(capsule_len - context_len);
    header_len = type_len + len_len + context_len;

    if ((size_t)(dst->end - dst->last) < payload_len) {
        return NGX_DECLINED;
    }

    commit = *src;
    p = commit->buf->pos;
    capsule_chain_advance(&commit, &p, header_len);
    capsule_chain_copy(&commit, &p, dst, payload_len);
    *src = commit;

    return NGX_OK;
}

/*
 * Encode one CONNECT-UDP DATAGRAM capsule into dst.
 *
 * capsule must be a DATAGRAM capsule whose payload points to one UDP payload.
 * dst is the output buffer that will be sent to the downstream client.  The
 * payload may already live inside dst, as udp_recv_upstream() does after
 * receiving directly into ctx->client_buffer.
 *
 * On NGX_OK, dst->pos points at the encoded capsule and dst->last points after
 * it.  If payload and dst overlap, the payload is moved inside dst before the
 * capsule header is written.  On NGX_AGAIN or NGX_ERROR, dst cursors are not
 * advanced into a partially encoded capsule.
 */
ngx_int_t
tunnel_capsule_encode_datagram(tunnel_capsule_t *capsule, ngx_buf_t *dst)
{
    u_char *p;
    size_t  payload_len, context_len, capsule_len, header_len;

    if (capsule == NULL || capsule->payload == NULL || dst == NULL) {
        return NGX_ERROR;
    }

    if (capsule->type != CAPSULE_DATAGRAM) {
        return NGX_ERROR;
    }

    payload_len = ngx_buf_size(capsule->payload);
    context_len = tunnel_capsule_varint_size(CAPSULE_DATAGRAM_CONTEXT_ID);
    capsule_len = context_len + payload_len;
    header_len = tunnel_capsule_varint_size(CAPSULE_DATAGRAM) +
                 tunnel_capsule_varint_size(capsule_len) + context_len;

    if (context_len == 0 || tunnel_capsule_varint_size(capsule_len) == 0 ||
        capsule->len != capsule_len) {
        return NGX_ERROR;
    }

    if ((size_t)(dst->end - dst->start) < header_len + payload_len) {
        return NGX_AGAIN;
    }

    ngx_memmove(dst->start + header_len, capsule->payload->pos, payload_len);

    p = dst->start;

    if (capsule_encode_varint(&p, dst->end, CAPSULE_DATAGRAM) != NGX_OK ||
        capsule_encode_varint(&p, dst->end, capsule_len) != NGX_OK ||
        capsule_encode_varint(&p, dst->end, CAPSULE_DATAGRAM_CONTEXT_ID) !=
            NGX_OK) {
        return NGX_ERROR;
    }

    dst->pos = dst->start;
    dst->last = dst->start + header_len + payload_len;

    return NGX_OK;
}

/*
 * Capsule Decoder
 *
 * @param pos `&src->pos`, src is ngx_buf_t
 * @param last `src->last`, src is ngx_buf_t
 * @param value reference to store the value
 *
 * Eg. (&src->pos, src->last, &type)
 */
static ngx_int_t
capsule_decode_varint(u_char **pos, u_char *last, uint64_t *value)
{
    u_char    *p;
    ngx_uint_t prefix, len, i;
    uint64_t   n;

    if (pos == NULL || *pos == NULL || value == NULL || *pos == last) {
        return NGX_AGAIN;
    }

    p = *pos;
    prefix = p[0] >> 6;
    len = (ngx_uint_t)1 << prefix;

    if ((size_t)(last - p) < len) {
        return NGX_AGAIN;
    }

    n = p[0] & 0x3f;
    for (i = 1; i < len; i++) {
        n = (n << 8) | p[i];
    }

    *value = n;
    *pos = p + len;

    return NGX_OK;
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

static ngx_int_t
capsule_chain_have(ngx_chain_t *chain, u_char *pos, uint64_t len)
{
    size_t n;

    while (len != 0) {
        if (chain == NULL) {
            return NGX_AGAIN;
        }

        if (pos == NULL || pos == chain->buf->last) {
            chain = chain->next;
            pos = chain == NULL ? NULL : chain->buf->pos;
            continue;
        }

        n = chain->buf->last - pos;
        if ((uint64_t)n >= len) {
            return NGX_OK;
        }

        len -= n;
        chain = chain->next;
        pos = chain == NULL ? NULL : chain->buf->pos;
    }

    return NGX_OK;
}

static ngx_int_t
capsule_chain_peek(ngx_chain_t *chain, u_char *pos, u_char *value)
{
    if (value == NULL) {
        return NGX_ERROR;
    }

    for (;;) {
        if (chain == NULL) {
            return NGX_AGAIN;
        }

        if (pos == NULL || pos == chain->buf->last) {
            chain = chain->next;
            pos = chain == NULL ? NULL : chain->buf->pos;
            continue;
        }

        *value = *pos;
        return NGX_OK;
    }
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

static void
capsule_chain_copy(ngx_chain_t **chain, u_char **pos, ngx_buf_t *dst, size_t n)
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
        dst->last = ngx_cpymem(dst->last, p, size);
        p += size;
        cl->buf->pos = p;
        n -= size;

        if (p == cl->buf->last) {
            cl = cl->next;
            p = cl == NULL ? NULL : cl->buf->pos;
        }
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
