
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Padding protocol defined by naiveproxy
 *
 */

#include "ngx_http_tunnel_module.h"

#define PADDING_RESPONSE_MIN 30
#define PADDING_RESPONSE_MAX 62
#define FNV1A_OFFSET_BASIS 14695981039346656037ULL
#define FNV1A_PRIME 1099511628211ULL
#define PADDING_RESPONSE_RETRY_MAX 5
#define RST_STREAM_DATA_MIN 48
#define RST_STREAM_DATA_MAX 72

#define PADDING_READ_HEADER 0
#define PADDING_READ_PAYLOAD 1
#define PADDING_READ_DISCARD 2

static ngx_int_t is_padding_enabled(ngx_http_request_t *r);
static ngx_int_t is_padding_present(ngx_http_request_t *r);
static ngx_int_t padding_generate_response_value(ngx_http_request_t   *r,
                                                 tunnel_padding_ctx_t *padding,
                                                 ngx_str_t            *value);
static void      padding_fill_response_value(u_char *data, size_t len);
static ngx_chain_t *padding_next_chain(ngx_http_request_t *r,
                                       ngx_chain_t       **chain);
static ngx_int_t
padding_h2_rst_stream_data_handler(ngx_http_v2_connection_t *h2c,
                                   ngx_http_v2_out_frame_t  *frame);

ngx_int_t
tunnel_padding_needed(ngx_http_request_t *r)
{
    if (is_padding_enabled(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (is_padding_present(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

size_t
tunnel_padding_buffer_size(ngx_http_request_t *r)
{
    ngx_http_tunnel_srv_conf_t *tscf;

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

    return ngx_min(tscf->buffer_size, (size_t)65535) +
           NGX_HTTP_TUNNEL_PADDING_HEADER_SIZE +
           NGX_HTTP_TUNNEL_MAX_PADDING_SIZE;
}

ngx_int_t
tunnel_padding_negotiate(ngx_http_request_t *r, tunnel_padding_ctx_t *padding)
{
    if (padding == NULL) {
        return NGX_ERROR;
    }

    if (padding_generate_response_value(r, padding, &padding->response_value) !=
        NGX_OK) {
        return NGX_ERROR;
    }

    padding->read_state = PADDING_READ_HEADER;

    return NGX_OK;
}

ngx_int_t
tunnel_padding_add_response_header(ngx_http_request_t   *r,
                                   tunnel_padding_ctx_t *padding)
{
    ngx_table_elt_t *h;

    if (is_padding_enabled(r) != NGX_OK) {
        return NGX_OK;
    }

    if (padding == NULL) {
        return NGX_OK;
    }

    if (padding->response_value.data == NULL) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "padding");
    h->value = padding->response_value;

    return NGX_OK;
}

ngx_int_t
tunnel_padding_decode_downstream(tunnel_padding_ctx_t *padding,
                                 ngx_http_request_t *r, ngx_chain_t **chain,
                                 ngx_uint_t eof, ngx_buf_t *dst,
                                 ngx_uint_t *activity)
{
    size_t       n;
    ngx_buf_t   *src;
    ngx_chain_t *cl;

    if (tunnel_padding_active(padding) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (padding->downstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
        return NGX_DECLINED;
    }

    while (padding->downstream_count < NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
        cl = padding_next_chain(r, chain);
        if (cl == NULL) {
            if (eof &&
                (padding->read_state != PADDING_READ_HEADER ||
                 padding->padding_header_size != 0 ||
                 padding->payload_size != 0 || padding->padding_size != 0)) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "padding request ended with incomplete frame");
                return NGX_HTTP_BAD_REQUEST;
            }

            return NGX_AGAIN;
        }

        src = cl->buf;

        switch (padding->read_state) {

        case PADDING_READ_HEADER:
            n = ngx_min((size_t)ngx_buf_size(src),
                        sizeof(padding->padding_header) -
                            padding->padding_header_size);

            ngx_memcpy(padding->padding_header + padding->padding_header_size,
                       src->pos, n);
            src->pos += n;
            padding->padding_header_size += n;

            if (padding->padding_header_size !=
                sizeof(padding->padding_header)) {
                continue;
            }

            padding->payload_size = ((size_t)padding->padding_header[0] << 8) |
                                    padding->padding_header[1];
            padding->padding_size = padding->padding_header[2];

            padding->padding_header_size = 0;

            if (padding->payload_size != 0) {
                padding->read_state = PADDING_READ_PAYLOAD;
                continue;
            }

            if (padding->padding_size != 0) {
                padding->read_state = PADDING_READ_DISCARD;
                continue;
            }

            goto padding_decode_finish;

        case PADDING_READ_PAYLOAD:
            if (dst->last == dst->end) {
                return NGX_AGAIN;
            }

            n = ngx_min((size_t)ngx_buf_size(src), padding->payload_size);
            n = ngx_min(n, (size_t)(dst->end - dst->last));

            if (n == 0) {
                return NGX_AGAIN;
            }

            dst->last = ngx_cpymem(dst->last, src->pos, n);
            src->pos += n;
            padding->payload_size -= n;
            *activity = 1;
            tunnel_utils_free_consumed_chain(r, chain, NULL);

            if (padding->payload_size != 0) {
                return NGX_AGAIN;
            }

            if (padding->padding_size != 0) {
                padding->read_state = PADDING_READ_DISCARD;
                continue;
            }

            goto padding_decode_finish;

        case PADDING_READ_DISCARD:
            n = ngx_min((size_t)ngx_buf_size(src), padding->padding_size);
            src->pos += n;
            padding->padding_size -= n;
            *activity = 1;
            tunnel_utils_free_consumed_chain(r, chain, NULL);

            if (padding->padding_size == 0) {
                goto padding_decode_finish;
            }

            continue;

        default:
            return NGX_HTTP_BAD_REQUEST;
        }

    padding_decode_finish:

        /* Padding Decode Finish */
        padding->read_state = PADDING_READ_HEADER;
        padding->payload_size = 0;
        padding->padding_size = 0;
        padding->downstream_count++;
        *activity = 1;
    }

    return NGX_DECLINED;
}

ngx_int_t
tunnel_padding_encode_downstream(tunnel_padding_ctx_t *padding, ngx_buf_t *b,
                                 size_t payload_size)
{
    size_t padding_size;

    if (tunnel_padding_active(padding) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (padding->upstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
        return NGX_DECLINED;
    }

    if (payload_size == 0 || payload_size > 65535) {
        return NGX_ERROR;
    }

    if (payload_size < 100) {
        padding_size = NGX_HTTP_TUNNEL_MAX_PADDING_SIZE - payload_size +
                       (ngx_random() % (payload_size + 1));
    } else {
        padding_size = ngx_random() % (NGX_HTTP_TUNNEL_MAX_PADDING_SIZE + 1);
    }

    if ((size_t)(b->end - b->start) <
        NGX_HTTP_TUNNEL_PADDING_HEADER_SIZE + payload_size + padding_size) {
        return NGX_AGAIN;
    }

    b->pos = b->start;
    b->start[0] = (u_char)(payload_size >> 8);
    b->start[1] = (u_char)payload_size;
    b->start[2] = (u_char)padding_size;

    if (padding_size) {
        ngx_memzero(b->last, padding_size);
        b->last += padding_size;
    }

    padding->upstream_count++;

    return NGX_OK;
}

static ngx_int_t
is_padding_enabled(ngx_http_request_t *r)
{
    ngx_http_tunnel_srv_conf_t *tscf;

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

    /* Only let HTTP2/3 support padding */
    if (!tscf->padding || !tunnel_relay_is_stream_downstream(r)) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

static ngx_int_t
is_padding_present(ngx_http_request_t *r)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t       i;
    u_char          *key;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                return NGX_DECLINED;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        key = (header[i].lowcase_key != NULL) ? header[i].lowcase_key
                                              : header[i].key.data;

        if (header[i].key.len == sizeof("padding") - 1 &&
            ngx_strncasecmp(key, (u_char *)"padding", sizeof("padding") - 1) ==
                0) {
            return NGX_OK;
        }
    }
}

static ngx_int_t
padding_generate_response_value(ngx_http_request_t   *r,
                                tunnel_padding_ctx_t *padding, ngx_str_t *value)
{
    ngx_uint_t attempt;
    uint64_t   hash;
    ngx_uint_t i;
    ngx_uint_t len;

    len = PADDING_RESPONSE_MIN +
          (ngx_random() % (PADDING_RESPONSE_MAX - PADDING_RESPONSE_MIN + 1));

    value->data = ngx_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }

    value->len = len;

    for (attempt = 0; attempt < PADDING_RESPONSE_RETRY_MAX; attempt++) {
        hash = FNV1A_OFFSET_BASIS;
        padding_fill_response_value(value->data, len);

        for (i = 0; i < len; i++) {
            hash ^= value->data[i];
            hash *= FNV1A_PRIME;
        }

        if (hash != padding->previous_header_hash) {
            padding->previous_header_hash = hash;
            return NGX_OK;
        }
    }

    value->data[0] = (value->data[0] == '!') ? '"' : '!';

    hash = FNV1A_OFFSET_BASIS;
    for (i = 0; i < len; i++) {
        hash ^= value->data[i];
        hash *= FNV1A_PRIME;
    }

    padding->previous_header_hash = hash;

    return NGX_OK;
}

static void
padding_fill_response_value(u_char *data, size_t len)
{
    static u_char codes[] = {'!', '"', '#', '$', '&', '\'', '(', ')', '*',
                             '+', ',', ';', '<', '>', '?',  '@', 'X'};
    uint64_t      bits;
    size_t        first;
    size_t        i;

    bits = ngx_random();
    bits = (bits << 32) | ngx_random();
    first = ngx_min(len, (size_t)46);

    for (i = 0; i < first; i++) {
        data[i] = codes[bits & 0x0f];
        bits >>= 4;
    }

    for (i = first; i < len; i++) {
        data[i] = codes[16];
    }
}

static ngx_chain_t *
padding_next_chain(ngx_http_request_t *r, ngx_chain_t **chain)
{
    ngx_chain_t *cl;

    for (;;) {
        cl = *chain;
        if (cl == NULL) {
            return NULL;
        }

        if (ngx_buf_size(cl->buf) != 0) {
            return cl;
        }

        *chain = cl->next;
        ngx_free_chain(r->pool, cl);
    }
}

void
tunnel_padding_h2_prepend_rst_stream_data(ngx_http_tunnel_ctx_t *ctx)
{
    u_char                   *p;
    size_t                    frame_size;
    size_t                    total_size;
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r;
    ngx_http_v2_stream_t     *stream;
    ngx_http_v2_connection_t *h2c;
    ngx_http_v2_out_frame_t  *frame;

    if (ctx == NULL || tunnel_padding_active(ctx->padding) == NGX_DECLINED) {
        return;
    }

    r = ctx->request;

    if (r->http_version != NGX_HTTP_VERSION_20 || r->stream == NULL ||
        !ctx->connected) {
        return;
    }

    stream = r->stream;
    h2c = stream->connection;

    if (stream->out_closed || stream->rst_sent || h2c->connection->error) {
        return;
    }

    total_size =
        RST_STREAM_DATA_MIN +
        (ngx_random() % (RST_STREAM_DATA_MAX - RST_STREAM_DATA_MIN + 1));
    frame_size = total_size - NGX_HTTP_V2_FRAME_HEADER_SIZE;

    if (frame_size < 2 || frame_size - 1 > 255) {
        return;
    }

    if (h2c->send_window < frame_size ||
        stream->send_window < (ssize_t)frame_size) {
        return;
    }

    frame = ngx_pcalloc(r->pool, sizeof(ngx_http_v2_out_frame_t));
    if (frame == NULL) {
        return;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return;
    }

    b = ngx_create_temp_buf(r->pool, total_size);
    if (b == NULL) {
        return;
    }

    b->tag = (ngx_buf_tag_t)&ngx_http_v2_module;
    b->memory = 1;
    b->flush = 1;
    b->last_buf = 1;

    p = b->last;
    p = ngx_http_v2_write_len_and_type(p, frame_size, NGX_HTTP_V2_DATA_FRAME);
    *p++ = NGX_HTTP_V2_END_STREAM_FLAG | NGX_HTTP_V2_PADDED_FLAG;
    p = ngx_http_v2_write_sid(p, stream->node->id);
    *p++ = (u_char)(frame_size - 1);
    ngx_memzero(p, frame_size - 1);
    p += frame_size - 1;
    b->last = p;

    cl->buf = b;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = padding_h2_rst_stream_data_handler;
    frame->stream = stream;
    frame->length = frame_size;
    frame->blocked = 0;
    frame->fin = 1;

    ngx_http_v2_queue_frame(h2c, frame);
    h2c->send_window -= frame_size;
    stream->send_window -= frame_size;
    stream->queued++;
    r->connection->buffered |= NGX_HTTP_V2_BUFFERED;
    r->connection->write->active = 1;
    r->connection->write->ready = 0;

    (void)ngx_http_v2_send_output_queue(h2c);
}

static ngx_int_t
padding_h2_rst_stream_data_handler(ngx_http_v2_connection_t *h2c,
                                   ngx_http_v2_out_frame_t  *frame)
{
    ngx_connection_t     *fc;
    ngx_event_t          *wev;
    ngx_chain_t          *cl;
    ngx_http_request_t   *r;
    ngx_http_v2_stream_t *stream;

    if (frame->first->buf->pos != frame->first->buf->last) {
        return NGX_AGAIN;
    }

    stream = frame->stream;
    r = stream->request;
    cl = frame->first;

    r->connection->sent += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
    r->header_size += NGX_HTTP_V2_FRAME_HEADER_SIZE;
    h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
    h2c->payload_bytes += frame->length;

    if (frame->fin) {
        stream->out_closed = 1;
    }

    ngx_free_chain(r->pool, cl);

    frame->next = stream->free_frames;
    stream->free_frames = frame;
    stream->queued--;

    fc = r->connection;
    if (stream->queued == 0 && !h2c->connection->buffered) {
        fc->buffered &= ~NGX_HTTP_V2_BUFFERED;
    }

    if (!stream->waiting && !stream->blocked) {
        wev = fc->write;
        wev->active = 0;
        wev->ready = 1;

        if (fc->error || !wev->delayed) {
            ngx_post_event(wev, &ngx_posted_events);
        }
    }

    return NGX_OK;
}
