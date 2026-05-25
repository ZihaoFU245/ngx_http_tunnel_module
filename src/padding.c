
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Padding protocol defined by naiveproxy
 *
 */

#include "ngx_http_tunnel_module.h"

#define PADDING_RESPONSE_MIN 30
#define PADDING_RESPONSE_MAX 62
#define RST_STREAM_DATA_MIN 48
#define RST_STREAM_DATA_MAX 72

enum {
    PADDING_READ_HEADER_B0 = 0,
    PADDING_READ_HEADER_B1,
    PADDING_READ_HEADER_B2,
    PADDING_READ_PAYLOAD,
    PADDING_READ_DISCARD
};

static ngx_int_t    is_padding_enabled(ngx_http_request_t *r);
static ngx_int_t    is_padding_present(ngx_http_request_t *r);
static ngx_int_t    padding_generate_response_value(ngx_http_request_t *r,
                                                    ngx_str_t          *value);
static ngx_chain_t *padding_next_chain(ngx_chain_t *chain);
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

ngx_int_t
tunnel_padding_add_response_header(ngx_http_request_t   *r,
                                   tunnel_padding_ctx_t *padding)
{
    ngx_str_t        value;
    ngx_table_elt_t *h;

    if (is_padding_enabled(r) != NGX_OK) {
        return NGX_OK;
    }

    if (padding == NULL) {
        return NGX_OK;
    }

    if (padding_generate_response_value(r, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "padding");
    h->value = value;

    return NGX_OK;
}

ngx_int_t
tunnel_padding_downstream_filter(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_uint_t            *activity)
{
    size_t                n;
    u_char               *p, *last;
    ngx_buf_t            *dst, *src;
    ngx_chain_t          *cl;
    ngx_http_request_t   *r;
    tunnel_padding_ctx_t *padding;

    r = ctx->request;
    dst = ctx->upstream_buffer;
    padding = ctx->padding;

    if (padding->downstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
        ctx->downstream_filter = NULL;
        return NGX_AGAIN;
    }

    for (;;) {
        switch (padding->read_state) {

        case PADDING_READ_HEADER_B0:
            cl = padding_next_chain(ctx->downstream_in);
            if (cl == NULL) {
                goto incomplete;
            }

            padding->payload_size = (size_t)*cl->buf->pos++ << 8;
            padding->read_state = PADDING_READ_HEADER_B1;
            *activity = 1;
            continue;

        case PADDING_READ_HEADER_B1:
            cl = padding_next_chain(ctx->downstream_in);
            if (cl == NULL) {
                goto incomplete;
            }

            padding->payload_size |= *cl->buf->pos++;
            padding->read_state = PADDING_READ_HEADER_B2;
            *activity = 1;
            continue;

        case PADDING_READ_HEADER_B2:
            cl = padding_next_chain(ctx->downstream_in);
            if (cl == NULL) {
                goto incomplete;
            }

            padding->padding_size = *cl->buf->pos++;
            *activity = 1;

            if (padding->payload_size != 0) {
                padding->read_state = PADDING_READ_PAYLOAD;
                continue;
            }

            if (padding->padding_size != 0) {
                padding->read_state = PADDING_READ_DISCARD;
                continue;
            }

            goto finish;

        case PADDING_READ_PAYLOAD:
            if (dst->last == dst->end) {
                return NGX_OK;
            }

            cl = padding_next_chain(ctx->downstream_in);
            if (cl == NULL) {
                goto incomplete;
            }

            src = cl->buf;
            n = ngx_min((size_t)ngx_buf_size(src), padding->payload_size);
            n = ngx_min(n, (size_t)(dst->end - dst->last));
            if (n == 0) {
                return *activity ? NGX_OK : NGX_AGAIN;
            }

            dst->last = ngx_cpymem(dst->last, src->pos, n);
            src->pos += n;
            padding->payload_size -= n;
            *activity = 1;

            if (padding->payload_size != 0) {
                return NGX_OK;
            }

            if (padding->padding_size != 0) {
                padding->read_state = PADDING_READ_DISCARD;
                continue;
            }

            goto finish;

        case PADDING_READ_DISCARD:
            cl = padding_next_chain(ctx->downstream_in);
            if (cl == NULL) {
                goto incomplete;
            }

            src = cl->buf;
            n = ngx_min((size_t)ngx_buf_size(src), padding->padding_size);
            p = src->pos;
            last = p + n;

            while (p < last) {
                if (*p++ != 0) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "padding request contained non-zero padding");
                    return NGX_HTTP_BAD_REQUEST;
                }
            }

            src->pos += n;
            padding->padding_size -= n;
            *activity = 1;

            if (padding->padding_size != 0) {
                return NGX_OK;
            }

            goto finish;

        default:
            return NGX_HTTP_BAD_REQUEST;
        }

    finish:

        /* Defer this, this iterates all chains */
        tunnel_utils_free_consumed_chain(r, &ctx->downstream_in, NULL);

        padding->read_state = PADDING_READ_HEADER_B0;
        padding->payload_size = 0;
        padding->padding_size = 0;
        padding->downstream_count++;
        *activity = 1;

        if (padding->downstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
            ctx->downstream_filter = NULL;
            return NGX_OK;
        }
    }

incomplete:

    if (ctx->downstream_eof &&
        (padding->read_state != PADDING_READ_HEADER_B0 ||
         padding->payload_size != 0 || padding->padding_size != 0)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "padding request ended with incomplete frame");
        return NGX_HTTP_BAD_REQUEST;
    }

    /*
     * Incomplete happens when downstream payload are partially arrived,
     * any progress made are indicated by `activity`, return OK to flush
     * decoded bytes. If no progress, return AGAIN so caller can early return
     * without sending anything.
     */
    return *activity ? NGX_OK : NGX_AGAIN;
}

ngx_int_t
tunnel_padding_upstream_filter(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity)
{
    ngx_int_t             rc;
    size_t                padding_size, payload_size;
    ngx_buf_t            *b, *hb;
    tunnel_padding_ctx_t *padding;

    padding = ctx->padding;

    if (padding->upstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
        ctx->upstream_filter = NULL;
        return NGX_DECLINED;
    }

    b = ctx->client_buffer;

    payload_size = b->last - b->pos;
    if (payload_size == 0) {
        return NGX_AGAIN;
    }

    if (payload_size > 65535 ||
        (size_t)(b->end - b->last) < NGX_HTTP_TUNNEL_MAX_PADDING_SIZE) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (payload_size < 100) {
        padding_size = NGX_HTTP_TUNNEL_MAX_PADDING_SIZE - payload_size +
                       (ngx_random() % (payload_size + 1));
    } else {
        padding_size = ngx_random() % (NGX_HTTP_TUNNEL_MAX_PADDING_SIZE + 1);
    }

    hb = ctx->downstream_out.buf;

    rc = downstream_prepare_addition_header(
        hb, NGX_HTTP_TUNNEL_PADDING_HEADER_SIZE);
    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hb->last[0] = (u_char)(payload_size >> 8);
    hb->last[1] = (u_char)payload_size;
    hb->last[2] = (u_char)padding_size;
    hb->last += NGX_HTTP_TUNNEL_PADDING_HEADER_SIZE;

    if (padding_size) {
        ngx_memzero(b->last, padding_size);
        b->last += padding_size;
    }

    padding->upstream_count++;
    if (padding->upstream_count >= NGX_HTTP_TUNNEL_K_FIRST_PADDINGS) {
        ctx->upstream_filter = NULL;
    }

    return NGX_OK;
}

static ngx_int_t
is_padding_enabled(ngx_http_request_t *r)
{
    ngx_http_tunnel_srv_conf_t *tscf;

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

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
padding_generate_response_value(ngx_http_request_t *r, ngx_str_t *value)
{
    static u_char codes[] = {'!', '"', '#', '$', '&', '\'', '(', ')', '*',
                             '+', ',', ';', '<', '>', '?',  '@', 'X'};
    ngx_uint_t    len, n;
    uint64_t      bits;
    size_t        first;
    size_t        i;

    len = PADDING_RESPONSE_MIN +
          (ngx_random() % (PADDING_RESPONSE_MAX - PADDING_RESPONSE_MIN + 1));

    value->data = ngx_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }
    value->len = len;

    first = ngx_min((size_t)len, (size_t)36);

    bits = ngx_random();
    n = 7;

    for (i = 0; i < first; i++) {
        value->data[i] = codes[bits & 0x0f];
        bits >>= 4;

        if (--n == 0) {
            bits = ngx_random();
            n = 7;
        }
    }

    for (i = first; i < (size_t)len; i++) {
        value->data[i] = codes[16]; /* fill tail with 'X' */
    }

    return NGX_OK;
}

static ngx_chain_t *
padding_next_chain(ngx_chain_t *chain)
{
    ngx_chain_t *cl;

    for (;;) {
        cl = chain;
        if (cl == NULL) {
            return NULL;
        }

        if (ngx_buf_size(cl->buf) != 0) {
            return cl;
        }

        chain = cl->next;
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

    stream->blocked = 1;
    if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
        r->connection->error = 1;
    }
    stream->blocked = 0;

    if (stream->queued) {
        r->connection->buffered |= NGX_HTTP_V2_BUFFERED;
        r->connection->write->active = 1;
        r->connection->write->ready = 0;
        return;
    }

    r->connection->buffered &= ~NGX_HTTP_V2_BUFFERED;
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
