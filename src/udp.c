
/*
 * Copyright(c) 2026 ZihaoFU245
 */

#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_udp_is_request(ngx_str_t *protocol)
{
    static ngx_str_t connect_udp = ngx_string("connect-udp");

    if (protocol->len != connect_udp.len ||
        ngx_strncasecmp(protocol->data, connect_udp.data, connect_udp.len) !=
            0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

ngx_int_t
tunnel_udp_set_target(ngx_http_request_t *r)
{
    ngx_str_t                  name = ngx_string("connect_target_host");
    ngx_http_variable_value_t *value;

    /* This invokes the variable handler, and will set resolved. */
    value = ngx_http_get_variable(r, &name, ngx_hash_key(name.data, name.len));
    if (value == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return value->not_found ? NGX_HTTP_BAD_REQUEST : NGX_OK;
}

ngx_int_t
tunnel_udp_init_upstream(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_tunnel_srv_conf_t *tscf;

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

    rc = tunnel_udp_set_target(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx->downstream_filter = tunnel_capsule_downstream_filter;
    ctx->upstream_filter = tunnel_capsule_upstream_filter;

    ctx->capsule = ngx_pcalloc(r->pool, sizeof(tunnel_capsule_ctx_t));
    if (ctx->capsule == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tunnel_connect_init_upstream_peer(r, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tunnel_connect_send_response(r, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;
    u->peer.type = SOCK_DGRAM;
    u->conf = &tscf->upstream;
    u->create_request = tunnel_connect_empty_request;
    u->reinit_request = tunnel_connect_empty_request;
    u->process_header = tunnel_udp_process_header;
    u->abort_request = tunnel_connect_abort_request;
    u->finalize_request = tunnel_connect_finalize_request;

    r->main->count++;
    ctx->content_handler_ref = 1;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

/*
 * UDP path hijack begins here
 */
ngx_int_t
tunnel_udp_process_header(ngx_http_request_t *r)
{
    ngx_int_t              rc;
    ngx_http_tunnel_ctx_t *ctx;
    ngx_http_upstream_t   *u;

    u = r->upstream;

    u->headers_in.status_n = NGX_HTTP_OK;
    ngx_str_set(&u->headers_in.status_line, "200 Connection Established");

    r->keepalive = 0;
    u->keepalive = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    rc = tunnel_relay_start(ctx);
    if (rc != NGX_OK) {
        tunnel_relay_finalize(ctx, rc >= NGX_HTTP_SPECIAL_RESPONSE
                                       ? rc
                                       : NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    return NGX_DONE;
}
