/*
 * Copyright(c) 2026 ZihaoFU245
 */

#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_connect_ip_is_request(ngx_http_request_t *r)
{
    static ngx_str_t connect_ip = ngx_string("connect-ip");

    if (r->connect_protocol.len != connect_ip.len ||
        ngx_strncmp(r->connect_protocol.data, connect_ip.data,
                    connect_ip.len) != 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

char *
tunnel_connect_ip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_loc_conf_t *tlcf = conf;

    if (tlcf->connect_ip != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    tlcf->connect_ip = 1;

    return NGX_CONF_OK;
}