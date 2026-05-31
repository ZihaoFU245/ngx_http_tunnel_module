
/*
 * Copyright(c) 2026 ZihaoFU245
 */

#include "ngx_http_tunnel_module.h"

static tunnel_extended_connect_regex_t tunnel_extended_connect_regexes[] = {
    {
        ngx_string("^/\\.well-known/masque/udp/([^/?#]+)/([0-9]{1,5})/(?:[?#].*)?$"),
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
tunnel_utils_match_protocol(ngx_str_t *protocol)
{
    if (tunnel_udp_is_request(protocol) == NGX_OK) {
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
tunnel_utils_free_consumed_chain(ngx_http_request_t *r, ngx_chain_t **chain,
                                 ngx_chain_t *limit)
{
    ngx_chain_t *cl;

    while (*chain != limit && *chain != NULL &&
           ngx_buf_size((*chain)->buf) == 0) {
        cl = *chain;
        *chain = cl->next;
        ngx_free_chain(r->pool, cl);
    }
}
