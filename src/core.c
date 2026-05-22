
/*
 * Copyright(c) 2026 ZihaoFU245
 *
 * Tunnel Module Core
 */

#include "ngx_http_tunnel_module.h"

static ngx_command_t ngx_http_tunnel_commands[] = {

    {ngx_string("tunnel_connect"),
     NGX_HTTP_SRV_CONF | NGX_CONF_NOARGS,
     ngx_http_tunnel_pass,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("tunnel_connect_proxy_auth_user_file"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_tunnel_proxy_auth_user_file,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, proxy_auth_user_file),
     NULL},

    {ngx_string("tunnel_connect_buffer_size"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, buffer_size),
     NULL},

    {ngx_string("tunnel_connect_upstream_timeout"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, connect_timeout),
     NULL},

    {ngx_string("tunnel_connect_idle_timeout"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, idle_timeout),
     NULL},

    {ngx_string("tunnel_connect_probe_resistance"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, probe_resistance),
     NULL},

    {ngx_string("tunnel_connect_probe_resistance_allow_methods"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, probe_resistance_allow_methods),
     NULL},

    {ngx_string("tunnel_connect_padding"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, padding),
     NULL},

    {ngx_string("tunnel_connect_udp"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, udp),
     NULL},

    {ngx_string("tunnel_connect_udp_path"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_set_complex_value_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, udp_path),
     NULL},

	{ngx_string("tunnel_connect_acl_eval_on"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     tunnel_acl_eval_on,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

	ngx_null_command
};

static ngx_http_module_t ngx_http_tunnel_module_ctx = {
    ngx_http_tunnel_add_variables,
    ngx_http_tunnel_init,

    NULL,
    NULL,

    ngx_http_tunnel_create_srv_conf,
    ngx_http_tunnel_merge_srv_conf,

    NULL,
	NULL
};

ngx_module_t ngx_http_tunnel_connect_module = {
    NGX_MODULE_V1,
    &ngx_http_tunnel_module_ctx,
    ngx_http_tunnel_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
	NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_tunnel_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_tunnel_srv_conf_t *tscf;

    if (r->method != NGX_HTTP_CONNECT) {
        return NGX_DECLINED;
    }

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

    if (!tscf->enable) {
        return NGX_DECLINED;
    }

#if (nginx_version < NGX_HTTP_TUNNEL_NGINX_1_31_0)
    rc = tunnel_auth_check(r, tscf);
    if (rc != NGX_OK) {
        /* Nginx Core by default send a keepalive header */
        r->keepalive = 0;
        return rc;
    }
#endif

    rc = tunnel_acl_eval(r);
    if (rc != NGX_OK) {
        if (rc == NGX_HTTP_BAD_REQUEST || rc == NGX_HTTP_FORBIDDEN) {
            return rc;
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "tunnel ACL denied target");
        r->keepalive = 0;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->content_handler = ngx_http_tunnel_content_handler;

    return NGX_DECLINED;
}

ngx_int_t
ngx_http_tunnel_content_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_int_t                   padding_needed;
    size_t                      client_buffer_size;
    ngx_http_tunnel_ctx_t      *ctx;
    ngx_http_tunnel_srv_conf_t *tscf;
    ngx_http_upstream_t        *u;

    if (r->method != NGX_HTTP_CONNECT) {
        return NGX_DECLINED;
    }

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

    if (!tscf->enable) {
        return NGX_DECLINED;
    }

    if (r != r->main) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_connect_module);
    if (ctx != NULL) {
        return NGX_DONE;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_tunnel_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    padding_needed = (r->connect_protocol.len == 0) ? tunnel_padding_needed(r)
                                                    : NGX_DECLINED;
    client_buffer_size = (padding_needed == NGX_OK)
                             ? tunnel_padding_buffer_size(r)
                             : tscf->buffer_size;

    ctx->client_buffer = ngx_create_temp_buf(r->pool, client_buffer_size);
    if (ctx->client_buffer == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->upstream_buffer = ngx_create_temp_buf(r->pool, tscf->buffer_size);
    if (ctx->upstream_buffer == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * For padding/capsule headers only.
     * Reserve 32 bytes. Padding headers only use 3 bytes, capsule contains
     * 2 varint, at most 16 bytes. reserve 32 is adequate.
     */
    ctx->downstream_out.buf = ngx_create_temp_buf(r->pool, HEADER_RESERVE_BYTES);
    if (ctx->downstream_out.buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Extended connect branching */
    rc = tunnel_extended_connect_branching(r, ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (padding_needed == NGX_OK) {
        ctx->padding = ngx_pcalloc(r->pool, sizeof(tunnel_padding_ctx_t));
        if (ctx->padding == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->downstream_filter = tunnel_padding_downstream_filter;
        ctx->upstream_filter = tunnel_padding_upstream_filter;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_tunnel_connect_module);

    if (tunnel_connect_init_upstream_peer(r, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = tunnel_connect_set_target(r, ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    u = r->upstream;
    u->conf = &tscf->upstream;
    u->create_request = tunnel_connect_empty_request;
    u->reinit_request = tunnel_connect_empty_request;
    u->process_header = tunnel_connect_process_header;
    u->abort_request = tunnel_connect_abort_request;
    u->finalize_request = tunnel_connect_finalize_request;

    r->main->count++;
    ctx->content_handler_ref = 1;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

char *
ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_srv_conf_t *tscf = conf;
    ngx_http_core_srv_conf_t   *cscf;

    if (tscf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    tscf->enable = 1;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    cscf->allow_connect = 1;

    return NGX_CONF_OK;
}

void *
ngx_http_tunnel_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_tunnel_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tunnel_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->proxy_auth_user_file = NGX_CONF_UNSET_PTR;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->idle_timeout = NGX_CONF_UNSET_MSEC;
    conf->probe_resistance = NGX_CONF_UNSET;
    conf->padding = NGX_CONF_UNSET;
    conf->acl_eval_index = NGX_CONF_UNSET_UINT;
    conf->udp = NGX_CONF_UNSET;
    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

char *
ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tunnel_srv_conf_t *prev = parent;
    ngx_http_tunnel_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->proxy_auth_user_file,
                             prev->proxy_auth_user_file, NULL);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 128 * 1024);

    if (conf->buffer_size < 64 * 1024) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"tunnel_buffer_size\" must be at least 64k");
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout,
                              60000);
    ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 30000);
    ngx_conf_merge_value(conf->probe_resistance, prev->probe_resistance, 0);
    ngx_conf_merge_str_value(conf->probe_resistance_allow_methods,
                             prev->probe_resistance_allow_methods, "");

#if (nginx_version >= NGX_HTTP_TUNNEL_NGINX_1_31_0)
    if (conf->probe_resistance ||
        conf->probe_resistance_allow_methods.len != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"tunnel_probe_resistance\" is not supported on "
                           "nginx 1.31.0 or newer; use nginx core "
                           "\"auth_basic\" for proxy authentication");
        return NGX_CONF_ERROR;
    }
#endif

    ngx_conf_merge_value(conf->padding, prev->padding, 0);
    ngx_conf_merge_value(conf->udp, prev->udp, 1);
    ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 0);
    ngx_conf_merge_value(conf->upstream.request_buffering,
                         prev->upstream.request_buffering, 0);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                         prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout,
                              conf->connect_timeout);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
							  prev->upstream.send_timeout,
							  conf->idle_timeout);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
							  prev->upstream.read_timeout,
							  conf->idle_timeout);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);
    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size, conf->buffer_size);

	ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
								 prev->upstream.next_upstream,
								 (NGX_CONF_BITMASK_SET |
								  NGX_HTTP_UPSTREAM_FT_ERROR |
         NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
		conf->upstream.next_upstream = NGX_CONF_BITMASK_SET |
									   NGX_HTTP_UPSTREAM_FT_OFF;
    }

    conf->upstream.ignore_input = 1;
    ngx_str_set(&conf->upstream.module, "tunnel");

    ngx_conf_merge_uint_value(conf->acl_eval_index, prev->acl_eval_index,
                              NGX_CONF_UNSET_UINT);

    if (conf->udp_path == NULL) {
        if (prev->udp_path != NULL) {
            conf->udp_path = prev->udp_path;
        } else {
            ngx_str_t                        value = ngx_string("$request_uri");
            ngx_http_compile_complex_value_t ccv;

            conf->udp_path =
                ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
            if (conf->udp_path == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(conf->udp_path, sizeof(ngx_http_complex_value_t));
            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value;
            ccv.complex_value = conf->udp_path;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}

/*
 * Add $connect_target_host is necessary
 * Though $request_uri provides the raw
 * authority header, but it only applys to
 * h2/h3 stream. HTTP/1.1 will miss.
 */
ngx_int_t
ngx_http_tunnel_add_variables(ngx_conf_t *cf)
{
    ngx_str_t            name = ngx_string("connect_target_host");
    ngx_http_variable_t *var;

    var = ngx_http_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = tunnel_get_target_host_handler;

    return NGX_OK;
}

ngx_int_t
tunnel_get_target_host_handler(ngx_http_request_t        *r,
                               ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->method != NGX_HTTP_CONNECT || r->host_start == NULL ||
        r->host_end == NULL) {
        v->valid = 0;
        v->no_cacheable = 0;
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = r->host_end - r->host_start;
    v->data = r->host_start;

    return NGX_OK;
}

/*
 * Used to skip precontent phase, but requires tunnel_pass to
 * be set before any location block. This is a balance between
 * functionality and complexity. If allow putting location block ahead,
 * it will be complex to achieve.
 */
ngx_int_t
ngx_tunnel_skip_phase_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_srv_conf_t *tscf;

    if (r->method != NGX_HTTP_CONNECT) {
        return NGX_DECLINED;
    }

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_connect_module);

    if (!tscf->enable) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_tunnel_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_tunnel_srv_conf_t *tscf;
    ngx_uint_t                  i;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    cscfp = cmcf->servers.elts;

    /* Do not register handlers if no tunnel servers are enabled */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        tscf = cscfp[i]->ctx->srv_conf[ngx_http_tunnel_connect_module.ctx_index];

        if (tscf->enable) {
            goto enabled;
        }
    }

    return NGX_OK;

enabled:

    if (tunnel_utils_init_extended_connect(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_tunnel_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_tunnel_skip_phase_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_tunnel_content_handler;

    return NGX_OK;
}
