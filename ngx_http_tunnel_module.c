/*
 * tunnel module core
 */

#include "ngx_http_tunnel_module.h"

static ngx_command_t ngx_http_tunnel_commands[] = {

    {ngx_string("tunnel_pass"),
     NGX_HTTP_SRV_CONF | NGX_CONF_NOARGS,
     ngx_http_tunnel_pass,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("tunnel_auth_username"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, auth_username),
     NULL},

    {ngx_string("tunnel_auth_password"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, auth_password),
     NULL},

    {ngx_string("tunnel_buffer_size"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, buffer_size),
     NULL},

    {ngx_string("tunnel_connect_timeout"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, connect_timeout),
     NULL},

    {ngx_string("tunnel_idle_timeout"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, idle_timeout),
     NULL},

    {ngx_string("tunnel_probe_resistance"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, probe_resistance),
     NULL},

    {ngx_string("tunnel_padding"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, padding),
     NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_tunnel_module_ctx = {
    NULL,
    ngx_http_tunnel_init,

    NULL,
    NULL,

    ngx_http_tunnel_create_srv_conf,
    ngx_http_tunnel_merge_srv_conf,

    NULL,
    NULL};

ngx_module_t ngx_http_tunnel_module = {
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
    NGX_MODULE_V1_PADDING};

ngx_int_t
ngx_http_tunnel_access_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_tunnel_srv_conf_t *tscf;

    if (r->method != NGX_HTTP_CONNECT)
    {
        return NGX_DECLINED;
    }

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

    if (!tscf->enable)
    {
        return NGX_DECLINED;
    }

    rc = ngx_http_tunnel_check_auth(r, tscf);
    if (rc != NGX_OK)
    {
        return rc;
    }

    r->content_handler = ngx_http_tunnel_content_handler;

    return NGX_DECLINED;
}

ngx_int_t
ngx_http_tunnel_content_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_cleanup_t *cln;
    ngx_http_tunnel_ctx_t *ctx;
    ngx_http_tunnel_srv_conf_t *tscf;

    if (r->method != NGX_HTTP_CONNECT)
    {
        return NGX_DECLINED;
    }

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

    if (!tscf->enable)
    {
        return NGX_DECLINED;
    }

    if (r != r->main)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->http_version != NGX_HTTP_VERSION_11)
    {
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx != NULL)
    {
        return NGX_DONE;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_tunnel_ctx_t));
    if (ctx == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    ctx->client_buffer = ngx_create_temp_buf(r->pool, tscf->buffer_size);
    if (ctx->client_buffer == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->upstream_buffer = ngx_create_temp_buf(r->pool, tscf->buffer_size);
    if (ctx->upstream_buffer == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_tunnel_module);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_tunnel_cleanup;
    cln->data = ctx;

    if (ngx_http_tunnel_init_upstream_peer(r, ctx) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_tunnel_parse_target(r, ctx);
    if (rc != NGX_OK)
    {
        return rc;
    }

    r->main->count++;

    if (ctx->resolved->sockaddr != NULL || ctx->resolved->naddrs != 0)
    {
        if (ngx_http_upstream_create_round_robin_peer(r, ctx->resolved) != NGX_OK)
        {
            r->main->count--;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_http_tunnel_connect_next(ctx) != NGX_OK)
        {
            ngx_http_tunnel_finalize(ctx, NGX_HTTP_BAD_GATEWAY);
        }

        return NGX_DONE;
    }

    {
        ngx_http_core_loc_conf_t *clcf;
        ngx_resolver_ctx_t temp;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_memzero(&temp, sizeof(ngx_resolver_ctx_t));
        temp.name = ctx->resolved->host;

        ctx->resolver_ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx->resolver_ctx == NULL)
        {
            r->main->count--;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ctx->resolver_ctx == NGX_NO_RESOLVER)
        {
            r->main->count--;
            return NGX_HTTP_BAD_GATEWAY;
        }

        ctx->resolving = 1;
        ctx->resolver_ctx->name = ctx->resolved->host;
        ctx->resolver_ctx->handler = ngx_http_tunnel_resolve_handler;
        ctx->resolver_ctx->data = ctx;
        ctx->resolver_ctx->timeout = clcf->resolver_timeout;

        if (ngx_resolve_name(ctx->resolver_ctx) != NGX_OK)
        {
            ctx->resolving = 0;
            ctx->resolver_ctx = NULL;
            r->main->count--;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_DONE;
}

char *
ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_srv_conf_t *tscf = conf;
    ngx_http_core_srv_conf_t *cscf;

    if (tscf->enable != NGX_CONF_UNSET)
    {
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
    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->idle_timeout = NGX_CONF_UNSET_MSEC;
    conf->probe_resistance = NGX_CONF_UNSET;
    conf->padding = NGX_CONF_UNSET;

    return conf;
}

char *
ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tunnel_srv_conf_t *prev = parent;
    ngx_http_tunnel_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->auth_username, prev->auth_username, "");
    ngx_conf_merge_str_value(conf->auth_password, prev->auth_password, "");
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 16 * 1024);
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout,
                              60000);
    ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 30000);
    ngx_conf_merge_value(conf->probe_resistance, prev->probe_resistance, 0);
    ngx_conf_merge_value(conf->padding, prev->padding, 0);

    if ((conf->auth_username.len == 0) != (conf->auth_password.len == 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "both tunnel_auth_username and tunnel_auth_password must be set together");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_tunnel_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_tunnel_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_tunnel_content_handler;

    return NGX_OK;
}
