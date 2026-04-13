#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    ngx_flag_t enable;
    ngx_str_t auth_username;
    ngx_str_t auth_password;
    size_t buffer_size;
    ngx_msec_t connect_timeout;
    ngx_msec_t idle_timeout;
    ngx_flag_t probe_resistance;
    ngx_flag_t padding;
} ngx_http_tunnel_srv_conf_t;

static char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static void *ngx_http_tunnel_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent,
                                            void *child);
static ngx_int_t ngx_http_tunnel_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_tunnel_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_content_handler(ngx_http_request_t *r);

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
    NULL,                 /* preconfiguration */
    ngx_http_tunnel_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_tunnel_create_srv_conf, /* create server configuration */
    ngx_http_tunnel_merge_srv_conf,  /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_tunnel_module = {
    NGX_MODULE_V1,
    &ngx_http_tunnel_module_ctx, /* module context */
    ngx_http_tunnel_commands,    /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_tunnel_access_handler(ngx_http_request_t *r)
{
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

    // TODO: Implement tunnel access handler logic

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_tunnel_content_handler(ngx_http_request_t *r)
{
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

    // TODO: Implement tunnel content handler logic

    return NGX_DECLINED;
}

static char *
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

static void *
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

static char *
ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tunnel_srv_conf_t *prev = parent;
    ngx_http_tunnel_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->auth_username, prev->auth_username, "");
    ngx_conf_merge_str_value(conf->auth_password, prev->auth_password, "");
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              16 * 1024);
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout,
                              60000);
    ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 30000);
    ngx_conf_merge_value(conf->probe_resistance, prev->probe_resistance, 0);
    ngx_conf_merge_value(conf->padding, prev->padding, 0);

    return NGX_CONF_OK;
}

static ngx_int_t
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
