#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
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

typedef struct
{
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_buf_t *client_buffer;
    ngx_buf_t *upstream_buffer;
    unsigned finalized : 1;
} ngx_http_tunnel_ctx_t;

static char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static void *ngx_http_tunnel_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent,
                                            void *child);
static ngx_int_t ngx_http_tunnel_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_tunnel_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_parse_target(ngx_http_request_t *r,
                                              ngx_url_t *url);
static ngx_int_t ngx_http_tunnel_start(ngx_http_tunnel_ctx_t *ctx);
static ngx_int_t ngx_http_tunnel_send_connected(ngx_http_request_t *r);
static void ngx_http_tunnel_connect_handler(ngx_event_t *ev);
static void ngx_http_tunnel_downstream_read_handler(ngx_http_request_t *r);
static void ngx_http_tunnel_downstream_write_handler(ngx_http_request_t *r);
static void ngx_http_tunnel_upstream_read_handler(ngx_event_t *ev);
static void ngx_http_tunnel_upstream_write_handler(ngx_event_t *ev);
static void ngx_http_tunnel_process(ngx_http_tunnel_ctx_t *ctx,
                                    ngx_uint_t from_upstream,
                                    ngx_uint_t do_write);
static void ngx_http_tunnel_finalize(ngx_http_tunnel_ctx_t *ctx,
                                     ngx_int_t rc);
static void ngx_http_tunnel_cleanup(void *data);
static ngx_int_t ngx_http_tunnel_test_connect(ngx_connection_t *c);

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
    ngx_int_t rc;
    ngx_url_t url;
    ngx_connection_t *c;
    ngx_http_cleanup_t *cln;
    ngx_http_core_loc_conf_t *clcf;
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

    ngx_memzero(&url, sizeof(ngx_url_t));

    rc = ngx_http_tunnel_parse_target(r, &url);
    if (rc != NGX_OK)
    {
        return rc;
    }

    c = r->connection;

    ctx->peer.sockaddr = url.addrs[0].sockaddr;
    ctx->peer.socklen = url.addrs[0].socklen;
    ctx->peer.name = &url.addrs[0].name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = c->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);
    if (rc == NGX_ERROR)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc == NGX_BUSY || rc == NGX_DECLINED)
    {
        return NGX_HTTP_BAD_GATEWAY;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = r->pool;
    ctx->peer.connection->log = c->log;
    ctx->peer.connection->read->log = c->log;
    ctx->peer.connection->write->log = c->log;

    r->main->count++;

    if (rc == NGX_AGAIN)
    {
        ctx->peer.connection->read->handler = ngx_http_tunnel_connect_handler;
        ctx->peer.connection->write->handler = ngx_http_tunnel_connect_handler;
        ngx_add_timer(ctx->peer.connection->write, tscf->connect_timeout);
        return NGX_DONE;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->tcp_nodelay)
    {
        if (ngx_tcp_nodelay(c) != NGX_OK
            || ngx_tcp_nodelay(ctx->peer.connection) != NGX_OK)
        {
            ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }
    }

    if (ngx_http_tunnel_start(ctx) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    return NGX_DONE;
}

static ngx_int_t
ngx_http_tunnel_parse_target(ngx_http_request_t *r, ngx_url_t *url)
{
    ngx_str_t authority;

    if (r->headers_in.server.len != 0)
    {
        authority = r->headers_in.server;

    } else if (r->host_start != NULL && r->host_end != NULL)
    {
        authority.data = r->host_start;
        authority.len = r->host_end - r->host_start;

    } else
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    url->url = authority;

    if (ngx_parse_url(r->pool, url) != NGX_OK)
    {
        if (url->err != NULL
            && ngx_strcmp(url->err, "host not found") == 0)
        {
            return NGX_HTTP_BAD_GATEWAY;
        }

        return NGX_HTTP_BAD_REQUEST;
    }

    if (url->no_port || url->naddrs == 0)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_tunnel_start(ngx_http_tunnel_ctx_t *ctx)
{
    ngx_connection_t *c;
    ngx_connection_t *pc;
    ngx_http_request_t *r;

    r = ctx->request;
    c = r->connection;
    pc = ctx->peer.connection;

    if (pc->write->timer_set)
    {
        ngx_del_timer(pc->write);
    }

    r->keepalive = 0;
    c->log->action = "tunneling connection";

    if (ngx_http_tunnel_send_connected(r) != NGX_OK)
    {
        return NGX_ERROR;
    }

    pc->read->handler = ngx_http_tunnel_upstream_read_handler;
    pc->write->handler = ngx_http_tunnel_upstream_write_handler;
    r->read_event_handler = ngx_http_tunnel_downstream_read_handler;
    r->write_event_handler = ngx_http_tunnel_downstream_write_handler;

    if (ctx->peer.connection->read->ready)
    {
        ngx_post_event(c->read, &ngx_posted_events);
        ngx_http_tunnel_process(ctx, 1, 1);
        return NGX_OK;
    }

    ngx_http_tunnel_process(ctx, 0, 1);

    return NGX_OK;
}

static ngx_int_t
ngx_http_tunnel_send_connected(ngx_http_request_t *r)
{
    ngx_int_t rc;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_str_set(&r->headers_out.status_line, "200 Connection Established");
    ngx_str_null(&r->headers_out.content_type);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_http_tunnel_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_request_t *r;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;
    r = ctx->request;

    if (ev->timedout)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (ngx_http_tunnel_test_connect(c) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->tcp_nodelay)
    {
        if (ngx_tcp_nodelay(r->connection) != NGX_OK
            || ngx_tcp_nodelay(c) != NGX_OK)
        {
            ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (ngx_http_tunnel_start(ctx) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

static void
ngx_http_tunnel_downstream_read_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_tunnel_process(ctx, 0, 0);
}

static void
ngx_http_tunnel_downstream_write_handler(ngx_http_request_t *r)
{
    ngx_http_tunnel_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
    if (ctx == NULL)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_tunnel_process(ctx, 1, 1);
}

static void
ngx_http_tunnel_upstream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_http_tunnel_process(ctx, 1, 0);
}

static void
ngx_http_tunnel_upstream_write_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_http_tunnel_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    ngx_http_tunnel_process(ctx, 0, 1);
}

static void
ngx_http_tunnel_process(ngx_http_tunnel_ctx_t *ctx, ngx_uint_t from_upstream,
                        ngx_uint_t do_write)
{
    size_t size;
    ssize_t n;
    ngx_buf_t *b;
    ngx_uint_t flags;
    ngx_connection_t *c;
    ngx_connection_t *dst;
    ngx_connection_t *pc;
    ngx_connection_t *src;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_request_t *r;

    r = ctx->request;
    c = r->connection;
    pc = ctx->peer.connection;

    if (ctx->finalized || pc == NULL)
    {
        return;
    }

    if (from_upstream)
    {
        src = pc;
        dst = c;
        b = ctx->upstream_buffer;

    } else {
        src = c;
        dst = pc;
        b = ctx->client_buffer;
    }

    for (;;)
    {
        if (do_write)
        {
            size = b->last - b->pos;

            if (size != 0 && dst->write->ready)
            {
                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR)
                {
                    ngx_http_tunnel_finalize(ctx, 0);
                    return;
                }

                if (n > 0)
                {
                    b->pos += n;

                    if (b->pos == b->last)
                    {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size != 0 && src->read->ready)
        {
            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0)
            {
                if (n == 0)
                {
                    src->read->eof = 1;
                }

                break;
            }

            if (n > 0)
            {
                b->last += n;
                do_write = 1;
                continue;
            }

            src->read->eof = 1;
        }

        break;
    }

    if ((pc->read->eof && ctx->upstream_buffer->pos == ctx->upstream_buffer->last)
        || (c->read->eof && ctx->client_buffer->pos == ctx->client_buffer->last)
        || (c->read->eof && pc->read->eof))
    {
        ngx_http_tunnel_finalize(ctx, 0);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (ngx_handle_write_event(pc->write, 0) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT : 0)
        != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_write_event(c->write, clcf->send_lowat) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    flags = c->read->eof ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(c->read, flags) != NGX_OK)
    {
        ngx_http_tunnel_finalize(ctx, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

static void
ngx_http_tunnel_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc)
{
    ngx_connection_t *pc;

    if (ctx->finalized)
    {
        return;
    }

    ctx->finalized = 1;

    pc = ctx->peer.connection;
    if (pc != NULL)
    {
        if (pc->read->timer_set)
        {
            ngx_del_timer(pc->read);
        }

        if (pc->write->timer_set)
        {
            ngx_del_timer(pc->write);
        }

        ngx_close_connection(pc);
        ctx->peer.connection = NULL;
    }

    ngx_http_finalize_request(ctx->request, rc);
}

static void
ngx_http_tunnel_cleanup(void *data)
{
    ngx_connection_t *pc;
    ngx_http_tunnel_ctx_t *ctx;

    ctx = data;
    if (ctx->finalized)
    {
        return;
    }

    ctx->finalized = 1;

    pc = ctx->peer.connection;
    if (pc == NULL)
    {
        return;
    }

    if (pc->read->timer_set)
    {
        ngx_del_timer(pc->read);
    }

    if (pc->write->timer_set)
    {
        ngx_del_timer(pc->write);
    }

    ngx_close_connection(pc);
    ctx->peer.connection = NULL;
}

static ngx_int_t
ngx_http_tunnel_test_connect(ngx_connection_t *c)
{
    int err;
    socklen_t len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)
    {
        if (c->write->pending_eof || c->read->pending_eof)
        {
            err = c->write->pending_eof ? c->write->kq_errno : c->read->kq_errno;
            (void) ngx_connection_error(c, err,
                                        "kevent() reported that connect() failed");
            return NGX_ERROR;
        }
    }
    else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1)
        {
            err = ngx_socket_errno;
        }

        if (err != 0)
        {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
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
