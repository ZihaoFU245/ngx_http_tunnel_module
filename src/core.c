/*
 * Tunnel Module Core
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

    {ngx_string("tunnel_acl_allow"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_tunnel_acl_set,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, acl_allow),
     NULL},

    {ngx_string("tunnel_acl_deny"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_tunnel_acl_set,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_tunnel_srv_conf_t, acl_deny),
     NULL},

	ngx_null_command
};

static ngx_http_module_t ngx_http_tunnel_module_ctx = {
	NULL,
	ngx_http_tunnel_init,

	NULL,
	NULL,

	ngx_http_tunnel_create_srv_conf,
	ngx_http_tunnel_merge_srv_conf,

	NULL,
	NULL
};

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
	NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_tunnel_access_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_tunnel_srv_conf_t *tscf;

	if (r->method != NGX_HTTP_CONNECT) {
		return NGX_DECLINED;
	}

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (!tscf->enable) {
		return NGX_DECLINED;
	}

	rc = tunnel_auth_check(r, tscf);
	if (rc != NGX_OK) {
		return rc;
	}

	r->content_handler = ngx_http_tunnel_content_handler;

	return NGX_DECLINED;
}

ngx_int_t
ngx_http_tunnel_content_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_tunnel_ctx_t *ctx;
	ngx_http_tunnel_srv_conf_t *tscf;
	ngx_http_upstream_t *u;

	if (r->method != NGX_HTTP_CONNECT) {
		return NGX_DECLINED;
	}

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (!tscf->enable) {
		return NGX_DECLINED;
	}

	if (r != r->main) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx != NULL) {
		return NGX_DONE;
	}

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_tunnel_ctx_t));
	if (ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->request = r;

	ctx->client_buffer = ngx_create_temp_buf(r->pool, tscf->buffer_size);
	if (ctx->client_buffer == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ctx->upstream_buffer = ngx_create_temp_buf(r->pool, tscf->buffer_size);
	if (ctx->upstream_buffer == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (tunnel_padding_needed(r) == NGX_OK) {
		ctx->padding = ngx_pcalloc(r->pool, sizeof(tunnel_padding_ctx_t));
		if (ctx->padding == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ctx->padding->buffer = ngx_create_temp_buf(
			r->pool, tunnel_padding_buffer_size(r));
		if (ctx->padding->buffer == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (tunnel_padding_negotiate(r, ctx) != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	ngx_http_set_ctx(r, ctx, ngx_http_tunnel_module);

	if (tunnel_connect_init_upstream_peer(r, ctx) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	rc = tunnel_connect_parse_target(r, ctx);
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
	ctx->content_ref_acquired = 1;

	ngx_http_upstream_init(r);

	return NGX_DONE;
}

char *
ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_tunnel_srv_conf_t *tscf = conf;
	ngx_http_core_srv_conf_t *cscf;

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
	conf->buffer_size = NGX_CONF_UNSET_SIZE;
	conf->connect_timeout = NGX_CONF_UNSET_MSEC;
	conf->idle_timeout = NGX_CONF_UNSET_MSEC;
	conf->probe_resistance = NGX_CONF_UNSET;
	conf->padding = NGX_CONF_UNSET;
	
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
	ngx_conf_merge_str_value(conf->auth_username, prev->auth_username, "");
	ngx_conf_merge_str_value(conf->auth_password, prev->auth_password, "");
	ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 16 * 1024);
	ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout,
							  60000);
	ngx_conf_merge_msec_value(conf->idle_timeout, prev->idle_timeout, 30000);
	ngx_conf_merge_value(conf->probe_resistance, prev->probe_resistance, 0);
	ngx_conf_merge_value(conf->padding, prev->padding, 0);
	ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
	ngx_conf_merge_uint_value(conf->upstream.store_access,
							  prev->upstream.store_access, 0600);
	ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
							  prev->upstream.next_upstream_tries, 0);
	ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering,
						 0);
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

	if ((conf->auth_username.len == 0) != (conf->auth_password.len == 0)) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "both tunnel_auth_username and tunnel_auth_password "
						   "must be set together");
		return NGX_CONF_ERROR;
	}

	if (conf->acl_allow == NULL) {
		conf->acl_allow = prev->acl_allow;
	}

	if (conf->acl_deny == NULL) {
		conf->acl_deny = prev->acl_deny;
	}

	if (conf->acl_allow != NULL && conf->acl_deny != NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "tunnel_acl_allow and tunnel_acl_deny are "
						   "mutually exclusive");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_tunnel_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_core_srv_conf_t **cscfp;
	ngx_http_tunnel_srv_conf_t *tscf;
	ngx_uint_t i;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	cscfp = cmcf->servers.elts;

	for (i = 0; i < cmcf->servers.nelts; i++) {
		tscf = cscfp[i]->ctx->srv_conf[ngx_http_tunnel_module.ctx_index];

		if (tscf->enable) {
			goto enabled;
		}
	}

	return NGX_OK;

enabled:

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_tunnel_access_handler;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_tunnel_content_handler;

	return NGX_OK;
}
