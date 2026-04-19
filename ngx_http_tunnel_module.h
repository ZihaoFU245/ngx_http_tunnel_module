#ifndef _NGX_HTTP_TUNNEL_MODULE_H_INCLUDED_
#define _NGX_HTTP_TUNNEL_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_round_robin.h>
#include <ngx_http_v2.h>

typedef struct {
	ngx_flag_t enable;
	ngx_str_t auth_username;
	ngx_str_t auth_password;
	size_t buffer_size;
	ngx_msec_t connect_timeout;
	ngx_msec_t idle_timeout;
	ngx_flag_t probe_resistance;
	ngx_flag_t padding;
} ngx_http_tunnel_srv_conf_t;

typedef struct {
	ngx_str_t response_value;
	ngx_buf_t *buffer;
	u_char read_header[3];
	size_t payload_rest;
	size_t discard_rest;
	unsigned response_ready : 1;
	unsigned output_active : 1;
	unsigned read_state : 2;
	unsigned read_header_size : 2;
	ngx_uint_t downstream_count;
	ngx_uint_t upstream_count;
	uint64_t previous_header_hash;
} ngx_http_tunnel_padding_ctx_t;

typedef struct {
	ngx_http_request_t *request;
	ngx_buf_t *client_buffer;
	ngx_buf_t *upstream_buffer;
	ngx_chain_t *downstream_chain;
	ngx_http_upstream_resolved_t *resolved;
	ngx_resolver_ctx_t *resolver_ctx;
	ngx_http_tunnel_padding_ctx_t *padding;
	unsigned finalized : 1;
	unsigned connected : 1;
	unsigned waiting_connect : 1;
	unsigned resolving : 1;
	unsigned peer_acquired : 1;
	unsigned request_body_started : 1;
	unsigned request_body_ref_released : 1;
	unsigned downstream_eof : 1;
} ngx_http_tunnel_ctx_t;

extern ngx_module_t ngx_http_tunnel_module;

char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void *ngx_http_tunnel_create_srv_conf(ngx_conf_t *cf);
char *ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t ngx_http_tunnel_init(ngx_conf_t *cf);
ngx_int_t ngx_http_tunnel_access_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_tunnel_content_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_tunnel_set_proxy_authenticate(ngx_http_request_t *r);
ngx_int_t ngx_http_tunnel_access_denied(ngx_http_request_t *r,
										ngx_http_tunnel_srv_conf_t *tscf);
ngx_int_t ngx_http_tunnel_check_auth(ngx_http_request_t *r,
									 ngx_http_tunnel_srv_conf_t *tscf);

ngx_int_t ngx_http_tunnel_init_upstream_peer(ngx_http_request_t *r,
											 ngx_http_tunnel_ctx_t *ctx);
ngx_int_t ngx_http_tunnel_parse_target(ngx_http_request_t *r,
									   ngx_http_tunnel_ctx_t *ctx);
ngx_int_t ngx_http_tunnel_connect_next(ngx_http_tunnel_ctx_t *ctx);
void ngx_http_tunnel_resolve_handler(ngx_resolver_ctx_t *resolver_ctx);

ngx_int_t ngx_http_tunnel_start(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t ngx_http_tunnel_send_connected(ngx_http_request_t *r);

static ngx_inline ngx_int_t
ngx_http_tunnel_stream_downstream(ngx_http_request_t *r)
{
	return r->http_version == NGX_HTTP_VERSION_20 ||
		   r->http_version == NGX_HTTP_VERSION_30;
}

ngx_int_t ngx_http_tunnel_padding_negotiate(ngx_http_request_t *r,
											ngx_http_tunnel_ctx_t *ctx);
ngx_int_t
ngx_http_tunnel_padding_add_response_header(ngx_http_request_t *r,
											ngx_http_tunnel_ctx_t *ctx);

static ngx_inline ngx_int_t
ngx_http_tunnel_padding_active(ngx_http_tunnel_ctx_t *ctx)
{
	return (ctx == NULL || ctx->padding == NULL) ? NGX_DECLINED : NGX_OK;
}

void
ngx_http_tunnel_padding_h2_prepend_rst_stream_data(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t
ngx_http_tunnel_padding_fill_upstream_buffer(ngx_http_tunnel_ctx_t *ctx,
											 ngx_uint_t *activity);
ngx_int_t ngx_http_tunnel_padding_send_downstream(ngx_http_tunnel_ctx_t *ctx,
												  ngx_uint_t *activity);
ngx_int_t ngx_http_tunnel_init_request_body(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t ngx_http_tunnel_process_stream(ngx_http_tunnel_ctx_t *ctx);
void ngx_http_tunnel_connect_handler(ngx_event_t *ev);
void ngx_http_tunnel_downstream_read_handler(ngx_http_request_t *r);
void ngx_http_tunnel_downstream_write_handler(ngx_http_request_t *r);
void ngx_http_tunnel_upstream_read_handler(ngx_event_t *ev);
void ngx_http_tunnel_upstream_write_handler(ngx_event_t *ev);
void ngx_http_tunnel_process(ngx_http_tunnel_ctx_t *ctx,
							 ngx_uint_t from_upstream, ngx_uint_t do_write);
void ngx_http_tunnel_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc);
void ngx_http_tunnel_cleanup(void *data);
void ngx_http_tunnel_release_peer(ngx_http_request_t *r, ngx_uint_t state);
ngx_int_t ngx_http_tunnel_test_connect(ngx_connection_t *c);

#endif
