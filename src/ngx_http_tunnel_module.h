#ifndef _NGX_HTTP_TUNNEL_MODULE_H_INCLUDED_
#define _NGX_HTTP_TUNNEL_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_round_robin.h>
#include <ngx_http_v2.h>

#define NGX_HTTP_TUNNEL_K_FIRST_PADDINGS 8

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
} tunnel_padding_ctx_t;

typedef struct {
	ngx_http_request_t *request;
	ngx_buf_t *client_buffer;
	ngx_buf_t *upstream_buffer;
	ngx_chain_t *downstream_chain;
	ngx_http_upstream_resolved_t *resolved;
	ngx_resolver_ctx_t *resolver_ctx;
	tunnel_padding_ctx_t *padding;
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
ngx_int_t tunnel_auth_set_proxy_authenticate(ngx_http_request_t *r);
ngx_int_t tunnel_auth_access_denied(ngx_http_request_t *r,
	ngx_http_tunnel_srv_conf_t *tscf);
ngx_int_t tunnel_auth_check(ngx_http_request_t *r,
	ngx_http_tunnel_srv_conf_t *tscf);

ngx_int_t tunnel_connect_init_upstream_peer(ngx_http_request_t *r,
	ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_connect_parse_target(ngx_http_request_t *r,
	ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_connect_next(ngx_http_tunnel_ctx_t *ctx);
void tunnel_resolve_handler(ngx_resolver_ctx_t *resolver_ctx);
void tunnel_connect_handler(ngx_event_t *ev);
ngx_int_t tunnel_connect_test(ngx_connection_t *c);

ngx_int_t tunnel_relay_start(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_relay_send_connected(ngx_http_request_t *r);
ngx_int_t tunnel_relay_is_stream_downstream(ngx_http_request_t *r);
ngx_int_t tunnel_relay_v1_process(ngx_http_tunnel_ctx_t *ctx,
	ngx_uint_t from_upstream, ngx_uint_t do_write);
ngx_int_t tunnel_relay_v2_init_request_body(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_relay_v2_process(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_relay_v3_init_request_body(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_relay_v3_process(ngx_http_tunnel_ctx_t *ctx);

ngx_int_t tunnel_padding_negotiate(ngx_http_request_t *r,
	ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_padding_add_response_header(ngx_http_request_t *r,
	ngx_http_tunnel_ctx_t *ctx);

static ngx_inline ngx_int_t
tunnel_padding_active(ngx_http_tunnel_ctx_t *ctx)
{
	return (ctx == NULL || ctx->padding == NULL) ? NGX_DECLINED : NGX_OK;
}

void tunnel_padding_h2_prepend_rst_stream_data(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_padding_send_upstream(ngx_http_tunnel_ctx_t *ctx,
	ngx_uint_t *activity);
ngx_int_t tunnel_padding_send_downstream(ngx_http_tunnel_ctx_t *ctx,
	ngx_uint_t *activity);

void tunnel_relay_downstream_read_handler(ngx_http_request_t *r);
void tunnel_relay_downstream_write_handler(ngx_http_request_t *r);
void tunnel_relay_upstream_read_handler(ngx_event_t *ev);
void tunnel_relay_upstream_write_handler(ngx_event_t *ev);
void tunnel_relay_process(ngx_http_tunnel_ctx_t *ctx,
	ngx_uint_t from_upstream, ngx_uint_t do_write);
void tunnel_relay_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc);
void tunnel_relay_cleanup(void *data);
void tunnel_relay_close(ngx_http_tunnel_ctx_t *ctx);
void tunnel_upstream_release_peer(ngx_http_request_t *r, ngx_uint_t state);

void tunnel_utils_release_request_body_ref(ngx_http_tunnel_ctx_t *ctx);
void tunnel_utils_clear_timer(ngx_event_t *ev);
void tunnel_utils_update_idle_timer(ngx_event_t *ev, ngx_msec_t timeout);
void tunnel_utils_free_consumed_chain(ngx_http_request_t *r,
	ngx_chain_t **chain, ngx_chain_t *limit);
ngx_uint_t tunnel_utils_copy_chain_to_buffer(ngx_http_request_t *r,
	ngx_chain_t **chain, ngx_buf_t *b, size_t limit);

#endif
