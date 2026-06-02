
/*
 * Copyright(c) 2026 ZihaoFU245
 */

#ifndef _NGX_HTTP_TUNNEL_MODULE_H_INCLUDED_
#define _NGX_HTTP_TUNNEL_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_TUNNEL_K_FIRST_PADDINGS 8
#define NGX_HTTP_TUNNEL_PADDING_HEADER_SIZE 3
#define NGX_HTTP_TUNNEL_MAX_PADDING_SIZE 255

#define HEADER_RESERVE_BYTES 32

#define CAPSULE_DATAGRAM 0x00
#define CAPSULE_DATAGRAM_CONTEXT_ID 0x00
#define NGX_HTTP_TUNNEL_MAX_DATAGRAM_CAPSULE 65508

#define NGX_HTTP_TUNNEL_NGINX_1_31_0 1031000

typedef struct ngx_http_tunnel_ctx_s ngx_http_tunnel_ctx_t;

/*
 * Relay filter rc:
 *   NGX_OK:    filter produced bytes, but the send stage still needs to run.
 *   NGX_AGAIN: filter needs more input or output space before it can proceed.
 */
typedef ngx_int_t (*tunnel_relay_downstream_filter_pt)(
    ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity);
typedef ngx_int_t (*tunnel_relay_upstream_filter_pt)(
    ngx_http_tunnel_ctx_t *ctx, ngx_uint_t *activity);

typedef enum {
    UNKNOWN_PROTOCOL = 0,
    WEBSOCKET,
    CONNECT_UDP,
    CONNECT_TCP,
    CONNECT_IP,
} ngx_http_tunnel_protocol_t; 			/* For the use of extended connect */

typedef struct {
	ngx_str_t 							pattern;
	ngx_regex_t 						*regex;
	ngx_uint_t 							host_capture;
	ngx_uint_t 							port_capture;
} tunnel_extended_connect_regex_t;		/* Regex patterns for matching capsule protocol */

typedef struct {
	ngx_flag_t 							enable;
	ngx_http_upstream_conf_t 			upstream;
	ngx_http_complex_value_t 			*proxy_auth_user_file;
	ngx_str_t 							probe_resistance_allow_methods;
	size_t 								buffer_size;
	ngx_msec_t 							connect_timeout;
	ngx_msec_t 							idle_timeout;
	ngx_flag_t 							probe_resistance;
	ngx_flag_t 							padding;
	ngx_uint_t 							acl_eval_index;
	ngx_flag_t 							udp;
	ngx_http_complex_value_t 			*udp_path;
} ngx_http_tunnel_srv_conf_t;

typedef struct {
    size_t                              payload_size;
    size_t                              padding_size;
    ngx_uint_t                          downstream_count;
    ngx_uint_t                          upstream_count;
    unsigned                            read_state : 3;
} tunnel_padding_ctx_t;

typedef struct {
    uint64_t                            capsule_len;
    uint64_t                            payload_size;
    unsigned                            read_state : 3;
} tunnel_capsule_ctx_t;

struct ngx_http_tunnel_ctx_s {
    ngx_http_request_t                  *request;
    ngx_chain_t                         *downstream_in; /* r->request_body->bufs */

    ngx_buf_t                           *buffer;
    ngx_chain_t                         downstream_out; /* 32 bytes header reserve */

    size_t                              flush_size;
    size_t                              buffer_tail_reserve;

    ngx_http_upstream_resolved_t        *resolved;
    ngx_http_tunnel_protocol_t          protocol;

    tunnel_padding_ctx_t                *padding;
    tunnel_capsule_ctx_t                *capsule;

    /* Data transform for padding, capsule */
    tunnel_relay_downstream_filter_pt   downstream_filter;
    tunnel_relay_upstream_filter_pt     upstream_filter;

    unsigned                            finalized : 1;
    unsigned                            content_handler_ref : 1;
    unsigned                            downstream_eof : 1;
    unsigned                            upstream_write_closed : 1;
    unsigned                            read_again_event_posted : 1;
    unsigned                            extended_connect : 1;

    unsigned                            downstream_empty_datagram : 1;
    unsigned                            upstream_empty_datagram : 1;
};

extern ngx_module_t ngx_http_tunnel_connect_module;

/* Configurations */
char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *tunnel_acl_eval_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_tunnel_proxy_auth_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
void *ngx_http_tunnel_create_srv_conf(ngx_conf_t *cf);
char *ngx_http_tunnel_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

/* Core functions */
ngx_int_t ngx_http_tunnel_init(ngx_conf_t *cf);
ngx_int_t ngx_http_tunnel_access_handler(ngx_http_request_t *r);
ngx_int_t ngx_tunnel_skip_phase_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_tunnel_content_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_tunnel_add_variables(ngx_conf_t *cf);
ngx_int_t tunnel_get_target_host_handler(ngx_http_request_t        *r,
                                         ngx_http_variable_value_t *v,
                                         uintptr_t                  data);
ngx_int_t tunnel_acl_eval(ngx_http_request_t *r);

#if (nginx_version < NGX_HTTP_TUNNEL_NGINX_1_31_0)
ngx_int_t tunnel_auth_access_denied(ngx_http_request_t         *r,
                                    ngx_http_tunnel_srv_conf_t *tscf);
ngx_int_t tunnel_auth_check(ngx_http_request_t         *r,
                            ngx_http_tunnel_srv_conf_t *tscf);
#endif

/* Upstream outbounds */
ngx_int_t tunnel_connect_init_upstream_peer(ngx_http_request_t    *r,
                                            ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_connect_set_target(ngx_http_request_t    *r,
                                    ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_connect_empty_request(ngx_http_request_t *r);
ngx_int_t tunnel_extended_connect_branching(ngx_http_request_t    *r,
                                            ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_connect_process_header(ngx_http_request_t *r);
void      tunnel_connect_abort_request(ngx_http_request_t *r);
void      tunnel_connect_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

ngx_int_t tunnel_udp_is_request(ngx_str_t *protocol);
ngx_int_t tunnel_udp_set_target(ngx_http_request_t *r);
ngx_int_t tunnel_udp_init_upstream(ngx_http_request_t    *r,
                                   ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_udp_process_header(ngx_http_request_t *r);

/* Capsule helpers */
ngx_int_t tunnel_capsule_is_header_present(ngx_http_request_t *r);
ngx_int_t tunnel_capsule_downstream_filter(ngx_http_tunnel_ctx_t *ctx,
                                           ngx_uint_t            *activity);
ngx_int_t tunnel_capsule_upstream_filter(ngx_http_tunnel_ctx_t *ctx,
                                         ngx_uint_t            *activity);

/* Bidirectional byte relay */
ngx_int_t tunnel_relay_start(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_relay_send_connected(ngx_http_request_t *r);

ngx_int_t tunnel_relay_init_request_body(ngx_http_tunnel_ctx_t *ctx);

/* Naive padding */
ngx_int_t tunnel_padding_needed(ngx_http_request_t *r);
ngx_int_t tunnel_padding_add_response_header(ngx_http_request_t   *r,
                                             tunnel_padding_ctx_t *padding);

void      tunnel_padding_h2_prepend_rst_stream_data(ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_padding_downstream_filter(ngx_http_tunnel_ctx_t *ctx,
                                           ngx_uint_t            *activity);
ngx_int_t tunnel_padding_upstream_filter(ngx_http_tunnel_ctx_t *ctx,
                                         ngx_uint_t            *activity);

void tunnel_relay_downstream_read_handler(ngx_http_request_t *r);
void tunnel_relay_downstream_write_handler(ngx_http_request_t *r);
void tunnel_relay_upstream_read_handler(ngx_event_t *ev);
void tunnel_relay_upstream_write_handler(ngx_event_t *ev);
void tunnel_relay_process(ngx_http_tunnel_ctx_t *ctx);
void tunnel_relay_post_downstream_read(ngx_http_tunnel_ctx_t *ctx);
void tunnel_relay_finalize(ngx_http_tunnel_ctx_t *ctx, ngx_int_t rc);
void tunnel_relay_cleanup(void *data);

void tunnel_utils_free_consumed_chain(ngx_http_request_t *r,
                                      ngx_chain_t **chain, ngx_chain_t *limit);
ngx_http_tunnel_protocol_t tunnel_utils_match_protocol(ngx_str_t *protocol);
ngx_int_t                  tunnel_utils_init_extended_connect(ngx_conf_t *cf);
ngx_int_t
tunnel_util_parse_extended_connect(ngx_http_request_t *r, ngx_str_t *params,
                                   ngx_http_upstream_resolved_t *resolved);

#define tunnel_relay_is_stream_downstream(r)                                   \
    ((r)->http_version == NGX_HTTP_VERSION_20 ||                               \
     (r)->http_version == NGX_HTTP_VERSION_30)

#define downstream_prepare_addition_header(b, size)                            \
    ((b)->pos != (b)->last                                                     \
         ? NGX_AGAIN                                                           \
         : ((b)->pos = (b)->start, (b)->last = (b)->start,                     \
            (size_t)((b)->end - (b)->last) < (size) ? NGX_ERROR : NGX_OK))

#define tunnel_padding_active(padding)                                         \
    ((padding) == NULL ? NGX_DECLINED : NGX_OK)

#endif
