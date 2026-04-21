#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_relay_v3_init_request_body(ngx_http_tunnel_ctx_t *ctx)
{
	return tunnel_relay_v2_init_request_body(ctx);
}

ngx_int_t
tunnel_relay_v3_process(ngx_http_tunnel_ctx_t *ctx)
{
	return tunnel_relay_v2_process(ctx);
}

