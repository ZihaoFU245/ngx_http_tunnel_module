#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_connect_init_upstream_peer(ngx_http_request_t *r,
								  ngx_http_tunnel_ctx_t *ctx)
{
	if (ngx_http_upstream_create(r) != NGX_OK) {
		return NGX_ERROR;
	}

	ctx->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
	if (ctx->resolved == NULL) {
		return NGX_ERROR;
	}

	r->upstream->resolved = ctx->resolved;

	return NGX_OK;
}

ngx_int_t
tunnel_connect_parse_target(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx)
{
	ngx_url_t url;
	ngx_str_t authority;
	ngx_http_upstream_resolved_t *resolved;

	if (r->host_start == NULL || r->host_end == NULL) {
		return NGX_HTTP_BAD_REQUEST;
	}

	authority.data = r->host_start;
	authority.len = r->host_end - r->host_start;

	ngx_memzero(&url, sizeof(ngx_url_t));
	url.url = authority;
	url.no_resolve = 1;

	if (ngx_parse_url(r->pool, &url) != NGX_OK) {
		return NGX_HTTP_BAD_REQUEST;
	}

	if (url.no_port) {
		return NGX_HTTP_BAD_REQUEST;
	}

	resolved = ctx->resolved;
	resolved->host = url.host;
	resolved->port = url.port;
	resolved->no_port = 0;

	if (url.naddrs == 1) {
		resolved->naddrs = 1;
		resolved->sockaddr = url.addrs[0].sockaddr;
		resolved->socklen = url.addrs[0].socklen;
		resolved->name = url.addrs[0].name;
	}

	return NGX_OK;
}

ngx_int_t
tunnel_connect_empty_request(ngx_http_request_t *r)
{
	return NGX_OK;
}

ngx_int_t
tunnel_connect_process_header(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_tunnel_ctx_t *ctx;
	ngx_http_upstream_t *u;

	u = r->upstream;

	if (ngx_http_tunnel_eval(r) != NGX_OK) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "tunnel ACL denied peer");
		u->headers_in.status_n = NGX_HTTP_FORBIDDEN;
		ngx_str_set(&u->headers_in.status_line, "403 Forbidden");
		u->headers_in.content_length_n = 0;
		u->keepalive = 0;
		return NGX_OK;
	}

	u->headers_in.status_n = NGX_HTTP_OK;
	ngx_str_set(&u->headers_in.status_line, "200 Connection Established");

	r->keepalive = 0;
	u->keepalive = 0;

	if (!tunnel_relay_is_stream_downstream(r)) {
		u->upgrade = 1;
		return NGX_OK;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);
	if (ctx == NULL) {
		return NGX_ERROR;
	}

	/*
	 * HTTP/2 and HTTP/3 CONNECT downstreams are streams, not raw client
	 * sockets. After upstream connects, the module takes over with a
	 * stream-aware relay while upstream keeps ownership of peer setup.
	 */
	rc = tunnel_relay_start(ctx);
	if (rc != NGX_OK) {
		/*
		 * Route every relay_start failure through tunnel_relay_finalize so
		 * the request-body ref acquired inside
		 * tunnel_relay_v2_init_request_body is released; otherwise
		 * ngx_http_finalize_request alone cannot bring r->main->count to zero
		 * and the request pool leaks.
		 */
		tunnel_relay_finalize(ctx, rc >= NGX_HTTP_SPECIAL_RESPONSE
									   ? rc
									   : NGX_HTTP_INTERNAL_SERVER_ERROR);
		return NGX_DONE;
	}

	return NGX_DONE;
}

void
tunnel_connect_abort_request(ngx_http_request_t *r)
{
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				   "abort tunnel upstream request");
}

void
tunnel_connect_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	ngx_http_tunnel_ctx_t *ctx;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				   "finalize tunnel upstream request");

	ctx = ngx_http_get_module_ctx(r, ngx_http_tunnel_module);

	/*
	 * Balance the reference acquired before ngx_http_upstream_init() for
	 * upstream-owned paths: HTTP/1 upgrade relay, ACL denial, connect errors,
	 * and any other path where process_header did not hand control to the
	 * stream relay with NGX_DONE.
	 */
	if (ctx == NULL) {
		if (r->main->count > 1) {
			r->main->count--;
		}
		return;
	}

	if (!ctx->finalized) {
		tunnel_utils_release_content_ref(ctx);
	}
}
