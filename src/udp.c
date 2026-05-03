#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_udp_is_request(ngx_http_request_t *r)
{
	static ngx_str_t connect_udp = ngx_string("connect-udp");

	if (r->connect_protocol.len != connect_udp.len ||
		ngx_strncmp(r->connect_protocol.data, connect_udp.data,
					connect_udp.len) != 0) {
		return NGX_DECLINED;
	}

	/* Connect UDP only with HTTP2 or HTTP3 */
	if (!tunnel_relay_is_stream_downstream(r)) {
		return NGX_DECLINED;
	}

	return NGX_OK;
}

ngx_int_t
tunnel_udp_parse_target(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx)
{
	u_char *p, *last, *host_start, *host_end, *port_start, *port_end, *q;
	u_char *src, *dst, *target_last;
	ngx_url_t url;
	ngx_int_t n;
	ngx_str_t host, port, target;
	ngx_uint_t host_has_colon, host_bracketed;
	ngx_http_tunnel_srv_conf_t *tscf;
	ngx_http_upstream_resolved_t *resolved;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (r->uri.len <= tscf->udp_path.len ||
		ngx_strncmp(r->uri.data, tscf->udp_path.data,
					tscf->udp_path.len) != 0) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "client sent invalid CONNECT-UDP path \"%V\"",
					  &r->uri);
		return NGX_HTTP_BAD_REQUEST;
	}

	p = r->uri.data + tscf->udp_path.len;
	last = r->uri.data + r->uri.len;

	host_start = p;
	while (p < last && *p != '/') {
		p++;
	}

	if (p == host_start || p == last) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "client sent CONNECT-UDP path without target host");
		return NGX_HTTP_BAD_REQUEST;
	}

	host_end = p++;
	port_start = p;

	while (p < last && *p != '/') {
		p++;
	}

	port_end = p;

	if (port_start == port_end || (p < last && p + 1 != last)) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "client sent invalid CONNECT-UDP target port");
		return NGX_HTTP_BAD_REQUEST;
	}

	for (q = host_start; q < host_end; q++) {
		if (*q == '%' &&
			(q + 2 >= host_end || ngx_hextoi(q + 1, 2) == NGX_ERROR)) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
						  "client sent invalid CONNECT-UDP target host");
			return NGX_HTTP_BAD_REQUEST;
		}
	}

	for (q = port_start; q < port_end; q++) {
		if (*q == '%' &&
			(q + 2 >= port_end || ngx_hextoi(q + 1, 2) == NGX_ERROR)) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
						  "client sent invalid CONNECT-UDP target port");
			return NGX_HTTP_BAD_REQUEST;
		}
	}

	host.len = host_end - host_start;
	host.data = ngx_pnalloc(r->pool, host.len);
	if (host.data == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	src = host_start;
	dst = host.data;

	ngx_unescape_uri(&dst, &src, host_end - host_start, NGX_UNESCAPE_URI);

	host.len = dst - host.data;

	port.len = port_end - port_start;
	port.data = ngx_pnalloc(r->pool, port.len);
	if (port.data == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	src = port_start;
	dst = port.data;

	ngx_unescape_uri(&dst, &src, port_end - port_start, NGX_UNESCAPE_URI);

	port.len = dst - port.data;
	if (port.len == 0) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "client sent empty CONNECT-UDP target port");
		return NGX_HTTP_BAD_REQUEST;
	}

	for (q = port.data; q < port.data + port.len; q++) {
		if (*q < '0' || *q > '9') {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
						  "client sent non-numeric CONNECT-UDP target port");
			return NGX_HTTP_BAD_REQUEST;
		}
	}

	n = ngx_atoi(port.data, port.len);
	if (n < 1 || n > 65535) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "client sent invalid CONNECT-UDP target port");
		return NGX_HTTP_BAD_REQUEST;
	}

	host_has_colon = 0;
	for (q = host.data; q < host.data + host.len; q++) {
		if (*q == ':') {
			host_has_colon = 1;
			break;
		}
	}

	host_bracketed = host.len >= 2 && host.data[0] == '[' &&
					 host.data[host.len - 1] == ']';

	target.len = host.len + 1 + port.len;
	if (host_has_colon && !host_bracketed) {
		target.len += 2;
	}

	target.data = ngx_pnalloc(r->pool, target.len);
	if (target.data == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	p = target.data;
	target_last = target.data + target.len;

	if (host_has_colon && !host_bracketed) {
		*p++ = '[';
		p = ngx_cpymem(p, host.data, host.len);
		*p++ = ']';
	} else {
		p = ngx_cpymem(p, host.data, host.len);
	}

	*p++ = ':';
	p = ngx_cpymem(p, port.data, port.len);

	if (p != target_last) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	ngx_memzero(&url, sizeof(ngx_url_t));
	url.url = target;
	url.no_resolve = 1;

	if (ngx_parse_url(r->pool, &url) != NGX_OK || url.no_port) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "client sent invalid CONNECT-UDP target \"%V\"",
					  &target);
		return NGX_HTTP_BAD_REQUEST;
	}

	if (ctx->resolved == NULL) {
		ctx->resolved = ngx_pcalloc(r->pool,
									sizeof(ngx_http_upstream_resolved_t));
		if (ctx->resolved == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
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
