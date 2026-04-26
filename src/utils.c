#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_utils_addrs_equal(struct sockaddr *a, socklen_t alen,
						 struct sockaddr *b, socklen_t blen)
{
	struct sockaddr_in *sin_a, *sin_b;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6 *sin6_a, *sin6_b;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
	struct sockaddr_un *sun_a, *sun_b;
	size_t path_a, path_b;
#endif

	if (a == NULL || b == NULL || a->sa_family != b->sa_family) {
		return NGX_DECLINED;
	}

	switch (a->sa_family) {

	case AF_INET:
		if (alen < (socklen_t)sizeof(struct sockaddr_in) ||
			blen < (socklen_t)sizeof(struct sockaddr_in)) {
			return NGX_DECLINED;
		}

		sin_a = (struct sockaddr_in *)a;
		sin_b = (struct sockaddr_in *)b;

		if (sin_a->sin_addr.s_addr != sin_b->sin_addr.s_addr) {
			return NGX_DECLINED;
		}

		return NGX_OK;

#if (NGX_HAVE_INET6)
	case AF_INET6:
		if (alen < (socklen_t)sizeof(struct sockaddr_in6) ||
			blen < (socklen_t)sizeof(struct sockaddr_in6)) {
			return NGX_DECLINED;
		}

		sin6_a = (struct sockaddr_in6 *)a;
		sin6_b = (struct sockaddr_in6 *)b;

		if (ngx_memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr,
					   sizeof(struct in6_addr)) != 0) {
			return NGX_DECLINED;
		}

		return NGX_OK;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
	case AF_UNIX:
		sun_a = (struct sockaddr_un *)a;
		sun_b = (struct sockaddr_un *)b;

		path_a = (size_t)alen > offsetof(struct sockaddr_un, sun_path)
					 ? (size_t)alen - offsetof(struct sockaddr_un, sun_path)
					 : 0;
		path_b = (size_t)blen > offsetof(struct sockaddr_un, sun_path)
					 ? (size_t)blen - offsetof(struct sockaddr_un, sun_path)
					 : 0;

		if (path_a != path_b) {
			return NGX_DECLINED;
		}

		if (path_a == 0) {
			return NGX_OK;
		}

		if (ngx_memcmp(sun_a->sun_path, sun_b->sun_path, path_a) != 0) {
			return NGX_DECLINED;
		}

		return NGX_OK;
#endif

	default:
		return NGX_DECLINED;
	}
}

void
tunnel_utils_release_request_body_ref(ngx_http_tunnel_ctx_t *ctx)
{
	ngx_http_request_t *r;

	if (ctx == NULL || !ctx->request_body_ref_acquired ||
		ctx->request_body_ref_released) {
		return;
	}

	r = ctx->request;
	if (r == NULL) {
		return;
	}

	ctx->request_body_ref_released = 1;

	if (r->main->count > 1) {
		r->main->count--;
	}
}

void
tunnel_utils_clear_timer(ngx_event_t *ev)
{
	if (ev->timer_set) {
		ngx_del_timer(ev);
	}
}

void
tunnel_utils_update_idle_timer(ngx_event_t *ev, ngx_msec_t timeout)
{
	if (ev->active) {
		ngx_add_timer(ev, timeout);
		return;
	}

	tunnel_utils_clear_timer(ev);
}

void
tunnel_utils_free_consumed_chain(ngx_http_request_t *r, ngx_chain_t **chain,
								 ngx_chain_t *limit)
{
	ngx_chain_t *cl;

	while (*chain != limit && *chain != NULL &&
		   ngx_buf_size((*chain)->buf) == 0) {
		cl = *chain;
		*chain = cl->next;
		ngx_free_chain(r->pool, cl);
	}
}

ngx_uint_t
tunnel_utils_copy_chain_to_buffer(ngx_http_request_t *r, ngx_chain_t **chain,
								  ngx_buf_t *b, size_t limit)
{
	size_t n;
	size_t size;
	ngx_uint_t copied;
	ngx_buf_t *src;
	ngx_chain_t *cl;

	copied = 0;

	for (;;) {
		tunnel_utils_free_consumed_chain(r, chain, NULL);

		cl = *chain;
		if (cl == NULL || b->last == b->end || limit == 0) {
			return copied;
		}

		src = cl->buf;
		size = b->end - b->last;
		n = ngx_min((size_t)ngx_buf_size(src), size);
		n = ngx_min(n, limit);

		if (n == 0) {
			return copied;
		}

		b->last = ngx_cpymem(b->last, src->pos, n);
		src->pos += n;
		limit -= n;
		copied = 1;
	}
}
