#include "ngx_http_tunnel_module.h"

ngx_int_t
ngx_http_tunnel_eval(ngx_http_request_t *r)
{
	ngx_http_tunnel_srv_conf_t   *tscf;
	ngx_http_upstream_srv_conf_t *uscf;
	ngx_http_upstream_server_t   *servers;
	ngx_http_tunnel_acl_state_t   state;
	ngx_peer_connection_t        *peer;
	ngx_uint_t                    i, j, hit;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (tscf->acl_allow != NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "tunnel ACL allow list configured");
		state = NGX_HTTP_TUNNEL_ACL_DENY_WHITE_LIST;
		uscf = tscf->acl_allow;
	} else if (tscf->acl_deny != NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "tunnel ACL deny list configured");
		state = NGX_HTTP_TUNNEL_ACL_ALLOW_BLACK_LIST;
		uscf = tscf->acl_deny;
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "tunnel ACL not configured");
		return NGX_OK;
	}

	if (r->upstream == NULL || r->upstream->peer.connection == NULL) {
		return NGX_ERROR;
	}

	peer = &r->upstream->peer;

	if (uscf->servers == NULL) {
		return NGX_ERROR;
	}

	hit = 0;
	servers = uscf->servers->elts;

	/*
	 * For each server in ACL list, compare it with connect
	 * target. The inner for loop is prepared for multiple
	 * addresses that server name resolved. This is address
	 * level blocking. Perhaps comparing server names is the
	 * correct idea. Consider domain A and B both resolved
	 * to address P. Then domain B can be blocked if domain
	 * A is on the list. This is not good for CDN. So ACL
	 * should as much accurate as possible.
	 *
	 * This is running in O(kn), for n servers and
	 * k address resolved. k is expected to be a small number.
	 *
	 * It is not intended for a super large ACL list, the runtime
	 * can behave terribly. In future, use a file for ACL and
	 * adopt `ngx_hash_t` for O(1) time lookup.
	 */
	for (i = 0; i < uscf->servers->nelts && !hit; i++) {
		for (j = 0; j < servers[i].naddrs; j++) {
			if (tunnel_utils_addrs_equal(
					peer->sockaddr, peer->socklen, servers[i].addrs[j].sockaddr,
					servers[i].addrs[j].socklen) == NGX_OK) {
				hit = 1;
				break;
			}
		}
	}

	switch (state) {

	case NGX_HTTP_TUNNEL_ACL_DENY_WHITE_LIST:
		return hit ? NGX_OK : NGX_ERROR;

	case NGX_HTTP_TUNNEL_ACL_ALLOW_BLACK_LIST:
		return hit ? NGX_ERROR : NGX_OK;

	default:
		return NGX_OK;
	}
}

char *
ngx_http_tunnel_acl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_tunnel_srv_conf_t    *tscf = conf;
	ngx_str_t                     *value;
	ngx_url_t                      u;
	ngx_http_upstream_srv_conf_t  *uscf;
	ngx_http_upstream_srv_conf_t **slot;

	slot = (ngx_http_upstream_srv_conf_t **)((char *)tscf + cmd->offset);

	if (*slot != NULL) {
		return "is duplicate";
	}

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url = value[1];
	u.no_resolve = 1;
	u.no_port = 1;

	uscf = ngx_http_upstream_add(cf, &u, 0);
	if (uscf == NULL) {
		return NGX_CONF_ERROR;
	}

	*slot = uscf;

	return NGX_CONF_OK;
}
