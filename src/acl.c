#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_ACL_VALUE ((void *)1)

static ngx_int_t acl_parse_target(ngx_http_request_t *r, ngx_url_t *target);
static ngx_int_t acl_add_rule(ngx_conf_t *cf, ngx_hash_keys_arrays_t *any_port,
							  ngx_hash_keys_arrays_t *exact_port,
							  ngx_str_t *name);
static ngx_int_t acl_build_key(ngx_pool_t *pool, ngx_str_t *host,
							   in_port_t port, ngx_uint_t any_port,
							   ngx_str_t *key, ngx_uint_t *hash);
static ngx_int_t acl_init_hash(ngx_conf_t *cf, ngx_hash_t *hash,
							   ngx_hash_keys_arrays_t *keys, char *name);
static ngx_int_t acl_target_matches(ngx_http_request_t *r,
									ngx_http_tunnel_acl_hash_t *acl,
									ngx_url_t *target, ngx_uint_t *hit);

ngx_int_t
ngx_http_tunnel_eval(ngx_http_request_t *r)
{
	ngx_http_tunnel_srv_conf_t  *tscf;
	ngx_http_tunnel_acl_hash_t  *acl;
	ngx_http_tunnel_acl_state_t  state;
	ngx_url_t                    target;
	ngx_uint_t                   hit;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (tscf->acl_allow != NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "tunnel ACL allow list configured");
		state = NGX_HTTP_TUNNEL_ACL_DENY_WHITE_LIST;
		acl = &tscf->acl_allow_hash;
	} else if (tscf->acl_deny != NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "tunnel ACL deny list configured");
		state = NGX_HTTP_TUNNEL_ACL_ALLOW_BLACK_LIST;
		acl = &tscf->acl_deny_hash;
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					   "tunnel ACL not configured");
		return NGX_OK;
	}

	if (acl_parse_target(r, &target) != NGX_OK) {
		return NGX_HTTP_BAD_REQUEST;
	}

	if (acl_target_matches(r, acl, &target, &hit) != NGX_OK) {
		return NGX_ERROR;
	}

	switch (state) {

	case NGX_HTTP_TUNNEL_ACL_DENY_WHITE_LIST:
		return hit ? NGX_OK : NGX_HTTP_FORBIDDEN;

	case NGX_HTTP_TUNNEL_ACL_ALLOW_BLACK_LIST:
		return hit ? NGX_HTTP_FORBIDDEN : NGX_OK;

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

ngx_int_t
ngx_http_tunnel_acl_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf,
						 ngx_http_tunnel_acl_hash_t *acl)
{
	ngx_hash_keys_arrays_t       any_port, exact_port;
	ngx_http_upstream_server_t  *servers;
	ngx_uint_t                   i;

	if (uscf == NULL || uscf->servers == NULL) {
		return NGX_ERROR;
	}

	ngx_memzero(&any_port, sizeof(ngx_hash_keys_arrays_t));
	any_port.pool = cf->pool;
	any_port.temp_pool = cf->temp_pool;

	if (ngx_hash_keys_array_init(&any_port, NGX_HASH_SMALL) != NGX_OK) {
		return NGX_ERROR;
	}

	ngx_memzero(&exact_port, sizeof(ngx_hash_keys_arrays_t));
	exact_port.pool = cf->pool;
	exact_port.temp_pool = cf->temp_pool;

	if (ngx_hash_keys_array_init(&exact_port, NGX_HASH_SMALL) != NGX_OK) {
		return NGX_ERROR;
	}

	servers = uscf->servers->elts;

	for (i = 0; i < uscf->servers->nelts; i++) {
		if (acl_add_rule(cf, &any_port, &exact_port, &servers[i].name) !=
			NGX_OK) {
			return NGX_ERROR;
		}
	}

	acl->any_port_nelts = any_port.keys.nelts;
	acl->exact_port_nelts = exact_port.keys.nelts;

	if (acl_init_hash(cf, &acl->any_port, &any_port,
					  "tunnel_acl_any_port_hash") != NGX_OK) {
		return NGX_ERROR;
	}

	if (acl_init_hash(cf, &acl->exact_port, &exact_port,
					  "tunnel_acl_exact_port_hash") != NGX_OK) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
acl_parse_target(ngx_http_request_t *r, ngx_url_t *target)
{
	ngx_str_t authority;

	if (r->host_start == NULL || r->host_end == NULL) {
		return NGX_ERROR;
	}

	authority.data = r->host_start;
	authority.len = r->host_end - r->host_start;

	ngx_memzero(target, sizeof(ngx_url_t));
	target->url = authority;
	target->no_resolve = 1;

	if (ngx_parse_url(r->pool, target) != NGX_OK) {
		return NGX_ERROR;
	}

	if (target->no_port) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
acl_add_rule(ngx_conf_t *cf, ngx_hash_keys_arrays_t *any_port,
			 ngx_hash_keys_arrays_t *exact_port, ngx_str_t *name)
{
	ngx_int_t  rc;
	ngx_str_t  key;
	ngx_url_t  rule;

	ngx_memzero(&rule, sizeof(ngx_url_t));
	rule.url = *name;
	rule.no_resolve = 1;

	if (ngx_parse_url(cf->pool, &rule) != NGX_OK) {
		return NGX_ERROR;
	}

	if (acl_build_key(cf->pool, &rule.host, rule.port, rule.no_port, &key,
					  NULL) != NGX_OK) {
		return NGX_ERROR;
	}

	rc = ngx_hash_add_key(rule.no_port ? any_port : exact_port, &key,
						  NGX_HTTP_TUNNEL_ACL_VALUE, 0);

	if (rc == NGX_BUSY) {
		return NGX_OK;
	}

	return rc;
}

static ngx_int_t
acl_build_key(ngx_pool_t *pool, ngx_str_t *host, in_port_t port,
			  ngx_uint_t any_port, ngx_str_t *key, ngx_uint_t *hash)
{
	u_char  *p;

	key->len = host->len;

	if (!any_port) {
		key->len += NGX_INT_T_LEN + 1;
	}

	key->data = ngx_pnalloc(pool, key->len);
	if (key->data == NULL) {
		return NGX_ERROR;
	}

	if (hash != NULL) {
		*hash = ngx_hash_strlow(key->data, host->data, host->len);

	} else {
		(void)ngx_hash_strlow(key->data, host->data, host->len);
	}

	if (!any_port) {
		p = ngx_sprintf(key->data + host->len, ":%ui", (ngx_uint_t)port);
		key->len = p - key->data;

		if (hash != NULL) {
			*hash = ngx_hash_key(key->data, key->len);
		}
	}

	return NGX_OK;
}

static ngx_int_t
acl_init_hash(ngx_conf_t *cf, ngx_hash_t *hash, ngx_hash_keys_arrays_t *keys,
			  char *name)
{
	ngx_hash_init_t  init;

	if (keys->keys.nelts == 0) {
		return NGX_OK;
	}

	ngx_memzero(&init, sizeof(ngx_hash_init_t));
	init.hash = hash;
	init.key = ngx_hash_key_lc;
	init.max_size = 10007;
	init.bucket_size = ngx_align(512, ngx_cacheline_size);
	init.name = name;
	init.pool = cf->pool;
	init.temp_pool = cf->temp_pool;

	return ngx_hash_init(&init, keys->keys.elts, keys->keys.nelts);
}

static ngx_int_t
acl_target_matches(ngx_http_request_t *r, ngx_http_tunnel_acl_hash_t *acl,
				   ngx_url_t *target, ngx_uint_t *hit)
{
	ngx_str_t   key;
	ngx_uint_t  hash;

	*hit = 0;

	if (acl->any_port_nelts) {
		if (acl_build_key(r->pool, &target->host, target->port, 1, &key,
						  &hash) != NGX_OK) {
			return NGX_ERROR;
		}

		if (ngx_hash_find(&acl->any_port, hash, key.data, key.len) != NULL) {
			*hit = 1;
			return NGX_OK;
		}
	}

	if (acl->exact_port_nelts) {
		if (acl_build_key(r->pool, &target->host, target->port, 0, &key,
						  &hash) != NGX_OK) {
			return NGX_ERROR;
		}

		if (ngx_hash_find(&acl->exact_port, hash, key.data, key.len) != NULL) {
			*hit = 1;
			return NGX_OK;
		}
	}

	return NGX_OK;
}
