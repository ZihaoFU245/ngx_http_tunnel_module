#include "ngx_http_tunnel_module.h"

static ngx_int_t acl_parse_state(ngx_http_request_t *r,
								 ngx_http_variable_value_t *value,
								 ngx_uint_t *state);

ngx_int_t
tunnel_acl_eval(ngx_http_request_t *r)
{
	ngx_uint_t                   state;
	ngx_http_variable_value_t   *value;
	ngx_http_tunnel_srv_conf_t  *tscf;

	tscf = ngx_http_get_module_srv_conf(r, ngx_http_tunnel_module);

	if (tscf->acl_eval_index == NGX_CONF_UNSET_UINT) {
		return NGX_OK;
	}

	value = ngx_http_get_indexed_variable(r, tscf->acl_eval_index);
	if (value == NULL || value->not_found) {
		return NGX_ERROR;
	}

	if (acl_parse_state(r, value, &state) != NGX_OK) {
		return NGX_ERROR;
	}

	switch (state) {

	case 0:
		return NGX_HTTP_FORBIDDEN;

	case 1:
		return NGX_OK;

	case 2:
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "tunnel ACL denied target");
		return NGX_HTTP_FORBIDDEN;

	case 3:
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					  "tunnel ACL granted target");
		return NGX_OK;

	default:
		return NGX_ERROR;
	}
}

char *
tunnel_acl_eval_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_tunnel_srv_conf_t  *tscf = conf;
	ngx_str_t                   *value, name;
	ngx_int_t                    index;

	if (tscf->acl_eval_index != NGX_CONF_UNSET_UINT) {
		return "is duplicate";
	}

	value = cf->args->elts;
	name = value[1];

	if (name.len < 2 || name.data[0] != '$') {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "invalid variable name \"%V\"", &name);
		return NGX_CONF_ERROR;
	}

	name.len--;
	name.data++;

	index = ngx_http_get_variable_index(cf, &name);
	if (index == NGX_ERROR) {
		return NGX_CONF_ERROR;
	}

	tscf->acl_eval_index = index;

	return NGX_CONF_OK;
}

static ngx_int_t
acl_parse_state(ngx_http_request_t *r, ngx_http_variable_value_t *value,
				ngx_uint_t *state)
{
	ngx_int_t  n;
	ngx_str_t  state_value;

	n = ngx_atoi(value->data, value->len);
	if (n < 0 || n > 3) {
		state_value.len = value->len;
		state_value.data = value->data;

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					  "invalid tunnel ACL state \"%V\"", &state_value);
		return NGX_ERROR;
	}

	*state = (ngx_uint_t)n;

	return NGX_OK;
}
