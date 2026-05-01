#include "ngx_http_tunnel_module.h"

#define NGX_HTTP_TUNNEL_AUTH_BUF_SIZE  2048

static ngx_int_t tunnel_auth_crypt_handler(ngx_http_request_t *r,
										   ngx_http_tunnel_srv_conf_t *tscf,
										   ngx_str_t *passwd, ngx_str_t *user,
										   ngx_str_t *client_passwd);
static ngx_int_t tunnel_auth_parse_basic(ngx_http_request_t *r, ngx_str_t *user,
										 ngx_str_t *passwd);

ngx_int_t
tunnel_auth_access_denied(ngx_http_request_t *r,
						  ngx_http_tunnel_srv_conf_t *tscf)
{
	/* 407 */
	if (!tscf->probe_resistance ||
		tscf->auth_failure_code == NGX_HTTP_PROXY_AUTH_REQUIRED) {

		static ngx_str_t realm = ngx_string("Basic realm=\"proxy\"");

		r->headers_out.proxy_authenticate =
			ngx_list_push(&r->headers_out.headers);
		if (r->headers_out.proxy_authenticate == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		r->headers_out.proxy_authenticate->hash = 1;
		r->headers_out.proxy_authenticate->next = NULL;
		ngx_str_set(&r->headers_out.proxy_authenticate->key,
					"Proxy-Authenticate");
		r->headers_out.proxy_authenticate->value = realm;

		return NGX_HTTP_PROXY_AUTH_REQUIRED;
	}

	/* 405 */
	if (tscf->auth_failure_code == NGX_HTTP_NOT_ALLOWED) {
		ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
		if (h == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		h->hash = 1;
		h->next = NULL;
		ngx_str_set(&h->key, "Allow");
		ngx_str_set(&h->value, "GET, POST, HEAD, OPTIONS");

		return NGX_HTTP_NOT_ALLOWED;
	}

	/* For other deny code, you can set a custom error_page */
	return tscf->auth_failure_code;
}

ngx_int_t
tunnel_auth_check(ngx_http_request_t *r, ngx_http_tunnel_srv_conf_t *tscf)
{
	off_t offset;
	ssize_t n;
	ngx_fd_t fd;
	ngx_int_t rc;
	ngx_err_t err;
	ngx_str_t pwd, user, user_file, passwd;
	ngx_uint_t i, level, left, login, file_passwd;
	ngx_file_t file;
	u_char buf[NGX_HTTP_TUNNEL_AUTH_BUF_SIZE];
	enum { sw_login, sw_passwd, sw_skip } state;

	if (tscf->proxy_auth_user_file == NULL) {
		return NGX_OK;
	}

	rc = tunnel_auth_parse_basic(r, &user, &passwd);
	if (rc == NGX_DECLINED) {
		return tunnel_auth_access_denied(r, tscf);
	}

	if (rc == NGX_ERROR) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_http_complex_value(r, tscf->proxy_auth_user_file, &user_file) !=
		NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

	if (fd == NGX_INVALID_FILE) {
		err = ngx_errno;

		if (err == NGX_ENOENT) {
			level = NGX_LOG_ERR;
			rc = NGX_HTTP_FORBIDDEN;

		} else {
			level = NGX_LOG_CRIT;
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_log_error(level, r->connection->log, err,
					  ngx_open_file_n " \"%s\" failed", user_file.data);

		return rc;
	}

	ngx_memzero(&file, sizeof(ngx_file_t));

	file.fd = fd;
	file.name = user_file;
	file.log = r->connection->log;

	state = sw_login;
	file_passwd = 0;
	login = 0;
	left = 0;
	offset = 0;

	for (;;) {
		i = left;

		n = ngx_read_file(&file, buf + left,
						  NGX_HTTP_TUNNEL_AUTH_BUF_SIZE - left, offset);

		if (n == NGX_ERROR) {
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			goto cleanup;
		}

		if (n == 0) {
			break;
		}

		for (i = left; i < left + n; i++) {
			switch (state) {

			case sw_login:
				if (login == 0) {

					if (buf[i] == '#' || buf[i] == CR) {
						state = sw_skip;
						break;
					}

					if (buf[i] == LF) {
						break;
						}
					}

					if (buf[i] == ':') {
						if (login == user.len) {
							state = sw_passwd;
							file_passwd = i + 1;
						} else {
							state = sw_skip;
						}

						break;
					}

					if (login >= user.len) {
						state = sw_skip;
						break;
					}

					if (buf[i] != user.data[login]) {
						state = sw_skip;
						break;
					}

					login++;

					break;

			case sw_passwd:
				if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
					buf[i] = '\0';

					pwd.len = i - file_passwd;
					pwd.data = &buf[file_passwd];

					rc = tunnel_auth_crypt_handler(r, tscf, &pwd, &user,
												   &passwd);
					goto cleanup;
				}

				break;

			case sw_skip:
				if (buf[i] == LF) {
					state = sw_login;
					login = 0;
				}

				break;
			}
		}

		if (state == sw_passwd) {
			left = left + n - file_passwd;
			ngx_memmove(buf, &buf[file_passwd], left);
			file_passwd = 0;

		} else {
			left = 0;
		}

		offset += n;
	}

	if (state == sw_passwd) {
		pwd.len = i - file_passwd;
		pwd.data = ngx_pnalloc(r->pool, pwd.len + 1);
		if (pwd.data == NULL) {
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			goto cleanup;
		}

		ngx_cpystrn(pwd.data, &buf[file_passwd], pwd.len + 1);

		rc = tunnel_auth_crypt_handler(r, tscf, &pwd, &user, &passwd);
		goto cleanup;
	}

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				  "user \"%V\" was not found in \"%s\"", &user, user_file.data);

	rc = tunnel_auth_access_denied(r, tscf);

cleanup:

	if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
					  ngx_close_file_n " \"%s\" failed", user_file.data);
	}

	ngx_explicit_memzero(buf, NGX_HTTP_TUNNEL_AUTH_BUF_SIZE);

	return rc;
}

static ngx_int_t
tunnel_auth_crypt_handler(ngx_http_request_t *r,
						  ngx_http_tunnel_srv_conf_t *tscf, ngx_str_t *passwd,
						  ngx_str_t *user, ngx_str_t *client_passwd)
{
	ngx_int_t rc;
	u_char *encrypted;

	if (passwd->len == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					  "user \"%V\": empty password hash", user);
		return tunnel_auth_access_denied(r, tscf);
	}

	encrypted = NULL;
	rc = ngx_crypt(r->pool, client_passwd->data, passwd->data, &encrypted);

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				   "rc: %i user: \"%V\" salt: \"%s\"", rc, user, passwd->data);

	if (rc != NGX_OK || encrypted == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if (ngx_strcmp(encrypted, passwd->data) == 0) {
		return NGX_OK;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				   "encrypted: \"%s\"", encrypted);

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				  "user \"%V\": password mismatch", user);

	return tunnel_auth_access_denied(r, tscf);
}

static ngx_int_t
tunnel_auth_parse_basic(ngx_http_request_t *r, ngx_str_t *user,
						ngx_str_t *passwd)
{
	ngx_str_t encoded, decoded;
	ngx_table_elt_t *header;
	u_char *colon;

	header = r->headers_in.proxy_authorization;
	if (header == NULL) {
		return NGX_DECLINED;
	}

	encoded = header->value;

	if (encoded.len < sizeof("Basic ") - 1 ||
		ngx_strncasecmp(encoded.data, (u_char *)"Basic ",
						sizeof("Basic ") - 1) != 0) {
		return NGX_DECLINED;
	}

	encoded.len -= sizeof("Basic ") - 1;
	encoded.data += sizeof("Basic ") - 1;

	while (encoded.len != 0 && encoded.data[0] == ' ') {
		encoded.len--;
		encoded.data++;
	}

	if (encoded.len == 0) {
		return NGX_DECLINED;
	}

	decoded.len = ngx_base64_decoded_length(encoded.len);
	decoded.data = ngx_pnalloc(r->pool, decoded.len + 1);
	if (decoded.data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(&decoded, &encoded) != NGX_OK) {
		return NGX_DECLINED;
	}

	decoded.data[decoded.len] = '\0';

	colon = ngx_strlchr(decoded.data, decoded.data + decoded.len, ':');
	if (colon == NULL || colon == decoded.data ||
		colon == decoded.data + decoded.len) {
		return NGX_DECLINED;
	}

	user->data = decoded.data;
	user->len = colon - decoded.data;

	colon++;

	passwd->data = colon;
	passwd->len = decoded.data + decoded.len - colon;

	return NGX_OK;
}

char *
ngx_http_tunnel_proxy_auth_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
									 void *conf)
{
	ngx_http_tunnel_srv_conf_t *tscf = conf;
	ngx_str_t *value;
	ngx_http_compile_complex_value_t ccv;

	if (tscf->proxy_auth_user_file != NGX_CONF_UNSET_PTR) {
		return "is duplicate";
	}

	tscf->proxy_auth_user_file =
		ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
	if (tscf->proxy_auth_user_file == NULL) {
		return NGX_CONF_ERROR;
	}

	value = cf->args->elts;

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = tscf->proxy_auth_user_file;
	ccv.zero = 1;
	ccv.conf_prefix = 1;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

char *
ngx_http_tunnel_auth_failure_code(ngx_conf_t *cf, ngx_command_t *cmd,
								  void *conf)
{
	ngx_http_tunnel_srv_conf_t *tscf = conf;
	ngx_int_t code;
	ngx_str_t *value;

	if (tscf->auth_failure_code != NGX_CONF_UNSET_UINT) {
		return "is duplicate";
	}

	value = cf->args->elts;
	code = ngx_atoi(value[1].data, value[1].len);
	if (code == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "Error code must be a number \"%V\"", &value[1]);
		return NGX_CONF_ERROR;
	}

	switch (code) {
	case NGX_HTTP_BAD_REQUEST:
	case NGX_HTTP_FORBIDDEN:
	case NGX_HTTP_NOT_FOUND:
	case NGX_HTTP_NOT_ALLOWED:
	case NGX_HTTP_PROXY_AUTH_REQUIRED:
		break;

	default:
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "invalid tunnel_auth_failure_code \"%V\", "
						   "it must be one of 400, 403, 404, 405, 407",
						   &value[1]);
		return NGX_CONF_ERROR;
	}

	tscf->auth_failure_code = code;

	return NGX_CONF_OK;
}
