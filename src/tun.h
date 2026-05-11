
/*
 * Copyright(c) 2026 ZihaoFU245
 */

#ifndef _TUNNEL_TUN_H_INCLUDED_
#define _TUNNEL_TUN_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_fd_t                            fd;
    ngx_str_t                           path;
} tunnel_tun_t;

ngx_int_t tunnel_tun_open(ngx_http_request_t *r, ngx_str_t *path,
                          tunnel_tun_t *tun);
void      tunnel_tun_close(ngx_log_t *log, tunnel_tun_t *tun);
ssize_t   tunnel_tun_read(tunnel_tun_t *tun, ngx_buf_t *dst, ngx_log_t *log);
ngx_int_t tunnel_tun_write_chain(ngx_http_request_t *r, ngx_chain_t **src,
                                 ngx_buf_t *dst);
ssize_t   tunnel_tun_send(tunnel_tun_t *tun, ngx_buf_t *src, ngx_log_t *log);

#endif
