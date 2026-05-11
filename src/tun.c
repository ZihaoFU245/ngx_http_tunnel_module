/*
 * Copyright(c) 2026 ZihaoFU245
 */

#include "ngx_http_tunnel_module.h"

ngx_int_t
tunnel_tun_open(ngx_http_request_t *r, ngx_str_t *path, tunnel_tun_t *tun)
{
    u_char  *name;
    ngx_fd_t fd;

    if (r == NULL || path == NULL || path->len == 0 || tun == NULL) {
        return NGX_ERROR;
    }

    name = ngx_pnalloc(r->pool, path->len + 1);
    if (name == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(name, path->data, path->len);
    name[path->len] = '\0';

    fd = ngx_open_file(name, NGX_FILE_RDWR | NGX_FILE_NONBLOCK, NGX_FILE_OPEN,
                       0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      ngx_nonblocking_n " \"%s\" failed", name);
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }
        return NGX_ERROR;
    }

    tun->fd = fd;
    tun->path.data = name;
    tun->path.len = path->len;

    return NGX_OK;
}

void
tunnel_tun_close(ngx_log_t *log, tunnel_tun_t *tun)
{
    if (tun == NULL || tun->fd == NGX_INVALID_FILE) {
        return;
    }

    if (ngx_close_file(tun->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &tun->path);
    }

    tun->fd = NGX_INVALID_FILE;
}

ssize_t
tunnel_tun_read(tunnel_tun_t *tun, ngx_buf_t *dst, ngx_log_t *log)
{
    size_t    size;
    ssize_t   n;
    ngx_err_t err;

    if (tun == NULL || tun->fd == NGX_INVALID_FILE || dst == NULL) {
        return NGX_ERROR;
    }

    size = dst->end - dst->last;
    if (size == 0) {
        return NGX_AGAIN;
    }

    n = ngx_read_fd(tun->fd, dst->last, size);
    if (n > 0) {
        dst->last += n;
        return n;
    }

    if (n == 0) {
        return 0;
    }

    err = ngx_errno;
    if (err == NGX_EAGAIN || err == NGX_EINTR) {
        return NGX_AGAIN;
    }

    ngx_log_error(NGX_LOG_ERR, log, err, ngx_read_fd_n " \"%V\" failed",
                  &tun->path);

    return NGX_ERROR;
}

ngx_int_t
tunnel_tun_write_chain(ngx_http_request_t *r, ngx_chain_t **src,
                       ngx_buf_t *dst)
{
    ngx_uint_t copied;

    if (r == NULL || src == NULL || dst == NULL) {
        return NGX_ERROR;
    }

    copied = tunnel_utils_copy_chain_to_buffer(r, src, dst,
                                               (size_t)(dst->end - dst->last));

    return copied ? NGX_OK : NGX_AGAIN;
}

ssize_t
tunnel_tun_send(tunnel_tun_t *tun, ngx_buf_t *src, ngx_log_t *log)
{
    size_t    size;
    ssize_t   n;
    ngx_err_t err;

    if (tun == NULL || tun->fd == NGX_INVALID_FILE || src == NULL) {
        return NGX_ERROR;
    }

    size = ngx_buf_size(src);
    if (size == 0) {
        return NGX_AGAIN;
    }

    n = ngx_write_fd(tun->fd, src->pos, size);
    if (n > 0) {
        src->pos += n;
        return n;
    }

    if (n == 0) {
        return NGX_AGAIN;
    }

    err = ngx_errno;
    if (err == NGX_EAGAIN || err == NGX_EINTR) {
        return NGX_AGAIN;
    }

    ngx_log_error(NGX_LOG_ERR, log, err, ngx_write_fd_n " \"%V\" failed",
                  &tun->path);

    return NGX_ERROR;
}
