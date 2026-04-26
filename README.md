# Nginx HTTP Tunnel Module

> [!IMPORTANT]
> HTTP/2 performs better then HTTP/3 in throughput,
> using http2 is more recommended. This could because
> of a configuration, or nginx core issue. Not likely
> to be an module issue.

```txt
This provides a subset features of HTTP CONNECT
over HTTP/1.1, HTTP2, and HTTP/3.

Naive Proxy used padding scheme is implemented in here,
works on h2 and h3 only. HTTP/1.1 is not targeted.

- [x] HTTP/1.1 CONNECT 
- [x] HTTP/2 CONNECT
- [x] HTTP/3, QUIC CONNECT
- [x] Non CONNECT method can co-exist with other HTTP methods
- [x] Basic username, password authentication
- [x] Naive Style Padding Scheme

Current module build relies on a nginx patch.
See patches, apply them to nginx source code,
then build nginx with flag:
`--add-module=/path/to/ngx_http_tunnel_module`
or 
`--add-dynamic-module=/path/to/ngx_http_tunnel_module`

1. An ongoing nginx PR (https://github.com/nginx/nginx/pull/707)
Upstream module changes is needed to apply for module HTTP/1.1
to work.
2. CONNECT needs to be allowed to pass through in Nginx
code for v2 and v3

- [ ] Extended Connect
- [x] Access Control

Basic Access control is done by using nginx upstream {...}
directive. File based Access Control is still considering.
```

## Example Configuration file

```nginx
load_module ngx_http_tunnel_module.so;  # If build as an dynamic module

user www-data;
worker_processes auto;
worker_cpu_affinity auto;

events {
	worker_connections 1024;
}

http {
	tcp_nopush on;
	tcp_nodelay on;
	server_tokens off;

    # If you are using with a file server
    sendfile on;
	include mime.types;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers off;

	limit_conn_zone $binary_remote_addr zone=addr:50m;  # 50MB shared memory

	upstream acl_list {
		server cnn.com;
		server youtube.com;
	}

	server {
		listen 0.0.0.0:443 ssl;
		listen 0.0.0.0:443 quic reuseport;

		server_name example.com;

		http2 on;
        http3 on;
        http3_max_concurrent_streams 128;
        http3_stream_buffer_size 1M;
        quic_gso on;

		limit_conn addr 50;
		limit_conn_status 429;

		client_body_buffer_size 1M;
		client_max_body_size 64M;

		resolver 1.1.1.1 8.8.8.8;

		ssl_certificate  fullchain.pem;
		ssl_certificate_key privkey.pem;

		tunnel_pass;                        # Enable tunnel module
		tunnel_buffer_size 16M;             # Buffer size for tunnel relay 
		tunnel_auth_username username;
		tunnel_auth_password password;
		tunnel_probe_resistance off;        # Used when auth is used, stop sending 407
        tunnel_padding off;                 # Opt in padding scheme for h2
        tunnel_connect_timeout 60s;
		tunnel_idle_timeout 30s;

		# -------------------------------
		# Only one of the tunnel acl 
		# directive can be set. If acl
		# allow is configured, it is a
		# white list. A black vice versa.
		# -------------------------------

		# tunnel_acl_allow acl_list;
		tunnel_acl_deny acl_list;			

		location / {
		    proxy_pass https://example.com$request_uri;
		    proxy_set_header Host example.com;
		    proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		    proxy_set_header X-Real-IP $remote_addr;
            proxy_ssl_server_name on;
            proxy_ssl_name example.com;
            proxy_redirect default;
		}
    }
}
```

## Module logic illustration

```txt
Tunnel Init Invoked
    -> Access Phase Handler
        -> Auth checking
            -> Check tunnel_probe_resistance
        -> Assign Content phase handler (Prevent other module preempt requests)
    -> Content Phase Handler
        -> Context and Buffer allocation
        -> Check padding needed
        -> init upstream peer
        -> Assign upstream handlers
        -> init upstream
```
