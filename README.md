# Nginx HTTP Tunnel Module

> [!NOTE]
> You might find tunnel performace is limited, typically
> in throughput. This is likely due to bad configurations.
> A good configuration can improve performance greatly,
> such as client max body size and kernel buffers for udp.


**This provides a subset features of HTTP CONNECT
over HTTP/1.1, HTTP2, and HTTP/3.**

```txt
Naive Proxy used padding scheme is implemented in here,
works on h2 and h3 only. HTTP/1.1 is not targeted.

- [x] HTTP/1.1 CONNECT 
- [x] HTTP/2 CONNECT
- [x] HTTP/3, QUIC CONNECT
- [x] Non CONNECT method can co-exist with other HTTP methods
- [x] Proxy authentication
- [x] Map based ACL
- [x] Naive Style Padding Scheme

Current module build relies on some nginx patches.
See patches, apply them to nginx source code,
try `patch -p1 < /path/to/ngx_http_tunnel_module/patches/*`
in nginx source code folder,
then build nginx with flag:
`--add-module=/path/to/ngx_http_tunnel_module`
or 
`--add-dynamic-module=/path/to/ngx_http_tunnel_module`

The patches are from nginx repo PRs.

1. An ongoing [nginx PR](https://github.com/nginx/nginx/pull/707)
provide upstream module changes.

2. CONNECT needs to be allowed to pass through in Nginx
code for v2 and v3

Features that are in WIP:

- [ ] Extended Connect, including `connect-udp`
```

## Tested Nginx Versions

- Nginx 1.29.* should all be fine, 1.29.8 is tested.

- Nginx 1.30.0 is tested to work.

## Implementation tricks

1. It is chosen to build as a nginx module as it can reuse nginx
core functionalities, including but not limited to, mature h2/h3
implementation, multiplexing, limit conn, upstream module.

2. This module relies on nginx upstream and http_v2, see header file.

3. Because the need of padding and capsule protocol (not yet implemented),
an intermediate buffer is required. That is, we can't simply wire upstream
module and request, the bidirectional byte relay must be explicitly handled.

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

	limit_conn_zone $binary_remote_addr zone=addr:1m;

	# ---------------------------------------------
	# A map is used in ACL for O(1) lookup,
	# $connect_target_host variable provides raw
	# authority header, it is your job to regex
	# match these authority headers. Test the ACL
	# before production, some clients put authority
	# as raw ip, raw host, or even host:port.
	# This can be tricky, be careful!
	#
	# Allowed mapping values:
	# 0/1: deny/allow
	# 2/3: deny/allow + logging
	# 
	# Example:
	# Blocking a single hostname:
	# ~^example\.com(:[0-9]+)?$ 
	# --------------------------------------------
	map $connect_target_host $is_granted {
		default 1;								# default allow

		~(^|:)fr\.a2dfp\.net(:|$)       0;		# deny
		~(^|:)static\.a-ads\.com(:|$)   2;		# deny + log
	}

	server {
		listen 0.0.0.0:443 ssl;
		listen 0.0.0.0:443 quic reuseport;

		server_name example.com;

		http2 on;
        http3 on;
        http3_max_concurrent_streams 128;
        http3_stream_buffer_size 128k;
        quic_gso on;

		add_header Alt-Svc 'h3=":443"; ma=86400';

		limit_conn addr 100;
		limit_conn_status 429;

		client_body_buffer_size 256k;
		client_max_body_size 16M;

		resolver 1.1.1.1 8.8.8.8;

		ssl_certificate  fullchain.pem;
		ssl_certificate_key privkey.pem;

		tunnel_pass;                        	# Enable tunnel module
		tunnel_buffer_size 2M;              	# Buffer size for tunnel relay 
		tunnel_proxy_auth_user_file /path/to/.htaccess;

		# 400, 403, 404, 405, or 407
		# You can set custom error_page
		# default to 405
		tunnel_auth_failure_code 405;

		# off: auth failures always return 407
		# and ignores custom failure code
		tunnel_probe_resistance off;
        tunnel_padding off;                 	# Opt in padding scheme for h2/h3
        tunnel_connect_timeout 60s;
		tunnel_idle_timeout 30s;

		# 0: deny, 1: allow, 2: deny + log, 3: allow + log.
		# $connect_target_host is the raw CONNECT authority.
		tunnel_acl_eval_on $is_granted;

		# location blocks are recommended to set after
		# tunnel configurations, as tunnel module
		# injects a precontent phase handler to skip
		# try_files and proxy_pass directive.
		# do not use return here, as it is in rewrite phase,
		# it will skip tunnel handler. This is a design decision
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
            -> Check tunnel_auth_failure_code / tunnel_probe_resistance
        -> Assign Content phase handler (Prevent other module preempt requests)
    -> Content Phase Handler
        -> Context and Buffer allocation
        -> Check padding needed
        -> init upstream peer
        -> Assign upstream handlers
        -> init upstream
```
