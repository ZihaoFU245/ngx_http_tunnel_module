# Nginx HTTP Tunnel Module

```txt
This provides a subset features of HTTP CONNECT
over HTTP/1.1, HTTP2. And HTTP3, but untested yet.

"untested" means throughput test have not been thoroughly
done. HTTP/1.1 and HTTP2 can achieve excellent throughput.
H3 uses nginx stream, same data/logic path as H2 in this module,
but working perfectly on H2 does not imply working perfectly
on H3.

- [x] HTTP/1.1 CONNECT 
- [x] HTTP/2 CONNECT
- [x] Non CONNECT method can co-exist with other HTTP methods
- [x] Basic username, password authentication

With an optimized build, nginx server during throughput
test can maintain about ~10M memory usage. Under 50Mbps upload
and 100Mbps download speed test. It utilizes nginx existing
network stack, integrate perfectly into nginx. Attach to
Access Phase and Content Phase, making it obey to Access Phase
checking, will work with limit_conn, and other security modules.
```

## Example Configuration file

```nginx
load_module ngx_http_tunnel_module.so;  # If it is build as an dynamic module

user www-data;
worker_processes auto;
worker_cpu_affinity auto;

events {
	worker_connections 1024;
}

http {
	sendfile on;    # If you are using file server
	tcp_nopush on;
	tcp_nodelay on; # Reduce latency
	types_hash_max_size 2048;
	server_tokens off;

	include mime.types;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers off;

	limit_conn_zone $binary_remote_addr zone=addr:50m;  # 50MB shared memory

	server {
		listen 0.0.0.0:443 ssl;
		listen 0.0.0.0:443 quic reuseport;
		server_name example.com;
		http2 on;

		limit_conn addr 50;
		limit_conn_status 429;

		client_body_buffer_size 16M;    # Prevent high Disk I/O
		client_max_body_size 64M;       # Prevent 413 Request Entity Too Large under high throughput

		resolver 1.1.1.1 8.8.8.8;

		ssl_certificate  fullchain.pem;
		ssl_certificate_key privkey.pem;

		tunnel_pass;                        # Enable tunnel module
		tunnel_buffer_size 32M;             # Buffer size for tunnel relay 
		tunnel_auth_username username;
		tunnel_auth_password password;
		tunnel_probe_resistance off;        # Used when auth is used, stop sending 407

		location / {
		    proxy_pass https://example.com$request_uri;
		    proxy_set_header Host example.com;
		    proxy_set_header X-Forwarded-Proto $scheme;
		    proxy_set_header X-Real-IP $remote_addr;
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
        -> Assign tunnel clean up handler
            -> Invoke tunnel close, finalize ongoing resolver
                -> Clear all timer
                -> Release Peer
        # Connect Stage
        -> init upstream peer (allocate Resolver and upstream init)
        -> Connect target parsing (Logic branch for h1.1 and h2/h3)
            A1: target given in direct ip address
                -> Direct invoke create Round Robin Peer
            A2: Given Hostname, async DNS resolve
                -> Resolve handler invoke create Round Robin Peer
        -> Invoke tunnel_connect_next
            -> Assign read/write handler
                -> Test connection, then start tunnel
                    -> Jump to "Tunnel Start"

Tunnel Start
    -> Clear Timer
    -> Check or enable tcp nodelay for HTTP/1.1
    -> Send 200 Connected
    -> If h2 or h3, init request body
        -> Invoke nginx read client request body
        -> Attach request body post handler
    -> Attach 4 read/write upstream/downstream handlers
    -> Kick off Tunnel Process
        A1: Raw, HTTP/1.1
            -> Jump V1_raw
        A2: Stream, H2/H3
            -> Jump Stream

V1_raw
    -> Invoke `ngx_http_tunnel_process_raw`

Stream
    -> Invoke `ngx_http_tunnel_process_stream`
```