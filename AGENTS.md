# Tasks

Read Spec and README

Read all the code and logic is a MUST. You must read all relevant code before any edits.

Nginx is experiencing request count is zero when sending to client issue,
the issue exists in stream data path, http2 suffers. And http3 is more severe.

You first need to investigate the issue, create a plan. Then apply your fixes.
If you think it is not a module issue, a config issue instead. Point it out.

error log:

```log
2026/04/22 08:15:30 [alert] 520190#520190: *1 http request count is zero while sending to client, client: 127.0.0.1, server: mirror.zihaofu245.me, request: "C
ONNECT uk3.testmy.net HTTP/2.0", upstream: "192.248.162.27:443", host: "uk3.testmy.net:443"
2026/04/22 08:15:43 [alert] 520190#520190: *1 http request count is zero while sending to client, client: 127.0.0.1, server: mirror.zihaofu245.me, request: "C
ONNECT uk3.testmy.net HTTP/2.0", upstream: "192.248.162.27:443", host: "uk3.testmy.net:443"
2026/04/22 08:16:42 [alert] 520190#520190: *19 http request count is zero while sending to client, client: 127.0.0.1, server: mirror.zihaofu245.me, request: "
CONNECT api.duckduckgo.com:443 HTTP/3.0", upstream: "52.142.124.215:443"
2026/04/22 08:16:44 [alert] 520190#520190: *39 http request count is zero while sending to client, client: 127.0.0.1, server: mirror.zihaofu245.me, request: "
CONNECT testmy.net:443 HTTP/3.0", upstream: "104.26.4.115:443"
2026/04/22 08:17:12 [alert] 520190#520190: *43 http request count is zero while sending to client, client: 127.0.0.1, server: mirror.zihaofu245.me, request: "
CONNECT uk3.testmy.net:443 HTTP/3.0", upstream: "192.248.162.27:443"
2026/04/22 08:17:16 [alert] 520190#520190: *45 http request count is zero while sending to client, client: 127.0.0.1, server: mirror.zihaofu245.me, request: "
CONNECT uk3.testmy.net:443 HTTP/3.0", upstream: "192.248.162.27:443"
```

With nginx config file:

```nginx
worker_processes auto;
worker_cpu_affinity auto;
error_log /home/zihao/.config/nginx/error.log;

events {
	worker_connections 1024;
}

http {
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	types_hash_max_size 2048;
	server_tokens off;
	access_log /home/zihao/.config/nginx/access.log;

	include mime.types;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers off;

	limit_conn_zone $binary_remote_addr zone=addr:100m;

	server {
		listen 0.0.0.0:18080 ssl;
		listen 0.0.0.0:18080 quic reuseport;
		server_name mirror.zihaofu245.me;

		http2 on;
		http3 on;
		http3_max_concurrent_streams 256;
		http3_stream_buffer_size 4M;
		quic_gso on;

		limit_conn addr 50;
		limit_conn_status 429;
		proxy_request_buffering off;
		# proxy_http_version 1.1;
		client_body_buffer_size 1M;
		client_max_body_size 0;

		client_body_timeout 300s;
		proxy_read_timeout 300s;
		proxy_connect_timeout 300s;

		resolver 1.1.1.1 8.8.8.8;

		ssl_certificate  /etc/letsencrypt/live/mirror.zihaofu245.me/fullchain.pem;
		ssl_certificate_key /etc/letsencrypt/live/mirror.zihaofu245.me/privkey.pem;

		add_header Alt-Svc 'h3=":18080"; ma=86400';

		tunnel_pass;
		tunnel_buffer_size 16M;
		# tunnel_auth_username zihaofu245;
		# tunnel_auth_password 1qwertyuiop0;
		tunnel_probe_resistance on;

		tunnel_idle_timeout 90s;
		tunnel_connect_timeout 60s;
		tunnel_padding on;

		location / {
			proxy_pass https://zihaofu245.me$request_uri;
			proxy_set_header Host zihaofu245.me;
			proxy_set_header X-Forwarded-Proto $scheme;
			proxy_set_header X-Real-IP $remote_addr;
			proxy_ssl_server_name on;
			proxy_ssl_name zihaofu245.me;
		}
    }
}
```