# Nginx HTTP Tunnel Module

> [!NOTE]
> You might find tunnel performance is limited, typically
> in throughput. This is likely due to bad configurations.
> A good configuration can improve performance greatly,
> such as client max body size and kernel buffers for udp.


**This provides a subset features of HTTP CONNECT
over HTTP/1.1, HTTP2, and HTTP/3.**

## Table of contents

- [Tested nginx versions](#tested-nginx-versions)
- [Why implement this?](#implementation-tricks)
- [How to build?](#how-to-build)
- [Example conf file](#example-configuration-file)
- [Module Logic Illustration](#module-logic-illustration)

## Intro

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
- [x] Connect-udp with capsule protocol, without QUIC DATAGRAM

Module build relies on some nginx patches.
See patches, apply them to nginx source code,

The patches do following:

1. Let nginx upstream module only open TCP/UDP connection
without any input, using `ignore_input` flag.

2. Let h2/h3 pseudo header parsing pass nginx core.

Read scripts/ to find out more information about
map based acl.

Features that are in WIP:
```

## Tested Nginx Versions

- Nginx 1.29.* should all be fine, 1.29.8 is tested.

- Nginx 1.30.0 is tested to work.

## How to build

First fetch source code

```bash
mkdir -p build
cd build

git clone https://github.com/nginx/nginx.git
git switch --detach {version} # Checkout on specific version

git clone https://github.com/ZihaoFU245/ngx_http_tunnel_module.git
git switch --detach {version} # Checkout on specific version

cd nginx
```

Apply patches in `patches/` folder, for nginx versions below
1.30.* and including 1.30.*. Apply `header_parsing.patch` and `upstream.patch`
For 1.31.* and above inclusion, apply `upstream-1.31.patch` instead.

On nginx 1.31.0 and newer, nginx core handles proxy authentication for
CONNECT requests. This module therefore does not build its `auth.c` auth path
on those versions.

```bash
git apply ../ngx_http_tunnel_module/patches/header_parsing.patch

git apply ../ngx_http_tunnel_module/patches/upstream.patch
# OR
git apply ../ngx_http_tunnel_module/patches/upstream-1.31.patch
# BASED ON YOUR NGINX VERSION
```

Check nginx build dependency before continue, standard build dependency.
Below has an example build configuration.

```bash
./auto/configure \
	--prefix=/usr/local/share/nginx \
	--sbin-path=/usr/local/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--pid-path=/run/nginx.pid \
	--lock-path=/var/lock/nginx.lock \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \
	--http-client-body-temp-path=/var/lib/nginx/body \
	--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
	--http-proxy-temp-path=/var/lib/nginx/proxy \
	--http-scgi-temp-path=/var/lib/nginx/scgi \
	--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
	--with-compat \
	--with-threads \
	--with-file-aio \
	--with-pcre-jit \
	--with-http_ssl_module \
	--with-http_v2_module \
	--with-http_v3_module \
	--with-http_realip_module \
	--with-http_auth_request_module \
	--with-http_mp4_module \
	--with-http_gunzip_module \
	--with-http_gzip_static_module \
	--with-cc-opt='-g -O2 -fPIC -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=3' \
	--with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' \	
	--add-dynamic-module=../ngx_http_tunnel_module \
	--without-http_tunnel_module
	# Must build without http tunnel module if you use the custom module
	# Specifically for nginx 1.31.* versions
```

Finally, run `make -j$(nproc)`.

## Implementation tricks

1. It is chosen to build as a nginx module as it can reuse nginx
core functionalities, including but not limited to, mature h2/h3
implementation, multiplexing, limit conn, upstream module.

2. This module relies on nginx upstream and http_v2, see header file.

## Example Configuration file

> [!IMPORTANT]
> Check `examples/` for minimum configuration files.
> Proxy Auth is different on nginx version >= 1.31.0, as
> nginx core supports proxy auth and there is no need to
> implement it again.

Below is a detailed config flags illustration.

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

	# Use Proxy Auth but on CONNECT only
	map $request_method $connect_auth_realm {
        default  off;
        CONNECT  "proxy";
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
		tunnel_buffer_size 128k;              	# Buffer size for tunnel relay 

		# NGINX 1.30 AND OLDER ONLY
		tunnel_proxy_auth_user_file /path/to/.htaccess;
		tunnel_probe_resistance off;
		tunnel_probe_resistance_allow_methods "";

		# NGINX 1.31.0 AND NEWER
		# auth_basic $connect_auth_realm;
		# auth_basic_user_file /path/to/.htaccess;
		# error_page 407 =405 @probe_resistance;

		# location @probe_resistance {
		#	 internal;
		#	 # add_header Allow "GET, POST, OPTIONS" always;
		# 	 return 405;
		# }

        tunnel_padding off;                 	# Opt in padding scheme for h2/h3
        tunnel_connect_timeout 60s;
		tunnel_idle_timeout 30s;

		# 0: deny, 1: allow, 2: deny + log, 3: allow + log.
		# $connect_target_host is the raw CONNECT authority.
		tunnel_acl_eval_on $is_granted;

		tunnel_udp on; 							# Enable connect udp with capsule protocol
		tunnel_udp_path $request_uri; 			# Path variable for parsing masque path

		# location blocks are recommended to set after
		# tunnel configurations, as tunnel module
		# injects a pre-content phase handler to skip
		# try_files and proxy_pass directive.
		# do not use return here, as it is in rewrite phase,
		# it will skip tunnel handler. This is a design decision.
		location / {
			# A file server example
		    root /var/www/html;
			index index.html;

			# To avoid The Discriminative Power of Cross-layer 
			# RTTs in Fingerprinting Proxy Traffic
			# It is recommended to either proxy_pass to a server
			# running on the same nginx instance or
			# run a file server here directly.
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
