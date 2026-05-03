# UDP support plan for ngx_http_tunnel_module

## Direction

Implement UDP as **MASQUE CONNECT-UDP using the HTTP Capsule Protocol over DATA frames**. Do not add QUIC DATAGRAM or HTTP/3 DATAGRAM support to nginx core.

This means the tunnel module will carry UDP payloads inside CONNECT request/response stream data:

```text
client <-> HTTP/2 or HTTP/3 CONNECT stream DATA <-> nginx module <-> UDP socket <-> target
```

The only nginx core work should be the minimum needed for extended CONNECT routing:

- preserve and validate `:protocol`;
- continue allowing extended CONNECT through HTTP/2 and HTTP/3 request parsing.

No nginx core QUIC DATAGRAM frame parser, SETTINGS changes, quarter-stream-id demux, or request-level datagram API should be added.

## Current reusable pieces

The existing module and local nginx patches already provide most of the TCP-side structure we need:

- `ngx_http_tunnel_access_handler()` handles auth and installs the tunnel content handler for CONNECT.
- `ngx_http_tunnel_content_handler()` creates module context, creates HTTP upstream, parses target, and starts nginx upstream.
- `tunnel_connect_process_header()` runs after upstream connect succeeds. This is still the right place to run ACL and then switch into relay mode.
- `ngx_http_upstream_conf_t.ignore_input` from nginx commit `555040665` lets the module use nginx upstream for peer setup without reading an upstream protocol response.
- nginx commit `70b0097f0` allows CONNECT stream request bodies for HTTP/2 and HTTP/3 without requiring `Content-Length`.
- nginx commit `a714c9ef4` allows extended CONNECT with `:scheme` and `:path`, but it does not yet preserve `:protocol`.

Reusable nginx core paths:

- `ngx_event_connect_peer()` already supports outbound UDP sockets when `ngx_peer_connection_t.type = SOCK_DGRAM`.
- HTTP upstream resolver and peer lifecycle can still be reused through `ngx_http_upstream_create()`, `ngx_http_upstream_resolved_t`, and `ngx_http_upstream_init()`.
- HTTP/2 and HTTP/3 DATA stream reading can be reused through `ngx_http_read_client_request_body()` and `ngx_http_read_unbuffered_request_body()`.
- HTTP/2 and HTTP/3 DATA stream writing can be reused through `ngx_http_output_filter()`.

## Required core change

Add normalized storage for `:protocol` on `ngx_http_request_t`, for example:

```c
ngx_str_t connect_protocol;
```

Then update pseudo-header parsing:

- `nginx/src/http/v2/ngx_http_v2.c`, around `ngx_http_v2_pseudo_header()`;
- `nginx/src/http/v3/ngx_http_v3_request.c`, around HTTP/3 pseudo-header parsing.

Validation rules:

- `:protocol` is allowed only on `CONNECT`;
- duplicate `:protocol` is `400`;
- empty `:protocol` is `400`;
- unknown pseudo-headers remain rejected;
- classic CONNECT remains the form with no `:scheme`, no `:path`, and no `:protocol`;
- extended CONNECT requires `:scheme`, `:path`, and `:protocol`.

This core change is the best place to attach CONNECT-UDP recognition because pseudo-headers are validated before modules see the request. The module should not parse protocol-specific raw HTTP/2 or HTTP/3 frames.

## Best module attach point

Keep the module attach point in `ngx_http_tunnel_content_handler()`.

Flow:

```text
ngx_http_tunnel_access_handler()
  shared CONNECT auth
  set r->content_handler = ngx_http_tunnel_content_handler

ngx_http_tunnel_content_handler()
  classify request:
    classic CONNECT              -> current TCP path
    :protocol = connect-udp      -> new MASQUE UDP path
    other extended CONNECT       -> reject or decline
```

Reasons:

- access phase remains shared auth and enablement only;
- content phase has normalized method, URI, pseudo-header state, selected server config, and request body support;
- TCP and UDP can diverge before allocating TCP-only buffers;
- upstream connection setup and ACL evaluation can stay structurally identical;
- the relay implementation can be isolated behind `tunnel_udp_process_header()`.

## MASQUE request model

Support this initial CONNECT-UDP form:

```text
:method = CONNECT
:scheme = https
:authority = proxy.example
:path = /.well-known/masque/udp/{target_host}/{target_port}/
:protocol = connect-udp
capsule-protocol = ?1
```

Initial scope:

- accept HTTP/2 and HTTP/3 downstreams;
- reject HTTP/1.1 because it has no extended CONNECT pseudo-headers;
- require `:protocol = connect-udp`;
- require capsule mode and use stream DATA only;
- support one fixed URI template first;
- parse `{target_host}` and `{target_port}` from `r->uri`;
- do not treat `:authority` as the UDP target, because it identifies the proxy authority in extended CONNECT.

Configuration can start conservative:

```nginx
tunnel_udp on;
tunnel_udp_path /.well-known/masque/udp/;
```

`tunnel_udp_path` can be optional in the first patch if we hard-code the well-known prefix, but having the directive makes tests and future routing cleaner.

## Implementation phases

### Phase 1: core `:protocol` passthrough

Implement only pseudo-header storage and validation.

Files:

- `nginx/src/http/ngx_http_request.h`
- `nginx/src/http/v2/ngx_http_v2.c`
- `nginx/src/http/v3/ngx_http_v3_request.c`

Details:

- add `r->connect_protocol`;
- parse `:protocol` into that field;
- reject `:protocol` before `:method` if the parser cannot know the method yet only after final pseudo-header validation, not immediately;
- in final pseudo-header validation, enforce that `:protocol` is present only for CONNECT;
- preserve current classic CONNECT behavior.

Tests:

- classic HTTP/2 CONNECT still passes;
- classic HTTP/3 CONNECT still passes;
- HTTP/2 CONNECT with `:protocol = connect-udp` passes parsing;
- HTTP/3 CONNECT with `:protocol = connect-udp` passes parsing;
- `GET` with `:protocol` is rejected;
- duplicate or empty `:protocol` is rejected.

### Phase 2: module classification and config

Add UDP-specific config fields:

```c
ngx_flag_t udp;
ngx_str_t  udp_path;
```

Add helpers:

```c
ngx_int_t tunnel_udp_is_request(ngx_http_request_t *r);
ngx_int_t tunnel_udp_parse_target(ngx_http_request_t *r,
    ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_udp_init_upstream(ngx_http_request_t *r,
    ngx_http_tunnel_ctx_t *ctx);
```

Classification rules:

- if `r->method != NGX_HTTP_CONNECT`, decline as today;
- if `r->connect_protocol.len == 0`, use existing TCP CONNECT path;
- if `r->connect_protocol == "connect-udp"` and `tunnel_udp on`, use UDP path;
- otherwise return `501 Not Implemented` or `400 Bad Request` depending on whether the protocol is unsupported or malformed.

Target parsing:

- require `r->uri` to start with `tunnel_udp_path`;
- parse the next two path segments as host and port;
- percent-decode the host segment before `ngx_parse_url()`;
- reject empty host, empty port, invalid port, or extra required template variables missing;
- build `host:port` in request pool and call `ngx_parse_url()` with `no_resolve = 1`;
- fill `ctx->resolved` exactly like TCP target parsing does.

### Phase 3: connected UDP upstream

Reuse HTTP upstream setup but switch peer type:

```c
tunnel_connect_init_upstream_peer(r, ctx);
tunnel_udp_parse_target(r, ctx);
r->upstream->peer.type = SOCK_DGRAM;
u->conf = &tscf->upstream;
u->create_request = tunnel_connect_empty_request;
u->reinit_request = tunnel_connect_empty_request;
u->process_header = tunnel_udp_process_header;
u->abort_request = tunnel_connect_abort_request;
u->finalize_request = tunnel_connect_finalize_request;
ngx_http_upstream_init(r);
```

`ngx_event_connect_peer()` will create a connected UDP socket and set UDP recv/send handlers. ACL should remain in `process_header`, after DNS resolution and peer selection, because the current ACL compares the concrete peer sockaddr.

### Phase 4: capsule codec

Add `src/capsule.c` and keep it independent from UDP socket logic.

Responsibilities:

- parse capsule type as QUIC variable-length integer;
- parse capsule length as QUIC variable-length integer;
- handle partial type, length, and payload across DATA buffer boundaries;
- expose complete UDP payload capsules to the relay loop;
- encode UDP payload capsules into output buffers/chains;
- reject malformed capsules with request finalization.

State should live in `ngx_http_tunnel_ctx_t`, for example:

```c
typedef struct {
    uint64_t type;
    uint64_t length;
    uint64_t received;
    ngx_uint_t state;
    ngx_buf_t *payload;
} tunnel_capsule_parse_t;
```

Keep the first implementation narrow:

- support the MASQUE UDP payload capsule needed for CONNECT-UDP;
- ignore or reject unsupported capsule types explicitly;
- enforce `tunnel_buffer_size` or a separate `tunnel_udp_max_datagram_size`;
- do not buffer an unbounded capsule payload.

### Phase 5: MASQUE UDP relay

Add `src/udp.c` and `src/udp_relay.c`.

UDP process-header behavior:

1. Run `ngx_http_tunnel_eval(r)`.
2. On deny, synthesize `403 Forbidden` like TCP path.
3. Send `200` response headers.
4. Add `Capsule-Protocol: ?1` response header.
5. Initialize unbuffered request-body reading.
6. Install downstream/upstream event handlers.
7. Start the UDP relay loop.

Relay loop:

- downstream DATA -> capsule parser -> UDP payload -> `pc->send()`;
- upstream UDP `pc->recv()` -> capsule encoder -> `ngx_http_output_filter()`;
- maintain separate input and output buffers because UDP preserves message boundaries;
- one UDP datagram maps to one UDP payload capsule;
- if a capsule is larger than configured maximum, finalize with `400`;
- if UDP send returns `NGX_AGAIN`, keep the datagram pending and retry on upstream write event;
- if HTTP output is blocked, keep the encoded capsule pending and retry on downstream write event;
- update idle timers on any successful read or write.

The TCP relay can be used as a structural reference, but do not mix TCP byte-stream assumptions into UDP. UDP relay needs message-boundary preserving buffers and a capsule parser.

### Phase 6: request body lifetime

Reuse the existing request-body reference pattern from `relay_v2.c`:

- set `r->request_body_no_buffering = 1`;
- call `ngx_http_read_client_request_body()`;
- track `request_body_ref_acquired` / `request_body_ref_released`;
- call `ngx_http_read_unbuffered_request_body()` from the UDP relay loop;
- move `r->request_body->bufs` into the capsule parser and then clear it;
- release the request-body ref on EOF or finalization.

This matters for HTTP/2 and HTTP/3 because leaked request-body refs keep `r->main->count` above zero and leak the request pool.

### Phase 7: timers and cleanup

Use the existing tunnel timeout semantics:

- upstream UDP read/write timers use `tunnel_idle_timeout`;
- downstream stream read/write timers use `tunnel_idle_timeout`;
- any capsule read, UDP send, UDP recv, or capsule write counts as activity;
- cleanup closes the connected UDP peer and releases request-body refs;
- after response headers are sent, relay errors finalize the request and close the peer.

For UDP, EOF semantics differ from TCP:

- client stream EOF means no more client-to-target datagrams, but upstream-to-client UDP datagrams may continue only if we intentionally support half-close;
- first implementation should finalize on client stream EOF to keep behavior simple;
- UDP socket EOF/error finalizes the tunnel.

### Phase 8: tests

Core tests:

- HTTP/2 and HTTP/3 classic CONNECT unchanged;
- HTTP/2 and HTTP/3 extended CONNECT preserve `:protocol`;
- invalid `:protocol` usage is rejected.

Module tests:

- `connect-udp` is rejected when `tunnel_udp off`;
- valid MASQUE path parses host and port;
- invalid path, missing host, invalid port, and oversized datagram are rejected;
- upstream peer type is `SOCK_DGRAM`;
- ACL allow/deny applies to UDP peer address;
- a UDP echo server receives one datagram from one capsule;
- one UDP response datagram is encoded as one response capsule;
- partial capsule headers split across DATA buffers are parsed correctly;
- partial capsule payloads split across DATA buffers are parsed correctly;
- blocked HTTP output preserves capsule bytes until retry;
- idle timeout closes inactive UDP tunnels;
- classic TCP CONNECT tests still pass.

## File layout

Recommended module additions:

```text
src/udp.c          request classification, target parsing, upstream setup
src/udp_relay.c    UDP socket and HTTP stream relay loop
src/capsule.c      capsule varint/parser/encoder
```

Recommended header additions:

```c
ngx_int_t tunnel_udp_is_request(ngx_http_request_t *r);
ngx_int_t tunnel_udp_init(ngx_http_request_t *r, ngx_http_tunnel_ctx_t *ctx);
ngx_int_t tunnel_udp_process_header(ngx_http_request_t *r);
ngx_int_t tunnel_udp_relay_start(ngx_http_tunnel_ctx_t *ctx);
```

## Recommended first milestone

Implement in this order:

1. Core `:protocol` storage and validation.
2. `tunnel_udp on` and request classification.
3. MASQUE path parser and connected UDP upstream setup with `SOCK_DGRAM`.
4. Minimal capsule parser/encoder for UDP payload capsules.
5. UDP relay over HTTP/2 DATA.
6. Reuse the same DATA/capsule relay over HTTP/3.
7. Broaden tests and then consider configurable URI templates.

This plan keeps nginx core changes small, preserves the existing upstream reuse model, and makes MASQUE support explicit without depending on QUIC DATAGRAM support.
