# Nginx module implementation spec: `ngx_http_tunnel_module`

## 1. Purpose

`ngx_http_tunnel_module` implements **classic HTTP CONNECT tunneling** for nginx in the HTTP subsystem.

This module acts as a **forward proxy for CONNECT requests**. When enabled, nginx accepts a client CONNECT request, establishes an outbound TCP connection to the requested authority, returns a successful CONNECT response, and then relays raw bytes between client and upstream until either side closes or a timeout occurs.

This module is intended as an open-source alternative to the nginx Plus tunnel feature set, but this implementation only targets a narrow, well-defined subset.

---

## 2. Scope

### 2.1 In scope

This implementation supports:

- classic HTTP CONNECT only
- HTTP/1.1 CONNECT
- HTTP/2 CONNECT
- HTTP/3 CONNECT
- direct connection to the authority requested by the client
- optional Basic proxy authentication using `Proxy-Authorization`
- configurable connect timeout
- configurable idle timeout
- configurable relay buffer size
- optional payload length padding protocol to mitigate traffic analysis

### 2.2 Out of scope

This implementation does **not** support:

- extended CONNECT
- path-based CONNECT routing
- WebSocket-over-CONNECT extensions
- MASQUE
- relaying CONNECT to another upstream proxy using `tunnel_pass <address>`
- adding `Via`, `X-Forwarded-For`, or similar forwarding headers
- ACL features such as CIDR allow/deny lists
- UDP tunneling
- request body handling for non-CONNECT methods
- transparent proxying
- MITM TLS interception
- socket keepalive tuning
- timing obfuscation or traffic shaping beyond payload length padding

If future support for extended CONNECT is added, it must be treated as a separate feature set and not mixed into this implementation.

---

## 3. Configuration model

### 3.1 Supported directive context

All directives in this module are valid in:

- `server {}` only

They are **not** valid in:

- `http {}`
- `location {}`

### 3.2 Rationale

Classic CONNECT is authority-form tunneling and is treated as **server-level proxy behavior**, not location-based content routing. Restricting configuration to `server {}` keeps the implementation simple and avoids ambiguity with extended CONNECT semantics.

The padding protocol operates at tunnel-session scope, which is also a server-level concept. Padding directives follow the same restriction.

---

## 4. Example configuration

### 4.1 Minimal configuration

```nginx
server {
	listen 0.0.0.0:3128;

	# Non CONNECT method goes here
	location / {
		proxy_pass http://example.com;
	}

	tunnel_pass;
}
```

### 4.2 Configuration with proxy authentication

```nginx
server {
	listen 0.0.0.0:3128;

	resolver 1.1.1.1 8.8.8.8;

	location / {
		proxy_pass http://example.com;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	}

	tunnel_pass;
	tunnel_auth_username myuser;
	tunnel_auth_password mypass;

	tunnel_buffer_size 16k;
	tunnel_connect_timeout 60s;
	tunnel_idle_timeout 30s;
	tunnel_probe_resistance off;
}
```

### 4.3 Configuration with padding

```nginx
server {
	listen 0.0.0.0:3128;

	resolver 1.1.1.1 8.8.8.8;

	location / {
		proxy_pass http://example.com;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	}

	tunnel_pass;
	tunnel_auth_username myuser;
	tunnel_auth_password mypass;
	tunnel_padding on;

	tunnel_buffer_size 16k;
	tunnel_connect_timeout 60s;
	tunnel_idle_timeout 30s;
	tunnel_probe_resistance off;
}
```

---

## 5. Request model

### 5.1 Supported request form

The module handles only requests whose normalized method is `CONNECT`.

#### HTTP/1.1 example

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
Proxy-Authorization: Basic dXNlcjpwYXNz
```

#### HTTP/2 and HTTP/3 conceptual form

```text
:method = CONNECT
:authority = example.com:443
```

#### HTTP/2 CONNECT with padding negotiation

When `tunnel_padding` is enabled, the CONNECT request from a padding-capable client carries an additional header, and the server echoes one in its successful response:

```text
:method = CONNECT
:authority = example.com:443
padding: <random non-Huffman-coded bytes, length in [16, 32]>
```

The module must rely on nginx core parsing and the normalized request structure. It must not implement protocol-specific raw parsing itself unless required by nginx internal request representation.

---

## 6. Directive specification

### 6.1 `tunnel_pass`

#### Syntax

```nginx
tunnel_pass;
```

#### Context

- `server`

#### Meaning

Enables classic CONNECT tunneling for the enclosing server block.

When a valid CONNECT request is received, nginx:

1. extracts the requested authority from the request
2. resolves the hostname if required
3. opens an outbound TCP connection to the requested target
4. returns a successful CONNECT response to the client
5. switches into bidirectional byte relay mode

#### Notes

- This directive takes **no argument** in this implementation.
- `tunnel_pass <address>;` is out of scope for v1.

---

### 6.2 `tunnel_auth_username`

#### Syntax

```nginx
tunnel_auth_username <value>;
```

#### Context

- `server`

#### Meaning

Username expected in Basic proxy authentication for CONNECT requests.

#### Notes

- Only applies to CONNECT handled by this module.
- This is not linked to nginx `auth_basic`.

---

### 6.3 `tunnel_auth_password`

#### Syntax

```nginx
tunnel_auth_password <value>;
```

#### Context

- `server`

#### Meaning

Password expected in Basic proxy authentication for CONNECT requests.

#### Notes

- Only applies to CONNECT handled by this module.
- Authentication is enabled only when both username and password are configured.

---

### 6.4 `tunnel_buffer_size`

#### Syntax

```nginx
tunnel_buffer_size <size>;
```

#### Context

- `server`

#### Meaning

Size of relay buffer used for copying bytes between client and upstream.

#### Default

```nginx
tunnel_buffer_size 16k;
```

#### Notes

- This is an nginx size value such as `4k`, `16k`, `64k`, `1m`.
- `16k` means 16 KiB, not 16 MB.
- The implementation may reject values below a minimum threshold if needed.
- When padding is active, the `original_data_size` field in `PaddedData` is two bytes, limiting a single padded message to 65535 bytes. If the relay buffer exceeds this, the implementation must split the payload across multiple `PaddedData` frames before writing.

---

### 6.5 `tunnel_connect_timeout`

#### Syntax

```nginx
tunnel_connect_timeout <time>;
```

#### Context

- `server`

#### Meaning

Maximum time allowed to establish the outbound TCP connection to the requested CONNECT target.

#### Default

```nginx
tunnel_connect_timeout 60s;
```

---

### 6.6 `tunnel_idle_timeout`

#### Syntax

```nginx
tunnel_idle_timeout <time>;
```

#### Context

- `server`

#### Meaning

Maximum period of inactivity allowed on an established tunnel. If no successful read or write occurs in either direction during this interval, the tunnel is closed and all associated resources are released.

#### Default

```nginx
tunnel_idle_timeout 30s;
```

---

### 6.7 `tunnel_probe_resistance`

#### Syntax

```nginx
tunnel_probe_resistance on | off;
```

#### Context

- `server`

#### Meaning

When enabled, authentication failures are disguised as normal method rejection rather than explicit proxy-authentication failure.

#### Default

```nginx
tunnel_probe_resistance off;
```

#### Notes

When this option is enabled and authentication fails, the module should return `405 Not Allowed` instead of `407 Proxy Authentication Required`.

This option only has meaning when proxy authentication is configured.

---

### 6.8 `tunnel_padding`

#### Syntax

```nginx
tunnel_padding on | off;
```

#### Context

- `server`

#### Meaning

Enables the padding protocol for CONNECT tunnels handled by this server block.

When `on`, the server participates in padding negotiation by inspecting the `padding` request header and emitting a `padding` response header on the successful CONNECT reply. If the client does not send a `padding` header, the server does not send one and padding mode remains inactive for that tunnel, regardless of this setting.

When `off`, no padding header is read or emitted, and no framing overhead is applied to the relay stream. Behavior is identical to a server without padding support.

#### Default

```nginx
tunnel_padding off;
```

#### Notes

- Padding negotiation is per-tunnel and opt-in from the client side. A non-padding-aware client connecting to a server with `tunnel_padding on` is unaffected.
- The padding protocol constants `kFirstPaddings` (8) and `kMaxPaddingSize` (255) are fixed in the implementation and are not configurable. See section 12 for their meaning.

---

## 7. nginx phase integration

The module participates in:

- access phase
- content phase

### 7.1 Access phase responsibilities

The access-phase handler must:

1. check whether the request method is CONNECT
2. return `NGX_DECLINED` for all non-CONNECT requests
3. check whether `tunnel_pass` is enabled in this server
4. validate authentication if configured
5. if `tunnel_padding` is `on`, inspect the request for a `padding` header and record whether the client supports padding in the per-request context
6. reject invalid or unauthorized CONNECT requests before content handling begins

#### Access phase return behavior

- non-CONNECT request: `NGX_DECLINED`
- CONNECT not enabled in this server: `NGX_DECLINED`
- CONNECT enabled and auth passes: `NGX_DECLINED` so later phase continues
- malformed authentication header: finalize request with error
- invalid credentials: finalize request with error, if `tunnel_probe_resistance` is set to on, it should return 405 instead of 407.

The access handler must not interfere with normal nginx handling of non-CONNECT methods.

---

### 7.2 Content phase responsibilities

The content-phase handler must:

1. verify method is CONNECT
2. verify `tunnel_pass` is enabled
3. extract and validate target authority
4. resolve hostname if needed
5. initiate outbound TCP connection
6. upon success, send successful CONNECT response, including the `padding` response header if padding was negotiated
7. install event handlers for bidirectional relay; if padding was negotiated, install the `PaddedData` framing layer on the relay handlers
8. manage idle timeout and final cleanup

For non-CONNECT requests, the content handler must return `NGX_DECLINED`.

---

## 8. CONNECT target parsing and validation

The requested CONNECT target must be treated as an **authority**, normally of the form:

```text
host:port
```

The module must validate:

- authority is present
- host is non-empty
- port is present
- port is numeric and in valid range
- authority format is acceptable for the implementation

If target validation fails, the request must be rejected before outbound connection is attempted.

The module must not attempt location-based URI routing for CONNECT.

---

## 9. Authentication behavior

### 9.1 Header used

The module must use:

```http
Proxy-Authorization: Basic <token>
```

It must not use the ordinary `Authorization` header for this feature.

### 9.2 Validation model

If both `tunnel_auth_username` and `tunnel_auth_password` are configured:

1. require `Proxy-Authorization`
2. require `Basic` scheme
3. decode base64 payload
4. parse `username:password`
5. compare against configured credentials

### 9.3 Authentication failure response

When authentication fails:

- if `tunnel_probe_resistance off`: return `407 Proxy Authentication Required`
- if `tunnel_probe_resistance on`: return `405 Not Allowed`

When returning `407`, the response should include an appropriate `Proxy-Authenticate` header.

Malformed authentication header may be handled as `400 Bad Request` or `407`, but the implementation must be consistent.

---

## 10. Upstream connection behavior

Once a CONNECT request is accepted:

1. determine the target host and port from request authority
2. resolve host using nginx resolver if DNS resolution is needed
3. open a TCP connection to the target
4. apply configured connect timeout
5. when the connection succeeds, send success response to client
6. enter relay mode (padded or raw, depending on negotiation outcome)

No forwarding headers are added, because after CONNECT succeeds the module is relaying raw bytes, not generating a forwarded HTTP request.

---

## 11. Successful CONNECT response

For a successful classic CONNECT tunnel, nginx must return:

```http
HTTP/1.1 200 Connection Established
```

For HTTP/2 and HTTP/3, nginx must return the protocol-appropriate successful response through normal nginx request finalization or header sending path.

When padding has been negotiated, the response must include a `padding` header before finalization:

```text
padding: <random non-Huffman-coded bytes, length in [30, 62]>
```

The padding header value must use bytes that are not efficiently Huffman-coded and must not be HPACK-indexable. This ensures the padding survives HTTP/2 header compression and lands on the wire at the intended length. See section 12.4 for construction requirements.

After success is acknowledged, the request transitions from HTTP request handling into stream-like tunnel relay.

---

## 12. Padding protocol

The padding protocol is an optional, opt-in extension that sits between the relay event handlers and the socket I/O. Its purpose is to mitigate length-based traffic analysis by randomizing the size distribution of the initial payload exchanges in each direction of a tunnel session.

The design follows the NaïveProxy padding specification. It opts for low overhead and simple implementation, with padding applied only to the first `kFirstPaddings` exchanges per direction where fingerprinting risk is highest. After that budget is exhausted, relay performance is identical to an unpadded tunnel.

### 12.1 Protocol constants

The following constants are fixed in the implementation and are not configurable:

- `kFirstPaddings = 8` — number of relay exchanges per direction that are padded
- `kMaxPaddingSize = 255` — maximum padding bytes appended per padded message

`kFirstPaddings` is chosen to cover the typical initial TLS and HTTP/2 handshake sequence, which comprises the most fingerprintable packet length distribution. This includes the common client sequence (TLS ClientHello; TLS ChangeCipherSpec + Finished; H2 Magic + SETTINGS + WINDOW_UPDATE; H2 HEADERS; H2 SETTINGS ACK) and the common server sequence (TLS ServerHello through Certificate; H2 SETTINGS; H2 WINDOW_UPDATE; H2 SETTINGS ACK; H2 200 OK).

`kMaxPaddingSize` is 255 because the `padding_size` field in `PaddedData` is a single `uint8_t`. There is no valid value above 255.

### 12.2 Opt-in negotiation

Padding is negotiated per-tunnel using the `padding` header in the CONNECT exchange:

1. The client signals capability by including a `padding` header in its CONNECT request. The value is a sequence of random non-Huffman-coded bytes with length chosen uniformly from [16, 32].
2. The server, if `tunnel_padding on`, detects this header in the access phase and records that the client supports padding.
3. In the content phase, the server includes a `padding` header in the 200 response with value length chosen uniformly from [30, 62].
4. After the server emits its `padding` response header, both sides activate `PaddedData` framing for the first `kFirstPaddings` relay exchanges per direction.

If the client does not send a `padding` header, the server emits no `padding` response header and padding mode is never activated for that tunnel. A NaïveProxy-aware server is therefore fully interoperable with any plain HTTP/2 client.

The first CONNECT request to a server cannot use Fast Open to send payload before the response, because the server's padding capability has not yet been confirmed and it is unknown whether to send padded or unpadded payload.

### 12.3 `PaddedData` wire format

Each padded relay exchange wraps the payload in the following structure:

```c
struct PaddedData {
    uint8_t original_data_size_high;  /* original_data_size / 256 */
    uint8_t original_data_size_low;   /* original_data_size % 256 */
    uint8_t padding_size;             /* random in [0, kMaxPaddingSize] */
    uint8_t original_data[original_data_size];
    uint8_t zeros[padding_size];
};
```

- `original_data_size` is encoded big-endian across the two leading bytes and must not exceed 65535. If a relay buffer contains more than 65535 bytes, it must be split into multiple `PaddedData` messages before writing.
- `padding_size` is drawn independently and uniformly at random from [0, `kMaxPaddingSize`] for each message.
- The trailing zero bytes are opaque filler. Their value is always `0x00`.
- The 3-byte header is always present, including for messages with `padding_size = 0`.

The total wire size of a padded message is `3 + original_data_size + padding_size` bytes.

### 12.4 Padding header value construction

The `padding` header value in the CONNECT request and response must be constructed to resist HTTP/2 header compression. Specifically:

- Bytes must not be efficiently HPACK Huffman-coded. Common ASCII letters and digits compress aggressively and must be avoided.
- The sequence must not match a previously transmitted header value, to prevent HPACK from referencing it by index in future frames.
- A practical approach is to draw random bytes from a range with high Huffman cost, or to generate random bytes and encode them as a representation that produces high per-symbol entropy in HPACK.

Request `padding` header value length: uniformly random in [16, 32].
Response `padding` header value length: uniformly random in [30, 62].

These ranges are calibrated to bring CONNECT request and response HEADERS frame lengths into the range typical of real HTTP/2 browser HEADERS frames.

### 12.5 Per-direction counters

Each tunnel session maintains two independent exchange counters: one for client-to-upstream and one for upstream-to-client. Both are initialized to zero when the tunnel is established.

For each relay write in a given direction:

- if the counter for that direction is less than `kFirstPaddings`: wrap the payload in `PaddedData` framing and increment the counter
- if the counter equals or exceeds `kFirstPaddings`: write raw bytes with no framing

The two directions are independent. One may exhaust its padding budget before the other.

Both counters must be stored in the per-tunnel context struct, allocated from the request memory pool, zeroed on allocation, and released during tunnel cleanup.

### 12.6 Padded relay state machine

Because nginx uses nonblocking I/O, a single `PaddedData` frame may be delivered across multiple read events. The implementation must not assume atomic delivery of a full frame. The read path must implement a state machine:

```
PADDED_READ_HEADER  →  PADDED_READ_PAYLOAD  →  PADDED_READ_DISCARD  →  (next frame or raw mode)
```

- `PADDED_READ_HEADER`: accumulate 3 bytes, decode `original_data_size` and `padding_size`
- `PADDED_READ_PAYLOAD`: read and forward `original_data_size` bytes
- `PADDED_READ_DISCARD`: read and discard `padding_size` bytes, then increment the counter and transition

Similarly, the write path must handle partial writes of the framed output. If the 3-byte header write is short, the remaining header bytes must be buffered and retried on the next write event.

If a received `PaddedData` header indicates sizes that would overflow the available buffer, the frame must be treated as malformed and the tunnel must be closed with `400 Bad Request`.

### 12.7 RST_STREAM frame padding (HTTP/2 only)

In HTTP/2, a padding-enabled proxy tends to emit RST_STREAM frames at a higher rate than a regular browser. To mitigate this, when padding mode is active and the implementation would emit an RST_STREAM frame, it must prepend an END_STREAM DATA frame padded to a total byte length chosen uniformly at random from [48, 72]. The combined sequence resembles an HTTP/2 HEADERS frame in length to a passive observer.

A side effect is that the server often replies to this DATA frame with a WINDOW_UPDATE because HTTP/2 flow control accounts for padding bytes. Whether this WINDOW_UPDATE creates a new distinguishing behavior is an acknowledged open question.

RST_STREAM padding applies only to HTTP/2 tunnels. It is not relevant for HTTP/1.1 or HTTP/3.

### 12.8 Known limitations

The padding protocol does not address:

- **TLS-over-TLS structure**: the double TLS handshake produces a characteristic round-trip count and packet enlargement pattern that padding cannot hide. Eliminating this requires MITM proxying, which is out of scope.
- **Long-session analysis**: after the first `kFirstPaddings` exchanges per direction, the relay stream is unpadded. Statistical analysis on sustained flows remains possible.
- **Uniform padding distribution**: the uniform draw from [0, 255] produces an offset distribution rather than a naturalistic browser-like length distribution. A sophisticated classifier may distinguish this from real traffic.
- **Single-connection multiplexing**: length obfuscation partly relies on HTTP/2 multiplexing. With only one active tunnel, there are no co-connections to provide covering traffic.

---

## 13. Relay behavior

After successful outbound connection:

- client bytes are copied to upstream
- upstream bytes are copied to client
- relay is full-duplex
- relay continues until error, EOF, timeout, or shutdown

### Relay requirements

- event-driven, nonblocking I/O only
- use nginx connection and event infrastructure
- no blocking socket operations
- buffer management must avoid leaks and invalid reuse
- partial reads and writes must be handled correctly
- EOF from either side must trigger orderly shutdown and cleanup

When padding is active, the `PaddedData` framing layer is applied on each relay write for the first `kFirstPaddings` exchanges per direction, and the corresponding decoder is applied on each relay read. After the counter for a direction reaches `kFirstPaddings`, that direction switches to raw relay mode. The two directions switch independently.

---

## 14. Timeout behavior

### 14.1 Connect timeout

If outbound TCP connection is not established before `tunnel_connect_timeout` expires:

- terminate the attempt
- finalize request with timeout error

### 14.2 Idle timeout

If an established tunnel has no successful read or write activity in either direction for `tunnel_idle_timeout`:

- close both sides of the tunnel
- release allocated resources

In padded relay mode, the idle timeout is reset after a full `PaddedData` frame (including padding bytes) has been successfully read or written, not mid-frame.

---

## 15. Error handling

The implementation must use consistent response mapping.

Recommended mapping:

- malformed CONNECT request or malformed authority: `400 Bad Request`
- malformed `PaddedData` frame received during padded relay: `400 Bad Request`
- authentication required or invalid auth: `407 Proxy Authentication Required`
- authentication failure with probe resistance enabled: `405 Not Allowed`
- DNS resolution failure: `502 Bad Gateway`
- outbound connect refused, network unreachable, or host unreachable: `502 Bad Gateway`
- outbound connect timeout: `504 Gateway Timeout`
- internal allocation or unexpected runtime failure: `500 Internal Server Error`

Do not emit proxy-specific headers except where required for `407`.

---

## 16. Resource management

The implementation must ensure:

- all allocated buffers are released
- all timers are canceled on finalization
- all sockets are closed on error or completion
- request and connection cleanup handlers are registered as needed
- no dangling event handlers remain after tunnel shutdown
- per-tunnel padding counters and partial-frame state are released in all exit paths, including error paths

This is mandatory. Tunnel code must not leak memory, leave stale timers, or retain dead file descriptors. The padding state machine adds additional cleanup obligations: partial-frame read buffers and direction counters must be freed with the tunnel context.

---

## 17. Non-CONNECT behavior

This module must not change nginx behavior for non-CONNECT requests.

For any request whose method is not CONNECT:

- access phase handler returns `NGX_DECLINED`
- content phase handler returns `NGX_DECLINED`
- other modules continue as normal

This is a strict requirement. No padding logic is ever invoked for non-CONNECT requests.

---

## 18. Implementation notes

### 18.1 Coding style

Implementation must follow nginx conventions:

- nginx memory pools
- nginx event model
- nginx connection types
- nginx naming and code style
- proper use of nginx logging and error reporting
- comments only where useful, not excessive narrative comments

### 18.2 Internal structure recommendation

A reasonable structure is:

- module configuration definitions
- directive parsing and merge logic
- access phase handler
- content phase handler
- target authority parsing helper
- proxy auth parsing helper
- outbound connection setup
- relay event handlers
- `PaddedData` encoder (write path)
- `PaddedData` decoder with state machine (read path)
- padding header value generator
- timeout handlers
- cleanup helpers

### 18.3 Important constraint

Do not build this as a normal HTTP upstream request proxy. After successful CONNECT, this becomes a tunnel relay problem, not a regular upstream response-body flow problem. The `PaddedData` layer sits inside the relay, not inside the nginx upstream machinery.

---

## 19. Explicit non-goals for v1

The following must not be partially implemented:

- `tunnel_pass <address>`
- location-level CONNECT routing
- extended CONNECT support
- upstream proxy chaining
- protocol tunneling beyond raw TCP relay
- adaptive or configurable padding beyond the fixed `kFirstPaddings` / `kMaxPaddingSize` scheme
- timing obfuscation or traffic shaping

Either implement them properly in a later version, or leave them fully absent from v1.

---

## 20. Suggested implementation milestone plan

### Milestone 1
- directive parsing
- `server {}` config only
- CONNECT detection
- no-op on non-CONNECT

### Milestone 2
- target authority parsing
- outbound connect
- simple 200 response
- basic byte relay

### Milestone 3
- connect timeout
- idle timeout
- cleanup correctness

### Milestone 4
- Basic proxy auth
- probe resistance mode

### Milestone 5
- HTTP/2 and HTTP/3 validation against nginx core request representation

### Milestone 6
- `tunnel_padding` directive
- padding header negotiation in access and content phase
- padding header value generator

### Milestone 7
- `PaddedData` encoder and decoder
- padded relay mode with per-direction counters
- partial-frame read state machine
- integration tests confirming non-padding clients are unaffected

### Milestone 8
- RST_STREAM DATA-frame prepend for HTTP/2

---

## 21. Final summary

This module is a **server-level classic CONNECT forward proxy** for nginx.

The implementation must:

- only handle CONNECT
- only operate when enabled by `tunnel_pass;`
- directly connect to the client-requested authority
- optionally require Basic proxy authentication
- return correct proxy error codes
- switch into nonblocking bidirectional relay mode after success
- leave all non-CONNECT traffic untouched
- when `tunnel_padding on`: negotiate padding capability via the `padding` header in the CONNECT exchange
- when padding is negotiated: apply `PaddedData` framing to the first `kFirstPaddings` relay exchanges per direction, then relay raw bytes for the remainder of the session
- never activate padding for clients that do not signal capability, preserving full interoperability with unaware clients
