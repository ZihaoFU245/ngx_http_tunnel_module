The module code is current messy and requires a refactor.

Observations:
1. https://github.com/nginx/nginx/pull/707/changes, there is an nginx repo tunnel module
PR, it deals with HTTP/1.1, and highly utilize upstream code.
2. The current code is all in scattered files, unorganized, and function are all in different places
3. Client upload does not  go thorugh intermediate buffer, and upstream does. This is an asymetry data
path. Maintainance is a pain. The introduce of `NGX_HTTP_TUNNEL_STREAM_MAX_ITERATIONS` prevents
starvation problem, it is a terrible design. It is a hard cap for client upload throughput
The starvation problem should not be force stop, it now breaks event driven architecture.
`NGX_AGAIN` or waiting event is the time for process to release resouces. Custom fairness
overlappign with nginx event logic and schduling. Scheduling should be a nginx core problem.

Overall:

* Asymmetric data path (upload direct, download via middle buffer)
* Over-reliance on manual relay (byte moving, lifecycle handling)
* `tunnel_buffer` misused as general transport buffer
* Padding tightly coupled with relay path
* Fixed iteration cap (`NGX_HTTP_TUNNEL_STREAM_MAX_ITERATIONS`) throttles throughput
* Custom fairness logic overlapping with nginx event scheduling
* Buffer roles unclear / overloaded
* H2 and H3 forced into same low-level path
* H3 higher memory usage and slower release
* Relay logic too complex and fragmented (`relay` vs `relay_stream`)
* Codebase lacks clear module separation (flat file structure)
* Over-prefixed function naming everywhere
* Inconsistent / unclear variable naming
* Not fully leveraging nginx upstream framework
* Too much ownership of connection lifecycle inside module
* Hard to reason about cleanup / finalization paths

Requirements:

1. The code base will be refactored into src/ folder. Only core functions should have 
prefix `ngx_http_tunnel_module`, sub modules should not, this reduces the length of functions
2. Functions should be kept organized, helper function should be in a `utils.c` file. 
3. Current code base has logic branching in relay, it should be done more cleanly. 
Access phase handler uses auth submodule and designate content phase handler. Content phase handler,
allocation resources, parse requests, call DNS sub modules, then use upstream module to establish
connections. It should be cleanly handeled, it can not tide to TCP only connections, it should leave
addon to handle future extended connect methods `:protocol = ` field. Lastly, the tunnel relay module.
It can be divided into relay, relay v2, and relay v3. Not 1 relay module handles all 3 http versions,
padding also a sub module. 
4. padding module does padding on first 8 IO. Follow SPEC's padding scheme. If 8 first IO
counter is reached, it should DECLINE, so relay module can continue. 
5. As copy bandwidth is way higher then network bandwidth, so connection should be moved to 
intermediate buffer, tunnel buffer, padding and unpadding works on the tunnel module buffer. 
The buffer defaults to 16k. 
6. The module should utilize nginx event driven achetecture, the forced fairness should be removed.
Instead should utilize `NGX_AGAIN` for example, to provide fairness. Overall scheuling should still
leave to nginx core. 
7. The code should contain nginx style comments, instead of plain code. The refactor code style should follow
nginx code style.

Steps:

1. Establish the clean baseline and guardrails.
   * Treat `30f9167` (`origin/master`, `h3: unsafe`) as the pre-refactor code
     baseline for the implementation.
   * Keep the existing public behavior and directives: `tunnel_pass`,
     `tunnel_auth_username`, `tunnel_auth_password`, `tunnel_buffer_size`,
     `tunnel_connect_timeout`, `tunnel_idle_timeout`,
     `tunnel_probe_resistance`, and `tunnel_padding`.
   * Keep existing CONNECT support for HTTP/1.1, HTTP/2, and HTTP/3; keep the
     existing H2-only padding negotiation safety gate unless the spec and tests
     are extended.
   * Do not add or remove features. Any change must be a structural refactor,
     a data-path symmetry fix, or an event-scheduling fix required by this
     plan.

2. Reorganize the source tree.
   * Move implementation files into `src/`.
   * Keep only nginx module entry points and directive handlers with the
     `ngx_http_tunnel_` prefix.
   * Use shorter submodule names for internal code:
     `tunnel_auth_*`, `tunnel_connect_*`, `tunnel_resolve_*`,
     `tunnel_relay_*`, `tunnel_relay_v1_*`, `tunnel_relay_v2_*`,
     `tunnel_relay_v3_*`, `tunnel_padding_*`, and `tunnel_utils_*`.
   * Update `config` to build the files from `src/`.

3. Split responsibilities into explicit submodules.
   * `src/core.c`: nginx module definition, directives, server-conf create and
     merge, phase registration, access-phase handoff, and content handler.
   * `src/auth.c`: proxy authorization validation and denial responses.
   * `src/connect.c`: CONNECT target parsing, resolver setup, upstream peer
     creation, connect retry, connect timeout handling, and connect test.
   * `src/relay.c`: relay dispatcher, common start/finalize/cleanup logic, and
     shared relay state transitions.
   * `src/relay_v1.c`: HTTP/1.1 raw downstream relay.
   * `src/relay_v2.c`: HTTP/2 stream downstream relay.
   * `src/relay_v3.c`: HTTP/3 stream downstream relay wrapper/path, separated
     from H2 even when it reuses common helpers initially.
   * `src/padding.c`: padding negotiation and first-8-IO padding/unpadding.
   * `src/utils.c`: shared helpers for timers, buffer reset/drain checks,
     chain cleanup, copying chains into buffers, and request-body reference
     release.
   * `src/ngx_http_tunnel_module.h`: public module structs and prototypes only;
     avoid large inline helper implementations except trivial predicates.

4. Clarify context and buffer ownership.
   * Keep one configured `tunnel_buffer_size`, defaulting to `16k`.
   * Use the module tunnel buffers as directional transport buffers:
     client/downstream to upstream and upstream to client/downstream.
   * Do not use padding buffers as general relay buffers. Padding may keep a
     dedicated output frame buffer only for constructed padded frames.
   * Track upload and download drain state explicitly so finalization does not
     depend on overloaded chain or padding state.

5. Refactor the content/connect sequence without changing behavior.
   * Access phase checks CONNECT and auth, then assigns the content handler.
   * Content handler allocates context and buffers, negotiates padding, installs
     cleanup, parses the target, initializes upstream peer state, and either
     starts resolver or connects directly.
   * Keep target parsing based on CONNECT authority today, but isolate it so
     future extended CONNECT `:protocol` handling can be added without changing
     relay internals.
   * Continue using nginx upstream peer selection and
     `ngx_http_upstream_create_round_robin_peer()` for resolved addresses.

6. Make relay dispatch version-specific.
   * Replace one low-level relay path branching on every protocol concern with
     a dispatcher that chooses v1, v2, or v3 once per event.
   * Keep HTTP/1.1 relay close to nginx upstream upgraded relay semantics:
     read into intermediate buffer, write from intermediate buffer, stop on
     `NGX_AGAIN`, EOF, timeout, or event readiness.
   * Keep HTTP/2 and HTTP/3 relay code separated at the file/API boundary even
     if both call shared stream helper functions.

7. Make upload and download data paths symmetric.
   * Preserve nginx unbuffered request-body reads for H2/H3 CONNECT request
     streams.
   * Move request-body chains into the downstream-to-upstream tunnel buffer
     before writing to the upstream socket.
   * Send upstream data from the tunnel buffer using `pc->send()`, not directly
     from request-body chains with `pc->send_chain()`.
   * Keep upstream-to-downstream data in the upstream tunnel buffer and pass it
     through the nginx output filter for H2/H3.
   * Ensure both directions reset buffer `pos`/`last` only after the buffer is
     fully drained.

8. Decouple padding from socket writes.
   * Padding negotiation remains driven by the configured flag and request
     header.
   * For downstream-to-upstream, unpadding reads from request-body chains and
     writes unpadded payload into the downstream-to-upstream tunnel buffer.
   * For upstream-to-downstream, padding reads from the upstream tunnel buffer
     and builds padded output frames in the padding frame buffer.
   * After the first eight padded IO units in either direction, padding
     functions return `NGX_DECLINED` so the relay continues with the normal
     unpadded buffer path.
   * Preserve existing malformed padded input handling and existing H2
     RST-stream padding behavior.

9. Remove custom fairness scheduling.
   * Remove `NGX_HTTP_TUNNEL_STREAM_MAX_ITERATIONS` and any logic that reposts
     local work solely because an iteration budget was exhausted.
   * Relay loops should stop when nginx returns `NGX_AGAIN`, when source/dest
     events are not ready, when buffers are full or drained, or when no work was
     performed.
   * Register read/write events with `ngx_handle_read_event()` and
     `ngx_handle_write_event()` after each processing pass.
   * Leave scheduling fairness to nginx core and the event module.

10. Preserve lifecycle and cleanup semantics.
    * Keep resolver cancellation on finalize/cleanup.
    * Keep request-body main-count release exactly once.
    * Keep upstream peer release exactly once.
    * Keep connection close behavior and HTTP/3 clean stream EOF handling.
    * Keep idle/connect timers but move timer helpers to `utils.c`.

11. Apply nginx style.
    * Use nginx indentation, naming, status-code returns, and comment style.
    * Comments should explain non-obvious nginx lifecycle, request-body, H2/H3,
      padding, or cleanup constraints.
    * Avoid broad rewrites outside the module unless required for build
      integration.

12. Verify the refactor.
    * Reconfigure nginx with `--add-module=../ngx_http_tunnel_module`.
    * Build nginx with warnings as errors.
    * Run config validation with the test nginx configuration adjusted only for
      local pid/temp paths when necessary.
    * Run at least one HTTP/1.1 CONNECT smoke test.
    * Run at least one HTTP/2 CONNECT smoke test with auth.
    * Run the existing idle-timeout test when an nginx instance can be started.
    * If H3 cannot be smoke-tested locally, document that limitation and rely
      on build/config validation plus unchanged H3 feature gating.
