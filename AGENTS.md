Following edits should be limited in `src/relay_v2.c`

Issues:

A. `tunnel_relay_v2_process` loop is assymetric, there should be 4 helper functions,
that can keep the main event loop clean. But there only exists 3 helper functions,
`receive_upstream` is inlined in the loop.

The file is currently messy, consider following improvements:

- The file only expose important function, such as `tunnel_relay_v2_process`,
`tunnel_relay_v2_init_request_body`. For all main functions, it starts as
`tunnel_relay_v2`. For functions that is helper functions, that must not
start with it, for example use  `recv_downstream` instead of `tunnel_relay_v2_receive downstream`,
the function is not used outside this file scope. It should be marked as
static, or `ngx_inline` for helpers.

- Important functions comes in the top of the files. Helper functions
is placed at near the end of the files. 

- Unnecesary helper functions should be pruned, simplified. Like
`tunnel_relay_v2_upload_padding_active` and `tunnel_padding_active`,
2 helper functions use 2 different precheck functions. This is not clean
and symmetric. The precheck should be unified only use `tunnel_padding_active`
only send upstream and send dowstream requires padding, they just invoke 
`tunnel_padding_active`, remove the other alise.

- This relay should be highly symmetric.
`recv_downstream`, `recv_upstream`, `send_downstream` and
`send_upstream`.

- Names like `tunnel_relay_v2_recv_upstream_precheck`, is not
easy to read. Use `recv_upstream_precheck` instead. 

B. The main event loop is currently using `for (;;)`, this is busy spinning
until the connection is closed, it disregards nginx core event archetecture.
Eventually may leads to a systemd SIGKILL, as it disregard SIGTERM.

- For events, such as `ngx_terminate`, `ngx_quit`, `ngx_exiting`. It should be checked
once in a while in the loop. Define 2 things:
`NGX_HTTP_RELAY_MAX_ITERATIONS` and `RELAY_CHECK_PERIOD`. The check period can be
used like `if (!(i % RELAY_CHECK_PERIOD)) {check ngx shutdown events}`

- Variable `loop_activity` should be removed. Activity is used only to track
tunnel activities, and shut them down after a period of idle times. If using
a hard cap for relay loop, then `loop_activity` has no meaning to keep.

C. A helper is needed to check weather the relay job is finished,
it is used to  for post event handling. Use `is_relay_finished` for
this helper. And do post events accordingly.

D. During refactor, object lifetime needs be tracked, and invoke
cleanup functions correctly.

Refactor process:

YOUR REFACTOR PLAN GOES HERE

1. Establish boundaries and invariants first
- Keep all behavior in `src/relay_v2.c` functionally equivalent for data flow, timeout handling, request-body progress, and finalize/cleanup contracts.
- Do not change nginx core, module public headers, or caller behavior outside relay-v2 integration points.
- Preserve object lifetime invariants for `ctx`, `r`, `u`, `pc`, timers, posted events, request body refs, and finalize idempotency.

2. Normalize file structure and naming
- Keep exported functions at top: `tunnel_relay_v2_init_request_body`, `tunnel_relay_v2_process`.
- Move internal helpers near end of file.
- Rename internal helpers to short local names without `tunnel_relay_v2_` prefix, mark as `static`/`static ngx_inline`:
`recv_downstream_precheck`, `recv_upstream_precheck`, `recv_downstream`, `recv_upstream`, `send_downstream`, `send_upstream`, `send_client_buffer`, `is_relay_finished`, `output_idle`, `padding_drained`.

3. Make relay operations symmetric
- Split the inlined upstream-recv logic into a dedicated `recv_upstream(...)` helper so the main loop has four symmetric operations:
`recv_downstream -> send_upstream -> send_downstream -> recv_upstream`.
- Keep each helper responsible for one direction and one transport edge only.
- Keep prechecks close to each operation and use consistent naming/shape across directions.

4. Remove redundant helper aliases
- Delete `tunnel_relay_v2_upload_padding_active`.
- Use `tunnel_padding_active(ctx)` directly in upstream/downstream send paths.
- Keep padding checks consistent in both directions and avoid two-layer aliasing.

5. Rework main event loop to bounded pump model
- Introduce constants:
`#define NGX_HTTP_RELAY_MAX_ITERATIONS ...`
`#define RELAY_CHECK_PERIOD ...`
- Replace unbounded relay pumping intent with bounded per-callback iterations.
- Remove `loop_activity`; keep one `activity` flag for timer refresh semantics.
- On every `RELAY_CHECK_PERIOD` iterations, check `ngx_terminate || ngx_quit || ngx_exiting` and return `NGX_DONE` when set.

6. Add completion helper for post-loop decision
- Implement `is_relay_finished(ctx, r, c, pc)` helper that centralizes finish condition:
EOF side state + upload drained + download drained (+ output idle and padding drained as needed).
- Use this helper after the bounded loop to decide `NGX_DONE` vs `NGX_OK`.
- Keep stall wakeup/post-event logic driven by this normalized completion status.

7. Preserve cleanup and lifetime guarantees during refactor
- Ensure no early returns bypass request-body ref release path.
- Keep timer management and event registration behavior unchanged in intent.
- Maintain compatibility with `tunnel_relay_finalize`, `tunnel_relay_close`, posted downstream read cancellation, and cleanup handler idempotency.

8. Verification plan
- Build: `make -C nginx -j4`.
- Config smoke: run nginx test config in local writable paths.
- Functional checks:
  - H2 CONNECT success/relay.
  - upstream reset (`ECONNRESET`) path exits tunnel cleanly.
  - idle timeout path finalizes.
  - graceful shutdown (`SIGTERM`) during active tunnel exits without prolonged worker stall.
- Regression checks:
  - no unexpected timer leaks.
  - no stale posted read events.
  - no request count/lifetime regressions.

9. Delivery format
- Keep refactor commit focused to `src/relay_v2.c` (and only minimal related declarations if strictly necessary).
- Include before/after control-flow summary in commit message:
asymmetric inline recv + unbounded loop -> symmetric helpers + bounded pump + periodic shutdown checks + centralized finish predicate.
