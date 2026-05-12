# ngx_http_tunnel_module relay refactor plan

## Goal

Use `ngx_http_tunnel_module/src/relay.c` as the only event loop for byte relay
tunnels.

`udp_relay.c` currently duplicates the relay loop and most recv/send mechanics
because CONNECT-UDP needs capsule decode/encode while CONNECT padding currently
preempts the plain recv/send path. The target design is one relay loop that
moves bytes through chain-owned queues and calls protocol-specific handlers as
filters.

## Current Shape

- `relay.c` owns the TCP CONNECT relay loop:
  - downstream HTTP request body chain -> `ctx->upstream_buffer` -> upstream
    socket
  - upstream socket -> `ctx->client_buffer` -> HTTP output filter
  - padding is special-cased inside `send_upstream()` and `recv_upstream()`
- `udp_relay.c` owns a second loop:
  - downstream HTTP request body chain -> capsule decode ->
    `ctx->upstream_buffer` -> upstream UDP/TCP peer socket
  - upstream socket -> capsule encode in `ctx->client_buffer` -> HTTP output
    filter
- `ctx->downstream_chain` is already chain-based, but both upload output and
  download output collapse into a single `ngx_buf_t`.
- Padding and capsule currently need header reservation or direct buffer
  cursor ownership because the loop operates on one mutable buffer at a time.

## Design Principles

- The relay loop owns event readiness, timers, shutdown, finalization, and
  progress detection.
- Protocol behavior is expressed as handlers plugged into the loop.
- Filters transform data without taking ownership of the underlying input
  chain unless they explicitly consume bytes by advancing buffer cursors.
- Ownership remains simple:
  - recv stages append chains into direction queues
  - filters consume from input queues and append to output queues
  - send stages consume from output queues
  - consumed chain links are freed by relay utilities
- No behavioral migration should combine loop unification and protocol format
  changes in the same patch.

## Make Relay Directions Chain-Based

Replace the single-buffer mental model with named queues in
`ngx_http_tunnel_ctx_t`.

Proposed fields:

```c
ngx_chain_t *downstream_in;
ngx_chain_t *downstream_out;
ngx_chain_t *upstream_in;
ngx_chain_t *upstream_out;
```

Mapping:

- `downstream_in`: bytes read from HTTP request body.
- `upstream_out`: bytes ready to send to the upstream peer.
- `upstream_in`: bytes read from the upstream peer.
- `downstream_out`: bytes ready for `ngx_http_output_filter()`.

MUST NOT keep `client_buffer` and `upstream_buffer`. As this is a refactor job,
and should purge unwanted parts.

downstream in is the nginx request body chain, recv down stream is to make this chain
ready. 

```c
ngx_int_t (*downstream_filter)(ngx_http_tunnel_ctx_t *ctx,
                                   ngx_uint_t *activity,
                                   ngx_chain_t downstream_in,
                                   ngx_chain_t upstream_out);
ngx_int_t (*upstream_filter)(ngx_http_tunnel_ctx_t *ctx,
                                 ngx_uint_t *activity,
                                 ngx_chain_t upstream_in,
                                 ngx_chain_t downstream_out);
```

Use filter ideas. downstream_filter is a template for padding and capsules.
The filter can return `NGX_AGAIN` if data is not enough, `NGX_ERROR` when there
is an error. `NGX_DONE` when it is finished, the step is done, caller functions
should return. `NGX_OK` when it's operation is finished, and caller function may
continue without return.

Caller function: Functions that call filters should be send_downstream and
send_upstream. It should not be in recv downstream and recv upstream, as they only
prepare the data.

The UDP path can be merged into relay.c, the upstream init is very similar
only upstream type is set to `SOCK_DGRAM`.And relay.c can be generic byte relay,
padding decode / encode, can be able to fit into a filter, and so is capsule
decode / encode. 

The padding state machine for decoding may be deprecated. Padded data is in the
shape of. Header 3 bytes, first 2 for payload size and 1 for padded zeros. filter
can utilize `AGAIN` event to decode it at once. So no need for a complex state machine.

Encode padded data and capsule is an inplace buffer operation, which reserve header bytes
first. As we are using chain, it can be simplified a lot. chain is a linked list, head
insertion is very simple.

capsule encode / decode datagram can be refactored into filter style. and so is
padded data encode / decode.

