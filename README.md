# Nginx HTTP Tunnel Module

This provides a subset features of HTTP CONNECT,
it does not support Extended Connect yet.

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