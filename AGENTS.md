# Code Style and Format

Follow nginx code style. Do not format any code.

# Refactor Guide

If the request is refactoring a file:

1. Core functions that are exposed to other files should
start with `tunnel_`

2. If functions are not helper functions, they must not start
with `tunnel_`, instead it should be context specific name.

3. In a file, core function, starts with `tunnel_` must
appear on top. All helper function must be placed below
core functions.

4. Helper function that are only used in current file, should
have flags `static` or `ngx_inline` according to actual functions.

5. Help functions with `ngx_inline` that needs to be used across
module, should be placed in header file.

6. Refactor must not change original logic and data path.

7. Newly added data types, first consider weather it should be added
in header file, instead scattered everywhere in source file.

# New Feature Guide

1. Must read already written files, must not edit files
just based on search query results.

2. Must not edit if you are unclear about the data flow

3. You must never assume. You must find concrete reason before
editing.

4. Follow nginx code style, and follow refactor code style.

5. Read Refactor section, keep refactor code style

# New job


Commit: 3e2f10eaf99a0c44cb5e6cfe36171df12dc16ea6

This commit is not clean:

1. A filter is holding pc->send operation, which is too powerful
2. The send operation lies in relay.c and capsule filter, duplicated code

Some fixes are good:

1. Capsule protocol contains upper case letters are fixed
2. Reduce default buffer size

TODO:

1. Some flags in tunnel context needs to consider removed,
`ctx->connected`: Only used in relay.c and padding.c and seems redundant
`ctx->cleanup_added`: Only in relay.c, and set but never checked.
Check these flags, if it is redundant remove them.

2. relay filter should remain transforming data. It could be done like this:
Because the buffer is configurable and we don't want to reject datagrams if it
exceeds the buffer size. So we send chains directly. Look at current relay
send_upstream, it has branching, if has filter we send chains, if not we
send upstream_buffer. This is a little complex. We could introduce a flag
`use_chain` a bit field, in tunnel context. So the filter can cleanly deduce
weather to use upstream_buffer or downstream_in. We also need a uint type for
recording the amount we send, call it `flush_size`. This is only used when we
need to control the amount of data to send. ie. In capsule, we shall set
use_chain and set flush_size to capsule payload size. Datagram needs to
be flushed in once, so a flag `upstream_flush` is needed, if upstream type is
stream, then this is always 1.

3. See relay recv_upstream, it checks if padding is active, and reserves max
padding size. We can actually add an entry in tunnel context called `buffer_tail_reserve`,
not downstream buffer tail reserve. Because upstream buffer, will soon be
deprecated, and there is no need to use upstream buffer. In recv_upstream,
it would reserve this amount of data, if it is 0, ignore the reserve check operation.
In padding, it will set this value to max padding size. And when padding filter
remove itself, it should set this value to 0.

4. Minor fix: in relay
```c
    if (!ctx->read_again_event_posted &&
        ((datagram &&
          ctx->upstream_buffer->pos == ctx->upstream_buffer->last) ||
         (!datagram && upload_drained)) &&
        r->reading_body && !ctx->downstream_eof && !pc->read->eof) {
        tunnel_relay_post_downstream_read(ctx);
    }
```
This is the condition to post an event. Should we also check if !activity?
This can avoid busy spinning. The condition checking is a little complicated,
separate them in different lines and between them, could add some comments
for clarification.

On finish these TODOs, total LOC should expect a reduction. Remove unused
helper functions, and codes. Avoid adding small helper functions, it can be
inlined in functions, or done with macro.
