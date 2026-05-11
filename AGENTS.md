# Code Style and Format

Code style follows nginx style. There is a `.clang-format`
file, it is recommended to use clang-format.

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

5. Read Refactor section, keey refactor code style

# New job

Add support for connect-ip.

Three new files already created, `connect_ip.c`, `tun.h` and `tun.c`.

Only implement connect ip over HTTP Data frame that is under capsules.

Existing Capsule code is in `capsule.c`, function `tunnel_capsule_*_datagram`
may be reused.

1. Add new config `tunnel_connect_ip`, `tunnel_connect_ip_tun_path`,
a complex value.

Requirements:

- tunnel_connect_ip can be in location { ... } block.
- tunnel_connect_ip_tun_path must be specified, and stored in a complex value.
- `tun.*` code MUST only support Linux now, and in #if (LINUX) #endif blocks.
on other platforms other then linux, it must not be compiled. The flags are
provided nginx, you must not introduce new dependency.
- `tunnel_connect_ip` in location block, then other location blocks must not
accept connect-ip packets. That is under `location /ip-tunnel { tunnel_connect_ip; }`,
connect ip is allowed only in `tunnel_connect_ip` if it is not set in server block.
- `tun.h` declares helper functions to tun related functions. The TUN submodule MUST
not create any `tun`, it MUST be user provided TUN. 
- You MUST NOT implement `connect_ip.c` now, only `tun`.
- `tun` module must not allocate any memory itself. It needs to allocate from nginx
request pool.
- You MUST read nginx core, to check if any reusable components.
- `tun` read SHALL read directly to a provided `ngx_buf_t`, write should be able to
write from chain to `ngx_buf_t`, and send will write to kernel tun.

Be careful:

- Event `ngx_reload` will create new worker process and gracefully shutdown old worker
process. So handle fd carefully, new worker process and old worker process fd.

- read / write provided by linux kernel is blocking. You must use non blocking read write,
if read write is unavailable, it should be cast to return NGX_AGAIN.



