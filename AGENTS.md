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

# New Feature Guide

1. Must read already written files, must not edit files
just based on search query results.

2. Must not edit if you are unclear about the data flow

3. You must never assume. You must find concrete reason before
editing.

4. Follow nginx code style, and follow refactor code style.

# New job

Implement ACL feature for tunnel module. 

The tunnel module is already relying on nginx http upstream
module, so we further reuse upstream stack.

A. add new config directive in core, that is
`tunnel_acl_allow` and `tunnel_acl_deny`

They should be use like this:

```nginx
upstream (allow / deny) {
    server backend1.example.com       weight=5;
    server backend2.example.com:8080;
    server unix:/tmp/backend3;

    server backup1.example.com:8080   backup;
    server backup2.example.com:8080   backup;
}
```

We ignore the weight and backup hints. Uses upstream to help us parse
the allow deny list.

Use in tunnel config,

```nginx
tunnel_acl_allow allowed;
tunnel_acl_deny denied;
```

B. add a new function called, `ngx_http_tunnel_eval`. It
is invoked in content phase. You would need to alter the order
functions invoked in content handler. 

Option1: content handler first init upstream and parse target,
then invoke eval. Finally allocate buffer memory.

Option2: Eval is invoked in process header. At this stage,
upstream is fully done, DNS is resolved. Before tunnel
start, we invoke eval. And of course, we don't want to
allocate resources before eval, so in content phase we can
register a allocation handler, allocate buffer just before
process header invokes `tunnel_relay_start` or we can defer
allocation after 200 is send. 

Defer after 200 is send, I think is the best idea. Allocation
takes time, we can put allocation after 200 is send, utilize
this waiting time.

If eval returned NGX_OK, it does nothing, continue request
processing. If returned other return code, like NGX_ERROR,
the requests should be finalized with 403, if acl not allowed.


