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

Read existing `acl.c` implementation, it is using upstream {...}
directive, with an exact match style. 

This new job is refactoring:

1. The old upstream {...} needs to be removed, as it is clumsy

2. Adopt nginx map directive.

3. Add new variable $connect_target_host, which contains the connect target
host:port, or sometimes only host:

```log
127.0.0.1 - - [03/May/2026:07:00:46 +0000] "CONNECT 176.58.88.183 HTTP/2.0" 499 0 "-" "-"
127.0.0.1 - - [03/May/2026:07:00:46 +0000] "CONNECT 185.40.234.176 HTTP/2.0" 499 0 "-" "-"
127.0.0.1 - - [03/May/2026:07:00:46 +0000] "CONNECT 208.83.233.233 HTTP/2.0" 499 0 "-" "-"
127.0.0.1 - - [03/May/2026:07:00:46 +0000] "CONNECT 185.34.3.207 HTTP/2.0" 499 0 "-" "-"
127.0.0.1 - - [03/May/2026:07:00:46 +0000] "CONNECT 172.237.28.183 HTTP/2.0" 499 0 "-" "-"
127.0.0.1 - - [03/May/2026:07:01:15 +0000] "CONNECT 192.200.0.101 HTTP/2.0" 200 2533 "-" "-"
127.0.0.1 - - [03/May/2026:07:01:17 +0000] "CONNECT 192.73.243.141 HTTP/2.0" 200 3654 "-" "-"
127.0.0.1 - - [03/May/2026:07:01:18 +0000] "CONNECT 104.248.8.210 HTTP/2.0" 200 3400 "-" "-"
```

Some logs.

4. In current version, url parsing is duplicated, in `acl.c`, function
`acl_parse_target` it parsed and in `connect.c` function `tunnel_connect_parse_target`
parsed again. Now in PREACCESS Phase, the target is parsed and stored in 
`$connect_target_host` and in content phase, only check if it is non NULL.

5. Add another variable called `$tunnel_acl_is_granted`, which is converted to
ngx_uint_t, an unsigned int.

0: access deny, strictly no log
1: access granted, strictly no log
2: access deny + ngx log
3: access grant + ngx log

A state machine switch case can be considered in implementation.

Consider config:

```nginx
map $tunnel_target_host $tunnel_acl_is_granted {
    hostnames;
    default 1;

    .ads.com      0;  # deny
    .malware.com  2;  # deny + log
}
```

Later in a server block:

```nginx
server {
    tunnel_pass;
    tunnel_acl_eval_on $tunnel_acl_is_granted;
}
```

6. This is a refactor job, so everything should be optimized to shortest
path, no stack on top. What needs to be removed, must be removed, no warpping
allowed.

7. This should expect a reduction is total LOC. As hash table and matching is
handoff to nginx map structure.
