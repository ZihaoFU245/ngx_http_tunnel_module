# Tasks

1. Read the `*spec.md` in this folder, for this current phase, do not implement any milestone.
Goto nginx source code folder, which is a fork of official nginx repo. 
In `src/http/ngx_http_core_module.h` `ngx_http_core_srv_conf_t` this struct has a field called
`allow_connect`. And in `src/http/ngx_http_request.c` line 2075-2084 parsing already allows connect method,
while in `ngx_http_v2.c` there is no logic support it and so is v3. You need to make some slight modifications
to enable them. 

- [x] IsCompleted ?

TODO:

- [x] Milestone 1
- [ ] Milestone 2
