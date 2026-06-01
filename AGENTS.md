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
