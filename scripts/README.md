This directory stores scripts to convert common blocklist 
into Nginx maps.

- `hosts_to_map.1.sh` : converts [StevenBlack Hosts](https://github.com/StevenBlack/hosts)

Usage:

`/path/to/script/*.sh --code 0 > blocklist.map`,
code can be 0-3, see README for details about the code number.

> [!WARNING]
> A large map can drag down nginx performance a lot

You may need to set `map_hash_max_size 200000;` and
`map_hash_bucket_size 256;` to get an optimal hash table.
As nginx map is lazy loaded, this can slow down nginx
very much. This is just an experimental feature,
it recommended to set up a custom DNS resovler alongside
nginx, and set `resovler` to achieve similar features.

Performance tuning: If you want to use a relatively large
map. `$connect_target_host` is raw authority, you may want
to extract the port field first, this takes O(1), then pass
to your map, this keeps lookup in O(1). If you only used 1
hashmap and contains regex in every key, then it will take
nginx O(n) to traversal. See example below:

```nginx
# This standardize the hostname
map $connect_target_host $target_domain {
    ~*^([^:]+)  $1;
    default     $connect_target_host;
}

map $target_domain $is_granted {
    # Omitted
}

server {
    tunnel_acl_eval_on $is_granted;
}
```
