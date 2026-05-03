#!/usr/bin/env sh

set -eu

URL_DEFAULT="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

usage() {
    cat <<'EOF'
Usage:
  hosts_to_map.sh --code <number> [--default <number>] [--url <url>]

Optimized for large lists:
1. Creates a map to strip ports from $connect_target_host.
2. Creates a hash-based map for $target_domain (O(1) lookup speed).
EOF
}

code=""
default_val="1"
url="$URL_DEFAULT"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --code) code="$2"; shift 2 ;;
        --default) default_val="$2"; shift 2 ;;
        --url) url="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$code" ]; then
    echo "Missing required --code <number>" >&2
    usage >&2
    exit 2
fi

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        echo "Need curl or wget" >&2; exit 127
    fi
}

fetch "$url" | awk -v code="$code" -v def="$default_val" '
BEGIN {
    # Block 1: Strip the port into a normalized variable
    print "# Step 1: Extract domain from host:port"
    print "map $connect_target_host $target_domain {"
    print "    ~*^([^:]+)  $1;"
    print "    default     $connect_target_host;"
    print "}\n"

    # Block 2: The high-speed lookup map
    print "# Step 2: High-speed hash lookup (Exact Match)"
    print "map $target_domain $is_granted {"
    print "    hostnames;"
    printf "    default %s;\n\n", def
}
{
    line = $0
    sub(/\r$/, "", line)

    # Preserve comments for readability
    if (line ~ /^[[:space:]]*#/) {
        sub(/^[[:space:]]*/, "", line)
        print "    # " line
        next
    }

    # Clean the line
    sub(/[[:space:]]*#.*/, "", line)
    if (line ~ /^[[:space:]]*$/) next

    n = split(line, f, /[[:space:]]+/)
    # Start from field 2 (skips the IP)
    for (i = 2; i <= n; i++) {
        host = tolower(f[i])
        if (host == "" || host == "localhost" || host == "0.0.0.0") continue

        # No regex symbols here! Just the raw domain for the hash table.
        printf "    %s  %s;\n", host, code
    }
}
END {
    print "}"
}'