set -u
umask 077

action=${1-}
name=${2-}
marker='# Managed by Wren; removed on disconnect.'

case $action in
up | down) ;;
*)
    echo "wren-tunnel: unknown action '$action'" >&2
    exit 2
    ;;
esac
if [[ ! $name =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]; then
    echo "wren-tunnel: invalid tunnel name '$name'" >&2
    exit 2
fi

dir=/etc/wireguard
conf=$dir/$name.conf

# Never clobber a config the user placed in /etc/wireguard themselves.
if [[ -e $conf || -L $conf ]]; then
    IFS= read -r first <"$conf" || first=
    if [[ $first != "$marker" ]]; then
        echo "wren-tunnel: $conf already exists and is not managed by Wren" >&2
        exit 1
    fi
fi

mkdir -p -m 700 "$dir" || exit 1
tmp=$(mktemp "$dir/.wren-$name.XXXXXX") || exit 1
if ! { printf '%s\n' "$marker" && cat; } >"$tmp" || ! mv -f "$tmp" "$conf"; then
    rm -f "$tmp"
    exit 1
fi

wg-quick "$action" "$conf"
rc=$?
if [[ $action == down || $rc -ne 0 ]]; then
    rm -f "$conf"
fi
exit "$rc"
