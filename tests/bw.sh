#!/bin/bash

set -o pipefail

REPO=$1
if [[ ! $BWRAP_NOREPO ]] ; then
    [[ -d $REPO ]] || exit 1
    shift
fi

declare -x BWRAPPED=1

[[ $USER ]] || { USER=$(id -un); export USER; }
[[ $HOSTNAME ]] || { HOSTNAME=$(hostname -f); export HOSTNAME; }
if [[ ! $HOME ]]; then
    HOME=/home/$USER
    if [[ ! -d $HOME ]]; then
        exit 2
    fi
    export HOME
fi
#                                                     shellcheck disable=SC2206
bwrap_args=(
    $XTRA_BWRAP_ARGS
    --bind    "/tmp/pytest-of-$USER" "/tmp/pytest-of-$USER"
)

one2one_ro=(
    "$REPO"
    "${HOME:-__fake__}/.config/git"

    /etc/os-release
    /etc/resolv.conf
    /etc/hostname
    /etc/hosts
    /etc/nsswitch.conf
    /etc/pki
    /etc/ssl/certs
    /etc/ca-certificates

    /etc/gitconfig
    /etc/bash_completion.d
    /etc/profile.d
    /etc/profile
)

for p in "${one2one_ro[@]}"; do
    if [[ -r "$p" ]]; then
        bwrap_args+=( --ro-bind "$p" "$p" )
    fi
done

if (( $# )); then
    CMD=( "$@" )
else
    CMD=( bash -i )
fi

(exec bwrap --ro-bind /usr /usr \
        --dir /tmp \
        --dir /var \
        --symlink /tmp /var/tmp \
        --proc /proc \
        --dev /dev \
        --symlink /usr/lib /lib \
        --symlink /usr/lib64 /lib64 \
        --symlink /usr/bin /bin \
        --symlink /usr/sbin /sbin \
        --dir "$HOME" \
        --args 14 \
        --unshare-all \
        --hostname "$HOSTNAME" \
        --share-net \
        --dir "/run/user/${UID:-$(id -u)}" \
        --setenv XDG_CONFIG_HOME "$HOME/.config" \
        --setenv XDG_RUNTIME_DIR "/run/user/${UID:-$(id -u)}" \
        --setenv GIT_PAGER "$(command -v cat)" \
        --die-with-parent \
        --file 11 /etc/passwd \
        --file 12 /etc/group \
        --file 13 "$HOME/.curlrc" \
        "${CMD[@]}") \
    11< <(printf '%s\n' "$(getent passwd ${UID:-$(id -u)})") \
    12< <(getent group "${GID:-$(id -g)}" 65534) \
    13< <(printf '%s\n' 'capath=/etc/ssl/certs') \
    14< <(printf '%s\0' "${bwrap_args[@]}")

