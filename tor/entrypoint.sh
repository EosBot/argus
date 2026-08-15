#!/bin/sh
set -eu

: "${TOR_CONTROL_PASSWORD:?TOR_CONTROL_PASSWORD is required}"

hashed_password="$(tor --hash-password "$TOR_CONTROL_PASSWORD" 2>/dev/null | tail -n 1)"
test -n "$hashed_password"

umask 077
{
    printf '%s\n' 'ClientOnly 1'
    printf '%s\n' 'AvoidDiskWrites 1'
    printf '%s\n' 'DataDirectory /var/lib/tor'
    printf '%s\n' 'SocksPort 0.0.0.0:9050 IsolateSOCKSAuth'
    printf '%s\n' 'SocksPolicy accept 127.0.0.0/8'
    printf '%s\n' 'SocksPolicy accept 10.0.0.0/8'
    printf '%s\n' 'SocksPolicy accept 172.16.0.0/12'
    printf '%s\n' 'SocksPolicy accept 192.168.0.0/16'
    printf '%s\n' 'SocksPolicy reject *'
    printf '%s\n' 'ControlPort 0.0.0.0:9051'
    printf 'HashedControlPassword %s\n' "$hashed_password"
    printf '%s\n' 'CookieAuthentication 0'
    printf '%s\n' 'Log notice stdout'
} > /tmp/argus-torrc

exec tor -f /tmp/argus-torrc
