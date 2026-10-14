#!/usr/bin/env bash
# Start a throwaway MIT KDC and kadmind for the live tests (principal.rs,
# `live_`), set up as the KDC image sets up a realm: the operator's admin
# principal krb5-operator/admin with a password, allowed everything by
# kadm5.acl, key extraction included.
#
#   scripts/test-kdc.sh <dir> [port]
#
# Unprivileged: everything lives in <dir>; the KDC listens on <port>
# (default 28888) and kadmind on the next one. Writes <dir>/test.env with
# the KRB5_OPERATOR_TEST_* variables the tests read; kdc.pid holds both
# daemons' process IDs. Needs krb5kdc, kadmind, kdb5_util, kadmin.local.
set -euo pipefail

DIR=$(mkdir -p "$1" && cd "$1" && pwd)
PORT=${2:-28888}
KADMIN_PORT=$((PORT + 1))
REALM=OPERATOR.TEST
PATH=$PATH:/usr/sbin:/usr/local/sbin

if [ -f "$DIR/kdc.pid" ]; then kill $(cat "$DIR/kdc.pid") 2>/dev/null || true; fi
rm -rf "${DIR:?}"/*

cat >"$DIR/krb5.conf" <<CONF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
[realms]
    $REALM = {
        kdc = 127.0.0.1:$PORT
        admin_server = 127.0.0.1:$KADMIN_PORT
    }
CONF
cat >"$DIR/kdc.conf" <<CONF
[kdcdefaults]
    kdc_ports = $PORT
    kdc_tcp_ports = $PORT
[realms]
    $REALM = {
        database_name = $DIR/principal
        key_stash_file = $DIR/stash
        acl_file = $DIR/kadm5.acl
        kadmind_port = $KADMIN_PORT
        kpasswd_port = $((PORT + 2))
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal
    }
[logging]
    kdc = FILE:$DIR/kdc.log
    admin_server = FILE:$DIR/kadmind.log
CONF
echo "krb5-operator/admin@$REALM xe" >"$DIR/kadm5.acl"

export KRB5_CONFIG=$DIR/krb5.conf KRB5_KDC_PROFILE=$DIR/kdc.conf
kdb5_util create -s -r "$REALM" -P masterpw >/dev/null
kadmin.local -r "$REALM" -q "addprinc -pw operatorpw krb5-operator/admin" >/dev/null

krb5kdc -n -r "$REALM" >"$DIR/kdc.out" 2>&1 &
echo $! >"$DIR/kdc.pid"
kadmind -nofork -r "$REALM" >"$DIR/kadmind.out" 2>&1 &
echo $! >>"$DIR/kdc.pid"
for p in "$PORT" "$KADMIN_PORT"; do
    for _ in $(seq 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then break; fi
        sleep 0.1
    done
done

cat >"$DIR/test.env" <<ENV
KRB5_OPERATOR_TEST_REALM=$REALM
KRB5_OPERATOR_TEST_KDC=127.0.0.1:$PORT
KRB5_OPERATOR_TEST_KADMIN=127.0.0.1:$KADMIN_PORT
KRB5_OPERATOR_TEST_PASSWORD=operatorpw
ENV
echo "KDC for $REALM on $PORT, kadmind on $KADMIN_PORT; env in $DIR/test.env"
