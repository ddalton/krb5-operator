#!/bin/sh
# Start an MIT KDC for $KRB5_REALM, creating its database (with the master
# key $KRB5_MASTER_KEY, from the operator's Secret) on first start. The
# database lives on the pod's volume, /var/lib/krb5kdc; config files are
# mounted by the operator (/etc/krb5kdc/kdc.conf, /etc/krb5.conf).
#
# The operator's admin principal ($KRB5_ADMIN_PRINCIPAL) gets its password
# ($KRB5_ADMIN_PASSWORD) at every start, so the Secret is what counts.
set -eu
: "${KRB5_REALM:?KRB5_REALM is required}"
: "${KRB5_MASTER_KEY:?KRB5_MASTER_KEY is required}"
export KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf
if [ ! -e /var/lib/krb5kdc/principal ]; then
    echo "Creating the database for $KRB5_REALM"
    kdb5_util create -s -r "$KRB5_REALM" -P "$KRB5_MASTER_KEY"
fi
if [ -n "${KRB5_ADMIN_PRINCIPAL:-}" ] && [ -n "${KRB5_ADMIN_PASSWORD:-}" ]; then
    if kadmin.local -r "$KRB5_REALM" -q "getprinc $KRB5_ADMIN_PRINCIPAL" 2>/dev/null | grep -q '^Principal:'; then
        kadmin.local -r "$KRB5_REALM" -q "cpw -pw $KRB5_ADMIN_PASSWORD $KRB5_ADMIN_PRINCIPAL" >/dev/null
    else
        kadmin.local -r "$KRB5_REALM" -q "addprinc -pw $KRB5_ADMIN_PASSWORD $KRB5_ADMIN_PRINCIPAL" >/dev/null
    fi
fi
kadmind -nofork &
exec krb5kdc -n
