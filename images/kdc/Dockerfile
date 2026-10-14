# MIT Kerberos KDC and kadmind, as the krb5-operator runs them (and the
# client tools, kinit and klist, for checking keytabs).
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-user \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/kdc-entrypoint
EXPOSE 88/tcp 88/udp 749/tcp
ENTRYPOINT ["/usr/local/bin/kdc-entrypoint"]
