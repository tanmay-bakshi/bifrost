ARG BIFROST_IMAGE=bifrost:e2e
FROM ${BIFROST_IMAGE} AS bifrost

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        dbus \
        iproute2 \
        netcat-openbsd \
        systemd-resolved \
        wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bifrost /usr/local/bin/bifrost /usr/local/bin/bifrost
COPY tools/vpn_e2e_consumer_entrypoint.sh /usr/local/bin/vpn-e2e-consumer-entrypoint

RUN chmod 0755 /usr/local/bin/vpn-e2e-consumer-entrypoint

WORKDIR /support-workspace
ENTRYPOINT ["/usr/local/bin/vpn-e2e-consumer-entrypoint"]
