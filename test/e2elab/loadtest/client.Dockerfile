# Load-test client image: simulates N independent VPN clients (one per
# network namespace) against a real server provisioned exactly like
# test/e2elab's own lab (see loadtest_test.go). Not systemd-based -- this
# container just needs a long-lived process so `docker exec` can drive
# per-namespace setup and the actual client daemons/processes.
#
#   docker build -f test/e2elab/loadtest/client.Dockerfile \
#     -t protean-loadtest-client .
#
# Run: --privileged (network namespaces + TUN devices), attached to the
# same docker network as the server container (see loadtest_test.go).
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables \
        wireguard-tools \
        openvpn \
        strongswan strongswan-swanctl libcharon-extra-plugins \
        iperf3 curl ca-certificates unzip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Xray-core client binary. The server side installs via the official
# XTLS/Xray-install script (scripts/protean-installer.sh's install_xray),
# which hard-refuses on any non-systemd host ("Only Linux distributions
# using systemd are supported") -- confirmed live, this client container
# has no init system at all (each simulated client just runs xray directly
# as a plain per-namespace process, not a service). Fetch the same release
# build straight from GitHub instead, which is all that installer does
# under the hood before its systemd-specific unit setup.
RUN curl -fsSL -o /tmp/xray.zip \
        https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
    && unzip -o /tmp/xray.zip -d /usr/local/bin xray \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip
RUN test -x /usr/local/bin/xray

CMD ["sleep", "infinity"]
