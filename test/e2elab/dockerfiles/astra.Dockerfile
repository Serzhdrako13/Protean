# Test host image, Astra Linux (Timeweb-only). Astra Common Edition 2.12 is
# Debian-based but has no official Docker image -- built here via
# debootstrap straight from Astra's own public package repository (no
# registration needed), same technique the community reference image
# (nikolai2038/astralinux) uses. Build context MUST be the repo root:
#
#   docker build -f test/e2elab/dockerfiles/astra.Dockerfile -t protean-e2elab:astra .
#
# Astra's repo is signed with its own key, not Debian's -- debootstrap
# only ships Debian's own keyring, so this bootstraps with
# --no-check-gpg. That's a real trust reduction, acceptable here because
# this produces a throwaway CI/test-only container (verifying the panel's
# install logic works, not a production trust boundary) -- not something
# to do for a real deployment image.
FROM debian:12 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        debootstrap ca-certificates \
    && apt-get clean
# debootstrap has no built-in script for Astra's "orel" suite name (it
# only ships Debian's own codenames) -- aliasing it to bookworm's script
# is the standard trick for bootstrapping a Debian derivative debootstrap
# doesn't know about; confirmed live that Astra's actual package set
# resolves and installs fine through it regardless (its own repo metadata
# drives what actually gets pulled, the script mostly affects internal
# defaults).
RUN ln -s /usr/share/debootstrap/scripts/bookworm /usr/share/debootstrap/scripts/orel
RUN mkdir -p /rootfs && debootstrap --arch=amd64 --variant=minbase --no-check-gpg \
        orel /rootfs https://dl.astralinux.ru/astra/frozen/2.12_x86-64/2.12.46/repository/
# Point the rootfs's own apt at the same repo (debootstrap only used it
# for the initial bootstrap) so the final stage's package installs
# resolve against Astra, not nothing -- and carry the same unauthenticated
# trust posture forward, since Astra's repo is still unsigned-by-Debian's-
# keyring from apt's perspective either way. Plain http, not https: a
# minbase debootstrap has no apt-transport-https method driver yet
# (confirmed live -- "method driver /usr/lib/apt/methods/https could not
# be found"), and Astra's own docs list HTTP as an equally valid protocol
# for this same repository.
RUN echo "deb [trusted=yes] http://dl.astralinux.ru/astra/frozen/2.12_x86-64/2.12.46/repository/ orel main contrib non-free" \
        > /rootfs/etc/apt/sources.list

FROM scratch
COPY --from=builder /rootfs /

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        openssh-server sudo curl ca-certificates unzip \
        iproute2 iptables procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY scripts/protean-installer.sh /usr/local/lib/protean/protean-installer.sh
RUN chmod 755 /usr/local/lib/protean/protean-installer.sh
COPY test/e2elab/dockerfiles/install-all.sh /tmp/install-all.sh
RUN bash /tmp/install-all.sh && rm /tmp/install-all.sh

RUN systemctl mask systemd-udevd.service systemd-udevd-control.socket \
        systemd-udevd-kernel.socket getty.target getty-static.service \
        console-getty.service systemd-remount-fs.service

RUN mkdir -p /var/run/sshd && systemctl enable ssh

RUN useradd -m -s /bin/bash ci-bootstrap \
    && echo "ci-bootstrap ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ci-bootstrap \
    && chmod 440 /etc/sudoers.d/ci-bootstrap \
    && mkdir -p /home/ci-bootstrap/.ssh \
    && chmod 700 /home/ci-bootstrap/.ssh
COPY test/e2elab/testkey.pub /home/ci-bootstrap/.ssh/authorized_keys
RUN chown -R ci-bootstrap:ci-bootstrap /home/ci-bootstrap/.ssh \
    && chmod 600 /home/ci-bootstrap/.ssh/authorized_keys

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
