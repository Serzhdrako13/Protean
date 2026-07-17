# Test host image, apt family (Debian/Ubuntu/Astra Linux). Build context
# MUST be the repo root (COPY paths below are relative to it):
#
#   docker build -f test/e2elab/dockerfiles/apt.Dockerfile \
#     --build-arg BASE_IMAGE=debian:12 -t protean-e2elab:apt-debian12 .
#
# Run: see test/e2elab/README.md (--privileged --cgroupns=host, etc).
#
# Installs OpenVPN/IKEv2/Xray/WireGuard/AmneziaWG via the REAL
# scripts/protean-installer.sh `install` verb -- exactly what a real "Set
# up" click runs on this distro family, not a hand-copied package list that
# could silently drift from it.
ARG BASE_IMAGE=debian:12
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        openssh-server sudo curl ca-certificates unzip \
        iproute2 iptables procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY scripts/protean-installer.sh /usr/local/lib/protean/protean-installer.sh
RUN chmod 755 /usr/local/lib/protean/protean-installer.sh
COPY test/e2elab/dockerfiles/install-all.sh /tmp/install-all.sh
RUN bash /tmp/install-all.sh && rm /tmp/install-all.sh

# Standard systemd-as-PID1-in-Docker recipe: mask units that don't make
# sense (or fail loudly) inside a container.
RUN systemctl mask systemd-udevd.service systemd-udevd-control.socket \
        systemd-udevd-kernel.socket getty.target getty-static.service \
        console-getty.service systemd-remount-fs.service

RUN mkdir -p /var/run/sshd && systemctl enable ssh

# ci-bootstrap: the identity sshexec.BootstrapHost connects as. Separate
# from the "protean" service account that bootstrap itself creates on
# first use -- this one only ever exists to stand that account up.
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
