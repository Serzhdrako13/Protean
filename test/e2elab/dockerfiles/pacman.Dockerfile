# Test host image, pacman family (Arch Linux). Build context MUST be the
# repo root:
#
#   docker build -f test/e2elab/dockerfiles/pacman.Dockerfile \
#     -t protean-e2elab:pacman-arch .
ARG BASE_IMAGE=archlinux:latest
FROM ${BASE_IMAGE}

RUN pacman -Sy --noconfirm --needed \
        systemd systemd-sysvcompat \
        openssh sudo dbus curl ca-certificates unzip \
        iproute2 iptables procps-ng

COPY scripts/protean-installer.sh /usr/local/lib/protean/protean-installer.sh
RUN chmod 755 /usr/local/lib/protean/protean-installer.sh
COPY test/e2elab/dockerfiles/install-all.sh /tmp/install-all.sh
RUN bash /tmp/install-all.sh && rm /tmp/install-all.sh

# systemd-networkd-wait-online is enabled by Arch's systemd package by
# default and spins until its own timeout inside a container -- it never
# sees Docker's externally-configured veth as "online" (networkd doesn't
# manage it), which otherwise blocks anything Wants=network-online.target
# (e.g. openvpn-server@.service) from starting for ~2 minutes. Confirmed
# live: systemctl list-jobs showed it stuck "running" indefinitely.
RUN systemctl mask systemd-udevd.service systemd-udevd-control.socket \
        systemd-udevd-kernel.socket getty.target getty-static.service \
        console-getty.service systemd-remount-fs.service \
        systemd-networkd-wait-online.service

RUN mkdir -p /var/run/sshd && systemctl enable sshd

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
