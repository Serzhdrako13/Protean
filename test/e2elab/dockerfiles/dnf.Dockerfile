# Test host image, dnf/yum family (RHEL-likes: CentOS Stream, Rocky,
# AlmaLinux, Fedora). Build context MUST be the repo root:
#
#   docker build -f test/e2elab/dockerfiles/dnf.Dockerfile \
#     --build-arg BASE_IMAGE=rockylinux:9 -t protean-e2elab:dnf-rocky9 .
#
# See apt.Dockerfile for the shared rationale (real protean-installer.sh
# install verb, not a hand-copied package list).
ARG BASE_IMAGE=rockylinux:9
FROM ${BASE_IMAGE}

# --allowerasing: RHEL9-family minimal base images ship curl-minimal, which
# conflicts with the full curl package -- confirmed live on rockylinux:9.
RUN dnf install -y --allowerasing \
        systemd \
        openssh-server sudo dbus curl ca-certificates unzip \
        iproute iptables procps-ng \
    && dnf clean all

COPY scripts/protean-installer.sh /usr/local/lib/protean/protean-installer.sh
RUN chmod 755 /usr/local/lib/protean/protean-installer.sh
COPY test/e2elab/dockerfiles/install-all.sh /tmp/install-all.sh
RUN bash /tmp/install-all.sh && rm /tmp/install-all.sh

RUN systemctl mask systemd-udevd.service systemd-udevd-control.socket \
        systemd-udevd-kernel.socket getty.target getty-static.service \
        console-getty.service systemd-remount-fs.service

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
