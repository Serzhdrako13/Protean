# Test host image, ALT Linux (Timeweb-only offering). Genuinely
# experimental: ALT's apt-get-over-rpm hybrid has no OS_FAMILY case in
# protean-installer.sh's detect_os today, so this is expected to hit
# "unsupported: no known package manager" at the install step rather than
# actually working -- built and attempted honestly (see
# test/e2elab/README.md for the actual outcome), not silently skipped, but
# also not a target this pass promises to fix.
#
#   docker build -f test/e2elab/dockerfiles/altlinux.Dockerfile \
#     -t protean-e2elab:altlinux .
ARG BASE_IMAGE=alt:p10
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y \
        systemd \
        openssh-server sudo dbus curl ca-certificates unzip \
        iproute2 iptables procps \
    || true

COPY scripts/protean-installer.sh /usr/local/lib/protean/protean-installer.sh
RUN chmod 755 /usr/local/lib/protean/protean-installer.sh
COPY test/e2elab/dockerfiles/install-all.sh /tmp/install-all.sh
# Expected to fail (see header comment) -- `|| true` so the image still
# builds far enough to report the actual failure mode via lab_test.go
# rather than aborting at image-build time.
RUN bash /tmp/install-all.sh; rm /tmp/install-all.sh

RUN systemctl mask systemd-udevd.service systemd-udevd-control.socket \
        systemd-udevd-kernel.socket getty.target getty-static.service \
        console-getty.service systemd-remount-fs.service || true

RUN mkdir -p /var/run/sshd && systemctl enable sshd || true

# ALT's sudo refuses to run at all if ANY file under sudoers.d fails its
# strict 0400 mode check -- confirmed live: the base image ships its own
# /etc/sudoers.d/99-sudopw at 0500, which alone was enough to block sudo
# entirely ("Permission denied") even with ci-bootstrap's own file correct.
RUN chmod 400 /etc/sudoers.d/*
# -G wheel: /usr/bin/sudo itself is mode 4750 root:wheel on ALT (not
# world-executable like on the other families here) -- confirmed live,
# ci-bootstrap couldn't even exec sudo ("Permission denied") without
# group membership, independent of the sudoers.d rule itself being valid.
RUN useradd -m -s /bin/bash -G wheel ci-bootstrap \
    && echo "ci-bootstrap ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ci-bootstrap \
    && chmod 400 /etc/sudoers.d/ci-bootstrap \
    && mkdir -p /home/ci-bootstrap/.ssh \
    && chmod 700 /home/ci-bootstrap/.ssh
COPY test/e2elab/testkey.pub /home/ci-bootstrap/.ssh/authorized_keys
RUN chown -R ci-bootstrap:ci-bootstrap /home/ci-bootstrap/.ssh \
    && chmod 600 /home/ci-bootstrap/.ssh/authorized_keys

STOPSIGNAL SIGRTMIN+3
# ALT doesn't ship the usual /sbin/init compat symlink -- confirmed live,
# only the real binary at /lib/systemd/systemd exists.
CMD ["/lib/systemd/systemd"]
