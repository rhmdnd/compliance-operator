FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:v1.22 as builder

WORKDIR /go/src/github.com/ComplianceAsCode/compliance-operator

ENV GOFLAGS="-mod=vendor" BUILD_FLAGS="-tags strictfipsruntime"

COPY . .

RUN subscription-manager register --org $(cat "/activation-key/org") --activationkey $(cat "/activation-key/activationkey")

RUN make manager

FROM registry.redhat.io/ubi9/ubi:latest

RUN INSTALL_PKGS="tar" && \
    if [ ! -e /usr/bin/dnf ]; then ln -s /usr/bin/microdnf /usr/bin/dnf; fi && \
        dnf update glibc -y && \
        dnf install -y --setopt=tsflags=nodocs $INSTALL_PKGS && \
        dnf clean all && rm -rf /var/cache/*

LABEL \
        io.k8s.display-name="OpenShift Compliance Operator" \
        io.k8s.description="An operator that performs compliance scanning and remediation on a cluster." \
        io.openshift.tags="openshift,compliance,security" \
        com.redhat.delivery.appregistry="false" \
        maintainer="Red Hat ISC <isc-team@redhat.com>" \
        License="GPLv2+" \
        name="openshift-compliance-operator" \
        com.redhat.component="openshift-compliance-operator-container" \
        io.openshift.maintainer.product="OpenShift Container Platform" \
        io.openshift.maintainer.component="Compliance Operator" \
        version=1.6.1-dev

ENV OPERATOR=/usr/local/bin/compliance-operator \
    USER_UID=1001 \
    USER_NAME=compliance-operator

COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/_output/bin/compliance-operator ${OPERATOR}
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/build/bin /usr/local/bin
# This is required for the bundle build.
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/bundle /bundle
RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
