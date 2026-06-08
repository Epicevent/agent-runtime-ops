ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG PRODUCT_IMAGE=""
ARG OPS_REPO_COMMIT=""
ARG RUNTIME_FAMILY="openclaw"

LABEL org.opencontainers.image.title="JI TECH OpenClaw runtime wrapper"
LABEL org.opencontainers.image.description="OpenClaw product image wrapped with JI TECH runtime document tooling"
LABEL org.opencontainers.image.family="openclaw"
LABEL org.opencontainers.image.base.name="${BASE_IMAGE}"
LABEL org.opencontainers.image.product.image="${PRODUCT_IMAGE}"
LABEL org.opencontainers.image.revision="${OPS_REPO_COMMIT}"

COPY images/shared-document-tools/ /usr/local/share/agent-runtime-document-tools/

RUN set -eu; \
    install -d /usr/local/share/agent-runtime-ops; \
    { \
      echo "family=${RUNTIME_FAMILY}"; \
      echo "base_image=${BASE_IMAGE}"; \
      echo "product_image=${PRODUCT_IMAGE}"; \
      echo "ops_repo_commit=${OPS_REPO_COMMIT}"; \
    } > /usr/local/share/agent-runtime-ops/wrapper.manifest

