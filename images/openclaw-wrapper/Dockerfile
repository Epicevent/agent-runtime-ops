ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG BASE_IMAGE
ARG PRODUCT_IMAGE=""
ARG OPS_REPO_COMMIT=""
ARG RUNTIME_FAMILY="openclaw"
ARG RUNTIME_USER="node"
ARG PRODUCT_COMPONENT=""
ARG RUNTIME_PROFILE_CUSTOMER=""
ARG RUNTIME_PROFILE_DEV=""
ARG RUNTIME_CONTRACT_CUSTOMER=""
ARG RUNTIME_CONTRACT_DEV=""
ARG RUNTIME_COMMAND_MODE=""
ARG RUNTIME_WORKING_DIR=""
ARG RUNTIME_HTTP_PORT=""
ARG RUNTIME_SOURCE_OUTPUT_TARGET=""
ARG RUNTIME_NAS_CONTAINER_ROOT=""
ARG RUNTIME_NAS_HOST_ROOT_TEMPLATE=""
ARG RUNTIME_NAS_READ_ONLY=""
ARG RUNTIME_NAS_PROPAGATION=""
ARG RUNTIME_NAS_CHILD_MOUNT_MODE=""
ARG CANONICAL_RECIPE_NAME=""
ARG CANONICAL_RECIPE_DIGEST=""

LABEL org.opencontainers.image.title="JI TECH OpenClaw runtime wrapper"
LABEL org.opencontainers.image.description="OpenClaw product image wrapped with JI TECH runtime document tooling"
LABEL org.opencontainers.image.family="openclaw"
LABEL org.opencontainers.image.base.name="${BASE_IMAGE}"
LABEL org.opencontainers.image.product.image="${PRODUCT_IMAGE}"
LABEL org.opencontainers.image.revision="${OPS_REPO_COMMIT}"
LABEL com.epicevent.agent-runtime.recipe.schema="v1"
LABEL com.epicevent.agent-runtime.recipe.name="${CANONICAL_RECIPE_NAME}"
LABEL com.epicevent.agent-runtime.recipe.digest="${CANONICAL_RECIPE_DIGEST}"
LABEL com.epicevent.agent-runtime.family="${RUNTIME_FAMILY}"
LABEL com.epicevent.agent-runtime.product-image="${PRODUCT_IMAGE}"
LABEL com.epicevent.agent-runtime.product-component="${PRODUCT_COMPONENT}"
LABEL com.epicevent.agent-runtime.wrapper-component="openclaw-wrapper"
LABEL com.epicevent.agent-runtime.runtime-profile.customer="${RUNTIME_PROFILE_CUSTOMER}"
LABEL com.epicevent.agent-runtime.runtime-profile.dev="${RUNTIME_PROFILE_DEV}"
LABEL com.epicevent.agent-runtime.runtime-contract.customer="${RUNTIME_CONTRACT_CUSTOMER}"
LABEL com.epicevent.agent-runtime.runtime-contract.dev="${RUNTIME_CONTRACT_DEV}"
LABEL com.epicevent.agent-runtime.command-mode="${RUNTIME_COMMAND_MODE}"
LABEL com.epicevent.agent-runtime.working-dir="${RUNTIME_WORKING_DIR}"
LABEL com.epicevent.agent-runtime.http-port="${RUNTIME_HTTP_PORT}"
LABEL com.epicevent.agent-runtime.source-output-target="${RUNTIME_SOURCE_OUTPUT_TARGET}"
LABEL com.epicevent.agent-runtime.nas.container-root="${RUNTIME_NAS_CONTAINER_ROOT}"
LABEL com.epicevent.agent-runtime.nas.host-root-template="${RUNTIME_NAS_HOST_ROOT_TEMPLATE}"
LABEL com.epicevent.agent-runtime.nas.read-only="${RUNTIME_NAS_READ_ONLY}"
LABEL com.epicevent.agent-runtime.nas.propagation="${RUNTIME_NAS_PROPAGATION}"
LABEL com.epicevent.agent-runtime.nas.child-mount-mode="${RUNTIME_NAS_CHILD_MOUNT_MODE}"
LABEL com.epicevent.agent-runtime.ops-repo-commit="${OPS_REPO_COMMIT}"

USER root

COPY images/shared-document-tools/ /usr/local/share/agent-runtime-document-tools/

RUN set -eu; \
    install -d /usr/local/share/agent-runtime-ops; \
    { \
      echo "family=${RUNTIME_FAMILY}"; \
      echo "base_image=${BASE_IMAGE}"; \
      echo "product_image=${PRODUCT_IMAGE}"; \
      echo "product_component=${PRODUCT_COMPONENT}"; \
      echo "runtime_profile_customer=${RUNTIME_PROFILE_CUSTOMER}"; \
      echo "runtime_profile_dev=${RUNTIME_PROFILE_DEV}"; \
      echo "runtime_contract_customer=${RUNTIME_CONTRACT_CUSTOMER}"; \
      echo "runtime_contract_dev=${RUNTIME_CONTRACT_DEV}"; \
      echo "command_mode=${RUNTIME_COMMAND_MODE}"; \
      echo "working_dir=${RUNTIME_WORKING_DIR}"; \
      echo "http_port=${RUNTIME_HTTP_PORT}"; \
      echo "source_output_target=${RUNTIME_SOURCE_OUTPUT_TARGET}"; \
      echo "nas_container_root=${RUNTIME_NAS_CONTAINER_ROOT}"; \
      echo "nas_host_root_template=${RUNTIME_NAS_HOST_ROOT_TEMPLATE}"; \
      echo "nas_read_only=${RUNTIME_NAS_READ_ONLY}"; \
      echo "nas_mount_propagation=${RUNTIME_NAS_PROPAGATION}"; \
      echo "nas_child_mount_mode=${RUNTIME_NAS_CHILD_MOUNT_MODE}"; \
      echo "canonical_recipe_name=${CANONICAL_RECIPE_NAME}"; \
      echo "canonical_recipe_digest=${CANONICAL_RECIPE_DIGEST}"; \
      echo "ops_repo_commit=${OPS_REPO_COMMIT}"; \
    } > /usr/local/share/agent-runtime-ops/wrapper.manifest

USER ${RUNTIME_USER}
