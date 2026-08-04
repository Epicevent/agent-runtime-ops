services:
  openclaw-gateway:
    image: "{{ image_ref }}"
    restart: unless-stopped
    env_file:
      - .env
      - "{{ target_home }}/.hermes/.env"
    environment:
      JITECH_RETRIEVAL_ENABLED: "{{ retrieval_enabled }}"
      JITECH_RETRIEVAL_COMPONENT_DIGEST: "{{ retrieval_component_digest }}"
      JITECH_RETRIEVAL_BINDING_DIGEST: "{{ retrieval_binding_digest }}"
      JITECH_RETRIEVAL_RESOURCE_PROFILE_DIGEST: "{{ retrieval_resource_profile_digest }}"
      HERMES_HOME: /opt/data
      HERMES_HOME_MODE: "0750"
      HERMES_DATA_DIR: /opt/data
      HERMES_WORKSPACE_DIR: /workspace
      HERMES_API_URL: http://127.0.0.1:8642
      HERMES_DASHBOARD_URL: http://127.0.0.1:9119
      HERMES_DASHBOARD: "1"
      HERMES_DASHBOARD_HOST: 127.0.0.1
      HERMES_DASHBOARD_PORT: "9119"
      HERMES_DASHBOARD_INSECURE: "1"
      API_SERVER_ENABLED: "true"
      API_SERVER_HOST: 127.0.0.1
      API_SERVER_KEY: ${API_SERVER_KEY}
      HERMES_API_TOKEN: ${API_SERVER_KEY}
      OPENCLAW_NAS_CONTAINER_PATH: /workspace/nas_docs
      HERMES_UID: "{{ runtime_uid }}"
      HERMES_GID: "{{ runtime_gid }}"
      OPENCLAW_NAS_DATA_GID: "{{ data_gid }}"
      HOME: /opt/data
      HOST: 0.0.0.0
      PORT: "3000"
      COOKIE_SECURE: "1"
      TRUST_PROXY: "1"
      LANG: ko_KR.UTF-8
      LANGUAGE: ko_KR:ko
      LC_ALL: ko_KR.UTF-8
    ports:
      - "127.0.0.1:{{ gateway_port }}:3000"
    labels:
      agent-runtime.instance-id: "{{ instance_id }}"
      agent-runtime.linux-account: "{{ linux_account }}"
      agent-runtime.slot: "{{ slot }}"
      agent-runtime.family: "{{ family }}"
      agent-runtime.profile: "{{ runtime_profile }}"
      agent-runtime.service: gateway
      agent-runtime.retrieval-enabled: "{{ retrieval_enabled }}"
      agent-runtime.retrieval-component-digest: "{{ retrieval_component_digest }}"
      agent-runtime.retrieval-binding-digest: "{{ retrieval_binding_digest }}"
      agent-runtime.retrieval-resource-profile-digest: "{{ retrieval_resource_profile_digest }}"
    group_add:
      - "{{ data_gid }}"
    volumes:
      - "{{ target_home }}/.hermes:/opt/data"
{% if retrieval_attachment_capable %}
      - type: bind
        source: "{{ target_home }}/.hermes/agent-runtime/kwrag-p1-state/{{ retrieval_binding_path_component }}"
        target: /opt/data/kwrag-p1-attachment
{% endif %}
      - "{{ target_home }}/.hermes/workspace:/workspace"
      - "{{ source_output }}:/opt/hermes-workspace:ro"
      # corpus (read-only knowledge): single-intent tree. read_only here is a
      # defense-in-depth second lock — the source mount / ro account is the
      # primary authority. Safe to stamp because nothing writable lives under it.
      - type: bind
        source: "{{ target_home }}/nas_docs"
        target: /workspace/nas_docs
        read_only: true
        bind:
          propagation: rslave
      # workspace (OCN): the agent's OWN writable area — a different KIND than
      # corpus, so a separate mount, never under the read-only tree. No
      # read_only; mode is rw from its source. Requires OCN mounted host-side at
      # {{ target_home }}/workspace (out of nas_docs). Container path /workspace/ocn
      # is provisional (Hermes /workspace is the local workspace) — confirm.
      - type: bind
        source: "{{ target_home }}/workspace"
        target: /workspace/ocn
        bind:
          propagation: rslave
    working_dir: /opt/hermes-workspace
