services:
  openclaw-gateway:
    image: "{{ image_ref }}"
    restart: unless-stopped
    env_file:
      - .env
      - "{{ target_home }}/.hermes/.env"
    environment:
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
    group_add:
      - "{{ data_gid }}"
    volumes:
      - "{{ target_home }}/.hermes:/opt/data"
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
