services:
  openclaw-gateway:
    image: "{{ image_ref }}"
    restart: unless-stopped
    init: true
    command:
      [
        "node",
        "dist/index.js",
        "gateway",
        "--bind",
        "${OPENCLAW_GATEWAY_BIND:-lan}",
        "--port",
        "18789",
      ]
    env_file:
      - .env
    environment:
      HOME: /home/node
      OPENCLAW_HOME: /home/node
      OPENCLAW_CONFIG_DIR: /home/node/.openclaw
      OPENCLAW_CONFIG_PATH: /home/node/.openclaw/openclaw.json
      OPENCLAW_STATE_DIR: /home/node/.openclaw
      OPENCLAW_WORKSPACE_DIR: /home/node/.openclaw/workspace
      OPENCLAW_NAS_CONTAINER_PATH: /home/node/nas_docs
      LANG: ko_KR.UTF-8
      LANGUAGE: ko_KR:ko
      LC_ALL: ko_KR.UTF-8
    ports:
      - "127.0.0.1:{{ gateway_port }}:18789"
      - "127.0.0.1:{{ bridge_port }}:18790"
    labels:
      agent-runtime.instance-id: "{{ instance_id }}"
      agent-runtime.linux-account: "{{ linux_account }}"
      agent-runtime.slot: "{{ slot }}"
      agent-runtime.family: "{{ family }}"
      agent-runtime.profile: "{{ runtime_profile }}"
      agent-runtime.service: gateway
    user: "{{ runtime_uid }}:{{ runtime_gid }}"
    group_add:
      - "{{ data_gid }}"
    volumes:
      - "{{ target_home }}/.openclaw:/home/node/.openclaw"
      - "{{ target_home }}/.openclaw/workspace:/home/node/.openclaw/workspace"
      - "{{ target_home }}/.openclaw-auth-profile-secrets:/home/node/.config/openclaw"
      # corpus (read-only knowledge): single-intent tree. read_only here is a
      # defense-in-depth second lock — the source mount / ro account is the
      # primary authority. Safe to stamp because nothing writable lives under it.
      - type: bind
        source: "{{ target_home }}/nas_docs"
        target: /home/node/nas_docs
        read_only: true
        bind:
          propagation: rslave
      # workspace (OCN): the agent's OWN writable area — a different KIND than
      # corpus, so a separate top-level mount, never under the read-only tree.
      # No read_only; mode is rw, inherited from its source. Requires OCN to be
      # mounted host-side at {{ target_home }}/workspace (out of nas_docs).
      - type: bind
        source: "{{ target_home }}/workspace"
        target: /home/node/workspace
        bind:
          propagation: rslave
