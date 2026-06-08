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
      - "{{ source_output }}:/app/dist/control-ui:ro"
      - type: bind
        source: "{{ target_home }}/nas_docs"
        target: /home/node/nas_docs
        read_only: true
        bind:
          propagation: rslave
    working_dir: /home/node/.openclaw/workspace
