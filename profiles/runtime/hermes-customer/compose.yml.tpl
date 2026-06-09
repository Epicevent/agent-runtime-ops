services:
  openclaw-gateway:
    image: "{{ image_ref }}"
    restart: unless-stopped
    command:
      - gateway
      - run
    env_file:
      - .env
    environment:
      HERMES_HOME: /opt/data
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
      HERMES_API_TOKEN: ${API_SERVER_KEY}
      OPENCLAW_NAS_CONTAINER_PATH: /workspace/nas_docs
      OPENCLAW_NAS_DATA_GID: "{{ data_gid }}"
      HOME: /opt/data/home
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
      agent-runtime.slot: "{{ slot }}"
      agent-runtime.family: "{{ family }}"
      agent-runtime.profile: "{{ runtime_profile }}"
      agent-runtime.service: gateway
    group_add:
      - "{{ data_gid }}"
    volumes:
      - "{{ target_home }}/.hermes:/opt/data"
      - "{{ target_home }}/.hermes/workspace:/workspace"
      - type: bind
        source: "{{ target_home }}/nas_docs"
        target: /workspace/nas_docs
        read_only: true
        bind:
          propagation: rslave
    working_dir: /opt/data/home
