#!/usr/bin/env bash
set -euo pipefail

image_ref="${1:?usage: hermes-wrapper-smoke.sh IMAGE_REF}"

recipe_name="$(docker inspect "$image_ref" --format '{{ index .Config.Labels "com.epicevent.agent-runtime.recipe.name" }}')"
if [[ "$recipe_name" != "hermes-runtime" ]]; then
  echo "smoke_status=skipped recipe_name=$recipe_name"
  exit 0
fi

workspace_dir="$(mktemp -d)"
data_dir="$(mktemp -d)"
mkdir -p "$workspace_dir/nas_docs"
printf 'wrapper smoke\n' > "$workspace_dir/nas_docs/README.txt"
workspace_uid="$(stat -c %u "$workspace_dir")"
runtime_uid="12000"
runtime_gid="12001"
data_gid="12002"
chmod 0750 "$workspace_dir" "$workspace_dir/nas_docs" "$data_dir"
chmod 0640 "$workspace_dir/nas_docs/README.txt"
sudo chown -R "$workspace_uid:$data_gid" "$workspace_dir"
sudo chown "$runtime_uid:$runtime_gid" "$data_dir"

cid="$(docker run -d --rm \
  -v "$data_dir:/opt/data" \
  -v "$workspace_dir:/workspace" \
  -e API_SERVER_KEY=dummy-local-smoke-key \
  -e HERMES_API_TOKEN=dummy-local-smoke-key \
  -e HERMES_UID="$runtime_uid" \
  -e HERMES_GID="$runtime_gid" \
  -e OPENCLAW_NAS_DATA_GID="$data_gid" \
  -e HERMES_ALLOW_INSECURE_REMOTE=1 \
  "$image_ref")"
trap 'docker logs "$cid" || true; docker rm -f "$cid" >/dev/null 2>&1 || true; sudo rm -rf "$workspace_dir" "$data_dir"' EXIT

for _ in {1..120}; do
  if ! docker inspect "$cid" --format '{{ .State.Running }}' | grep -Fx true >/dev/null; then
    docker logs "$cid" || true
    echo "smoke_status=fail reason=container_exited" >&2
    exit 1
  fi
  if docker exec "$cid" node -e '
    const http = require("http");
    const endpoints = [
      "http://127.0.0.1:3000/",
      "http://127.0.0.1:8642/health",
      "http://127.0.0.1:9119/api/status",
    ];
    function check(url) {
      return new Promise((resolve, reject) => {
        const request = http.get(url, (response) => {
          response.resume();
          if (response.statusCode >= 200 && response.statusCode < 400) {
            resolve();
          } else {
            reject(new Error(`${url} returned ${response.statusCode}`));
          }
        });
        request.on("error", reject);
        request.setTimeout(2000, () => request.destroy(new Error(`${url} timed out`)));
      });
    }
    Promise.all(endpoints.map(check)).then(
      () => process.exit(0),
      (error) => {
        console.error(error.message);
        process.exit(1);
      }
    );
  '; then
    docker exec "$cid" sh -lc '
      node_pid="$(pgrep -f "node .*server-entry[.]js" | head -n1)"
      test -n "$node_pid"

      uid="$(awk "/^Uid:/ {print \$2}" /proc/"$node_pid"/status)"
      gid="$(awk "/^Gid:/ {print \$2}" /proc/"$node_pid"/status)"
      groups="$(awk "/^Groups:/ {for (i=2; i<=NF; i++) print \$i}" /proc/"$node_pid"/status)"
      test "$uid" = "$HERMES_UID"
      test "$gid" = "$HERMES_GID"
      test "$uid" != "10000"
      test "$gid" != "10000"
      printf "%s\n" "$groups" | grep -Fx "$OPENCLAW_NAS_DATA_GID" >/dev/null
    '
    docker exec -i "$cid" node <<'NODE'
const http = require('http');

function getJson(path) {
  return new Promise((resolve, reject) => {
    const request = http.get(`http://127.0.0.1:3000${path}`, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
      });
      response.on('end', () => {
        let json;
        try {
          json = JSON.parse(body);
        } catch (error) {
          reject(new Error(`${path} returned non-JSON status=${response.statusCode}: ${body.slice(0, 200)}`));
          return;
        }
        resolve({ status: response.statusCode, json });
      });
    });
    request.on('error', reject);
    request.setTimeout(2000, () => request.destroy(new Error(`${path} timed out`)));
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

(async () => {
  const workspace = await getJson('/api/workspace');
  assert(workspace.status === 200, `/api/workspace status=${workspace.status}`);
  assert(workspace.json.isValid === true, '/api/workspace isValid must be true');
  assert(workspace.json.path === '/workspace', `/api/workspace path=${workspace.json.path}`);
  assert(workspace.json.source === 'env', `/api/workspace source=${workspace.json.source}`);

  const rootFiles = await getJson('/api/files?action=list');
  assert(rootFiles.status === 200, `/api/files?action=list status=${rootFiles.status}`);
  assert(!rootFiles.json.error, `/api/files?action=list error=${rootFiles.json.error}`);
  assert(Array.isArray(rootFiles.json.entries), '/api/files?action=list entries must be an array');

  const nasFiles = await getJson('/api/files?path=nas_docs');
  assert(nasFiles.status === 200, `/api/files?path=nas_docs status=${nasFiles.status}`);
  assert(nasFiles.json.root === 'nas_docs', `/api/files?path=nas_docs root=${nasFiles.json.root}`);
  assert(!nasFiles.json.error, `/api/files?path=nas_docs error=${nasFiles.json.error}`);
  assert(Array.isArray(nasFiles.json.entries), '/api/files?path=nas_docs entries must be an array');
})().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
NODE
    echo "smoke_status=ok recipe_name=$recipe_name"
    exit 0
  fi
  sleep 2
done

docker logs "$cid" || true
echo "smoke_status=fail reason=endpoints_not_ready" >&2
exit 1
