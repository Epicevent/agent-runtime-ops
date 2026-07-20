"""저장됨 ≠ 유효함 — 시크릿 키의 실제 유효성을 provider 에 물어보는 probe (7/20).

배경(사고): runtime-secret set --check 는 값을 컨테이너 env 에 쓴 뒤 "env 에
도달했나 + 컨테이너가 사나"만 본다. 오타·만료·"dummy"가 전부 통과한다. 그 키가
정말 먹히는지는 provider 에 콜을 한 번 날려야만 안다 — 그게 이 모듈이다.
nas probe 의 "마운트됨 ≠ 연결됨"과 같은 축의 시크릿 판.

**이 모듈은 읽기 전용이다.** 어떤 값도 쓰지 않는다. 사고의 재발 방지는 내 기억이
아니라 이 사실에 있다: 키를 확인하려고 쓰기 명령(set)을 쓸 이유가 사라진다.

값 유출 방지(§0):
  · 콜은 `docker exec <컨테이너> sh -lc <스크립트>` 로 **컨테이너 안에서** 돈다.
    스크립트가 `$KEY`(env)를 읽어 provider 에 붙으므로 값이 컨테이너 밖으로 안 나온다.
  · 스크립트는 **HTTP 상태코드만** stdout 으로 뱉는다(-o /dev/null -w %{http_code}).
    본문·URL·에러문·키 어느 것도 안 나온다. opsctl 은 그 3자리 숫자만 받는다.
  · 반환은 valid/invalid/unreachable 뿐 — 값은 절대 아니다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .common import run_text


@dataclass(frozen=True)
class ProviderCheck:
    """한 provider 키의 유효성 확인 방법. url 은 값을 담지 않는다(인증은 헤더/쿼리로,
    컨테이너 셸이 env 를 확장해 넣는다)."""

    key: str            # env 변수명 (예: GEMINI_API_KEY)
    url: str            # 가장 싼 인증 엔드포인트 (대개 모델 목록)
    auth: str           # "header:<name>" | "query:<name>" | "bearer"
    invalid_codes: tuple[int, ...] = (400, 401, 403)


# 7/20 실측(각 provider 문서). GEMINI 는 오늘 라이브 실증 대상 — 완전 구현.
# 나머지는 문서 근거의 정의만 두고, 라이브 검증 전까지 PROBE_VERIFIED 에 안 넣는다
# (추측을 "확정"으로 승격하지 않는다; 사고의 교훈).
PROVIDER_CHECKS: dict[str, ProviderCheck] = {
    "GEMINI_API_KEY": ProviderCheck(
        "GEMINI_API_KEY",
        "https://generativelanguage.googleapis.com/v1beta/models",
        "header:x-goog-api-key",
    ),
    # 아래는 문서 근거 정의(미검증). 라이브로 닫기 전엔 probe 대상에서 제외된다.
    "ANTHROPIC_API_KEY": ProviderCheck("ANTHROPIC_API_KEY", "https://api.anthropic.com/v1/models", "header:x-api-key"),
    "OPENAI_API_KEY": ProviderCheck("OPENAI_API_KEY", "https://api.openai.com/v1/models", "bearer"),
    "DEEPSEEK_API_KEY": ProviderCheck("DEEPSEEK_API_KEY", "https://api.deepseek.com/models", "bearer"),
    "GROQ_API_KEY": ProviderCheck("GROQ_API_KEY", "https://api.groq.com/openai/v1/models", "bearer"),
    "MISTRAL_API_KEY": ProviderCheck("MISTRAL_API_KEY", "https://api.mistral.ai/v1/models", "bearer"),
    "TOGETHER_API_KEY": ProviderCheck("TOGETHER_API_KEY", "https://api.together.xyz/v1/models", "bearer"),
    "ELEVENLABS_API_KEY": ProviderCheck("ELEVENLABS_API_KEY", "https://api.elevenlabs.io/v1/user", "header:xi-api-key"),
}

# 라이브로 실증되어 probe 가 실제로 도는 키. 지금은 GEMINI 만 — 완벽하게 컨트롤한다.
# 새 provider 는 샌드박스(oc20/oc14)에서 실콜로 닫은 뒤에만 여기 추가한다.
PROBE_VERIFIED: frozenset[str] = frozenset({"GEMINI_API_KEY"})

_PROBE_TIMEOUT_S = 10


def _auth_curl_arg(check: ProviderCheck) -> str:
    """컨테이너 셸에서 $KEY(env)를 인증에 넣는 curl 조각. 값은 셸이 확장하므로
    opsctl 은 값을 보지 못한다. -w %{http_code} 라 stdout 은 상태코드뿐."""
    kind, _, name = check.auth.partition(":")
    if kind == "header":
        return f'-H "{name}: ${check.key}"'
    if kind == "bearer":
        return f'-H "Authorization: Bearer ${check.key}"'
    if kind == "query":
        return f'-G --data-urlencode "{name}=${check.key}"'
    raise ValueError(f"unknown auth kind: {check.auth}")


def build_probe_script(check: ProviderCheck) -> str:
    """컨테이너 안에서 돌 sh 스크립트. 값은 env 에서만 읽고, HTTP 상태코드만 낸다.

    출력 계약(오직 이 셋):
      absent      — env 에 키가 없음
      notool      — 컨테이너에 curl 이 없음(다른 도구는 상태코드 신뢰도가 낮아 제외)
      http=<코드> — curl 이 받은 3자리 상태코드(000=도달 실패/타임아웃)
    """
    curl_auth = _auth_curl_arg(check)
    # set -u 는 안 쓴다(빈 env 를 absent 로 다루려고 직접 검사). 값은 어디에도 echo 안 함.
    return (
        f'v="${check.key}"; '
        f'if [ -z "$v" ]; then echo absent; exit 0; fi; '
        f'if ! command -v curl >/dev/null 2>&1; then echo notool; exit 0; fi; '
        f'code=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time {_PROBE_TIMEOUT_S} '
        f'{curl_auth} "{check.url}" 2>/dev/null); '
        f'echo "http=$code"'
    )


def classify_probe_output(check: ProviderCheck, stdout: str, rc: int) -> tuple[str, str]:
    """컨테이너 스크립트 출력 → (상태, 상세). 상태 ∈ valid|invalid|unreachable|absent|error.
    값은 어디에도 실리지 않는다(입력에 값이 애초에 없다)."""
    if rc != 0:
        return "error", f"docker_exec_rc={rc}"
    line = stdout.strip().splitlines()[-1] if stdout.strip() else ""
    if line == "absent":
        return "absent", "key not set in container env"
    if line == "notool":
        return "unreachable", "no curl in container"
    if line.startswith("http="):
        raw = line[5:].strip()
        try:
            code = int(raw)
        except ValueError:
            return "error", "unparseable http code"
        if code == 0:
            return "unreachable", "network/timeout"
        if 200 <= code < 300:
            return "valid", f"http={code}"
        if code in check.invalid_codes:
            return "invalid", f"http={code}"
        return "unreachable", f"http={code}"  # 5xx 등: provider 문제, 키 무효 아님
    return "error", "no probe output"


def probe_key_in_container(container: str, check: ProviderCheck) -> tuple[str, str]:
    """컨테이너 하나에서 키 하나를 잰다. 읽기 전용(docker exec sh, 콜만)."""
    proc = run_text(["docker", "exec", container, "sh", "-lc", build_probe_script(check)])
    return classify_probe_output(check, proc.stdout, proc.returncode)
