"""자체 taint 엔진 2단계(같은 파일 함수 간) 오탐 통제 샘플.

자체 엔진은 여기서 0건이어야 한다 — 헬퍼의 본문이 실제로 씻거나 버리거나 상수를 돌려주는 경우다.
Semgrep OSS taint는 같은 파일 함수의 본문을 보지 못해(모르는 호출 = 인자 오염 전파) 이 파일에서 몇 건을
잡는데, 그것은 Semgrep의 알려진 오탐이고 catalog/tests.py가 그 건수(EXPECTED_INTER_SEMGREP_FALSE_POSITIVES)를
고정한다. 이 파일에는 싱크를 가진 헬퍼를 두지 않는다 — 헬퍼 자체가 매개변수 소스로 잡히기 때문이다.
"""

import os
import shlex

import requests

ALLOWED_TABLES = {"users", "orders"}


def to_port(value):
    return int(value)  # 본문이 정수로 변환한다


def scan(request):
    port = to_port(request.GET.get("port"))
    os.system(f"nc -z 127.0.0.1 {port}")  # 본문 판단: 깨끗 (Semgrep: 모르는 호출 전파 → 오탐)


def pick_table(name):
    if name not in ALLOWED_TABLES:
        raise ValueError("허용되지 않은 테이블")
    return name


def count_rows(conn, request):
    table = pick_table(request.GET.get("table"))
    conn.cursor().execute("SELECT count(*) FROM " + table)  # 본문의 allowlist 가드 (Semgrep: 오탐)


def quote(arg):
    return shlex.quote(arg)


def ping(request):
    os.system("ping -c 1 " + quote(request.GET.get("host")))  # 본문이 셸 인용 (Semgrep: 오탐)


def audit(value):
    print("audit:", value)
    return "ok"  # 매개변수를 버리고 상수를 돌려준다


def run_audited(request):
    os.system(audit(request.GET.get("cmd")))  # 반환값은 상수 (Semgrep: 오탐)


def default_target():
    return "https://api.example.com/health"


def health(request):
    _unused = request.GET.get("x")
    return requests.get(default_target(), timeout=5)  # 상수 반환 — 둘 다 깨끗


def ping_pong_a(value):
    return ping_pong_b(value)


def ping_pong_b(value):
    return ping_pong_a(value)


def never_returns(request):
    os.system(ping_pong_a(request.GET.get("cmd")))  # 기저 사례 없는 상호 재귀 — 돌아오지 않는다 (Semgrep: 오탐)
