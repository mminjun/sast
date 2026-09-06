"""자체 taint 엔진 2단계(같은 파일 함수 간) 정탐 샘플 — 의도적으로 취약하게 작성된 코드다.

실행하거나 참고용으로 복사하지 말 것. 기대 건수는 catalog/tests.py EXPECTED_INTER_FINDINGS.
"Semgrep 못 잡음" 표시 케이스는 Semgrep OSS taint(taint_python.yaml)가 놓치고 자체 엔진만 잡는 것 —
이름 규약이 거짓말하는 헬퍼와 헬퍼 안 입력이 반환으로 나오는 경우. 나머지는 둘 다 잡되 자체 엔진의
경로가 호출자의 입력부터 이어진다 (docs/decisions.md 2026-09-06 custom-taint 2단계).
"""

import os
import subprocess

import requests


# --- 이름 규약이 거짓말하는 헬퍼 (Semgrep은 validate_/sanitize_ 접두사를 sanitizer로 믿는다) ---


def sanitize_host(host):
    return host.strip()  # 이름만 sanitize — 아무것도 걸러내지 않는다


def ping_sanitized(request):
    host = sanitize_host(request.GET.get("host"))
    os.system("ping -c 1 " + host)  # KISA-IV-05 (inter — Semgrep 못 잡음)


def clean_query(q):
    return q  # 이름만 clean


def find_user(conn, request):
    q = clean_query(request.GET.get("q"))
    conn.cursor().execute("SELECT * FROM users WHERE name = '" + q + "'")  # KISA-IV-01 (inter — Semgrep 못 잡음)


# --- 헬퍼 안 입력이 반환으로 나온다 (Semgrep은 인자 없는 모르는 호출을 깨끗하다고 본다) ---


def read_command():
    line = input("cmd> ")
    return line


def run_from_console():
    os.system(read_command())  # KISA-IV-05 (inter — Semgrep 못 잡음)


def upstream_url():
    return os.environ["UPSTREAM"]


def fetch_upstream():
    target = upstream_url()
    return requests.get(target, timeout=5)  # KISA-IV-12 (inter — Semgrep 못 잡음)


# --- 둘 다 잡되 자체 엔진은 호출자의 입력부터 경로가 이어진다 ---


def build_command(host):
    prefix = "traceroute "
    return prefix + host


def wrap_command(host):
    cmd = build_command(host)
    return cmd + " -m 5"


def traceroute(request):
    host = request.GET.get("host")
    os.popen(wrap_command(host))  # KISA-IV-05 (두 단계 반환 체인)


def run_shell(command):
    subprocess.run(command, shell=True)  # KISA-IV-05 (헬퍼 안 싱크 — 호출자 경로)


def run_positional(request):
    cmd = request.GET.get("cmd")
    run_shell(cmd)


def run_keyword(request):
    run_shell(command=request.POST["cmd"])


def resolve_target(request):
    return requests.get(defined_later(request.GET.get("url")), timeout=5)  # KISA-IV-12 (정의가 뒤에 있는 헬퍼)


def defined_later(url):
    return url.strip()


def repeat(value, times):
    if times == 0:
        return value
    return repeat(value, times - 1)


def eval_repeated(request):
    eval(repeat(request.GET.get("expr"), 2))  # KISA-IV-02 (기저 사례 있는 재귀)
