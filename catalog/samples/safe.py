"""TST-005 오탐 시험용 안전 샘플 — vulnerable.py의 각 취약점에 대한 올바른 대응.

여기서 findings가 하나라도 나오면 룰이 과탐지하는 것이다(오탐). 정탐 못지않게
중요한 기준이라 취약 샘플과 짝으로 유지한다.
"""

import hashlib
import logging
import os
import pickle
import random
import re
import secrets
import shlex
import ssl
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import bcrypt
import requests
import yaml
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.utils.html import escape

logger = logging.getLogger(__name__)

ALLOWED_NEXT = {"/dashboard", "/projects"}

DEBUG = os.getenv("DJANGO_DEBUG", "").lower() == "true"

ALLOWED_HOSTS = {"api.example.com"}
ALLOWED_TABLES = {"users", "orders"}
LOCALHOST = "127.0.0.1"
REPORT_ROOT = Path("/var/reports").resolve()


def get_user(conn, user_id):
    cursor = conn.cursor()
    # 파라미터 바인딩 — 질의 구조가 입력으로 바뀌지 않는다
    cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
    return cursor.fetchall()


def run_expression(name):
    # eval 대신 명시적 분기
    table = {"double": lambda x: x * 2, "square": lambda x: x * x}
    return table[name]


def read_report(name):
    # 허용 디렉토리 기준으로 정규화한 뒤 밖을 벗어나는지 확인
    target = (REPORT_ROOT / name).resolve()
    if not target.is_relative_to(REPORT_ROOT):
        raise ValueError("경로가 허용 범위를 벗어납니다.")
    return target.read_text(encoding="utf-8")


def ping(host):
    # 인자를 리스트로 전달, shell 미사용
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


def fetch_preview(target):
    # 허용 목록으로 대상 호스트 제한
    if target not in ALLOWED_HOSTS:
        raise ValueError("허용되지 않은 호스트입니다.")
    return requests.get("https://api.example.com/preview", timeout=5)


def fetch_legacy():
    return urllib.request.urlopen("https://api.example.com/legacy", timeout=5)


def checksum(data):
    # 보안 목적이 아닌 체크섬임을 명시
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


DB_PASSWORD = os.environ["POSTGRES_PASSWORD"]
API_KEY = os.environ["EXTERNAL_API_KEY"]


def issue_reset_token():
    # 암호학적 난수
    reset_token = secrets.token_urlsafe(32)
    return reset_token


def pick_sample(items):
    # 보안과 무관한 random 사용은 탐지 대상이 아니다
    chosen = random.choice(items)
    return chosen


def call_internal():
    return requests.get("https://internal.example.com", timeout=5, verify=True)


def store_password(password):
    # 솔트를 포함한 적응형 해시
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def load_profile(blob):
    # pickle 대신 JSON
    import json

    return json.loads(blob)


def load_settings(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def handler(request):
    try:
        do_work()
    except Exception:
        # 사용자에겐 일반화된 메시지, 상세는 서버 로그로
        return JsonResponse({"error": "처리 중 오류가 발생했습니다."}, status=500)


def cleanup_quietly(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        # 구체적인 예외만 잡고, 무시하는 이유를 로그로 남긴다
        logger.info("이미 삭제된 경로: %s", path)


def parse_amount(value):
    try:
        return int(value)
    except ValueError:
        # 삼키지 않고 기록 후 다시 던진다
        logger.error("금액 파싱 실패: %r", value)
        raise


def make_temp_file():
    # mktemp(경쟁 조건) 대신 생성과 열기가 원자적인 API
    return tempfile.NamedTemporaryFile(delete=False)


def open_tls(sock):
    # 폐기된 ssl.wrap_socket 대신 검증이 켜진 기본 컨텍스트
    context = ssl.create_default_context()
    return context.wrap_socket(sock, server_hostname="api.example.com")


def submit_view(request):
    # csrf_exempt 없이 CSRF 미들웨어 보호를 그대로 유지한다
    return JsonResponse({"ok": True})


def append_log(line):
    # with 문으로 열어 블록을 벗어나면 반드시 닫힌다
    with open("app.log", "a", encoding="utf-8") as log:
        log.write(line)


def go_next(request):
    # 허용 목록으로 대상 경로를 제한한 뒤에만 이동
    target = request.GET.get("next", "/dashboard")
    if target not in ALLOWED_NEXT:
        target = "/dashboard"
    return redirect(target)


# DB 비밀번호는 환경변수 POSTGRES_PASSWORD에서 읽는다 — 값은 소스·주석에 적지 않는다


def remember_login(request, token):
    resp = JsonResponse({"ok": True})
    # 인증 값은 만료를 지정하지 않은 세션 쿠키로 — 브라우저 종료 시 소멸
    resp.set_cookie("auth_token", token, httponly=True, secure=True)
    # 영속 쿠키는 비민감 설정값에만 쓴다
    resp.set_cookie("theme", "dark", max_age=60 * 60 * 24 * 30)
    return resp


def make_signing_key():
    return RSA.generate(4096)


def make_tls_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


# --- taint 오탐 통제 (taint_python.yaml) ---
# 매개변수를 외부 입력으로 보는 룰이라, "매개변수를 받지만 안에서 검증한 뒤 쓰는" 함수가 걸리면
# 안 된다. 검증 형태(정규식·allowlist·타입 변환·파일명 추출·인용·검증 헬퍼)별로 하나씩 둔다.


def ping_local():
    target = LOCALHOST
    os.system("ping -c 1 " + target)  # 상수만 흐른다 — 입력이 없다


def ping_host_checked(host):
    # 정규식으로 허용 문자만 통과시킨 뒤 사용
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("잘못된 호스트")
    os.system("ping -c 1 " + host)


def query_table(conn, table):
    # 식별자는 바인딩할 수 없으므로 allowlist로 제한
    if table not in ALLOWED_TABLES:
        raise ValueError("허용되지 않은 테이블")
    conn.cursor().execute("SELECT * FROM " + table)


def scan_port(host, port):
    # 정수로 변환한 값만 명령에 들어간다
    number = int(port)
    os.system(f"nc -z {LOCALHOST} {number}")


def read_upload(name):
    # 파일 이름만 남기면 상위 디렉토리로 나갈 수 없다
    safe_name = os.path.basename(name)
    return open(os.path.join("/var/uploads", safe_name), "rb").read()


def read_by_name(name):
    safe_name = Path(name).name
    return (REPORT_ROOT / safe_name).read_text(encoding="utf-8")


def ping_quoted(host):
    # 셸 인용 처리
    quoted = shlex.quote(host)
    os.system("ping -c 1 " + quoted)


def validate_host(host):
    if host not in ALLOWED_HOSTS:
        raise ValueError("허용되지 않은 호스트")
    return host


def fetch_via_helper(target):
    # 검증을 헬퍼로 뺀 형태 — 이름 규약(validate_*)으로 신뢰한다
    host = validate_host(target)
    return requests.get("https://" + host + "/preview", timeout=5)


def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse("<h1>Hello " + escape(name) + "</h1>")  # 이스케이프 뒤 출력


def do_work():
    pass
