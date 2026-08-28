"""TST-005 오탐 시험용 안전 샘플 — vulnerable.py의 각 취약점에 대한 올바른 대응.

여기서 findings가 하나라도 나오면 룰이 과탐지하는 것이다(오탐). 정탐 못지않게
중요한 기준이라 취약 샘플과 짝으로 유지한다.
"""

import hashlib
import logging
import os
import pickle
import random
import secrets
import ssl
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import bcrypt
import requests
import yaml
from django.http import JsonResponse

logger = logging.getLogger(__name__)

DEBUG = os.getenv("DJANGO_DEBUG", "").lower() == "true"

ALLOWED_HOSTS = {"api.example.com"}
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


def do_work():
    pass
