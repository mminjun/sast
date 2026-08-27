"""TST-005 정탐 시험용 취약 샘플 — 의도적으로 취약하게 작성된 코드다.

실행하거나 참고용으로 복사하지 말 것. catalog/rules의 KISA 룰 13개가 각각
정확히 걸리는지 확인하는 고정 자산이며, 안전한 대응 코드는 safe.py에 있다.

이 파일은 우리 SAST로 우리 코드를 분석할 때(도그푸딩) 당연히 탐지된다 —
분석 대상에서 catalog/samples/를 제외하고 돌려야 한다.
"""

import hashlib
import os
import pdb
import pickle
import random
import ssl
import subprocess
import urllib.request

import requests
import yaml
from django.http import JsonResponse

DEBUG = True  # KISA-EH-01


def get_user(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # KISA-IV-01
    return cursor.fetchall()


def run_expression(expr):
    return eval(expr)  # KISA-IV-02


def read_report(name):
    return open("/var/reports/" + name).read()  # KISA-IV-03


def ping(host):
    os.system(f"ping -c 1 {host}")  # KISA-IV-05
    subprocess.run(f"nslookup {host}", shell=True)  # KISA-IV-05


def fetch_preview(target):
    return requests.get(f"https://{target}/preview")  # KISA-IV-12


def fetch_legacy(target):
    return urllib.request.urlopen("http://" + target)  # KISA-IV-12


def checksum(data):
    return hashlib.md5(data).hexdigest()  # KISA-SF-04


DB_PASSWORD = "p@ssw0rd-literal"  # KISA-SF-06
API_KEY = "EXAMPLE-NOT-A-REAL-KEY-0123456789"  # KISA-SF-06


def issue_reset_token():
    reset_token = random.randint(100000, 999999)  # KISA-SF-08
    return reset_token


def call_internal():
    return requests.get("https://internal.example.com", verify=False)  # KISA-SF-11


def make_unverified_context():
    return ssl._create_unverified_context()  # KISA-SF-11


def store_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  # KISA-SF-14


def load_profile(blob):
    return pickle.loads(blob)  # KISA-CE-05


def load_settings(text):
    return yaml.load(text)  # KISA-CE-05


def handler(request):
    try:
        do_work()
    except Exception as exc:
        return JsonResponse({"error": str(exc)})  # KISA-EH-01


def debug_here():
    pdb.set_trace()  # KISA-EN-02
    breakpoint()  # KISA-EN-02


def do_work():
    pass
