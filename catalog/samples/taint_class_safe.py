"""자체 taint 엔진 3단계(클래스 필드 경유) 오탐 통제 샘플.

자체 엔진은 여기서 0건이어야 한다 — 씻은 값·상수를 필드에 넣거나, 본문이 씻는 메서드를 거치거나, 읽기 전에
같은 메서드 안에서 덮어쓰는 경우다. Semgrep OSS taint는 같은 클래스 메서드의 본문을 보지 못해 몇 건을 잡는데,
그것은 Semgrep의 알려진 오탐이고 catalog/tests.py가 그 건수(EXPECTED_CLASS_SEMGREP_FALSE_POSITIVES)를 고정한다.
호출 순서에 따른 오탐(clear() 되돌림)은 엔진의 범위 밖이라 이 파일에 넣지 않는다(decisions 참고).
"""

import os
import shlex

import requests

ALLOWED_HOSTS = {"api.example.com"}


class Scanner:
    def load(self, request):
        self.port = int(request.GET.get("port"))  # 씻은 값 대입

    def run(self):
        os.system(f"nc -z 127.0.0.1 {self.port}")


class Local:
    def __init__(self):
        self.target = "localhost"  # 상수 대입

    def run(self):
        os.system("ping -c 1 " + self.target)


class Quoted:
    def run(self, request):
        os.system("ping -c 1 " + self.quote(request.GET.get("host")))  # 본문이 씻는 메서드 (Semgrep: 오탐)

    def quote(self, value):
        return shlex.quote(value)


class Overwritten:
    def load(self, request):
        self.cmd = request.GET.get("cmd")

    def run(self):
        self.cmd = "ls -l"  # 읽기 전에 같은 메서드 안에서 덮어쓴다
        os.system(self.cmd)


class Checked:
    def load(self, request):
        host = request.GET.get("host")
        if host not in ALLOWED_HOSTS:
            raise ValueError("허용되지 않은 호스트")
        self.host = host  # allowlist 검사 뒤 대입

    def fetch(self):
        return requests.get("https://" + self.host + "/health", timeout=5)


class OtherField:
    def load(self, request):
        self.note = request.GET.get("note")

    def run(self):
        os.system("uptime")
        print(self.note)  # 다른 이름 필드는 읽지만 싱크가 아니다
