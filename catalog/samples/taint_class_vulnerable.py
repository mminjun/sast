"""자체 taint 엔진 3단계(클래스 필드 경유) 정탐 샘플 — 의도적으로 취약하게 작성된 코드다.

실행하거나 참고용으로 복사하지 말 것. 기대 건수는 catalog/tests.py EXPECTED_CLASS_FINDINGS.
"Semgrep 못 잡음" 표시 케이스는 필드가 다른 메서드에서 대입되는 것 — Semgrep OSS taint는 메서드 안에서만
추적한다. 엔진은 흐름 비민감이다(호출 순서를 보지 않는다, docs/decisions.md 2026-09-06 custom-taint 3단계).
"""

import os
import subprocess

import requests


class Pinger:
    def load(self, request):
        self.host = request.GET.get("host")

    def run(self):
        os.system("ping -c 1 " + self.host)  # KISA-IV-05 (class — Semgrep 못 잡음: load → run)


class Job:
    def __init__(self, command):
        self.command = command

    def start(self):
        subprocess.run(self.command, shell=True)  # KISA-IV-05 (class — __init__ 매개변수 → 필드)


class Report:
    def set_file(self, filename):
        self.filename = filename

    def render(self):
        return open("/var/reports/" + self.filename).read()  # KISA-IV-03 (class — 메서드 매개변수 → 필드)


class Chain:
    def load(self, request):
        self.raw = request.POST["expr"]

    def prepare(self):
        self.expr = self.raw.strip()

    def evaluate(self):
        eval(self.expr)  # KISA-IV-02 (class — 필드 → 필드 체인: raw → expr)


class Proxy:
    def load(self, request):
        self.url = request.GET.get("url")

    def fetch(self):
        return self.get(self.url)

    def get(self, target):
        return requests.get(target, timeout=5)  # KISA-IV-12 (class — 필드가 메서드 요약을 거쳐 싱크)


class Multi:
    def from_get(self, request):
        self.query = request.GET.get("q")

    def from_post(self, request):
        self.query = request.POST["q"]

    def search(self, conn):
        conn.cursor().execute("SELECT * FROM t WHERE name = '" + self.query + "'")  # KISA-IV-01 (class — 두 메서드가 대입, paths_count 2)


class Builder:
    def run(self, request):
        cmd = self.build(request.GET.get("c"))
        os.system(cmd)  # KISA-IV-05 (메서드 요약 경유 — Semgrep도 잡음(모르는 호출 전파))

    def build(self, x):
        return "ping " + x
