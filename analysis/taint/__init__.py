"""자체 taint 분석 엔진 (SFR-009 — docs/decisions.md 2026-09-06 custom-taint).

Semgrep OSS taint가 못 하는 것(같은 파일 안 함수 간 추적, 클래스 필드 경유)을 우리가 한다. 이 패키지는
Django를 import하지 않는다 — 표준 라이브러리 `ast`만 쓰고, 나중에 CI 게이트 스크립트(Django 없는 러너)가 같은
엔진을 부를 수 있게 한다. 진입점은 engine.analyze_directory, 결과는 Semgrep JSON과 같은 모양(report.py)이라
catalog의 표준화가 그대로 태운다. KISA 코드는 Semgrep 룰 metadata처럼 문자열로만 다룬다(analysis→catalog
의존 없음, QLT-001).
"""

from .engine import analyze_directory, analyze_source

__all__ = ['analyze_directory', 'analyze_source']
