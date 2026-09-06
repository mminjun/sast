## 프로젝트 개요

KISA 개발보안 가이드 기반 SAST(정적 애플리케이션 보안 테스트) 웹 시스템.
소스코드를 업로드하면 정적 분석으로 보안 취약점을 찾아 대시보드로 보여준다.
상세 계획은 docs/plan.md 참조. 이 파일과 plan.md를 항상 먼저 읽는다.

## 기술 스택

- 백엔드: Django + Django REST Framework
- 프론트: React (별도 폴더로 분리, DRF와 API 통신)
- DB: PostgreSQL
- 분석 엔진: Semgrep (외부 연계, 직접 진단 로직 구현 안 함)

## 앱 구조 (QLT-001 모듈화 — 책임별 분리)

- accounts — 사용자 인증, 역할(관리자/일반), 권한
- projects — 분석 프로젝트 관리, 사용자 할당
- analysis — 소스 업로드, Semgrep 실행, 상태 관리
- catalog — KISA 49개 진단 기준, 결과 저장·조회

각 기능은 위 앱으로 분리한다. 한 앱에 여러 책임을 섞지 않는다.

## 보안 규칙 (필수 — 이 프로젝트는 보안 도구다)

- 비밀번호: bcrypt로 해시 (적응형·느린 해시). SHA-2 등 범용 고속 해시를 비밀번호 저장에 단독 사용 금지 — 무차별 대입에 취약. 단, Django 표준 BCryptSHA256PasswordHasher처럼 bcrypt의 72바이트 입력 제한을 우회하려 SHA256으로 전처리하는 건 허용(실제 저장 강도는 bcrypt가 담당).
- 접근 제어: 클라이언트가 보낸 ID를 신뢰하지 말고, 항상 DB의 권한 관계를
  서버에서 재검증한다 (IDOR 방어, SEC-005).
- 파일 처리: zip 업로드/압축 해제 시 경로를 검증한다. 격리 영역 밖을
  가리키는 경로·심볼릭 링크를 차단한다 (Zip Slip / Path Traversal 방어, SEC-008).
- 작업 격리: 분석 대상 소스는 분석 실행 건별로 격리된 디렉토리에서
  처리하고, 그 밖의 파일에 접근하지 않는다 (SEC-007).
- 권한 노출: 권한 없는 리소스 접근은 존재 여부가 드러나지 않게 응답한다 (SEC-006).
- 시크릿·키를 코드나 로그, 커밋에 남기지 않는다.

## 작업 방식

- 큰 작업(여러 파일 생성/수정)은 코드 작성 전 계획부터 제시한다 (Plan Mode).
- 한 번에 한 기능씩 완주한다. 요구사항이 모호하면 먼저 질문한다.
- 새 의존성 추가 전 승인받는다.
- 각 요구사항 구현 시 대응하는 RFP 번호(SFR/DAR/SEC/TST/QLT)를 커밋 메시지나
  주석에 남긴다 (추적성).
- 기능 구현 완료 시 docs/requirements-map.md의 해당 번호 상태를 갱신한다.
- 하루 작업 종료 시 docs/worklog.md에 기록을 남긴다.
- 스크린샷·공개 문서에 들어갈 화면은 찍기 전에 사람 이름·이메일·개인 경로가 없는지 먼저 확인한다.
  있으면 데이터 이름을 중립적으로 바꾸거나(예: sample-service) 화면에서 가린 뒤 찍는다.
## 개발 실행

- 분석 실행은 큐(django.tasks, DB 백엔드)에 등록만 되고 워커가 처리한다. 화면에서 실행을
  확인하려면 runserver 외에 `venv\Scripts\python manage.py analysis_worker`를 따로 띄운다
  (semgrep이 PATH에 있어야 하므로 venv\Scripts 경로 포함). 워커 없이는 QUEUED에 머문다.
- 테스트는 immediate 백엔드로 돌아 워커·Redis가 필요 없다. 큐 등록 자체를 검증하는 시험은
  `override_settings(TASKS=...)`로 DummyBackend를 쓴다.

## 룰 작성

- 새 룰은 스크래치에서 취약·안전 샘플로 정탐·오탐을 실측한 뒤 저장소로 옮긴다. 룰마다
  `metadata.kisa_code`(필수)와 `metadata.engine`(taint 룰만 `semgrep-taint`)을 적는다.
- 인젝션 계열 Python 룰은 `catalog/rules/taint_python.yaml`(mode: taint)에 있다. 같은 항목의 패턴
  룰을 병행하지 않는다 — 핑거프린트는 KISA 코드 기준이라 같은 줄이 두 번 집계된다.
- 샘플(`catalog/samples`)·기대 건수(`catalog/tests.py EXPECTED_*`)·`seed_catalog`를 함께 갱신한다.
- 자체 taint 엔진(`analysis/taint`)은 Django를 import하지 않는다. 소스·싱크·sanitizer는 `spec.py`에 있고
  `taint_python.yaml`과 정합성 시험으로 묶여 있다 — 한쪽을 고치면 다른 쪽도 고친다. 범위: 함수 내·같은 파일
  함수 간·클래스 필드(흐름 비민감). 파일 간·상속·호출 순서는 범위 밖 — Semgrep 대비 N/M 숫자는 `catalog/tests.py`의
  `EXPECTED_*` 상수가 고정한다.

## 테스트 실행

- 평소(코드 고치며 반복, 약 1분):
  `venv\Scripts\python manage.py test --exclude-tag=semgrep --noinput --parallel 4`
  — 실제 Semgrep을 도는 무거운 시험(`@tag('semgrep')`: catalog 정탐·오탐 샘플, analysis 실제
  제외 실증)을 건너뛴다.
- 커밋 전·룰/샘플/실행 경로를 건드렸을 때(전체):
  `venv\Scripts\python manage.py test --noinput --parallel 4`.
  Semgrep 시험만 따로: `... test --tag=semgrep --noinput`.
- `--noinput`은 항상 붙인다 — 테스트 DB가 남아 있으면 삭제 확인 프롬프트에서 멈춘다.
  테스트는 동시에 두 개 돌리지 않는다(같은 테스트 DB).
- 실제 Semgrep을 호출하는 시험을 새로 만들면 `@tag('semgrep')`을 붙인다.
- 테스트 실행 중에는 비밀번호 해셔가 MD5로 바뀐다(config/settings.py, 속도 목적, 운영 불변).
  저장 방식 자체를 검증하는 시험은 `override_settings`로 bcrypt를 고정한다.

## 완료 기준

- 기능이 실제로 동작하고, 관련 테스트/시연으로 확인될 때 완료로 본다.
- 완료를 주장할 때 근거(실행 결과, 테스트 출력)를 함께 제시한다.