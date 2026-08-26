# 작업 일지

형식: 날짜 / 한 일 / 막힌 것·해결 / 다음 할 일

## 2026-08-25 (킥오프)
- RFP 50개 해석 완료, 멘토 질의응답
- MVP 범위·비목표 확정, 스택 확정 (Django+DRF+React+PG+Semgrep)
- 하네스 구축 (CLAUDE.md, plan.md, 추적표)
- 다음: PostgreSQL 확인 → Django 세팅 → 6테이블

## 2026-08-26
- docker-compose.yml 작성: PostgreSQL 16(sast-db), DB `sast`, 127.0.0.1:5432,
  named volume `sast-db-data`, healthcheck (DAR-001)
- 시크릿 분리: `.env`(커밋 제외) + `.env.example`(템플릿), `.gitignore`에 `.env` 규칙 추가
- 검증: 컨테이너 healthy / PostgreSQL 16.15 접속 확인 / down→up 후 테이블 잔존(영속성) 확인 /
  `.env` 미추적 확인 / 비밀번호 없을 때 기동 실패(fail-fast) 확인
- 다음: Django + DRF 프로젝트 생성 → settings의 DATABASES를 .env에 연결 → 6테이블
- Django 뼈대 정리 (QLT-001, DAR-001, SEC-010)
  - 앱 4개 생성·등록: accounts / projects / analysis / catalog + DRF
  - settings.py를 .env 기반으로: SECRET_KEY(하드코딩 제거, fail-fast), DEBUG(기본 False),
    ALLOWED_HOSTS, DATABASES를 SQLite → PostgreSQL(psycopg3, compose와 POSTGRES_* 키 공유)
  - requirements.txt 신규: 직접 의존성 4종 버전 고정
  - db.sqlite3 삭제 (PG 전환으로 불필요, git 미추적 확인 후)
  - 검증: `manage.py check` 0건 / PostgreSQL 16.15 실접속 / ENGINE=postgresql /
    SECRET_KEY 하드코딩 아님 / `.env` 없을 때 `KeyError`로 기동 실패(fail-fast) / `.env` 미추적
  - 다음: accounts 커스텀 User(이메일 로그인) 정의 → 첫 migrate → 6테이블 (bcrypt 승인 필요)