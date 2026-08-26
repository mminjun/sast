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
- accounts 인증·역할 구현 (SFR-001~003, DAR-002, SEC-001~004, TST-001~002)
  - 커스텀 User(AbstractUser 기반, email 로그인) + Role(ADMIN/USER) + UserManager
  - bcrypt 1순위 해셔, DRF 기본 권한 IsAuthenticated, JWT(simplejwt) access 30분/refresh 1일
  - 엔드포인트: /api/auth/ login·refresh·logout(blacklist)·me
  - IsAdminRole 권한 클래스 — 역할은 토큰 클레임이 아니라 DB 현재 값으로 검사
  - 첫 migrate 실행 (12테이블), 신규 의존성 bcrypt 5.0.0 / simplejwt 5.5.1 버전 고정
  - 검증: 테스트 15개 전부 통과 / accounts_user 존재·auth_user 없음 /
    실제 저장 해시 접두사 bcrypt_sha256 / manage.py check 0건
  - 자체 보안 검토(secure-review) 후 3건 수정 — 커밋 전 반영
    - 이메일 대소문자 무시(save 정규화 + Lower UniqueConstraint + iexact 조회)
    - 로그인 빈도 제한 5/min (ScopedRateThrottle)
    - 로그아웃 시 refresh 토큰 소유자 검증, 실패 응답은 통일
    - 재검증: 테스트 22개(신규 7개 포함) 전부 통과
  - 다음: projects 앱 — 프로젝트·할당 테이블 + IDOR 방어(SEC-005)