# SAST — KISA 개발보안 가이드 기반 정적 분석 웹 시스템

소스코드(zip)를 업로드하면 Semgrep으로 정적 분석해 KISA 소프트웨어 개발보안 가이드
49개 진단 기준에 매핑된 취약점을 대시보드로 보여주는 웹 시스템입니다.

- 백엔드: Django + Django REST Framework (JWT 인증)
- 프론트엔드: React + Vite (`frontend/`)
- DB: PostgreSQL (docker-compose)
- 분석 엔진: Semgrep (자체 룰 `catalog/rules/*.yaml`만 사용)

## 실행 방법 (Getting Started)

### 사전 준비물

- Python 3.13
- Node.js 20 이상 (개발은 v24 기준)
- Docker + Docker Compose (PostgreSQL 용)

### 1. 클론 및 파이썬 의존성 설치

```bash
git clone <repo-url> sast
cd sast
python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

Semgrep CLI는 `requirements.txt`에 포함되어 있어 별도 설치가 필요 없습니다.

### 2. 환경변수 설정 (.env)

템플릿 `.env.example`을 복사해 `.env`를 만들고 값을 채웁니다.
`.env`는 `.gitignore`로 커밋에서 제외됩니다.

```bash
# Windows PowerShell: Copy-Item .env.example .env
cp .env.example .env
```

필수 값 (없으면 서버가 기동 자체를 거부합니다 — fail-fast):

| 변수 | 설명 |
|---|---|
| `POSTGRES_DB` / `POSTGRES_USER` | DB 이름·사용자 (기본 `sast`) |
| `POSTGRES_PASSWORD` | DB 비밀번호. 생성: `python -c "import secrets; print(secrets.token_urlsafe(24))"` |
| `POSTGRES_HOST` / `POSTGRES_PORT` | 기본 `127.0.0.1` / `5432` |
| `DJANGO_SECRET_KEY` | 반드시 새로 생성. 생성: `python -c "from django.core.management.utils import get_random_secret_key as g; print(g())"` |
| `DJANGO_DEBUG` | 기본 `False`. **로컬 개발에서는 `True`로 설정** |
| `DJANGO_ALLOWED_HOSTS` | 기본 `127.0.0.1,localhost` |

### 3. PostgreSQL 기동 (docker-compose)

```bash
docker compose up -d db
```

`.env`의 `POSTGRES_*` 값을 컨테이너와 Django가 공유합니다.
DB 포트는 `127.0.0.1`에만 바인딩됩니다 (외부 노출 없음).

### 4. 마이그레이션

```bash
python manage.py migrate
```

### 5. KISA 진단 기준 49개 시드

```bash
python manage.py seed_catalog
```

`catalog/data/kisa_rules.json`(49개 항목)과 `catalog/rules/*.yaml`(Semgrep 룰↔항목
매핑)을 읽어 카탈로그를 등록·갱신합니다. 멱등이라 재실행해도 안전하며,
`--dry-run` 옵션으로 DB를 건드리지 않고 검증만 할 수 있습니다.

### 6. 관리자 계정 생성

```bash
python manage.py createsuperuser
```

이메일·비밀번호를 물어봅니다 (username 없음 — 이메일 로그인). 이렇게 만든 계정은
자동으로 `ADMIN` 역할이 부여되어, 웹 UI에서 사용자 관리(계정 생성·비활성화 등)를
할 수 있습니다. 일반 사용자 계정은 이 admin 계정으로 로그인한 뒤 UI에서 만듭니다.

### 7. 백엔드 기동

```bash
python manage.py runserver
```

API 서버가 `http://127.0.0.1:8000`에서 뜹니다. 프론트 dev 서버가 `/api` 요청을
여기로 프록시하므로 **백엔드를 먼저 띄운 상태**에서 프론트를 실행합니다.

### 8. 프론트엔드 기동

새 터미널에서:

```bash
cd frontend
npm install
npm run dev
```

브라우저에서 `http://localhost:5173` 접속 → 6번에서 만든 admin 이메일/비밀번호로
로그인합니다.

### 요약 (전체 순서)

```bash
pip install -r requirements.txt   # 1. 의존성 (venv 안에서)
cp .env.example .env              # 2. 환경변수 채우기
docker compose up -d db           # 3. PostgreSQL
python manage.py migrate          # 4. 스키마
python manage.py seed_catalog     # 5. 진단 기준 49개
python manage.py createsuperuser  # 6. admin 계정
python manage.py runserver        # 7. 백엔드 (127.0.0.1:8000)
cd frontend && npm install && npm run dev   # 8. 프론트 (localhost:5173)
```

## CI 게이트 (GitHub Actions)

PR이 올라오면 `.github/workflows/sast-scan.yml`이 PR 브랜치와 base를 각각 우리 룰셋
(`catalog/rules`)으로 스캔해 비교하고, **신규 HIGH가 1건이라도 있으면 병합을 막습니다.**

- "신규"의 정의는 웹 비교 화면과 같습니다 — 서버와 같은 핑거프린트(`catalog/fingerprint.py`,
  룰 | 경로 | 코드 조각)로 짝짓기 때문에 줄 번호가 밀린 것은 신규로 잡지 않습니다.
- 결과는 job summary와 PR 코멘트에 심각도별 건수와 신규 항목 목록으로 남습니다
  (코멘트는 갱신되어 쌓이지 않음). 신규 MEDIUM/LOW·해결·유지는 보고만 합니다.
- 스캔 제외: `catalog/samples`, `dogfood`, `tests.py` — 의도적으로 취약한 샘플/픽스처라
  진단 대상이 아닙니다. 판단 로직은 `scripts/sast_gate.py`, 근거는 `docs/decisions.md` 9/4.

![신규 HIGH로 차단된 PR](docs/images/ci-gate-blocked.png)

로컬에서 같은 판정을 재현하려면 (Semgrep JSON 두 개를 넘기면 됩니다):

```bash
semgrep scan --config=catalog/rules --json --metrics=off \
  --exclude=catalog/samples --exclude=dogfood --exclude=tests.py \
  --exclude=venv --exclude=frontend --output=head.json .
python scripts/sast_gate.py --head head.json --base base.json --base-root <base 체크아웃>
```

## 더 읽을 것

- `CLAUDE.md` — 프로젝트 규칙(보안 규칙 포함)
- `docs/plan.md` — 상세 계획
- `docs/requirements-map.md` — RFP 요구사항별 구현 상태
- `docs/decisions.md` — 설계 결정 기록
