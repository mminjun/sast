# 실행 방법 (Setup)

두 가지 경로가 있다. 방문자용 소개는 [README](../README.md)를 본다.

- **Docker로 띄우기** — 제품을 써 보려면 이쪽. Docker만 있으면 되고 명령 3개다.
- **개발 환경** — 코드를 고치며 핫리로드가 필요하면 이쪽. 터미널 3개(백엔드·워커·프론트).

둘은 공존한다 — 같은 `docker-compose.yml`이고, 개발 환경은 그중 `db`만 쓴다.

## Docker로 띄우기

```bash
git clone https://github.com/mminjun/sast.git && cd sast
cp .env.example .env            # Windows PowerShell: Copy-Item .env.example .env
docker compose up               # db + web + worker
```

`.env`에서 채울 값은 4개다. 기본값을 두지 않아 비어 있으면 기동이 즉시 실패한다(fail-fast — 예측 가능한 키로
조용히 뜨는 것보다 낫다. 근거는 `docs/decisions.md` 2026-09-07).

| 변수 | 값 |
|---|---|
| `POSTGRES_PASSWORD`, `DJANGO_SECRET_KEY` | 무작위 값. 둘 다 같은 한 줄로 만든다: `python -c "import secrets; print(secrets.token_urlsafe(50))"` — Python이 없으면 `docker run --rm python:3.13-slim python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DJANGO_SUPERUSER_EMAIL`, `DJANGO_SUPERUSER_PASSWORD` | 첫 로그인에 쓸 관리자 계정. 비밀번호는 Django 검증기(8자 이상, 흔한 값 금지 등)를 통과해야 하고, placeholder를 그대로 두면 기동이 멈춘다 |

첫 기동에서 `web`이 마이그레이션 → 진단 기준 49개 시드 → 관리자 계정 생성(이미 있으면 건너뜀)을 하고
gunicorn을 띄운다. `worker`는 `web`이 응답한 뒤에 뜬다. 이미지 빌드(프론트 `npm ci` + Python 의존성 + Semgrep)는
첫 한 번만 걸린다. 브라우저에서 `http://localhost:8000` → `.env`의 관리자 이메일/비밀번호로 로그인한다.
이후 절차는 아래 "첫 분석 해보기"와 같다.

알아 둘 것:

- **포트·데이터.** web은 `127.0.0.1:8000`에만 바인딩된다(`.env`의 `WEB_PORT`로 변경). 업로드·실행 작업 영역과
  접근 로그는 named volume(`sast-media`, `sast-logs`)에 있고 DB는 `sast-db-data`다. `docker compose down`은
  volume을 지우지 않는다 — 전부 지우려면 `docker compose down -v`.
- **로그.** `docker compose logs -f web worker`. 분석이 `대기열`에 머물면 worker 로그를 본다.
- **워커 재시작.** worker는 시작할 때 `--reap-all`로 `실행중`에 남은 실행을 전부 `실패`로 정리한다 — 컨테이너가
  실행 도중 내려간 경우의 복구다. 워커를 2개 이상 띄우려면(`--scale worker=2`) compose의 이 옵션을 빼고
  `--worker-id`를 서로 다르게 준다.
- **호스트 개발과 같이 쓰기.** 개발 환경의 runserver도 8000을 쓰므로 둘을 동시에 띄우려면 `WEB_PORT`를 바꾼다.
  둘은 같은 DB(`sast-db`)를 공유하고 media·logs는 따로다. `.env`의 `POSTGRES_HOST=127.0.0.1`은 호스트용이고
  컨테이너는 compose가 `db`로 덮어쓴다.
- **컨테이너 안에서 테스트.** `docker compose run --rm web python manage.py test --exclude-tag=semgrep --noinput --parallel 4`
  (전체는 `--exclude-tag`를 뺀다). CI는 호스트에서 돌므로 필수는 아니다.
- **`DJANGO_ALLOWED_HOSTS`를 바꾸면 `127.0.0.1`을 남긴다.** web의 healthcheck가 그 주소로 `/`를 요청한다.

## 개발 환경 (핫리로드)

로컬에서 백엔드·워커·프론트를 각각 띄운다. 코드를 고치며 반복할 때 쓴다.

### 사전 준비물

- Python 3.13
- Node.js 20 이상 (개발은 v24 기준)
- Docker + Docker Compose (PostgreSQL 용)

### 1. 클론 및 파이썬 의존성 설치

```bash
git clone https://github.com/mminjun/sast.git
cd sast
python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

Semgrep CLI는 `requirements.txt`에 포함되어 있어 별도 설치가 필요 없다.

### 2. 환경변수 설정 (.env)

템플릿 `.env.example`을 복사해 `.env`를 만들고 값을 채운다. `.env`는 `.gitignore`로 커밋에서 제외된다.

```bash
# Windows PowerShell: Copy-Item .env.example .env
cp .env.example .env
```

필수 값 (없으면 서버가 기동 자체를 거부한다 — fail-fast):

| 변수 | 설명 |
|---|---|
| `POSTGRES_DB` / `POSTGRES_USER` | DB 이름·사용자 (기본 `sast`) |
| `POSTGRES_PASSWORD` | DB 비밀번호. 생성: `python -c "import secrets; print(secrets.token_urlsafe(24))"` |
| `POSTGRES_HOST` / `POSTGRES_PORT` | 기본 `127.0.0.1` / `5432` |
| `DJANGO_SECRET_KEY` | 반드시 새로 생성. 생성: `python -c "from django.core.management.utils import get_random_secret_key as g; print(g())"` |
| `DJANGO_DEBUG` | 기본 `False`. **로컬 개발에서는 `True`로 설정** |
| `DJANGO_ALLOWED_HOSTS` | 기본 `127.0.0.1,localhost` |
| `DJANGO_SUPERUSER_EMAIL` / `DJANGO_SUPERUSER_PASSWORD` | Docker용. 개발 환경에서는 비워 두고 6번에서 `createsuperuser`를 써도 된다 |

선택 값(`.env.example`에 설명): 업로드·압축 해제 상한(`ANALYSIS_MAX_*`), Semgrep 타임아웃, 자체 taint 엔진
on/off와 시간 예산(`ANALYSIS_CUSTOM_TAINT_*`), 큐 백엔드(`ANALYSIS_TASK_BACKEND`).

### 3. PostgreSQL 기동 (docker-compose)

```bash
docker compose up -d db
```

`.env`의 `POSTGRES_*` 값을 컨테이너와 Django가 공유한다. DB 포트는 `127.0.0.1`에만 바인딩된다 (외부 노출 없음).

### 4. 마이그레이션

```bash
python manage.py migrate
```

### 5. KISA 진단 기준 49개 시드

```bash
python manage.py seed_catalog
```

`catalog/data/kisa_rules.json`(49개 항목)과 `catalog/rules/*.yaml`(Semgrep 룰↔항목 매핑)을 읽어 카탈로그를
등록·갱신한다. 멱등이라 재실행해도 안전하며, `--dry-run` 옵션으로 DB를 건드리지 않고 검증만 할 수 있다.

### 6. 관리자 계정 생성

```bash
python manage.py createsuperuser
```

이메일·비밀번호를 묻는다 (username 없음 — 이메일 로그인). 이렇게 만든 계정은 자동으로 `ADMIN` 역할이 부여되어
웹 UI에서 사용자 관리(계정 생성·비활성화 등)를 할 수 있다. 일반 사용자 계정은 이 admin 계정으로 로그인한 뒤
UI에서 만든다. `.env`에 `DJANGO_SUPERUSER_*`를 채웠다면 `python manage.py ensure_superuser`로도 된다(멱등).

### 7. 백엔드 기동

```bash
python manage.py runserver
```

API 서버가 `http://127.0.0.1:8000`에서 뜬다. 프론트 dev 서버가 `/api` 요청을 여기로 프록시하므로 **백엔드를
먼저 띄운 상태**에서 프론트를 실행한다.

### 7-1. 분석 워커 기동

새 터미널에서 (venv 활성화 — 워커가 Semgrep을 실행하므로 `semgrep`이 PATH에 있어야 한다):

```bash
python manage.py analysis_worker
```

분석 실행 요청은 큐에 등록만 하고(상태 `대기열`) 이 워커가 순서대로 처리한다. 큐는 PostgreSQL
테이블(`django-tasks-db`)이라 Redis 같은 별도 서비스는 없다. **워커를 띄우지 않으면 실행이 대기열에 머물고**,
5분이 지나면 화면이 "워커가 실행 중인지 확인하세요"라고 알린다. `DJANGO_DEBUG=True`면 워커도 코드 변경 시 자동
재시작된다.

- **동시 실행 수 = 워커 프로세스 수.** 한 워커는 한 번에 한 건만 처리한다. Semgrep이 코어를 전부 쓰므로 노트북은
  1개, 서버는 코어 수를 보고 2~3개(`--worker-id`를 서로 다르게 주어 여러 개 실행).
- 워커가 작업 도중 종료되면 그 실행은 `실행중`에 남는데, 워커를 다시 시작하면 시작 시 자동으로
  `실패`("워커가 중단되어…")로 정리되어 재실행할 수 있다 (`python manage.py reap_stale_runs`로 수동 정리도 가능).
- 워커 없이 요청 안에서 동기 실행하려면 `.env`에 `ANALYSIS_TASK_BACKEND=immediate` (큐 도입 전과 같은 동작,
  테스트가 이 모드로 돈다).

### 8. 프론트엔드 기동

새 터미널에서:

```bash
cd frontend
npm install
npm run dev
```

브라우저에서 `http://localhost:5173` 접속 → 6번에서 만든 admin 이메일/비밀번호로 로그인한다.

### 요약 (전체 순서)

```bash
pip install -r requirements.txt   # 1. 의존성 (venv 안에서)
cp .env.example .env              # 2. 환경변수 채우기
docker compose up -d db           # 3. PostgreSQL
python manage.py migrate          # 4. 스키마
python manage.py seed_catalog     # 5. 진단 기준 49개
python manage.py createsuperuser  # 6. admin 계정
python manage.py runserver        # 7. 백엔드 (127.0.0.1:8000)
python manage.py analysis_worker  # 7-1. 분석 워커 (새 터미널, venv 활성화)
cd frontend && npm install && npm run dev   # 8. 프론트 (localhost:5173)
```

## 첫 분석 해보기

1. 프로젝트 목록에서 프로젝트를 만든다(관리자만).
2. 프로젝트 상세에서 소스 zip을 올리고 실행한다. 샘플로는 `catalog/samples/`를 zip으로 묶으면 된다 —
   언어별 `vulnerable.*`/`safe.*`와 taint 샘플 4개가 들어 있고, 각 파일의 주석에 기대 결과가 적혀 있다.
3. 워커가 처리하면 실행 상세에서 결과·코드 조각·오염 경로를 본다. 두 번째 실행부터 "이전 분석과 비교"가 열린다.

## 테스트 실행

```bash
# 평소(약 1분): 실제 Semgrep을 도는 무거운 시험을 건너뛴다
python manage.py test --exclude-tag=semgrep --noinput --parallel 4
# 전체(커밋 전·룰/샘플/실행 경로를 건드렸을 때)
python manage.py test --noinput --parallel 4
# Semgrep 시험만
python manage.py test --tag=semgrep --noinput
```

`--noinput`은 항상 붙인다 — 테스트 DB가 남아 있으면 삭제 확인 프롬프트에서 멈춘다. 테스트는 동시에 두 개 돌리지
않는다(같은 테스트 DB). 테스트 중에는 비밀번호 해셔가 MD5로 바뀐다(속도 목적, 운영 불변).

## CI 게이트를 로컬에서 재현하기

PR마다 `.github/workflows/sast-scan.yml`이 PR 브랜치와 base를 각각 우리 룰셋으로 스캔해 비교하고, 신규 HIGH가
1건이라도 있으면 병합을 막는다. 같은 판정을 로컬에서 내려면 Semgrep JSON 두 개를 넘기면 된다:

```bash
semgrep scan --config=catalog/rules --json --metrics=off \
  --exclude=catalog/samples --exclude=dogfood --exclude=tests.py \
  --exclude=venv --exclude=frontend --output=head.json .
python scripts/sast_gate.py --head head.json --base base.json --base-root <base 체크아웃>
```

스캔 제외(`catalog/samples`, `dogfood`, `tests.py`)는 의도적으로 취약한 샘플·픽스처라 진단 대상이 아니다. 판단
로직은 `scripts/sast_gate.py`, 근거는 `docs/decisions.md` 2026-09-04.

## 자체 분석 zip 만들기 (도그푸딩)

```bash
python scripts/make_selfscan_zip.py selfscan.zip
```

git이 추적하는 파일만 담고 `.env` 등 금지 이름을 다시 검사한다 — 작업 영역의 `.env`가 zip에 섞여 들어간 사고
(`docs/decisions.md` 2026-09-05)의 재발 방지다.
