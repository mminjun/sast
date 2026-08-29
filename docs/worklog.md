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

## 2026-08-27
- projects 앱 구현 (SFR-004~006, DAR-003~004, SEC-003~006, TST-003)
  - Project(DAR-003) + ProjectMember(DAR-004, through 테이블) 모델. created_by는 PROTECT,
    멤버십은 CASCADE, UniqueConstraint(project, user)로 중복 할당 DB 차원 차단
  - ProjectViewSet: ModelViewSet 대신 mixin 조합(Create/List/Retrieve/Update)으로
    삭제 라우트 자체를 미생성(비목표를 라우트 부재로 표현), PUT 제외 PATCH만 허용
  - IDOR 방어(SEC-005) 핵심: get_queryset()에서 관리자=전체/일반=할당분만 스코핑 →
    상세·수정·할당이 전부 이 queryset을 거치는 get_object()라 URL의 project_id 조작으로
    스코프 밖에 도달 불가. get_permissions()는 화이트리스트(list/retrieve만 인증, 나머지
    전부 IsAdminRole)라 기본 차단(SEC-003/004 실제 적용 완료)
  - 응답 정책: 미할당·미존재 프로젝트 GET → 동일 404(존재 은닉), 쓰기 실패는 id 무관 균일
    403 (SEC-006)
  - 할당 API: 개별 추가/해제 — POST/DELETE /api/projects/{id}/members/(/{user_id}/)
  - 신규 테이블 없음, 신규 의존성 없음. 마이그레이션 1개(projects.0001_initial)
  - 검증: 테스트 54개 전부 통과(신규 32개, 기존 22개 회귀 없음) / manage.py check 0건 /
    psql로 projects_project·projects_project_member 2개 테이블·FK·unique 제약 확인 /
    수동 IDOR 시연(curl) — 할당 프로젝트 200 / 미할당·미존재 프로젝트 동일 404 /
    목록이 할당분만 반환 / 미할당 프로젝트 PATCH 403, 데모 데이터는 시연 후 정리
  - 자체 보안 검토(secure-review) 후 1건 수정 — 커밋 전 반영
    - ProjectViewSet에 lookup_value_regex=r'\d+' 추가: 숫자가 아닌 pk가 500 대신 404가
      되도록 (member_detail 액션과 비대칭이던 부분을 통일)
    - 재검증: 테스트 54개(신규 1개 포함) 전부 통과
  - 다음: analysis 앱 — zip 업로드 → Semgrep 실행 파이프라인 (SFR-007~009, SEC-007~008)
- analysis 앱 구현 (SFR-007~009, DAR-005, SEC-007~009, TST-004)
  - AnalysisRun(DAR-005) 모델: project CASCADE·created_by PROTECT, workspace_id(UUID, 격리
    디렉토리 명명용), status(TextChoices: PENDING/RUNNING/SUCCEEDED/FAILED, SFR-015),
    raw_result(JSONField — Semgrep 원본, 표준화는 catalog 앱 몫)
  - 업로드/실행 API 2단계 분리: POST /api/projects/{id}/analysis-runs/(zip 업로드+검증+등록,
    관리자) / POST /api/analysis-runs/{id}/execute/(Semgrep 트리거, 관리자) / GET 목록·상세는
    스코프된 인증 사용자(일반=할당 프로젝트만) — projects 앱과 동일한 IDOR 방어 원칙 재사용
  - 작업 영역 격리(SEC-007): MEDIA_ROOT/analysis_runs/<workspace_id>/, 경로는 저장 문자열이
    아니라 매번 재계산
  - Zip Slip 방어(SEC-008): extractall() 미사용, 절대경로·드라이브문자·`..`·심볼릭링크 차단 +
    resolve()+relative_to() 최종 검증. 전수 검증 후 추출이라 부분 추출 없음. zip bomb 상한
    100MB/1000개(사용자 확정값)
  - Semgrep 1.175.0 신규 의존성(승인받음), 라이선스 LGPL-2.1 확인(subprocess 호출만이라
    카피레프트 미전이). 동기 실행(요청 안 블로킹), 타임아웃 120초, 룰셋은 임시 `p/python`
    (catalog에서 KISA 49개 매핑으로 교체 예정)
  - 검증: analysis 테스트 30개 신규(전체 84개, 회귀 없음) / manage.py check 0건 / 실제
    서버로 수동 시연 — 업로드→격리 디렉토리에 정확히 이 실행 건 소스만 추출 확인→실행
    (10초, 동기)→SUCCEEDED+raw_result 저장 확인→재실행 시도 409→미할당 일반 사용자
    list/detail 404, execute 403(IDOR)까지 관통 확인, 데모 데이터는 시연 후 정리
  - 자체 보안 검토(secure-review) 후 3건 수정 — 커밋 전 반영
    - zip bomb 방어를 zip 메타데이터 선언값이 아니라 추출 시 실측 바이트 수 기준으로 변경
      (선언값 위조로 상한 우회 가능했음)
    - 분석 실행 상태 전환(PENDING/FAILED→RUNNING)을 조건부 UPDATE로 원자화 —
      동시 실행 요청의 중복 Semgrep 실행 경합 제거
    - Semgrep 호출에 `--metrics=off` 추가 — 고객 소스코드를 다루는 도구의 기본 텔레메트리 차단
    - 재검증: analysis 테스트 30개(기존 케이스 포함) 전부 통과
  - 다음: catalog 앱 — KISA 49개 진단 기준 등록, Semgrep 결과 표준화(raw_result → Finding),
    결과 조회·심각도 필터 (SFR-012~014, 016~017, DAR-006~007)
- catalog 앱 구현 (SFR-012~014, 016~017, DAR-006~007, 009, QLT-002, 004, TST-005~007)
  - 진단 기준 49개 등록: KISA 소프트웨어 보안약점 진단가이드 2021.11 기준을 그대로
    `catalog/data/kisa_rules.json`에 시드. 코드 체계는 `KISA-<유형약어>-<절 내 순번>`
    (IV/SF/TS/EH/CE/EN/AA). 유형 분포 IV17/SF16/TS2/EH3/CE5/EN4/AA2 = 49 확인
  - 심각도는 개발자 판단으로 확정(멘토 승인 사항 — 가이드에 항목별 등급이 없다).
    3단계 원칙(직접 침해=H / 조건부·정찰·가용성=M / 간접=L)으로 H26/M20/L3 배정하고,
    실탐지 13개는 항목별 사유를 `severity_reason` 필드와 decisions.md 양쪽에 기록
  - 자체 Semgrep 룰 13개 작성(`catalog/rules/*.yaml`), 공개 레지스트리 `p/python` 폐기.
    `metadata.kisa_code`가 룰↔항목 매핑의 단일 원본 — 룰 YAML 추가 + 시드 재실행이면
    코드 수정 없이 카탈로그가 갱신된다(SFR-012, QLT-002)
  - 표준화 계층(SFR-014): raw_result → Finding. 심각도는 `normalize_severity()` 한 곳에서
    결정 — 카탈로그 등급이 최종, Semgrep 값은 미매핑 시 폴백(QLT-004). 실행 성공 시
    시그널(analysis→catalog 단방향)로 자동 연결, 멱등
  - 조회 API 6종: 카탈로그 목록·상세·집계 / 결과 목록·집계·재표준화. 심각도·유형·항목
    필터(SFR-017), 심각도 높은 순 정렬, 잘못된 필터 값은 400
  - IDOR 방어는 projects·analysis와 같은 원칙(스코프 쿼리셋). 스코프 검사가 필터 검증보다
    먼저 실행돼 400/404 차이로 실행의 존재를 떠볼 수 없다(SEC-006)
  - 신규 의존성 PyYAML 6.0.3(MIT, 승인받음). 마이그레이션 1개(catalog.0001_initial),
    테이블 2개 추가로 plan.md §4의 6테이블 설계 완성
  - **실제로 돌려보고서야 드러난 외부 도구 연계 문제 4건** (decisions.md에 별도 기록)
    - Semgrep이 룰 파일을 cp949로 읽어 한글 메시지에서 룰 로딩 실패 → `PYTHONUTF8=1`
    - Semgrep이 `.gitignore`를 존중해 작업 영역(`media/` 아래) 전체를 건너뜀 → 결과 0건인데
      종료 코드 0이라 SUCCEEDED로 보였다. **어제 analysis 시연이 이걸 놓친 원인** —
      상태·저장 여부만 봤지 raw_result 안의 results가 빈 배열인 건 안 봤다 → `--no-git-ignore`
    - Semgrep이 미인증 상태에서 코드 조각을 `requires login`으로 가림 → 격리 디렉토리의
      파일에서 직접 읽는다(계정 연동은 외부 의존을 늘리는 선택이라 하지 않음)
    - `subprocess.run(text=True)`가 로케일 코덱으로 출력을 디코딩 → `encoding='utf-8'`
    - 교훈: 분석 관련 검증의 완료 기준을 상태값이 아니라 **결과 건수**로 잡는다
  - 검증: 전체 테스트 180개 통과(기존 84 + catalog 신규 96, 회귀 0건) / manage.py check 0건 /
    psql로 catalog_rule·catalog_finding 스키마·인덱스·FK 확인 / 실제 설정으로 업로드→실행→
    표준화→조회 관통 25개 항목 확인 — 취약 샘플 20건 정탐, 안전 샘플 0건 오탐, 응답에
    절대경로·workspace UUID 없음, 카탈로그 등급이 도구 등급을 양방향으로 역전
    (EH-01 ERROR→MEDIUM, SF-08 WARNING→HIGH). 데모 데이터는 검증 후 정리
  - 자체 보안 검토(secure-review) 후 3건 수정 — 커밋 전 반영
    - 재표준화를 `select_for_update`로 직렬화 — 동시 요청 시 앞 트랜잭션이 커밋한 행을
      뒤 트랜잭션이 지우지 못해 결과가 두 배로 저장될 수 있었다
    - 코드 조각 추출에 파일 크기(2MB)·줄 길이(500자) 상한 + 수집 1회 캐시 — 줄 수만
      제한하면 한 줄짜리 대용량 파일에서 메모리가 튄다
    - 결과 목록 뷰에만 페이지네이션(50/최대 200) — 전역 설정으로 걸면 기존 앱 응답 형태가
      바뀌어 회귀가 된다
    - 재검증: 수정 확인 19개 + API 48개 + 전체 180개 통과
  - 후속 과제로 기록(코드 미변경): DRF BrowsableAPIRenderer는 로컬 시연 중이라 유지하되
    운영 배포 시 JSONRenderer만 남긴다. 전역 설정이라 한 앱만 바꾸면 불일치가 생긴다
  - 다음: 중간발표 자료 정리 → React 화면 (pen.dev 목업) → 도그푸딩(우리 SAST로 우리 코드
    분석, `catalog/samples/`는 제외)

## 2026-08-28
- 도그푸딩 — 우리 SAST로 이 프로젝트 자체를 분석 (plan.md §7, 발표 자료용)
  - 보고서: `docs/self-scan-20260828.md`. 분석 실행 #18(본 실행)·#19(대조군), 프로젝트 #17은
    발표 근거라 **DB에 보존**한다 (기존 시연 데이터처럼 정리하지 않음)
  - Semgrep 직접 실행이 아니라 실제 API(로그인→프로젝트 생성→zip 업로드→실행→조회)로 관통 —
    "우리가 만든 SAST에 우리 코드를 올려서 분석했다"가 도그푸딩의 요건
  - 대상: 추적 중인 `.py` 46개 / 4,749 LOC (운영 42개 2,545 + 테스트 4개 2,204)
  - 제외: `catalog/samples/`(의도적 취약 자산) 2개, `*/migrations/`(자동 생성물) 9개,
    `venv/`·`media/`·`.env`·`.git/`(미추적이라 후보에서 제외됨). 룰이 전부 python이라
    비-Python 파일은 대상 밖. **제외 사유를 결과와 함께 공개**한다 — 목록 없이 숫자만 내면
    "유리한 것만 골라 스캔했다"로 읽힌다
  - 제외는 zip 생성 시점에 실현했다. `run_semgrep()`이 격리 디렉토리 전체를 `--no-git-ignore`로
    스캔하므로 **zip에 넣지 않는 것이 유일한 제외 수단**이다 (스캔 단계 제외 옵션 없음)
  - 결과: **33건, 전부 KISA-SF-06(하드코드된 중요정보)·HIGH. 전부 `*/tests.py`. 운영 코드 0건**
    - 트리아지 33건 완료 → 정탐·수용 33 / 오탐 0. 근본 원인은 공유 테스트 상수 `PASSWORD` 1개
    - 29건이 `password=PASSWORD`(리터럴 아닌 참조)인데도 잡혔다 — 엔진의 상수 전파.
      "grep과 뭐가 다르냐"에 대한 답으로 발표에 쓸 수 있다
  - **대조군 #19**: 같은 파이프라인에 `catalog/samples/` 2개만 올려 20건·룰 13개 전부 발화·
    `safe.py` 오탐 0 확인. 이게 있어야 운영 코드 0건이 "룰이 안 돌아서 0건"이 아니게 된다
  - 검증(완료 기준을 상태값 아닌 수치로 — 8/27 교훈 적용): `paths.scanned` **46 = zip 파일 수와
    일치** / `errors` 0건 / 원본 33 = 표준화 33 / unmapped 0 / 미인증 401 / 격리 디렉토리에
    46개 `.py`만 존재(samples·migrations 0)
  - **도그푸딩이 찾은 건 취약점이 아니라 우리 도구의 결함**이었다 (보고서 §6에 후속 과제로 기록)
    - F-1 결과 그룹핑 부재: 원인 1개가 33건으로 보고돼 사용자가 33번 확인해야 한다 (우선순위 높음)
    - F-2 트리아지 상태 저장 없음: "검토·수용" 기록할 곳이 없어 다음 분석에 같은 33건이 다시 뜬다
    - F-3 룰에 `*/tests.py` 예외 추가는 **하지 않기로 결정** — 테스트 디렉토리에 들어간 진짜
      시크릿을 놓친다. F-2(사람이 판정해 기록)로 푸는 게 맞다
  - 코드 변경 없음. 새 의존성 없음. 마이그레이션 없음
  - 한계 명시(보고서 §7): 49개 중 13개만 실탐지 / Python만 / IDOR·권한 로직은 패턴 룰로 검증
    불가(테스트 180개 담당) — **SAST 0건과 "보안 검증됨"은 다른 말**
  - 다음: 발표 자료에 §4 집계·§5 트리아지·§6 후속 과제 반영 → React 화면 (pen.dev 목업)
- React 프론트엔드 구축 (SFR-001~002·004·007~008·013·015~017의 화면, SEC-002~006 UI 반영)
  - dashboard.pen 목업은 Pencil 에디터 미연결로 읽기 불가 → 사용자 결정으로 목업 없이
    표준 구성. 언어는 JavaScript(시연 일정 우선, 사용자 결정)
  - `frontend/` Vite+React SPA. 신규 npm 의존성 5종(react/react-dom/react-router-dom/
    vite/@vitejs/plugin-react, 전부 MIT, 계획 승인으로 갈음). Python 의존성·백엔드 수정 0
  - 화면 5개: 로그인 / 프로젝트 목록·생성 / 프로젝트 상세(zip 업로드·실행) /
    실행 결과(심각도 집계·필터·페이지네이션 50) / 카탈로그 49개(유형·심각도·구현여부·검색)
  - JWT: access는 메모리, refresh는 sessionStorage. refresh는 **single-flight**(사용자
    지적 — rotation+blacklist라 중복 갱신이 정상 세션을 로그아웃시킴. StrictMode 이중
    마운트가 실제로 이 경합을 만든다). CORS는 Vite dev proxy로 회피(백엔드 무수정).
    근거는 decisions.md
  - 검증(결과 건수 기준 — 8/27 교훈): 프록시 경유 실 API로 로그인→me(ADMIN)→프로젝트
    1건→카탈로그 49/13→보존된 도그푸딩 실행 #18 결과 33건·HIGH 필터 33건·summary 33건
    일치 / 로그아웃 후 폐기 refresh 재사용 401 확인 / `npm run build` 통과(52 모듈)
  - 자체 보안 검토(secure-review) 후 낮음 2건 수정 — 커밋 전 반영
    - refresh 실패 시 세션 정리를 401/403에만 한정(일시 장애에 유효 토큰을 버리지 않게)
    - 로그아웃은 noAuthRetry(만료 access로 갱신을 거치면 blacklist가 헛돌고 새 refresh만 남음)
  - 다음: 브라우저 실제 화면 확인(관리자·일반 E2E) → 시연 리허설. 멤버 할당 UI는
    사용자 목록 API가 없어 범위 밖으로 기록
- 오후 — 일반 계정 생성 + 브라우저 E2E로 권한 격리 실증 (TST-001~003, SEC-003~006)
  - user@sast.local(일반 역할) 생성 + 프로젝트 #17 할당. 회원가입 UI가 없는 건 의도
    (관리자 통제 모델, decisions.md) — 계정은 백엔드에서 만든다
  - **사고 1건**: `manage.py shell`에 스크립트를 stdin 파이프로 넣었더니 대화형 콘솔이
    블록 안 빈 줄에서 깨져 **절반만 실행** — 비밀번호 없는 계정이 남았다. DB 상태를 조회로
    확인 후 `shell -c "exec(open(...).read())"` 방식 + 멱등 스크립트(set_password를 조건
    밖으로)로 재실행해 복구. 교훈: DB를 바꾸는 스크립트는 부분 실행을 전제로 멱등하게
  - API 검증: user 로그인 → me(USER) → 목록에 #17만 → 프로젝트 생성 시도 403
  - 브라우저 E2E(사용자 직접 수행): admin으로 대조군 "테스트 프로젝트 B" 생성(미할당 유지)
    → user 화면에서 미할당 프로젝트 비표시 확인. 일반 계정에서 생성·업로드·실행 버튼
    미노출 확인 — 프로젝트별 권한 격리(SEC-005~006)·역할 통제(TST-002)를 화면으로 실증
  - requirements-map.md를 8/28 기준으로 갱신 — 위 항목들의 구현 위치에 frontend 페이지
    추가, E2E 근거 표기, 비목표(SFR-011, 멤버 할당 UI) 사유 유지
  - 다음: 시연 리허설(9/3 최종 발표), 발표 자료에 E2E 시나리오 반영
- 저녁 — admin 전용 사용자 관리 (SEC-003, SFR-005, SEC-001, TST-002)
  - 오전 shell 파이프 사고가 동기 — shell로 하던 계정 관리를 UI로. 범위는 계획 승인으로
    확정: 일반 계정 생성 / 삭제(물리+비활성화 병행) / 프로젝트별 할당·해제 UI.
    역할 변경(admin 승격)은 범위 밖 — 생성 role은 서버가 USER 강제
  - 백엔드: /api/users/ 4개 엔드포인트(GET 목록·POST 생성·DELETE·PATCH is_active), 전부
    IsAuthenticated+IsAdminRole. accounts 앱 소속 유지, URL만 별도 모듈(user_urls.py).
    config/urls.py 1줄 외 기존 코드 무수정 — members API·UserSerializer·client.js 그대로
  - 핵심 방어: role·is_active는 시리얼라이저 필드 부재로 mass assignment 차단 /
    validate_password 명시 호출(DRF는 자동 적용 안 함) / email__iexact + IntegrityError
    savepoint 2단(CI 유일 제약) / 자기 자신·마지막 활성 admin은 select_for_update로
    대상+활성 admin 전원 잠가 상호 동시 제거 경합까지 차단 / 이력(PROTECT 3종) 계정
    삭제는 409로 변환해 비활성화 안내, 멤버십(CASCADE)만은 실삭제 허용을 테스트로 고정
  - 프론트: RequireAdmin 가드(편의, 차단은 서버) + 네비 "사용자 관리" + UsersPage(생성
    폼·목록·비활성 토글·삭제 확인) + ProjectDetailPage 멤버 섹션(셀렉트 할당·해제) +
    .btn-danger. 409는 "비활성화하세요" 문구로 분기
  - 검증: 테스트 209개 전부 통과(신규 29, 회귀 0) / npm run build 54 모듈 / 실서버 API
    E2E 20개 체크 전부 통과 — role=ADMIN 실어도 USER 생성, 할당→200·해제→즉시 404,
    비활성화 즉시 기존 access 401·로그인 401, 자기 자신 400, 잔여 데이터 0(시연용
    프로젝트 #17·#18 불변). 브라우저 클릭 스루는 시연 리허설에서
  - 자체 보안 검토(secure-review) 2회(백엔드/프론트) — 백엔드 낮음 1건 수정(password
    max_length=128), 프론트 통과(참고 2건은 decisions.md에 기록)
  - 사고 예방 개선: DB를 바꾸는 검증 스크립트는 실행 전 시나리오·생성 계정·정리 방식을
    요약 제시하고 승인 후 실행 (사용자 요청, 이후 관례로)
  - 다음: 브라우저에서 사용자 관리 화면 확인(시연 리허설에 포함), main 병합은 PR로

## 2026-08-29
- 밤 — 카탈로그 심각도 범례 + 49개 전체 등급 근거 완비 (SFR-013, QLT-004)
  - CatalogPage 필터 아래 범례 카드 추가: 높음/보통/낮음 의미 한 줄씩(SeverityBadge
    재사용으로 결과 화면과 색 일관) + 3단 등급 정책·미매핑 폴백(Semgrep 등급, 그마저
    불명확하면 MEDIUM) 각주. 표시용 UI만 — 등급 결정 로직 무수정
  - 미구현 36개 항목의 severity_reason 보완 — 기존 실탐지 13개 문장은 불변, 49개 전체
    근거 완비. 등급 자체는 8/27 확정값 그대로이며 사유 문장만 추가. decisions.md에 같은
    문장 동기화(catalog 테스트의 decisions.md 대조 계약 준수)
  - 검증: git diff로 severity_reason 줄 36쌍만 변경 확인 / seed_catalog 재실행 —
    신규 0/갱신 49(멱등) / DB에서 49개 전부 severity_reason 채움 확인(total 49 =
    with_reason 49) / catalog 테스트 96개 통과 / npm run build 통과(54 모듈)
  - 커밋 a499b24(범례 UI)·1af065c(등급 근거 완비), main 푸시 완료
- 밤 2차 — 탐지 룰 8개 추가, 실탐지 13→21개 (feature/detection-rules, SFR-012~013, TST-005)
  - 1차 EH-03·AA-02·IV-11·CE-02 / 2차 IV-07·SF-13·SF-12·SF-07 — 배치별로 룰 YAML +
    취약/대응 샘플 쌍 + 기대값 갱신 후 실탐지 테스트로 검증하고 커밋
  - 겹침 통제: AA-02는 기존 룰 점유 API(eval·os.system·pickle·md5·random) 제외 —
    경계를 decisions.md에 기록. CE-02는 대입문 형태만(즉시 소비형은 IV-03 영역).
    신규 대응 코드가 기존 룰에 걸리지 않는 것까지 확인해 기존 정탐 20건 불변 유지
  - SF-13은 pattern-regex(AST는 주석을 못 본다) — '키워드[:=]값' 형태 한정으로 오탐 억제
  - 검증: 정탐 31건/21룰 기대값 일치, safe.py 오탐 0, catalog 테스트 96개 통과(실탐지
    포함, 스킵 없음), seed_catalog 재실행 신규 0/갱신 49 — 실탐지 21/미구현 28
  - 커밋 7f3e0e8(1차)·bc5f0ee(2차) + 문서 갱신 커밋
  - 다음: PR로 main 병합, 시연 리허설(9/3 최종 발표), 발표 자료에 등급 정책 화면 반영
- 낮 — 분석 대상 0개 실패 처리 (fix/empty-source-validation, TST-008, SFR-015)
  - 배경: 빈 zip(엔트리 0)·지원 언어 파일 없는 zip을 실행하면 Semgrep이 빈 디렉토리에
    exit 0을 반환해 SUCCEEDED·0건으로 끝났다. 대상 없는 입력은 유효하지 않은 분석으로
    보고 실패 처리하기로 결정 (TST-008 취지)
  - `run_semgrep()` 서두에서 격리 디렉토리의 지원 확장자 파일
    (`ANALYSIS_SCAN_TARGET_SUFFIXES`, 현재 `.py` — 룰 21개 전부 python) 존재를 확인,
    0개면 Semgrep 미호출로 FAILED + "분석 가능한 소스 파일이 없습니다" 저장.
    기존 타임아웃·비정상 종료 분기와 같은 저장 패턴, 상태 기계·업로드 단계 무수정
    (업로드=소스 등록, 실행=분석 — 2단계 API 의미 유지). 확장자를 룰 YAML에서 동적
    파생하지 않은 이유: analysis→catalog 역방향 의존 회피(QLT-001), settings 주석에 기록
  - 프론트 무수정 — RunDetailPage가 이미 실패 배지+`error_message`를 표시
  - 검증: 신규 테스트 2개(빈 zip·비지원 파일만 zip → FAILED + `assert_not_called`)
    포함 전체 211개 통과, 회귀 0건 / manage.py check 0건 / 브라우저 확인은 사용자
    TST-008 시연에서 (dogfood/empty.zip·broken-not-a-zip.zip 준비됨)
  - 다음: 브라우저 TST-008 확인 → PR로 main 병합
