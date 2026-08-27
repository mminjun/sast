# 결정 기록

형식: 날짜 | 결정 | 근거 | 관련 요구사항

## 2026-08-25

- 분석 엔진: 외부 연계(Semgrep) | 진단 로직 직접 구현은 기간 내 불가,
  멘토 허용 확인. 룰 독립 관리(YAML)가 QLT-002 충족 | SFR-009, SEC-010
- 백엔드: Django + DRF | 인증·권한·관리자·ORM 기본 내장으로 RFP 관리
  요구(SFR-001~006) 빠른 구현. 검증된 보안 기본값(secure by default) | SFR-001~006
- 프론트: React (탈출구: Django 템플릿) | 포트폴리오 완성도,
  pen.dev 목업 활용. 막히면 부분 후퇴 | -
- DB: PostgreSQL | 실무 표준, 관계형·무결성·마이그레이션 요구 충족 | DAR-001, 010
- 비밀번호 해시: bcrypt | SHA-2는 고속 해시라 무차별 대입에 취약, 적응형(느린) 해시가 비밀번호에 적합. Django BCryptSHA256의 SHA256 전처리는 72바이트 제한 우회용이며 고속 해시 단독 사용과 무관 | SEC-001, DAR-002
- 소스 등록: zip 업로드만 | SFR-007이 방식 선택을 수행사에 위임,
  가장 단순한 방식으로 핵심 흐름 집중 | SFR-007
- 분석 언어: Python만 구현 | SFR-010이 "확장 가능한 구조"만 요구,
  구조는 열어두고 1개 언어 집중 | SFR-010, 011
- 진단 항목: 카탈로그 49개 등록 + 일부만 실탐지 | 멘토 승인
  ("좋은 아이디어"), 시간 제약 | SFR-013
- 인증 포함 결정 | 멘토는 생략 허용했으나 RFP 명시 요구사항(SFR-001~003)
  이해 증명 목적으로 최소 구현(로그인+2역할) 포함 | SFR-001~003
- 심각도 부여 기준: KISA 유형 분류 기반 | KISA 49개 기준은 유형 분류는 제공하나 항목별 심각도 등급은 미제공, Semgrep 도구 등급을 그대로 쓰면 근거 약함. 유형의 영향 성격(침해 직접성)으로 High/Medium/Low 확정 | QLT-004, SFR-014

## 2026-08-26

- DB 로컬 실행: Docker Compose + named volume(sast-db-data) | 호스트에 PG를 직접
  설치하지 않아 버전(16) 고정·재현이 쉽고, 컨테이너를 지워도 볼륨에 데이터가 남는다.
  재기동 후 테이블 잔존 확인 | DAR-001
- DB 시크릿: .env 분리, .env.example만 커밋 | 비밀번호를 compose 파일에 리터럴로 쓰면
  커밋에 시크릿이 남는다. compose는 `${VAR:?}` 필수 문법을 써서 값이 없으면 기동 실패 —
  빈 비밀번호로 뜨면 Postgres가 host 연결을 trust 인증으로 열어버리므로 fail-fast가 안전 | DAR-001, SEC-010
- DB 포트 바인딩: 127.0.0.1만 | 기본 `5432:5432`는 모든 인터페이스에 열려 같은 네트워크의
  다른 기기에서 DB에 직접 붙을 수 있다. 개발 편의보다 노출 최소화 우선 | SEC-006
- SECRET_KEY: `os.environ[...]` 기본값 없이 fail-fast | 기본값을 두면 `.env` 누락 시
  예측 가능한 키로 조용히 기동돼 세션·토큰 위조가 가능하다. compose의 `${VAR:?}`와 같은 원칙.
  startproject가 박아둔 `django-insecure-...` 키는 워킹트리에 노출된 값이라 재사용하지 않고 폐기 | SEC-010
- DEBUG 기본값 False | 환경변수 누락 시 디버그가 켜지는 방향이 아니라 꺼지는 방향이
  안전한 기본값. DEBUG=False에서 ALLOWED_HOSTS가 비면 전 요청이 400이라 함께 .env로 분리 | SEC-006
- Django DB 설정에 compose와 같은 `POSTGRES_*` 키 재사용 | Django 전용 키를 따로 두면
  컨테이너와 앱이 서로 다른 값을 바라볼 수 있다. `POSTGRES_HOST`만 추가 | DAR-001
- 첫 migrate 보류 | 지금 migrate하면 `auth.User`로 고정되는데 DAR-002/SFR-001은 이메일 로그인
  커스텀 User를 요구한다. 이후 `AUTH_USER_MODEL` 교체 시 DB 초기화가 필요하므로
  accounts 커스텀 User 정의 후 첫 migrate | DAR-002, SFR-001
- 의존성 버전 고정: requirements.txt에 직접 의존성만 `==` | 취약점 공지·릴리즈 노트 추적
  대상을 명확히 한다. 전이 의존성까지 고정하는 lock은 현 규모에 과함 | SEC-010
- User 모델: AbstractUser 상속(username 제거, email을 USERNAME_FIELD) | 완전 커스텀
  (AbstractBaseUser)은 permissions·admin 연동을 직접 붙여야 해서 인증 코드에 실수가 날
  여지가 크다. 검증된 기본 구현을 최대한 물려받는 편이 MVP 기간에 안전 | DAR-002, SFR-001
- 역할: User.role TextChoices 필드(ADMIN/USER) | RFP가 2역할만 요구하므로 Group 체계는
  간접 계층만 늘린다. 기본값은 USER — 실수로 만들어진 계정이 관리자가 되지 않게 | SFR-003, SEC-003
- 인증: JWT(djangorestframework-simplejwt) | React SPA와 붙일 때 CSRF·CORS 부담이 없고
  DRF와 통합돼 있다. refresh 회전 + 로그아웃 시 blacklist로 유출 토큰 수명을 줄인다 | SFR-002
- **인가는 JWT 클레임이 아니라 DB의 현재 role로 판단** | 토큰은 서명돼 있어도 발급 시점의
  스냅샷이라, role을 클레임에 담아 검사하면 강등된 사용자가 토큰 만료 전까지 관리자로
  통과한다. 클라이언트가 들고 온 값을 신뢰하지 않는다는 원칙(IDOR 방어)과 같은 이유.
  테스트로 강등 즉시 403이 되는지 확인 | SEC-003, SEC-005
- DRF 기본 권한을 IsAuthenticated로 | 기본이 AllowAny면 권한 지정을 빠뜨린 엔드포인트가
  조용히 공개된다. 기본 차단 후 필요한 곳만 명시적으로 여는 편이 실수에 강하다 | SEC-002, SEC-004
- 회원가입(자가 등록) API 없음 | RFP는 관리자가 사용자를 관리하는 모델이고, 공개 가입은
  누구나 계정을 만들 수 있는 경로가 되어 MVP 범위·보안 모두에 맞지 않는다 | SFR-004

### 자체 보안 검토(secure-review) 후속 수정 — 2026-08-26

- 이메일 대소문자 무시: save()에서 소문자 정규화 + `Lower('email')` UniqueConstraint +
  `get_by_natural_key`를 iexact로 | `normalize_email`은 도메인만 소문자화하고 PostgreSQL의
  unique 인덱스도 대소문자를 구분해서, 이메일이 로그인 식별자인데 `Kim@x.com`과 `kim@x.com`이
  별개 계정으로 공존할 수 있었다. 쓰기 경로가 create_user 하나가 아니므로(admin·스크립트)
  모델 save()를 단일 관문으로 삼고, DB 제약으로 이중 방어 | SFR-001
- 로그인 빈도 제한: ScopedRateThrottle 5/min | bcrypt는 오프라인 크래킹을 늦출 뿐 온라인
  자동 대입은 막지 못한다. ScopedRateThrottle은 throttle_scope를 지정한 뷰에만 걸리므로
  전역 설정해도 다른 엔드포인트에 영향이 없다. 기본 캐시가 프로세스별 LocMemCache라
  운영에서는 공유 캐시 필요 | SEC-001
- 로그아웃 시 refresh 토큰 소유자 검증 | 서명·만료 검증만으로는 "내 토큰"인지 알 수 없어,
  타인의 refresh 토큰을 확보하면 강제 로그아웃시킬 수 있었다. 실패 사유(형식 오류/타인 토큰)는
  구분하지 않고 동일 응답 — 응답 차이가 토큰 유효성 확인 수단이 되지 않게 | SEC-005, SEC-006
- JWT 특성상 로그아웃해도 access 토큰은 만료(30분)까지 유효하다 | blacklist는 refresh에만
  적용된다. 즉시 무효화가 필요하면 access 수명을 줄이는 것이 통상적 절충. 시연 시 설명 | SFR-002

## 2026-08-27

- IDOR 방어: 뷰의 if문이 아니라 get_queryset()에 권한을 건다 | 상세·수정·할당이 전부
  get_object()를 거치므로, URL의 project_id를 조작해도 스코프 밖 행에는 애초에 도달할
  방법이 없다. 검사 지점을 뷰 로직 여러 곳에 흩뿌리면 하나는 빠뜨릴 위험이 있다 |
  SEC-005, SFR-006
- ProjectMember(연결 테이블)에 프로젝트별 역할 필드를 두지 않는다 | 멤버십=읽기 권한,
  쓰기 권한은 전역 User.role이 결정. RFP가 2역할만 요구하는데 권한 계층을 둘로 나누면
  검사 지점이 늘어난다. 필요해지면 컬럼 추가로 확장 가능 | SFR-003, SFR-005
- 프로젝트 삭제 라우트를 아예 생성하지 않는다 (ModelViewSet 대신 mixin 조합) | 비목표를
  405가 아니라 라우트 부재로 표현한다 — "구현했는데 막았다"가 아니라 "만들지 않았다"가
  더 정확한 상태 표현 | SFR-004 (비목표, plan.md §5)
- 응답 정책: 읽기 실패는 404, 쓰기 실패는 403 | 일반 사용자가 미할당·미존재 프로젝트를
  GET하면 완전히 동일한 404(존재 은닉). 반면 쓰기는 권한 검사가 객체 조회보다 먼저 실행돼
  id와 무관하게 항상 403 — 두 경우 모두 응답 차이로 프로젝트 존재 여부를 알아낼 수 없다 |
  SEC-005, SEC-006
- 할당 API: 목록 통째 교체(PUT)가 아니라 개별 추가·해제(POST/DELETE) | 요청 1건=변경
  1건이라 감사 기록(assigned_by/assigned_at)이 자연스럽고, "할당 해제 → 즉시 404"
  IDOR 시연(TST-003)이 깔끔하다. 빈 배열 전송으로 전원 해제되는 사고 위험도 없다 | SFR-005

### 자체 보안 검토(secure-review) 후속 수정 — 2026-08-27

- ProjectViewSet에 lookup_value_regex=r'\d+' 추가 | pk가 숫자가 아닌 값(예: /api/projects/abc/)이
  오면 정수 필드 캐스팅에서 500이 날 수 있었다. member_detail 액션은 이미 \d+ 정규식을 쓰고
  있었는데 목록·상세 라우트만 비대칭이었다. URL 매칭 단계에서 걸러 404로 통일 | SEC-006

## 2026-08-27 (analysis 앱)

- Semgrep 버전 고정: 1.175.0 | pip 기준 최신 안정 버전. 라이선스는
  github.com/semgrep/semgrep의 LICENSE 파일(SPDX LGPL-2.1)로 확인. subprocess로
  외부 CLI를 호출만 하고 소스를 링크하지 않으므로 카피레프트 의무가 전이되지
  않는다 (plan.md "직접 진단 로직 구현 안 함"과 일치) | SEC-010
- zip 상한: 압축 해제 후 총 100MB / 파일 1000개 (멘토·사용자 확정값) | zip bomb
  기본 방어(SEC-008). 처음엔 zip 중앙 디렉토리의 선언된 file_size 합만 검사했는데,
  이 값은 조작 가능해서 secure-review에서 지적받아 실제 추출 시 청크 단위로 읽은
  바이트 수를 다시 상한과 비교하도록 고쳤다(선언값은 빠른 1차 거름망, 실측값이
  최종 방어) | SEC-008
- 업로드/실행 API 2단계 분리 | 대기/실행중/완료/실패 4개 상태(SFR-015)가 실제로
  관찰 가능해야 의미가 있는데, 업로드 요청 안에서 바로 실행까지 끝내면 RUNNING이
  거의 관측 불가능해진다. 업로드 실패와 분석 실패도 독립적으로 재시도 가능해짐 |
  SFR-007, SFR-008, SFR-015
- Semgrep 실행: 동기(요청-응답 안 블로킹) | Celery 등 새 인프라 도입 없이 일정
  내 완주하는 것을 우선했다. 상태 필드는 동기 실행이라도 조회 시점에 의미가
  있다(경합 방지 원자적 UPDATE로 RUNNING이 실제로 관측 가능) | SFR-008~009
- Semgrep 룰셋: 임시로 공개 레지스트리 `p/python` | catalog 앱(KISA 49개 매핑)이
  아직 없어서 파이프라인(업로드→실행→저장) 자체가 동작함을 먼저 증명. 룰셋
  교체는 catalog 작업 때 진행 (QLT-002 진단 항목 독립성과 연결) | SFR-013, QLT-002
- AnalysisRun 격리 디렉토리 이름: PK 대신 workspace_id(UUID) | 순차 정수 PK를
  파일시스템 경로에 그대로 노출하지 않기 위해서다. 경로는 저장된 문자열이
  아니라 workspace_id + settings.ANALYSIS_WORKSPACE_ROOT로 매번 재계산 — DB
  경로 문자열을 신뢰해 파일시스템을 조작하지 않는다 | SEC-007
- Zip Slip 방어: extractall() 대신 전수 검증 후 수동 추출 | 절대경로·드라이브
  문자(Windows)·`..` 세그먼트·심볼릭 링크(external_attr) 각각을 문자열/메타데이터
  수준에서 차단하고, 마지막에 resolve()+relative_to()로 실제 목적지 경로가
  격리 루트를 벗어나는지 재확인한다(우회 기법이 달라져도 최종 검증이 잡음).
  검증은 추출 전 모든 항목에 대해 먼저 끝내고, 하나라도 걸리면 아무것도 쓰지
  않는다(부분 추출 방지) | SEC-008
- 결과 저장 범위: raw_result에 Semgrep 원본 JSON만 저장 | KISA 49개 항목 매핑·
  표준화(SFR-014, DAR-006)는 catalog 앱의 책임이라 오늘은 있는 그대로만
  보관한다. 앱 간 책임을 섞지 않는다(QLT-001) | SFR-009, DAR-005

### 자체 보안 검토(secure-review) 후속 수정 — 2026-08-27 (analysis)

- zip bomb 방어를 선언값이 아니라 실측값 기준으로 | info.file_size(zip 중앙
  디렉토리 선언값)는 조작 가능해서, 이 값만 검사하면 실제로는 상한을 넘는
  zip도 통과해 무제한으로 디스크에 쓸 수 있었다. 추출 루프에서 1MB 청크로
  읽으며 누적 바이트 수를 상한과 비교, 초과 시 즉시 중단하고 디렉토리를
  지운다 | SEC-008
- 분석 실행 상태 전환을 원자적 UPDATE로 | 상태 확인(if run.status in ...)과
  RUNNING 저장이 분리돼 있으면 거의 동시에 들어온 두 실행 요청이 모두 통과해
  Semgrep이 중복 실행될 수 있었다. `filter(status__in=[PENDING, FAILED]).update(...)`
  로 확인과 전환을 하나의 쿼리로 묶어 두 번째 요청은 반드시 막힌다 | SEC-009
- Semgrep 호출에 `--metrics=off` 추가 | 고객 소스코드를 다루는 보안 도구가
  기본값으로 익명 사용 지표조차 외부로 보낼 이유가 없다. 코드 자체는
  전송되지 않지만, 무엇이 외부로 나가는지를 최소화한다 | SEC-010