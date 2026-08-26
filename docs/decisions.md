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