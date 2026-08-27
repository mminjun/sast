# RFP 요구사항 구현 추적

상태: ⬜ 미착수 / 🔨 진행중 / ✅ 완료 / ❌ 비목표(이유는 plan.md)

## SFR (시스템 기능)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| SFR-001 | 사용자 로그인 | ✅ | accounts/urls.py `POST /api/auth/login/` | 이메일+비밀번호, 커스텀 User |
| SFR-002 | 인증 수단 발급 | ✅ | accounts (simplejwt) | JWT access/refresh, logout 시 blacklist |
| SFR-003 | 역할 기반 접근 제어 | ✅ | accounts/permissions.py `IsAdminRole` | 관리자/일반 2역할, DB 값으로 재검증 |
| SFR-004 | 분석 프로젝트 관리 | ✅ | projects/views.py `ProjectViewSet` | 등록·조회·수정, 삭제 라우트 미생성(mixin 조합) |
| SFR-005 | 프로젝트 사용자 할당 | ✅ | projects/views.py `members`/`member_detail` | 개별 추가·해제, assigned_by·assigned_at 기록 |
| SFR-006 | 프로젝트 조회 범위 | ✅ | projects/views.py `get_queryset` | 관리자=전체, 일반=할당분만 |
| SFR-007 | 분석 대상 소스 관리 | ⬜ | analysis | zip 업로드만 |
| SFR-008 | 정적 분석 실행 | ⬜ | analysis | 관리자만 |
| SFR-009 | 분석 처리 체계 | ⬜ | analysis | Semgrep 연계 |
| SFR-010 | 분석 언어 확장성 | ⬜ | analysis | 구조만, Python 구현 |
| SFR-011 | 초기 분석 대상 지원 | ❌ | - | Python만 (Java/JS 비목표) |
| SFR-012 | 진단 항목 등록 | ⬜ | catalog | Semgrep 룰 추가 절차 |
| SFR-013 | 진단 기준 카탈로그 | ⬜ | catalog | 49개 등록+일부 탐지 |
| SFR-014 | 분석 결과 표준화 | ⬜ | catalog | |
| SFR-015 | 분석 실행 상태 관리 | ⬜ | analysis | 대기/진행/완료/실패 |
| SFR-016 | 분석 결과 조회 | ⬜ | catalog | |
| SFR-017 | 진단 결과 검색·필터 | ⬜ | catalog | 심각도 필터 |

## DAR (데이터)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| DAR-001 | 데이터 저장소 | ✅ | docker-compose.yml (PG16) + config/settings.py | Django→PG 접속 확인(16.15). 테이블은 커스텀 User 확정 후 첫 migrate |
| DAR-002 | 사용자 데이터 | ✅ | accounts/models.py `User` | 이메일 unique, role, 첫 migrate 완료 |
| DAR-003 | 프로젝트 데이터 | ✅ | projects/models.py `Project` | |
| DAR-004 | 프로젝트 권한 데이터 | ✅ | projects/models.py `ProjectMember` | 연결 테이블, assigned_by·assigned_at |
| DAR-005 | 분석 실행 데이터 | ⬜ | analysis/models | |
| DAR-006 | 진단 결과 데이터 | ⬜ | catalog/models | |
| DAR-007 | 진단 기준 데이터 | ⬜ | catalog/models | 49개 |
| DAR-008 | 분석 시점 이력 보존 | ❌ | - | 단순화(심각도·명칭 복사만) |
| DAR-009 | 구조화된 부가정보 | ⬜ | JSON 필드 | |
| DAR-010 | 데이터 관계 무결성 | 🔨 | FK 제약 | projects: created_by PROTECT, 멤버십 CASCADE, UniqueConstraint(project,user) 적용. analysis/catalog는 해당 앱에서 |

## SEC (보안)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| SEC-001 | 비밀번호 보호 | ✅ | settings.PASSWORD_HASHERS | BCryptSHA256 1순위, 저장 해시 `bcrypt_sha256$` 확인 |
| SEC-002 | 보호 기능 인증 | ✅ | settings.REST_FRAMEWORK | DRF 기본 권한 IsAuthenticated (기본 차단) |
| SEC-003 | 관리자 기능 통제 | ✅ | projects/views.py `get_permissions` | IsAdminRole 실제 적용(생성·수정·할당). analysis/catalog는 해당 앱에서 추가 적용 필요 |
| SEC-004 | 일반 사용자 권한 통제 | ✅ | projects/views.py `get_permissions` | 읽기만 허용, 나머지는 화이트리스트 밖이라 기본 차단. analysis/catalog는 해당 앱에서 추가 적용 필요 |
| SEC-005 | 프로젝트 소속 검증 | ✅ | projects/views.py `get_queryset` | IDOR 방어 — queryset 스코핑, client project_id 미신뢰, DB 관계로 재검증 |
| SEC-006 | 비인가 정보 노출 방지 | 🔨 | projects/views.py | 미할당·미존재 프로젝트 응답 동일(404), 쓰기 응답도 id 무관 균일(403) — projects만 적용, 전체 앱 기준 기본 수준은 계속 진행 |
| SEC-007 | 분석 작업 영역 격리 | ⬜ | analysis | 실행별 디렉토리 |
| SEC-008 | 파일 경로 검증 | ⬜ | analysis | Zip Slip 방어 |
| SEC-009 | 분석 실행 보호 | ⬜ | analysis | 타임아웃, 기본 수준 |
| SEC-010 | 외부 구성요소 관리 | 🔨 | requirements.txt | 직접 의존성 4종 버전 고정 완료, Semgrep 버전·라이선스는 도입 시 |

## TST (테스트)
| 번호 | 이름 | 상태 | 비고 |
|---|---|---|---|
| TST-001 | 인증 기능 시험 | ✅ | accounts/tests.py — 로그인 성공/실패, 미인증 401, bcrypt 저장 |
| TST-002 | 역할 권한 시험 | ✅ | accounts/tests.py — 일반 사용자 403, 역할 강등 즉시 반영. 시연 필수 |
| TST-003 | 프로젝트 접근 시험 | ✅ | projects/tests.py `IdorDefenseTests` 등 22개. curl 수동 시연: 할당 200 / 미할당·미존재 동일 404 / 쓰기 균일 403 |
| TST-004 | 분석 처리 시험 | ⬜ | 파이프라인 관통 |
| TST-005 | 진단 항목 시험 | ⬜ | 취약/정상 샘플, 시연 핵심 |
| TST-006 | 카탈로그 시험 | ⬜ | |
| TST-007 | 분석 결과 관리 시험 | ⬜ | |
| TST-008 | 오류 처리 시험 | ⬜ | 기본 수준 |

## QLT (품질)
| 번호 | 이름 | 상태 | 비고 |
|---|---|---|---|
| QLT-001 | 모듈화 | 🔨 | accounts(완료)·projects(완료) 책임 분리 확인, analysis/catalog는 구현 시 |
| QLT-002 | 진단 항목 독립성 | ⬜ | Semgrep 룰 구조로 충족 |
| QLT-003 | 확장성 | ⬜ | SFR-010과 동일 |
| QLT-004 | 결과 일관성 | ⬜ | 정규화 계층 |
| QLT-005 | 데이터 정합성 | 🔨 | FK+트랜잭션 | projects: UniqueConstraint(project,user) + IntegrityError를 savepoint로 400 전환 |