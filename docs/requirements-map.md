# RFP 요구사항 구현 추적

상태: ⬜ 미착수 / 🔨 진행중 / ✅ 완료 / ❌ 비목표(이유는 plan.md)

## SFR (시스템 기능)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| SFR-001 | 사용자 로그인 | ✅ | accounts/urls.py `POST /api/auth/login/` + frontend `LoginPage` | 이메일+비밀번호, 커스텀 User. UI 완결 — 브라우저 E2E 확인(8/28) |
| SFR-002 | 인증 수단 발급 | ✅ | accounts (simplejwt) | JWT access/refresh, logout 시 blacklist |
| SFR-003 | 역할 기반 접근 제어 | ✅ | accounts/permissions.py `IsAdminRole` | 관리자/일반 2역할, DB 값으로 재검증 |
| SFR-004 | 분석 프로젝트 관리 | ✅ | projects/views.py `ProjectViewSet` + frontend `ProjectListPage`/`ProjectDetailPage` | 등록·조회·수정, 삭제 라우트 미생성(mixin 조합). 목록·생성·상세 UI 완결(8/28) |
| SFR-005 | 프로젝트 사용자 할당 | ✅ | projects/views.py `members`/`member_detail` | 개별 추가·해제, assigned_by·assigned_at 기록. 할당 **UI는 비목표**(사용자 목록 API 부재) — API·shell로 수행 |
| SFR-006 | 프로젝트 조회 범위 | ✅ | projects/views.py `get_queryset` | 관리자=전체, 일반=할당분만. 브라우저 E2E — 일반 계정 목록에 할당분만 표시(8/28) |
| SFR-007 | 분석 대상 소스 관리 | ✅ | analysis/views.py `ProjectAnalysisRunsView` + frontend `ProjectDetailPage` | zip 업로드, Zip Slip 방어(SEC-008), 관리자만. 업로드 UI 완결(8/28) |
| SFR-008 | 정적 분석 실행 | ✅ | analysis/views.py `AnalysisRunExecuteView` + frontend 실행 버튼(`ProjectDetailPage`/`RunDetailPage`) | 업로드와 분리된 2단계 트리거, 관리자만. 동기 실행 중 버튼 잠금 UI(8/28) |
| SFR-009 | 분석 처리 체계 | ✅ | analysis/services.py `run_semgrep` | Semgrep subprocess 동기 연계. 룰셋을 `p/python`에서 자체 KISA 룰(`catalog/rules/`)로 교체 완료. `--no-git-ignore`·`PYTHONUTF8=1`·`encoding='utf-8'` 필요 (docs/decisions.md 외부 도구 연계 문제) |
| SFR-010 | 분석 언어 확장성 | ✅ | catalog/rules + catalog 전반 | 구조로 충족 — 카탈로그 49개는 언어 중립, 탐지는 룰 YAML 추가만으로 확장(파서·모델·API에 언어 분기 없음), 엔진이 다중 언어 지원. 실제 2번째 언어 룰은 미작성(범위 선택, plan.md §5) |
| SFR-011 | 초기 분석 대상 지원 | ❌ | - | Python만 (Java/JS 비목표) |
| SFR-012 | 진단 항목 등록 | ✅ | catalog/management/commands/seed_catalog.py | 룰 YAML 1개 추가 + 시드 재실행이면 코드 수정 없이 카탈로그 반영. kisa_code 오타는 시드 시점에 실패(드리프트 감지) |
| SFR-013 | 진단 기준 카탈로그 | ✅ | catalog/models.py `DiagnosticRule` + `/api/catalog/rules/` + frontend `CatalogPage` | 49개 전부 등록, 그중 13개 실탐지. 유형·심각도·구현여부 필터, `/api/catalog/summary/` 집계. 49개 표시·필터 UI 완결(8/28) |
| SFR-014 | 분석 결과 표준화 | ✅ | catalog/services.py `ingest_findings` | raw_result → Finding. 실행 성공 시 시그널로 자동 연결, 멱등. 관리자용 재표준화 API 별도 |
| SFR-015 | 분석 실행 상태 관리 | ✅ | analysis/models.py `AnalysisStatus` + frontend `StatusBadge` | 대기/실행중/완료/실패 4상태. 원자적 전환으로 RUNNING 관측 가능. 4상태 배지 UI 표시(8/28) |
| SFR-016 | 분석 결과 조회 | ✅ | catalog/views.py `RunFindingListView`/`RunFindingSummaryView` + frontend `RunDetailPage` | 실행별 결과 목록 + 심각도·항목별 집계. 심각도 높은 순 정렬. 집계 카드·목록·코드조각 UI 완결(8/28) |
| SFR-017 | 진단 결과 검색·필터 | ✅ | catalog/views.py `RunFindingListView.get_queryset` + frontend 필터 칩 | severity·category·rule·q 필터. 알 수 없는 값은 400. 심각도 필터 칩·페이지네이션(50) UI 완결(8/28) |

## DAR (데이터)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| DAR-001 | 데이터 저장소 | ✅ | docker-compose.yml (PG16) + config/settings.py | Django→PG 접속 확인(16.15) |
| DAR-002 | 사용자 데이터 | ✅ | accounts/models.py `User` | 이메일 unique, role |
| DAR-003 | 프로젝트 데이터 | ✅ | projects/models.py `Project` | |
| DAR-004 | 프로젝트 권한 데이터 | ✅ | projects/models.py `ProjectMember` | 연결 테이블, assigned_by·assigned_at |
| DAR-005 | 분석 실행 데이터 | ✅ | analysis/models.py `AnalysisRun` | workspace_id(UUID)로 격리 디렉토리 명명, raw_result는 Semgrep 원본 |
| DAR-006 | 진단 결과 데이터 | ✅ | catalog/models.py `Finding` (`catalog_finding`) | 표준화된 결과. file_path는 격리 루트 기준 상대경로, semgrep_check_id는 접두사 제거 후 저장 |
| DAR-007 | 진단 기준 데이터 | ✅ | catalog/models.py `DiagnosticRule` (`catalog_rule`) | KISA 49개. code unique, severity_reason으로 등급 근거 보관 |
| DAR-008 | 분석 시점 이력 보존 | ❌ | catalog/models.py `Finding` 스냅샷 컬럼 | 단순화 — rule_code·rule_name·severity만 복사(전체 이력 테이블 비목표) |
| DAR-009 | 구조화된 부가정보 | ✅ | JSONField | `DiagnosticRule.semgrep_rule_ids`/`extra`, `Finding.extra`(cwe·kisa_name·semgrep_severity) |
| DAR-010 | 데이터 관계 무결성 | ✅ | FK 제약 + 인덱스 | projects: created_by PROTECT, 멤버십 CASCADE, UniqueConstraint(project,user). analysis: project CASCADE, created_by PROTECT, workspace_id unique. catalog: run CASCADE, rule PROTECT(미매핑 허용 null), code unique, (run,severity)·(run,rule) 인덱스 |

## SEC (보안)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| SEC-001 | 비밀번호 보호 | ✅ | settings.PASSWORD_HASHERS | BCryptSHA256 1순위, 저장 해시 `bcrypt_sha256$` 확인 |
| SEC-002 | 보호 기능 인증 | ✅ | settings.REST_FRAMEWORK + frontend `RequireAuth` | DRF 기본 권한 IsAuthenticated (기본 차단). catalog 엔드포인트 6종 미인증 401 확인. 프론트는 미인증 시 /login 리다이렉트 — 차단 자체는 서버 담당(8/28) |
| SEC-003 | 관리자 기능 통제 | ✅ | projects/analysis/catalog 각 뷰 | IsAdminRole 적용 — 프로젝트 생성·수정·할당, 업로드·실행, 재표준화. 3개 앱 전부 적용. E2E — 일반 계정 생성 시도 403(8/28) |
| SEC-004 | 일반 사용자 권한 통제 | ✅ | 각 앱 `get_permissions`/`permission_classes` | 읽기만 허용, 나머지는 기본 차단. 시리얼라이저 전 필드 read_only. E2E — 일반 계정에 생성·업로드·실행 버튼 미노출(UI 숨김은 편의, 차단은 서버)(8/28) |
| SEC-005 | 프로젝트 소속 검증 | ✅ | projects·analysis·catalog의 스코프 쿼리셋 | IDOR 방어 — 결과 조회도 스코프된 run을 거쳐야 도달. 할당 해제 즉시 404 (테스트로 고정). 브라우저 E2E — 미할당 프로젝트가 일반 계정에 안 보임(8/28) |
| SEC-006 | 비인가 정보 노출 방지 | ✅ | 전 앱 (기본 수준, plan.md §5) | 미할당·미존재 동일 404(본문까지 동일), 쓰기 균일 403, **스코프 검사가 필터 검증보다 먼저**라 400/404 차이로 존재를 떠볼 수 없음. 응답·저장값에 서버 절대경로·workspace UUID 없음. 프론트도 404 사유를 구분 없이 "찾을 수 없습니다"로만 표시(8/28) |
| SEC-007 | 분석 작업 영역 격리 | ✅ | analysis/services.py `workspace_dir` + catalog/services.py `_relative_path` | 실행별 디렉토리 분리. Semgrep이 돌려준 절대경로를 상대경로로 정규화하고, 격리 밖 경로의 결과는 저장하지 않음 |
| SEC-008 | 파일 경로 검증 | ✅ | analysis/services.py `_is_unsafe_member` | 절대경로·드라이브문자·`..`·심볼릭링크·resolve() 최종검증 다중 방어, zip bomb 상한(100MB/1000개, 실측값 기준) |
| SEC-009 | 분석 실행 보호 | ✅ | analysis/services.py + catalog/services.py `ingest_findings` | Semgrep 타임아웃(120초), 실행 상태 원자적 전환. 표준화는 `select_for_update`로 직렬화, 코드 조각은 파일 크기·줄 길이 상한(secure-review 수정) |
| SEC-010 | 외부 구성요소 관리 | ✅ | requirements.txt | 직접 의존성 6종 버전 고정. Semgrep 1.175.0(LGPL-2.1, subprocess 호출만이라 카피레프트 미전이), PyYAML 6.0.3(MIT), `--metrics=off`로 텔레메트리 차단. 운영 배포 전 후속 과제: DRF BrowsableAPIRenderer 비활성 |

## TST (테스트)
| 번호 | 이름 | 상태 | 비고 |
|---|---|---|---|
| TST-001 | 인증 기능 시험 | ✅ | accounts/tests.py — 로그인 성공/실패, 미인증 401, bcrypt 저장. + 브라우저 E2E — 로그인·세션 복원·로그아웃(폐기 refresh 재사용 401 확인)(8/28) |
| TST-002 | 역할 권한 시험 | ✅ | accounts/tests.py — 일반 사용자 403, 역할 강등 즉시 반영. 시연 필수. + 브라우저 E2E — 일반 계정에 관리 버튼 미노출, 프로젝트 생성 시도 403(8/28) |
| TST-003 | 프로젝트 접근 시험 | ✅ | projects/tests.py `IdorDefenseTests` 등 22개. curl 수동 시연: 할당 200 / 미할당·미존재 동일 404 / 쓰기 균일 403. + 브라우저 E2E — 미할당 프로젝트 목록 숨김 + 상세 URL 직접 접근 404(IDOR 차단)(8/28) |
| TST-004 | 분석 처리 시험 | ✅ | analysis/tests.py 30개 + 실서버 수동 시연 — 업로드→압축해제→Semgrep 실행→결과조회 관통 |
| TST-005 | 진단 항목 시험 | ✅ | catalog/tests.py `DetectionSampleTests` — 실제 Semgrep으로 `catalog/samples/vulnerable.py` 정탐 20건/13룰, `safe.py` **오탐 0건**. 시연 핵심 |
| TST-006 | 카탈로그 시험 | ✅ | catalog/tests.py `SeedCatalogTests`·`SeedValidationTests`·`CatalogReadTests` — 49개 등록·유형 분포·멱등·드리프트 감지·조회 필터 |
| TST-007 | 분석 결과 관리 시험 | ✅ | catalog/tests.py `IngestTests`·`FindingReadTests`·`ReingestTests`·`PaginationTests` — 변환·멱등·필터·집계·재표준화 |
| TST-008 | 오류 처리 시험 | 🔨 | 기본 수준 — 잘못된 필터 400, 원본 없는 재표준화 409, 미존재 404, 표준화 실패 시 실행 보존+로그. 통일 에러 응답 포맷은 미정 |

## QLT (품질)
| 번호 | 이름 | 상태 | 비고 |
|---|---|---|---|
| QLT-001 | 모듈화 | ✅ | 4개 앱 책임 분리. analysis는 catalog를 import하지 않고 시그널만 발신 — 단방향 의존을 소스 검사 테스트로 고정(`test_analysis_app_does_not_import_catalog`) |
| QLT-002 | 진단 항목 독립성 | ✅ | 룰은 `catalog/rules/*.yaml`에 독립. `metadata.kisa_code`가 룰↔항목 매핑의 단일 원본이고, 시드 커맨드가 스캔해 반영 |
| QLT-003 | 확장성 | ✅ | SFR-010과 동일 — 카탈로그 언어 중립 + 룰 YAML 추가로 확장, 코드 수정 없음 |
| QLT-004 | 결과 일관성 | ✅ | catalog/services.py `normalize_severity` 한 곳에 집중. 카탈로그 등급이 최종, Semgrep 값은 미매핑 시 폴백. 양방향 역전(EH-01 ERROR→MEDIUM, SF-08 WARNING→HIGH)을 실제 분석으로 확인 |
| QLT-005 | 데이터 정합성 | ✅ | FK+트랜잭션. projects: UniqueConstraint(project,user) + IntegrityError를 savepoint로 400 전환. catalog: 재표준화를 `select_for_update`로 직렬화해 동시 요청 시 결과 중복 방지 |

---

## 현황 요약 (2026-08-28 기준)

- SFR 17개: 완료 15 / 비목표 1(SFR-011 — Python만, Java/JS는 plan.md §5) / — SFR-010은 구조 충족
- DAR 10개: 완료 9 / 비목표 1(DAR-008, 스냅샷으로 단순화)
- SEC 10개: 완료 10 (SEC-006·009는 plan.md §5의 "기본 수준" 기준)
- TST 8개: 완료 7 / 진행중 1(TST-008)
- QLT 5개: 완료 5
- 테스트: **180개 전부 통과** (accounts·projects·analysis 84 + catalog 96)
- **프론트엔드(8/28)**: React SPA로 로그인→프로젝트→업로드→실행→결과(심각도 필터)→카탈로그 49개
  전 화면 완결. 관리자·일반 계정 브라우저 E2E로 권한 격리까지 실증(위 SFR/SEC/TST 각 행의 8/28 표기).
  멤버 할당 UI는 비목표(사용자 목록 API 부재, SFR-005 비고)
