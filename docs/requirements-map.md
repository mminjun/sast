# RFP 요구사항 구현 추적

상태: ⬜ 미착수 / 🔨 진행중 / ✅ 완료 / ❌ 비목표(이유는 plan.md)

## SFR (시스템 기능)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| SFR-001 | 사용자 로그인 | ✅ | accounts/urls.py `POST /api/auth/login/` + frontend `LoginPage` | 이메일+비밀번호, 커스텀 User. UI 완결 — 브라우저 E2E 확인(8/28) |
| SFR-002 | 인증 수단 발급 | ✅ | accounts (simplejwt) | JWT access/refresh, logout 시 blacklist |
| SFR-003 | 역할 기반 접근 제어 | ✅ | accounts/permissions.py `IsAdminRole` | 관리자/일반 2역할, DB 값으로 재검증 |
| SFR-004 | 분석 프로젝트 관리 | ✅ | projects/views.py `ProjectViewSet` + frontend `ProjectListPage`/`ProjectDetailPage` | 등록·조회·수정, 삭제 라우트 미생성(mixin 조합). 목록·생성·상세 UI 완결(8/28) |
| SFR-005 | 프로젝트 사용자 할당 | ✅ | projects/views.py `members`/`member_detail` + frontend `ProjectDetailPage` 멤버 섹션 | 개별 추가·해제, assigned_by·assigned_at 기록. 사용자 목록 API 신설(8/28 저녁)로 할당·해제 UI 완결 — 셀렉트로 할당, 해제 즉시 404. members API는 무수정 재활용 |
| SFR-006 | 프로젝트 조회 범위 | ✅ | projects/views.py `get_queryset` | 관리자=전체, 일반=할당분만. 브라우저 E2E — 일반 계정 목록에 할당분만 표시(8/28) |
| SFR-007 | 분석 대상 소스 관리 | ✅ | analysis/views.py `ProjectAnalysisRunsView` + frontend `ProjectDetailPage` | zip 업로드, Zip Slip 방어(SEC-008), 관리자만. 업로드 UI 완결(8/28) |
| SFR-008 | 정적 분석 실행 | ✅ | analysis/views.py `AnalysisRunExecuteView` + frontend 실행 버튼(`ProjectDetailPage`/`RunDetailPage`) | 업로드와 분리된 2단계 트리거, 관리자만. 동기 실행 중 버튼 잠금 UI(8/28) |
| SFR-009 | 분석 처리 체계 | ✅ | analysis/services.py `run_semgrep` | Semgrep subprocess 동기 연계. 룰셋을 `p/python`에서 자체 KISA 룰(`catalog/rules/`)로 교체 완료. `--no-git-ignore`·`PYTHONUTF8=1`·`encoding='utf-8'` 필요 (docs/decisions.md 외부 도구 연계 문제) |
| SFR-010 | 분석 언어 확장성 | ✅ | catalog/rules + catalog 전반 | 완료(9/2 판정 조정, decisions.md) — 요구는 "확장 가능한 구조"이고 카탈로그 49개는 언어 중립, 파서·모델·API에 언어 분기 없이 룰 YAML 추가만으로 확장, 엔진이 다중 언어 지원. 실제 추가 언어 룰 작성은 SFR-011로 분리 — 9/4 C 룰 추가로 실증(같은 항목 7개를 Python·C 룰이 각각 탐지, 코드 변경 0) |
| SFR-011 | 초기 분석 대상 지원 | 🔨 | catalog/rules/c_*.yaml, `catalog/samples/vulnerable.c`·`safe.c`, settings `ANALYSIS_SCAN_TARGET_SUFFIXES` | 부분 충족 — Python·C 2개 언어 구현(9/4 C 룰 13개: 신규 실탐지 6개 IV-16·IV-17·SF-03·TS-01·CE-01·CE-03 + Python 항목의 C 판 7개, .c/.h 인식). Java/JS 등 추가 확장은 룰 세트 추가로 가능. 패턴만으로 못 잡는 항목(IV-14·IV-03·CE-04 등)과 사유는 decisions.md 9/4 |
| SFR-012 | 진단 항목 등록 | ✅ | catalog/management/commands/seed_catalog.py | 룰 YAML 1개 추가 + 시드 재실행이면 코드 수정 없이 카탈로그 반영. kisa_code 오타는 시드 시점에 실패(드리프트 감지) |
| SFR-013 | 진단 기준 카탈로그 | ✅ | catalog/models.py `DiagnosticRule` + `/api/catalog/rules/` + frontend `CatalogPage` | 49개 전부 등록, 그중 27개 실탐지(8/29 룰 8개 추가, 9/4 C 룰로 6개 추가). 유형·심각도·구현여부 필터, `/api/catalog/summary/` 집계. 49개 표시·필터 UI 완결(8/28). 심각도 범례 카드(등급 정책·폴백 각주, 8/29) |
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
| DAR-007 | 진단 기준 데이터 | ✅ | catalog/models.py `DiagnosticRule` (`catalog_rule`) | KISA 49개. code unique, severity_reason으로 등급 근거 보관 — 49개 전체 완비(8/29, 실탐지 13개→전체 확장) |
| DAR-008 | 분석 시점 이력 보존 | ✅ | catalog/models.py `Finding` 스냅샷 컬럼 | 완료(9/2 판정 조정, decisions.md) — 요구의 보존 위치는 "진단 결과에"이고 항목 코드·명칭·심각도를 결과 행에 복사해 달성. 카탈로그 자체의 시점별 버전 관리는 요구에 없는 확장이라 범위 외. 한계: 유형(category)은 rule 참조로 남아 기준 개정 시 혼합 표시 가능 |
| DAR-009 | 구조화된 부가정보 | ✅ | JSONField | `DiagnosticRule.semgrep_rule_ids`/`extra`, `Finding.extra`(cwe·kisa_name·semgrep_severity) |
| DAR-010 | 데이터 관계 무결성 | ✅ | FK 제약 + 인덱스 | projects: created_by PROTECT, 멤버십 CASCADE, UniqueConstraint(project,user). analysis: project CASCADE, created_by PROTECT, workspace_id unique. catalog: run CASCADE, rule PROTECT(미매핑 허용 null), code unique, (run,severity)·(run,rule) 인덱스 |

## SEC (보안)
| 번호 | 이름 | 상태 | 구현 위치 | 비고 |
|---|---|---|---|---|
| SEC-001 | 비밀번호 보호 | ✅ | settings.PASSWORD_HASHERS | BCryptSHA256 1순위, 저장 해시 `bcrypt_sha256$` 확인 |
| SEC-002 | 보호 기능 인증 | ✅ | settings.REST_FRAMEWORK + frontend `RequireAuth` | DRF 기본 권한 IsAuthenticated (기본 차단). catalog 엔드포인트 6종 미인증 401 확인. 프론트는 미인증 시 /login 리다이렉트 — 차단 자체는 서버 담당(8/28) |
| SEC-003 | 관리자 기능 통제 | ✅ | projects/analysis/catalog 각 뷰 + accounts `UserListCreateView`/`UserDetailView` | IsAdminRole 적용 — 프로젝트 생성·수정·할당, 업로드·실행, 재표준화, **사용자 관리(목록·생성·삭제·비활성화, 8/28 저녁)**. 생성 role은 서버가 USER 강제(mass assignment 차단), 자기 자신·마지막 활성 admin 방지, 이력 계정 409. E2E — 일반 계정 생성 시도 403(8/28) |
| SEC-004 | 일반 사용자 권한 통제 | ✅ | 각 앱 `get_permissions`/`permission_classes` | 읽기만 허용, 나머지는 기본 차단. 시리얼라이저 전 필드 read_only. E2E — 일반 계정에 생성·업로드·실행 버튼 미노출(UI 숨김은 편의, 차단은 서버)(8/28) |
| SEC-005 | 프로젝트 소속 검증 | ✅ | projects·analysis·catalog의 스코프 쿼리셋 | IDOR 방어 — 결과 조회도 스코프된 run을 거쳐야 도달. 할당 해제 즉시 404 (테스트로 고정). 브라우저 E2E — 미할당 프로젝트가 일반 계정에 안 보임(8/28) |
| SEC-006 | 비인가 정보 노출 방지 | ✅ | 전 앱 (기본 수준, plan.md §5) | 미할당·미존재 동일 404(본문까지 동일), 쓰기 균일 403, **스코프 검사가 필터 검증보다 먼저**라 400/404 차이로 존재를 떠볼 수 없음. 응답·저장값에 서버 절대경로·workspace UUID 없음. 프론트도 404 사유를 구분 없이 "찾을 수 없습니다"로만 표시(8/28) |
| SEC-007 | 분석 작업 영역 격리 | ✅ | analysis/services.py `workspace_dir` + catalog/services.py `_relative_path` | 실행별 디렉토리 분리. Semgrep이 돌려준 절대경로를 상대경로로 정규화하고, 격리 밖 경로의 결과는 저장하지 않음 |
| SEC-008 | 파일 경로 검증 | ✅ | analysis/services.py `_is_unsafe_member` | 절대경로·드라이브문자·`..`·심볼릭링크·resolve() 최종검증 다중 방어, zip bomb 상한(기본 zip 200MB·해제 500MB·20,000개, .env로 조정) |
| SEC-009 | 분석 실행 보호 | ✅ | analysis/services.py + catalog/services.py `ingest_findings` | Semgrep 타임아웃(기본 600초, .env로 조정), 실행 상태 원자적 전환. 표준화는 `select_for_update`로 직렬화, 코드 조각은 파일 크기·줄 길이 상한(secure-review 수정) |
| SEC-010 | 외부 구성요소 관리 | ✅ | requirements.txt | 직접 의존성 6종 버전 고정. Semgrep 1.175.0(LGPL-2.1, subprocess 호출만이라 카피레프트 미전이), PyYAML 6.0.3(MIT), `--metrics=off`로 텔레메트리 차단. 운영 배포 전 후속 과제: DRF BrowsableAPIRenderer 비활성 |

## TST (테스트)
| 번호 | 이름 | 상태 | 비고 |
|---|---|---|---|
| TST-001 | 인증 기능 시험 | ✅ | accounts/tests.py — 로그인 성공/실패, 미인증 401, bcrypt 저장. + 브라우저 E2E — 로그인·세션 복원·로그아웃(폐기 refresh 재사용 401 확인)(8/28) |
| TST-002 | 역할 권한 시험 | ✅ | accounts/tests.py — 일반 사용자 403, 역할 강등 즉시 반영. 시연 필수. + 브라우저 E2E — 일반 계정에 관리 버튼 미노출, 프로젝트 생성 시도 403(8/28). + 사용자 관리 API 권한 29개 케이스(미인증 401, 일반 균일 403, 강등 즉시 403, role 강제, 자기 자신·마지막 admin·409, 비활성화 즉시 효력)(8/28 저녁) |
| TST-003 | 프로젝트 접근 시험 | ✅ | projects/tests.py `IdorDefenseTests` 등 22개. curl 수동 시연: 할당 200 / 미할당·미존재 동일 404 / 쓰기 균일 403. + 브라우저 E2E — 미할당 프로젝트 목록 숨김 + 상세 URL 직접 접근 404(IDOR 차단)(8/28) |
| TST-004 | 분석 처리 시험 | ✅ | analysis/tests.py 30개 + 실서버 수동 시연 — 업로드→압축해제→Semgrep 실행→결과조회 관통 |
| TST-005 | 진단 항목 시험 | ✅ | catalog/tests.py `DetectionSampleTests` — 실제 Semgrep으로 `catalog/samples/vulnerable.py` 정탐 31건/21룰(8/29 확장), `safe.py` **오탐 0건**; C는 `vulnerable.c` 정탐 31건/13룰, `safe.c` **오탐 0건**(assert·헬퍼 함수 NULL 검사 케이스 포함, 9/4). 두 언어 동시 분석 시 공유 항목 7개가 양쪽 파일에서 잡히는지도 확인. 시연 핵심 |
| TST-006 | 카탈로그 시험 | ✅ | catalog/tests.py `SeedCatalogTests`·`SeedValidationTests`·`CatalogReadTests` — 49개 등록·유형 분포·멱등·드리프트 감지·조회 필터 |
| TST-007 | 분석 결과 관리 시험 | ✅ | catalog/tests.py `IngestTests`·`FindingReadTests`·`ReingestTests`·`PaginationTests` — 변환·멱등·필터·집계·재표준화 |
| TST-008 | 오류 처리 시험 | ✅ | 기본 수준 — 잘못된 필터 400, 원본 없는 재표준화 409, 미존재 404, 표준화 실패 시 실행 보존+로그. 8/29: zip 아닌 파일 업로드 400 거부·분석 대상 0개(빈 zip 포함) 실행 시 Semgrep 미호출 FAILED+사유 저장(analysis/tests.py 2건). 검증 대상 3종 테스트 고정 — 상태(깨진 zip 400, 빈 zip FAILED), 오류 정보(error_message 저장), 재확인 절차(FAILED 재실행 `test_failed_run_can_be_retried`). 응답 포맷 통일은 QLT-004 후순위로 분리 |

## QLT (품질)
| 번호 | 이름 | 상태 | 비고 |
|---|---|---|---|
| QLT-001 | 모듈화 | ✅ | 4개 앱 책임 분리. analysis는 catalog를 import하지 않고 시그널만 발신 — 단방향 의존을 소스 검사 테스트로 고정(`test_analysis_app_does_not_import_catalog`) |
| QLT-002 | 진단 항목 독립성 | ✅ | 룰은 `catalog/rules/*.yaml`에 독립. `metadata.kisa_code`가 룰↔항목 매핑의 단일 원본이고, 시드 커맨드가 스캔해 반영 |
| QLT-003 | 확장성 | ✅ | SFR-010과 동일 — 카탈로그 언어 중립 + 룰 YAML 추가로 확장, 코드 수정 없음 |
| QLT-004 | 결과 일관성 | ✅ | catalog/services.py `normalize_severity` 한 곳에 집중. 카탈로그 등급이 최종, Semgrep 값은 미매핑 시 폴백. 양방향 역전(EH-01 ERROR→MEDIUM, SF-08 WARNING→HIGH)을 실제 분석으로 확인 |
| QLT-005 | 데이터 정합성 | ✅ | FK+트랜잭션. projects: UniqueConstraint(project,user) + IntegrityError를 savepoint로 400 전환. catalog: 재표준화를 `select_for_update`로 직렬화해 동시 요청 시 결과 중복 방지 |

---

## RFP 외 자체 개선 (요구사항 밖 — 근거·상세는 docs/decisions.md, 일자는 worklog.md)

| 항목 | 내용 | 구현 위치 |
|---|---|---|
| 결과 열람 접근 로그 (9/1) | 결과 조회 3종 + diff·run-changes 열람을 INFO 기록, 성공 응답만 | config/access_log.py, logs/access.log |
| 사용자 관리 개선 (9/1) | User.name 표시, 할당 프로젝트 목록(팝오버), 이력 계정 삭제 가드(PROTECT+409) | accounts, projects, frontend `UsersPage` |
| Finding fingerprint (9/2) | 실행 간 매칭 키 — sha256(룰\|경로\|정규화 스니펫)+순번, 라인 밀림에 안정, 기존 데이터 백필 | catalog/fingerprint.py, 마이그레이션 0002·0003 |
| 실행 간 diff API (9/2) | 신규/해결/유지 분류, base 자동 선택, 중복 보정 | catalog `GET /api/analysis-runs/{id}/diff/` |
| 비교 페이지 (9/2) | 상태 칩·심각도·유형·검색 필터, 안내 3종 | frontend `ComparePage` |
| 프로젝트 대시보드 (9/2) | 메트릭 카드 4종, 심각도 스택 추이(CSS), 비교 요약·룰 상위 위젯 | frontend `ProjectDashboard` |
| 코드 조각 문맥·강조 (9/4) | 취약 줄 앞뒤 3줄을 extra.context에 표시용으로 저장, 화면은 줄 번호+취약 줄만 색 강조. 핑거프린트는 code_snippet만 봐 비교 안정성 유지 | catalog/services.py `_extract_lines`, frontend `CodeSnippet` |
| 분석 이력화 (9/2) | 프로젝트 내 회차(sequence) 표시, 행별 직전 대비 변화량 | analysis(sequence), catalog `GET /api/projects/{id}/run-changes/` |
| CI 게이트 (9/4) | PR마다 base·head를 우리 룰셋으로 스캔해 서버와 같은 핑거프린트로 신규/해결/유지 분류, job summary·PR 코멘트 요약, 신규 HIGH면 실패. 조각 읽기를 `catalog/snippet.py`로 분리해 서버와 공유 | `.github/workflows/sast-scan.yml`, `scripts/sast_gate.py`, `catalog/snippet.py` |

## 현황 요약 (2026-09-02 기준)

- SFR 17개: 완료 16 / 부분 충족 1(SFR-011 — Python·C 2개 언어 구현, 9/4. Java/JS 등은 룰 세트 추가로 확장 가능, plan.md §5)
- DAR 10개: 완료 10 (DAR-008은 9/2 판정 조정 — decisions.md)
- SEC 10개: 완료 10 (SEC-006·009는 plan.md §5의 "기본 수준" 기준)
- TST 8개: 완료 8
- QLT 5개: 완료 5
- **합계: 50개 중 완료 49 / 부분 충족 1** (9/2 판정 조정으로 47→49, DAR-008·SFR-010; SFR-011은 9/4 C 룰로 부분 충족 — decisions.md)
- 테스트: **269개 전부 통과** (accounts 56 · projects 33 · analysis 42 · catalog 125 · scripts 13 — 9/4 기준)
- 프론트엔드: 7화면 완결 — 로그인 / 프로젝트 목록 / 프로젝트 상세(대시보드 포함) /
  실행 결과 상세 / 실행 비교 / 카탈로그 / 사용자 관리. 관리자·일반 계정 브라우저 E2E로
  권한 격리 실증(각 행의 8/28 표기), diff 시연은 demo-app v1~v3로 실서버 검증(9/2)
