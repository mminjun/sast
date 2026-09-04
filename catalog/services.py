"""Semgrep 원본 결과 → 표준화된 Finding 변환 (SFR-014, DAR-006, QLT-004).

analysis 앱은 Semgrep을 돌려 raw_result(원본 JSON)까지만 책임진다. 그 결과를 KISA
49개 기준에 맞춰 정규화하는 것이 이 모듈이다 (QLT-001 책임 분리).

원본을 지우지 않으므로, 표준화 규칙이 바뀌면 재수집(ingest_findings 재호출)만으로
다시 만들 수 있다.
"""

import re
from collections import Counter, namedtuple
from pathlib import Path

from django.db import transaction
from django.db.models import F, Q

from analysis.models import AnalysisRun, AnalysisStatus
from analysis.services import fs_path, source_dir, strip_extended_prefix, strip_nul

from .fingerprint import assign_fingerprints
from .models import DiagnosticRule, Finding, FindingStatus, Severity
# 코드 조각 읽기 규칙(줄 수·길이 상한, 문맥)은 catalog/snippet.py 한 곳에 있다 —
# CI 게이트(scripts/sast_gate.py)도 같은 함수로 조각을 만들어야 핑거프린트가 맞는다.
from .snippet import read_snippet

# 매핑에 실패했을 때만 쓰는 폴백 표 (QLT-004).
SEMGREP_SEVERITY_FALLBACK = {
    'ERROR': Severity.HIGH,
    'WARNING': Severity.MEDIUM,
    'INFO': Severity.LOW,
}

# carried: 직전 실행·재표준화 전 판정에서 status를 물려받은 건수 (오탐 관리).
IngestResult = namedtuple('IngestResult', 'created skipped unmapped carried')


def normalize_severity(rule, semgrep_severity):
    """최종 심각도를 결정한다 (QLT-004).

    카탈로그(DiagnosticRule)에 매핑된 결과는 카탈로그 등급이 최종이다. Semgrep의
    ERROR/WARNING/INFO를 메인 기준으로 쓰지 않는 이유는 세 가지다 (docs/decisions.md).
      1. 그 값은 도구가 범용 기준으로 매긴 것이라 KISA 유형 분류와 접점이 없다 —
         왜 그 등급인지 우리가 설명할 근거가 없다.
      2. 우리가 작성하지 않은 룰은 애초에 KISA 항목 매핑이 없어, 그대로 쓰면
         "KISA 49개 기준 시스템"이라는 전제가 깨진다.
      3. 그래서 Semgrep 값은 매핑이 없는 예외 상황에서 결과를 버리지 않기 위한
         안전망으로만 쓴다.

    알 수 없는 값의 기본은 LOW가 아니라 MEDIUM이다 — 등급을 모를 때 낮게 매기면
    실제 취약점이 목록 아래로 묻힌다. 기본 권한 차단·DEBUG 기본 False와 같은
    '안전한 기본값' 원칙을 등급에도 적용한다.
    """
    if rule is not None:
        return rule.severity
    return SEMGREP_SEVERITY_FALLBACK.get(
        (semgrep_severity or '').strip().upper(),
        Severity.MEDIUM,
    )


def bare_check_id(check_id):
    """Semgrep이 붙인 config 경로 접두사를 떼고 룰 id만 남긴다.

    Semgrep은 check_id에 설정 경로를 접두사로 붙여 준다
    (`catalog.rules.kisa-iv-01-sql-injection`). 설정 경로가 절대경로면 서버
    디렉토리 구조가 그 안에 섞여 들어와 DB와 API 응답에 남는다 — file_path를
    상대경로로 정규화하는 것과 같은 이유로 막는다 (SEC-006, SEC-007).

    전체 값은 AnalysisRun.raw_result에 그대로 남아 있으므로 정보 손실은 없고,
    남는 값은 룰 YAML의 id와 형식이 같아져 DiagnosticRule.semgrep_rule_ids와
    직접 비교할 수 있게 된다.
    """
    return re.split(r'[\\/.]', check_id or '')[-1]


def _relative_path(raw_path, source_root):
    """Semgrep이 돌려준 절대경로를 격리 루트 기준 상대경로로 바꾼다 (SEC-006, SEC-007).

    격리 루트 밖을 가리키는 경로는 신뢰하지 않고 None을 돌려준다 — 호출자가 해당
    결과를 저장하지 않는다. 정상 흐름에서는 나올 수 없는 값이고, 나온다면 경로
    처리 어딘가가 깨졌다는 뜻이라 저장하는 편이 더 위험하다.
    """
    if not raw_path:
        return None
    # Semgrep에는 확장 경로(\\?\)로 넘기므로 결과 경로에도 그 접두사가 붙어 온다.
    # 접두사가 남아 있으면 격리 루트와 비교가 안 돼 결과가 통째로 버려진다.
    raw_path = strip_extended_prefix(raw_path)
    try:
        return Path(raw_path).resolve().relative_to(source_root).as_posix()
    except (ValueError, OSError):
        return None


def _read_snippet(source_root, relative_path, start_line, end_line, cache):
    """해당 위치의 코드 조각을 격리 디렉토리의 파일에서 직접 읽는다.

    Semgrep은 로그인하지 않은 상태에서 extra.lines를 'requires login'으로 가려서
    준다. 계정을 붙이면 고객 소스를 다루는 도구에 외부 의존이 하나 늘어나므로
    (`--metrics=off` 결정과 같은 이유), 이미 우리 격리 디렉토리에 있는 파일에서
    직접 읽는다.

    한 줄에 여러 룰이 걸리면 결과 건마다 같은 파일을 다시 열게 되므로, 수집 1회
    범위에서 (경로, 줄 범위) 단위로 캐시한다.
    반환은 (조각 문자열, 문맥 dict 또는 None). 문맥은 {'start_line', 'lines'} 형태로,
    lines에는 취약 줄 앞뒤 SNIPPET_CONTEXT_LINES줄이 함께 들어 있다.
    """
    if start_line < 1 or not relative_path:
        return '', None

    cache_key = (relative_path, start_line, end_line)
    if cache_key not in cache:
        cache[cache_key] = _extract_lines(source_root, relative_path, start_line, end_line)
    return cache[cache_key]


def _extract_lines(source_root, relative_path, start_line, end_line):
    """파일에서 지정 줄 범위와 그 앞뒤 문맥을 한 번에 읽는다.

    읽을 수 없으면 ('', None). 경로는 이미 _relative_path()를 통과한 값이지만, 파일을
    여는 지점에서 한 번 더 격리 루트 안인지 확인한다 (analysis의 zip 추출과 같은
    다중 방어).
    """
    target = (source_root / relative_path).resolve()
    try:
        target.relative_to(source_root)
    except ValueError:
        return '', None

    # 읽기·절단·조합 규칙은 catalog/snippet.py 한 곳에 있다 (CI 게이트와 공유).
    # 260자 넘는 경로도 읽을 수 있도록 확장 경로로 연다 (analysis.services.fs_path).
    return read_snippet(fs_path(target), start_line, end_line)

def _build_finding(item, run, rules_by_code, source_root, snippet_cache):
    """Semgrep 결과 1건을 Finding으로 바꾼다. 저장하지 않을 결과면 None."""
    relative_path = _relative_path(item.get('path'), source_root)
    if relative_path is None:
        return None

    extra = item.get('extra') or {}
    metadata = extra.get('metadata') or {}
    kisa_code = metadata.get('kisa_code') or ''
    rule = rules_by_code.get(kisa_code)

    start_line = (item.get('start') or {}).get('line') or 0
    end_line = (item.get('end') or {}).get('line') or start_line
    semgrep_severity = extra.get('severity') or ''
    snippet, context = _read_snippet(
        source_root, relative_path, start_line, end_line, snippet_cache
    )

    return Finding(
        run=run,
        rule=rule,
        # 분석 시점 스냅샷 (DAR-008 비목표 — 심각도·명칭만 복사).
        # 매핑에 실패해도 룰이 주장한 코드는 남겨 둔다 — 무엇이 어긋났는지 보이게.
        rule_code=rule.code if rule else kisa_code,
        rule_name=rule.name if rule else '',
        severity=normalize_severity(rule, semgrep_severity),
        semgrep_check_id=bare_check_id(item.get('check_id')),
        file_path=relative_path,
        start_line=start_line,
        end_line=end_line,
        message=strip_nul(extra.get('message') or ''),
        code_snippet=snippet,
        extra={
            'cwe': metadata.get('cwe', ''),
            'kisa_name': metadata.get('kisa_name', ''),
            # 도구가 원래 뭐라고 했는지 남긴다 — 최종 등급이 카탈로그에서 왔다는 것을
            # 결과만 보고도 대조할 수 있어야 한다 (QLT-004).
            'semgrep_severity': semgrep_severity,
            # 표시용 문맥(취약 줄 앞뒤). 핑거프린트는 code_snippet만 보므로 여기 값이
            # 달라져도 실행 간 매칭에는 영향이 없다.
            'context': context,
        },
    )


def previous_succeeded_run(run):
    """같은 프로젝트의 직전 완료(SUCCEEDED) 실행. 없으면 None.

    "직전"은 생성 시각 기준, 동시각이면 pk 기준이다. diff 화면의 비교 기준 자동 선택
    (RunDiffView)과 판정 승계(ingest_findings)가 이 함수를 같이 쓴다 — 두 곳이 다른
    실행을 고르면 "비교에서는 유지인데 판정은 승계되지 않는" 어긋남이 생긴다.
    """
    return (
        AnalysisRun.objects
        .filter(project_id=run.project_id, status=AnalysisStatus.SUCCEEDED)
        .exclude(pk=run.pk)
        .filter(
            Q(created_at__lt=run.created_at)
            | Q(created_at=run.created_at, pk__lt=run.pk)
        )
        .order_by('-created_at', '-pk')
        .first()
    )


# 판정 승계에 옮기는 필드. status_changed_by/at도 원본 그대로 — "누가 언제 처음
# 판정했는지"가 회차를 넘어 남아야 한다.
_STATUS_FIELDS = ('status', 'status_note', 'status_changed_by_id', 'status_changed_at')


def _status_by_fingerprint(run, *, only_marked):
    """run의 판정을 {fingerprint: (status, note, by_id, at)}로 모은다.

    빈 fingerprint는 넣지 않는다 — 백필 이전 데이터·예외 상황의 흔적이라 빈 값끼리
    짝지어지면 엉뚱한 finding에 판정이 붙는다 (diff의 _diff_rows와 같은 이유).
    only_marked=True면 OPEN(미판정)은 제외한다.
    """
    if run is None:
        return {}
    queryset = Finding.objects.filter(run=run).exclude(fingerprint='')
    if only_marked:
        queryset = queryset.exclude(status=FindingStatus.OPEN)
    return {
        row[0]: tuple(row[1:])
        for row in queryset.values_list('fingerprint', *_STATUS_FIELDS)
    }


def _carry_over_status(run, findings):
    """새로 만든 findings에 판정을 입힌다 (오탐 관리 승계 규칙, docs/decisions.md 2026-09-05).

    우선순위: ① 이 run에 이미 있던 판정(OPEN 포함) > ② 직전 완료 실행의 판정(OPEN 제외).

    ①이 OPEN까지 포함하는 이유: 관리자가 승계된 오탐을 이 run에서 "다시 OPEN"으로
    되돌린 뒤 재표준화하면, OPEN을 무시할 경우 직전 실행의 오탐 판정이 다시 승계돼
    되돌림이 조용히 취소된다. 이 run에 있던 핑거프린트는 그 상태를 그대로 쓰고, 이
    run에 없던(새) 핑거프린트만 직전 실행에서 받는다. 매칭은 fingerprint(순번 :N 포함)
    정확 일치 — diff처럼 그룹 안 위치 짝짓기는 하지 않는다.

    호출자는 이 run의 findings를 지우기 전에 불러야 한다(①을 삭제 전에 수집).
    """
    own = _status_by_fingerprint(run, only_marked=False)
    inherited = _status_by_fingerprint(previous_succeeded_run(run), only_marked=True)
    carried = 0
    for finding in findings:
        source = own.get(finding.fingerprint) or inherited.get(finding.fingerprint)
        if source is None:
            continue
        for field, value in zip(_STATUS_FIELDS, source):
            setattr(finding, field, value)
        carried += 1
    return carried


def ingest_findings(run):
    """run.raw_result를 표준화해 Finding으로 저장한다 (SFR-014, DAR-006).

    멱등하다 — 같은 run에 대해 여러 번 호출해도 결과가 누적되지 않고, 이미 붙어 있던
    판정(오탐/수용)도 보존된다. 기존 결과를 지우고 다시 넣는 과정을 한 트랜잭션으로
    묶어, 실패 시 이전 결과(판정 포함)가 남아 있게 한다 (중간에 끊겨 '결과 0건'으로
    보이는 상태를 만들지 않는다).
    """
    results = (run.raw_result or {}).get('results') or []
    source_root = source_dir(run).resolve()
    rules_by_code = {rule.code: rule for rule in DiagnosticRule.objects.all()}

    findings = []
    skipped = 0
    # 수집 1회 동안만 유지되는 조각 캐시 — 같은 줄에 여러 룰이 걸린 경우 파일을
    # 반복해서 열지 않는다.
    snippet_cache = {}
    for item in results:
        finding = _build_finding(item, run, rules_by_code, source_root, snippet_cache)
        if finding is None:
            skipped += 1
            continue
        findings.append(finding)

    # diff 매칭 키. run 단위·결정적 계산이라 재수집해도 같은 값이 나온다(멱등성 유지).
    assign_fingerprints(findings)

    with transaction.atomic():
        # 같은 run의 표준화를 직렬화한다. 잠그지 않으면 거의 동시에 들어온 재표준화
        # 두 건에서 뒤 트랜잭션의 DELETE가 자기 스냅샷 이후 커밋된 행을 지우지 못해
        # 양쪽 INSERT가 모두 남는다 — 취약점 건수가 두 배로 보고된다.
        # analysis의 실행 상태 원자적 전환(SEC-009)과 같은 유형의 경합이다.
        # 판정 변경(FindingStatusView)도 같은 행을 잠근다 — 아래 DELETE와 INSERT 사이에
        # 끼어든 판정이 지워진 행에 쓰여 사라지는 경합을 막는다.
        AnalysisRun.objects.select_for_update().get(pk=run.pk)
        # 판정 승계는 반드시 DELETE 전에 — 자기 run의 판정(①)은 지우면 되찾을 수 없다.
        carried = _carry_over_status(run, findings)
        Finding.objects.filter(run=run).delete()
        Finding.objects.bulk_create(findings)

    unmapped = sum(1 for finding in findings if finding.rule_id is None)
    return IngestResult(
        created=len(findings), skipped=skipped, unmapped=unmapped, carried=carried,
    )


# --- 실행 간 비교 (diff — RFP 외 자체 개선, docs/decisions.md 2026-09-02) ---

# diff 항목에 내려보내는 필드. 화면이 코드 조각까지 보고 싶으면 기존 findings
# 목록을 쓰면 된다 — diff는 변화의 요약이라 가볍게 유지한다.
# category는 rule 참조에서 온다(미매핑은 null) — 비교 화면의 분류 필터용.
DIFF_ITEM_FIELDS = (
    'rule_code', 'rule_name', 'severity', 'category', 'file_path', 'start_line',
    'message',
)
# 판정은 diff의 status(new/resolved/persisted)와 이름이 겹치므로 finding_status로 내보낸다.
_DIFF_STATUS_FIELD = 'finding_status'
# 신규가 가장 급하고, 유지는 이미 알던 것 — 화면 정렬 기준을 응답에서 고정한다.
_DIFF_STATUS_RANK = {'new': 0, 'resolved': 1, 'persisted': 2}
_DIFF_SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def _diff_rows(run):
    """diff 계산에 필요한 필드만 뽑는다. 반환: (rows, 빈 fingerprint 건수, 오탐 건수).

    두 종류를 매칭 대상에서 뺀다. (1) fingerprint가 빈 행 — 백필 이전 데이터나 예외
    상황의 흔적이라, 매칭에 넣으면 빈 값끼리 서로 짝지어지는 사고가 난다. (2) 오탐
    (FALSE_POSITIVE) 판정 — 사람이 아니라고 확인한 건이 신규/해결/유지 어디에도
    섞이지 않게 한다. 수용(ACCEPTED)은 남긴다 — 알지만 고치지 않은 것이지 여전히
    존재하는 취약점이다. 두 제외 건수는 응답에서 서로 다른 키(excluded /
    false_positive)로 드러낸다.
    """
    included, excluded, false_positive = [], 0, 0
    rows = Finding.objects.filter(run=run).values(
        'rule_code', 'rule_name', 'severity', 'file_path', 'start_line',
        'message', 'fingerprint', 'status', category=F('rule__category'),
    ).order_by('start_line', 'id')
    for row in rows:
        if not row['fingerprint']:
            excluded += 1
        elif row['status'] == FindingStatus.FALSE_POSITIVE:
            false_positive += 1
        else:
            included.append(row)
    return included, excluded, false_positive


def _grouped(rows):
    """순번(:N)을 뗀 기본 해시로 묶는다. rows가 start_line 순이라 그룹 안도 그 순서다."""
    groups = {}
    for row in rows:
        groups.setdefault(row['fingerprint'].rsplit(':', 1)[0], []).append(row)
    return groups


def _item(status_value, row):
    item = {field: row[field] for field in DIFF_ITEM_FIELDS}
    item['status'] = status_value
    item[_DIFF_STATUS_FIELD] = row['status']
    return item


def diff_findings(base_run, target_run):
    """두 실행의 결과를 신규(new)/해결(resolved)/유지(persisted)로 분류한다.

    매칭은 fingerprint의 기본 해시 그룹 단위로, 양쪽을 각각 start_line 오름차순
    정렬해 앞에서부터 순서대로 짝짓는다. 순번(:N)을 그대로 대조하지 않고 그룹
    안에서 위치로 짝짓는 이유: 동일 코드 중복 중 앞쪽만 고쳐지면 남은 건의 순번이
    당겨져(:2→:1) 순번 대조로는 유지/해결의 줄 위치가 뒤바뀌어 보인다. 순번 부여
    (ingest) 방식은 그대로 두고 보정은 diff 계산에서만 한다. 알려진 한계: 동일
    코드가 대량으로 자리를 옮기면 위치 짝짓기가 어긋날 수 있다 (decisions.md).

    유지 항목은 target 쪽 데이터로 보고한다 — 화면에서 그 줄로 이동할 대상은
    현재(target) 소스다. 해결 항목만 base 쪽 데이터다 (target에는 이미 없다).
    base_run이 None이면(비교할 이전 실행 없음) 전부 신규다.
    """
    base_rows, base_excluded, base_fp = _diff_rows(base_run) if base_run else ([], 0, 0)
    target_rows, target_excluded, target_fp = _diff_rows(target_run)

    base_groups = _grouped(base_rows)
    target_groups = _grouped(target_rows)

    items = []
    for key in base_groups.keys() | target_groups.keys():
        base_group = base_groups.get(key, [])
        target_group = target_groups.get(key, [])
        matched = min(len(base_group), len(target_group))
        items.extend(_item('persisted', row) for row in target_group[:matched])
        items.extend(_item('resolved', row) for row in base_group[matched:])
        items.extend(_item('new', row) for row in target_group[matched:])

    items.sort(key=lambda item: (
        _DIFF_STATUS_RANK[item['status']],
        _DIFF_SEVERITY_RANK.get(item['severity'], 3),
        item['file_path'],
        item['start_line'],
    ))
    counts = Counter(item['status'] for item in items)
    return {
        'summary': {status_value: counts.get(status_value, 0)
                    for status_value in ('new', 'resolved', 'persisted')},
        'excluded': {'base': base_excluded, 'target': target_excluded},
        # 오탐 판정으로 뺀 건수 — 화면이 "비교 키 없음"과 구분해 안내한다.
        'false_positive': {'base': base_fp, 'target': target_fp},
        'items': items,
    }


def run_change_counts(project_id):
    """프로젝트의 완료 실행마다 직전 완료 실행 대비 신규/해결 건수.

    실행 목록이 "수정본이 쌓이는 이력"으로 읽히도록 행마다 변화량을 보여주기
    위한 것 — 실행마다 diff API를 호출하는 대신 프로젝트 단위로 한 번에 계산한다.
    매칭 규칙은 diff_findings와 동일(기본 해시 그룹, 빈 fingerprint 제외)이며,
    건수만 필요하므로 그룹별 개수 차이로 충분하다 — 그룹 안 위치 짝짓기는
    유지/신규/해결의 '어느 줄인가'를 바꿀 뿐 개수는 바꾸지 않는다.

    반환: {run_id: {'new': n, 'resolved': n}} — 직전 완료 실행이 없는 첫 실행과
    미완료 실행은 키 자체가 없다(화면은 '—'로 표시).
    """
    run_ids = list(
        AnalysisRun.objects
        .filter(project_id=project_id, status=AnalysisStatus.SUCCEEDED)
        .order_by('created_at', 'id')
        .values_list('id', flat=True)
    )
    counters = {run_id: Counter() for run_id in run_ids}
    rows = (
        Finding.objects.filter(run_id__in=run_ids)
        .exclude(fingerprint='')
        # diff_findings와 같은 규칙 — 오탐은 변화량에서도 뺀다. 여기만 포함하면 목록의
        # 신규 건수와 비교 화면의 신규 건수가 어긋난다.
        .exclude(status=FindingStatus.FALSE_POSITIVE)
        .values_list('run_id', 'fingerprint')
    )
    for run_id, fingerprint in rows:
        counters[run_id][fingerprint.rsplit(':', 1)[0]] += 1

    changes = {}
    previous = None
    for run_id in run_ids:
        if previous is not None:
            current, before = counters[run_id], counters[previous]
            changes[run_id] = {
                'new': sum(
                    max(0, count - before.get(key, 0)) for key, count in current.items()
                ),
                'resolved': sum(
                    max(0, count - current.get(key, 0)) for key, count in before.items()
                ),
            }
        previous = run_id
    return changes
