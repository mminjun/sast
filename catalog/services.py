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
from django.db.models import F

from analysis.models import AnalysisRun, AnalysisStatus
from analysis.services import source_dir

from .fingerprint import assign_fingerprints
from .models import DiagnosticRule, Finding, Severity

# 코드 조각 저장 상한. Semgrep이 조각을 주지 않아 우리가 직접 파일에서 읽으므로
# (아래 _read_snippet 참고), 한 건이 통째로 파일을 삼키지 않도록 제한을 둔다.
MAX_SNIPPET_LINES = 20
MAX_SNIPPET_CHARS = 2000
# 한 줄에서 남길 최대 길이. 줄 수만 제한하면 '한 줄짜리 거대 파일'을 막지 못한다.
MAX_SNIPPET_LINE_CHARS = 500
# 이 크기를 넘는 파일은 조각 추출을 건너뛴다. 줄 단위로 읽어도 한 줄의 길이는
# 제한되지 않으므로, 난독화·압축된 1줄 파일이면 그 한 줄이 통째로 메모리에 올라온다
# (압축 해제 상한이 100MB라 그만큼까지 가능). 그 정도 파일의 조각은 읽어도 쓸모없다.
MAX_SNIPPET_SOURCE_BYTES = 2 * 1024 * 1024

# 매핑에 실패했을 때만 쓰는 폴백 표 (QLT-004).
SEMGREP_SEVERITY_FALLBACK = {
    'ERROR': Severity.HIGH,
    'WARNING': Severity.MEDIUM,
    'INFO': Severity.LOW,
}

IngestResult = namedtuple('IngestResult', 'created skipped unmapped')


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
    """
    if start_line < 1 or not relative_path:
        return ''

    cache_key = (relative_path, start_line, end_line)
    if cache_key not in cache:
        cache[cache_key] = _extract_lines(source_root, relative_path, start_line, end_line)
    return cache[cache_key]


def _extract_lines(source_root, relative_path, start_line, end_line):
    """파일에서 지정 줄 범위를 읽는다. 읽을 수 없으면 빈 문자열.

    경로는 이미 _relative_path()를 통과한 값이지만, 파일을 여는 지점에서 한 번 더
    격리 루트 안인지 확인한다 (analysis의 zip 추출과 같은 다중 방어).
    """
    target = (source_root / relative_path).resolve()
    try:
        target.relative_to(source_root)
    except ValueError:
        return ''

    picked = []
    try:
        if not target.is_file():
            return ''
        # 줄 단위로 읽기 전에 파일 크기부터 본다 — 줄 수를 제한해도 한 줄의 길이는
        # 제한되지 않으므로, 큰 파일에서는 한 줄을 읽는 것만으로 메모리가 튄다.
        if target.stat().st_size > MAX_SNIPPET_SOURCE_BYTES:
            return ''

        last_line = min(end_line or start_line, start_line + MAX_SNIPPET_LINES - 1)
        # 분석 대상 소스의 인코딩은 우리가 정할 수 없으므로 깨진 바이트는 대체 문자로
        # 두고 계속한다 — 조각 하나 때문에 수집 전체가 실패하면 안 된다.
        with target.open('r', encoding='utf-8', errors='replace') as handle:
            for number, line in enumerate(handle, start=1):
                if number > last_line:
                    break
                if number >= start_line:
                    picked.append(line.rstrip('\n')[:MAX_SNIPPET_LINE_CHARS])
    except OSError:
        return ''

    return '\n'.join(picked)[:MAX_SNIPPET_CHARS]


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
        message=extra.get('message') or '',
        code_snippet=_read_snippet(
            source_root, relative_path, start_line, end_line, snippet_cache
        ),
        extra={
            'cwe': metadata.get('cwe', ''),
            'kisa_name': metadata.get('kisa_name', ''),
            # 도구가 원래 뭐라고 했는지 남긴다 — 최종 등급이 카탈로그에서 왔다는 것을
            # 결과만 보고도 대조할 수 있어야 한다 (QLT-004).
            'semgrep_severity': semgrep_severity,
        },
    )


def ingest_findings(run):
    """run.raw_result를 표준화해 Finding으로 저장한다 (SFR-014, DAR-006).

    멱등하다 — 같은 run에 대해 여러 번 호출해도 결과가 누적되지 않는다. 기존 결과를
    지우고 다시 넣는 과정을 한 트랜잭션으로 묶어, 실패 시 이전 결과가 남아 있게 한다
    (중간에 끊겨 '결과 0건'으로 보이는 상태를 만들지 않는다).
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
        AnalysisRun.objects.select_for_update().get(pk=run.pk)
        Finding.objects.filter(run=run).delete()
        Finding.objects.bulk_create(findings)

    unmapped = sum(1 for finding in findings if finding.rule_id is None)
    return IngestResult(created=len(findings), skipped=skipped, unmapped=unmapped)


# --- 실행 간 비교 (diff — RFP 외 자체 개선, docs/decisions.md 2026-09-02) ---

# diff 항목에 내려보내는 필드. 화면이 코드 조각까지 보고 싶으면 기존 findings
# 목록을 쓰면 된다 — diff는 변화의 요약이라 가볍게 유지한다.
# category는 rule 참조에서 온다(미매핑은 null) — 비교 화면의 분류 필터용.
DIFF_ITEM_FIELDS = (
    'rule_code', 'rule_name', 'severity', 'category', 'file_path', 'start_line',
    'message',
)
# 신규가 가장 급하고, 유지는 이미 알던 것 — 화면 정렬 기준을 응답에서 고정한다.
_DIFF_STATUS_RANK = {'new': 0, 'resolved': 1, 'persisted': 2}
_DIFF_SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def _diff_rows(run):
    """diff 계산에 필요한 필드만 뽑는다. fingerprint가 빈 행은 매칭 대상에서 뺀다.

    빈 값은 백필 이전 데이터나 예외 상황의 흔적이다 — 매칭에 넣으면 빈 값끼리
    서로 짝지어지는 사고가 난다. 제외 건수는 응답의 excluded로 드러낸다.
    """
    included, excluded = [], 0
    rows = Finding.objects.filter(run=run).values(
        'rule_code', 'rule_name', 'severity', 'file_path', 'start_line',
        'message', 'fingerprint', category=F('rule__category'),
    ).order_by('start_line', 'id')
    for row in rows:
        if row['fingerprint']:
            included.append(row)
        else:
            excluded += 1
    return included, excluded


def _grouped(rows):
    """순번(:N)을 뗀 기본 해시로 묶는다. rows가 start_line 순이라 그룹 안도 그 순서다."""
    groups = {}
    for row in rows:
        groups.setdefault(row['fingerprint'].rsplit(':', 1)[0], []).append(row)
    return groups


def _item(status_value, row):
    item = {field: row[field] for field in DIFF_ITEM_FIELDS}
    item['status'] = status_value
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
    base_rows, base_excluded = _diff_rows(base_run) if base_run else ([], 0)
    target_rows, target_excluded = _diff_rows(target_run)

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
