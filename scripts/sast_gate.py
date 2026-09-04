"""CI 게이트 — PR 브랜치와 base의 Semgrep 결과를 비교해 신규 HIGH가 있으면 실패한다.

GitHub Actions(.github/workflows/sast-scan.yml)가 head(PR)와 base를 각각 우리 룰셋
(catalog/rules)으로 스캔한 JSON 두 개를 넘기면, 이 스크립트가

  1. 결과마다 코드 조각을 체크아웃된 소스에서 읽고(Semgrep은 로그인 없이는 lines를
     'requires login'으로 가린다 — 서버 ingest가 파일에서 읽는 것과 같은 이유),
  2. 서버와 같은 함수(catalog/fingerprint.py)로 핑거프린트를 만들어,
  3. 서버 diff(catalog/services.py diff_findings)와 같은 규칙으로 신규/해결/유지를 나누고,
  4. 마크다운 요약을 job summary·PR 코멘트용 파일로 쓰고,
  5. 신규 HIGH가 1건이라도 있으면 exit 1로 워크플로를 실패시킨다.

"신규"의 정의를 서버의 비교 화면과 같게 유지하는 것이 핵심이다 — 규칙(핑거프린트·
조각 읽기)은 재구현하지 않고 catalog의 순수 모듈을 import한다. 이 스크립트는 Django
없이 돈다 (docs/decisions.md 2026-09-04). RFP 외 자체 개선.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from catalog.fingerprint import assign_fingerprints  # noqa: E402
from catalog.snippet import read_snippet  # noqa: E402

CATALOG_PATH = REPO_ROOT / 'catalog' / 'data' / 'kisa_rules.json'

# 카탈로그 매핑이 없을 때만 쓰는 폴백 — catalog/services.py SEMGREP_SEVERITY_FALLBACK와
# 같은 표, 알 수 없는 값은 MEDIUM(normalize_severity와 동일: 모를 때 낮게 매기지 않는다).
SEMGREP_SEVERITY_FALLBACK = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}
DEFAULT_SEVERITY = 'MEDIUM'
SEVERITIES = ('HIGH', 'MEDIUM', 'LOW')
# 이 심각도의 신규 탐지가 있으면 차단한다. MEDIUM/LOW 신규는 보고만 한다.
BLOCKING_SEVERITIES = ('HIGH',)
STATUSES = ('new', 'resolved', 'persisted')
STATUS_LABELS = {'new': '신규', 'resolved': '해결', 'persisted': '유지'}
# PR 코멘트를 찾아 갱신하기 위한 마커 — 워크플로의 코멘트 단계가 이 접두사로 찾는다.
COMMENT_MARKER = '<!-- sast-gate -->'
MESSAGE_MAX_CHARS = 160


class CiFinding:
    """Semgrep 결과 1건. assign_fingerprints()가 요구하는 속성만 갖는다 (Finding 모델의
    부분집합 — 필드 이름을 같게 둬 서버와 같은 함수를 그대로 쓴다)."""

    __slots__ = (
        'rule_code', 'rule_name', 'semgrep_check_id', 'severity', 'file_path',
        'start_line', 'end_line', 'message', 'code_snippet', 'fingerprint',
    )

    def __init__(self, **fields):
        for name in self.__slots__:
            setattr(self, name, fields.get(name))


def load_catalog(path=CATALOG_PATH):
    """KISA 코드 → {'name', 'severity'}. 최종 심각도는 카탈로그가 정한다 (QLT-004)."""
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)
    return {
        rule['code']: {'name': rule['name'], 'severity': rule['severity']}
        for rule in data['rules']
    }


def bare_check_id(check_id):
    """catalog/services.py bare_check_id와 같은 규칙 — config 경로 접두사를 뗀다."""
    return re.split(r'[\\/.]', check_id or '')[-1]


def normalize_path(raw_path, source_root):
    """Semgrep 결과 경로를 스캔 루트 기준 상대 POSIX 경로로 — 서버의 file_path 형식."""
    path = Path(raw_path)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(Path(source_root).resolve())
        except ValueError:
            return None
    text = path.as_posix()
    return text[2:] if text.startswith('./') else text


def load_findings(results, source_root, catalog):
    """Semgrep JSON의 results를 CiFinding 목록으로 바꾸고 핑거프린트를 매긴다."""
    findings = []
    for item in results:
        file_path = normalize_path(item.get('path') or '', source_root)
        if not file_path:
            continue
        extra = item.get('extra') or {}
        metadata = extra.get('metadata') or {}
        kisa_code = metadata.get('kisa_code') or ''
        rule = catalog.get(kisa_code)
        start_line = (item.get('start') or {}).get('line') or 0
        end_line = (item.get('end') or {}).get('line') or start_line
        snippet, _context = read_snippet(
            Path(source_root) / file_path, start_line, end_line,
        )
        if rule:
            severity = rule['severity']
        else:
            severity = SEMGREP_SEVERITY_FALLBACK.get(
                (extra.get('severity') or '').strip().upper(), DEFAULT_SEVERITY,
            )
        findings.append(CiFinding(
            rule_code=kisa_code,
            rule_name=rule['name'] if rule else '',
            semgrep_check_id=bare_check_id(item.get('check_id')),
            severity=severity,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            message=(extra.get('message') or '').replace(chr(0), ''),
            code_snippet=snippet,
            fingerprint='',
        ))
    assign_fingerprints(findings)
    return findings


def _grouped(findings):
    """순번(:N)을 뗀 기본 해시로 묶는다. 그룹 안은 start_line 순 (diff_findings와 동일)."""
    groups = {}
    for finding in sorted(findings, key=lambda f: (f.start_line, f.end_line, f.message)):
        groups.setdefault(finding.fingerprint.rsplit(':', 1)[0], []).append(finding)
    return groups


def classify(base_findings, head_findings):
    """신규/해결/유지 분류 — catalog/services.py diff_findings와 같은 규칙.

    기본 해시가 같은 그룹 안에서 양쪽을 start_line 순으로 앞에서부터 짝짓는다
    (짝지어진 것=유지(head 데이터), base에 남은 것=해결, head에 남은 것=신규).
    """
    base_groups = _grouped(base_findings)
    head_groups = _grouped(head_findings)
    items = []
    for key in base_groups.keys() | head_groups.keys():
        base_group = base_groups.get(key, [])
        head_group = head_groups.get(key, [])
        matched = min(len(base_group), len(head_group))
        items.extend(('persisted', f) for f in head_group[:matched])
        items.extend(('resolved', f) for f in base_group[matched:])
        items.extend(('new', f) for f in head_group[matched:])
    items.sort(key=lambda pair: (
        STATUSES.index(pair[0]),
        SEVERITIES.index(pair[1].severity) if pair[1].severity in SEVERITIES else 3,
        pair[1].file_path,
        pair[1].start_line,
    ))
    return items


def blocking_items(items):
    return [f for status, f in items if status == 'new' and f.severity in BLOCKING_SEVERITIES]


def _cell(text):
    """표 셀용 — 줄바꿈·연속 공백은 한 칸으로, 파이프는 이스케이프, 길이 제한."""
    text = re.sub(r'\s+', ' ', text or '').strip().replace('|', '\\|')
    if len(text) > MESSAGE_MAX_CHARS:
        text = text[:MESSAGE_MAX_CHARS - 1] + '…'
    return text


def _table(findings):
    lines = [
        '| 심각도 | 항목 | 위치 | 메시지 |',
        '| --- | --- | --- | --- |',
    ]
    for f in findings:
        label = f'{f.rule_code} {f.rule_name}'.strip() or f.semgrep_check_id
        lines.append(
            f'| {f.severity} | {_cell(label)} | `{f.file_path}:{f.start_line}` '
            f'| {_cell(f.message)} |'
        )
    return '\n'.join(lines)


def render_markdown(items, *, base_label='', head_label='', base_scanned=True):
    """job summary와 PR 코멘트에 같이 쓰는 마크다운."""
    counts = Counter((status, f.severity) for status, f in items)
    blocked = blocking_items(items)
    verdict = '🚫 차단' if blocked else '✅ 통과'
    reason = (
        f'신규 {"/".join(BLOCKING_SEVERITIES)} {len(blocked)}건 — 병합 전에 해결해야 합니다.'
        if blocked else
        f'신규 {"/".join(BLOCKING_SEVERITIES)} 없음.'
    )

    out = [COMMENT_MARKER, f'## SAST 게이트 — {verdict}', '', reason, '']
    scope = f'`{head_label}`' if head_label else 'PR 브랜치'
    if base_scanned:
        base_text = f'`{base_label}`' if base_label else 'base'
        out.append(
            f'KISA 룰셋(`catalog/rules`)으로 {scope}와 {base_text}를 각각 스캔해 '
            '비교했습니다. 매칭 키는 서버와 같은 핑거프린트(룰 | 경로 | 코드 조각)라 '
            '줄 번호 이동은 신규로 잡지 않습니다.'
        )
    else:
        out.append(f'KISA 룰셋(`catalog/rules`)으로 {scope}를 스캔했습니다. '
                   '비교할 base가 없어 전부 신규로 봅니다.')
    out += [
        '',
        '| 상태 | ' + ' | '.join(SEVERITIES) + ' | 합계 |',
        '| --- | ' + ' | '.join('---' for _ in SEVERITIES) + ' | --- |',
    ]
    for status in STATUSES:
        row = [counts.get((status, sev), 0) for sev in SEVERITIES]
        out.append(
            f'| {STATUS_LABELS[status]} | ' + ' | '.join(str(n) for n in row)
            + f' | {sum(row)} |'
        )

    by_status = {status: [f for s, f in items if s == status] for status in STATUSES}
    out += ['', f'### 신규 {len(by_status["new"])}건']
    if by_status['new']:
        out.append(_table(by_status['new']))
    else:
        out.append('없음.')
    for status in ('resolved', 'persisted'):
        findings = by_status[status]
        if not findings:
            continue
        out += [
            '', '<details>',
            f'<summary>{STATUS_LABELS[status]} {len(findings)}건</summary>', '',
            _table(findings), '', '</details>',
        ]
    return '\n'.join(out) + '\n'


def _load_results(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle).get('results') or []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--head', required=True, help='PR 브랜치 스캔 결과 JSON')
    parser.add_argument('--head-root', default='.', help='head 스캔의 cwd(소스 루트)')
    parser.add_argument('--base', help='base 스캔 결과 JSON (없으면 전부 신규)')
    parser.add_argument('--base-root', help='base 스캔의 cwd(소스 루트)')
    parser.add_argument('--head-label', default='')
    parser.add_argument('--base-label', default='')
    parser.add_argument('--catalog', default=str(CATALOG_PATH))
    parser.add_argument('--summary', help='마크다운을 덧붙일 파일 (GITHUB_STEP_SUMMARY)')
    parser.add_argument('--comment', help='PR 코멘트 본문을 쓸 파일')
    args = parser.parse_args(argv)

    # 로컬 Windows 콘솔(cp949)에서도 한글·기호가 든 마크다운을 출력할 수 있게.
    # 러너(리눅스, UTF-8)에서는 영향이 없다.
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    catalog = load_catalog(args.catalog)
    head = load_findings(_load_results(args.head), args.head_root, catalog)
    base = []
    if args.base:
        base = load_findings(
            _load_results(args.base), args.base_root or args.head_root, catalog,
        )

    items = classify(base, head)
    markdown = render_markdown(
        items, base_label=args.base_label, head_label=args.head_label,
        base_scanned=bool(args.base),
    )
    print(markdown)
    if args.summary:
        with open(args.summary, 'a', encoding='utf-8') as handle:
            handle.write(markdown)
    if args.comment:
        with open(args.comment, 'w', encoding='utf-8') as handle:
            handle.write(markdown)

    blocked = blocking_items(items)
    if blocked:
        print(f'::error::신규 {"/".join(BLOCKING_SEVERITIES)} {len(blocked)}건 — 게이트 차단')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
