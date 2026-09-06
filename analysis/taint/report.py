"""분석 결과를 Semgrep JSON 결과와 같은 모양으로 (docs/decisions.md 2026-09-06 custom-taint 판단 5).

catalog의 표준화(ingest_findings)가 Semgrep 결과와 같은 코드로 다루게 하려는 것이다 — check_id·path·start/end·
extra.metadata(kisa_code, cwe, engine)를 같은 자리에 두고, 오염 경로는 텍스트 어댑터가 아니라 여기서 바로
`extra.taint_trace`(source/steps/sink, 노드마다 path·line·code — catalog/taint_trace.py와 같은 형식)에 싣는다.
"""

from . import spec


def check_id(kisa_code):
    return f'{spec.ENGINE}-{kisa_code.lower()}'


def to_item(finding, abs_path):
    """Finding 1건 → Semgrep 결과 item. path는 Semgrep처럼 절대경로(표준화가 격리 루트 기준 상대경로로 바꾼다)."""
    source = {k: v for k, v in finding.taint.source.items() if k in ('path', 'line', 'code')}
    return {
        'check_id': check_id(finding.kisa_code),
        'path': abs_path,
        'start': {'line': finding.sink['line']},
        'end': {'line': finding.sink['line']},
        'extra': {
            'message': finding.message,
            'severity': 'ERROR',
            'metadata': {
                'kisa_code': finding.kisa_code,
                'cwe': finding.cwe,
                'engine': spec.ENGINE,
            },
            'taint_trace': {
                'source': source,
                'steps': [dict(step) for step in finding.taint.steps],
                'sink': dict(finding.sink),
            },
        },
    }
