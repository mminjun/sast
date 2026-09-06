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
    source = {k: v for k, v in finding.taint.source.items() if k in ('path', 'line', 'code', 'role')}
    sink = finding.sink
    # 싱크와 같은 줄의 경유(같은 줄에서 호출하고 바로 싱크에 넣는 `os.system(helper(x))`의 '반환' 노드)는 표시 중복이다.
    steps = [
        dict(step) for step in finding.taint.steps
        if not (step['line'] == sink['line'] and step['path'] == sink['path'])
    ]
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
                'steps': steps,
                'sink': dict(sink),
                # 같은 싱크에 도달한 경로 수 — 대표 1개만 담는다. 나중에 전체를 담을 때는 여기에
                # 'alternatives': [trace, ...]를 더한다(기존 소비자는 source/steps/sink만 본다).
                'paths_count': finding.paths_count,
            },
        },
    }
