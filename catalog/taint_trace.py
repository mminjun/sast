"""Semgrep 텍스트 출력의 오염 경로(dataflow trace) 어댑터 (SFR-014, DAR-009).

Semgrep 1.175.0 OSS는 taint 룰의 "소스 → 중간 변수 → 싱크" 경로를 JSON에 싣지 않는다
(`--dataflow-traces`는 text·SARIF 출력에만 영향, SARIF의 codeFlows도 비어 있음 — 실측,
docs/decisions.md 2026-09-06 taint). 그래서 실행 때 `--text-output=<작업 영역>/dataflow_trace.txt`를
같이 받아 두고, 표준화(ingest) 때 이 모듈이 그 텍스트를 읽어 Finding.extra['taint_trace']를 채운다.

형식(1.175.0 실측, 120칸에서 강제로 감김 — COLUMNS 환경변수로 바꿀 수 없다):
    <4칸 들여쓰기>path — 120칸을 넘으면 다음 줄(2칸)로 이어짐
       ❯❯❱ <rule id — 길면 다음 줄(7칸)로 이어짐>
          ❰❰ Blocking ❱❱
          <message>
            6┆ os.system(line)                       ← 싱크 (finding의 시작 줄)
          Taint comes from:
            3┆ def e1_var_hop(host):                 ← 소스
          Taint flows through these intermediate variables:
            3┆ def e1_var_hop(host):                 ← (소스 줄이 한 번 더 온다 — 정규화에서 뺀다)
            4┆ cmd = "ping " + host
                This is how taint reaches the sink:
            6┆ os.system(line)
            ⋮┆----------------------------------------  ← 다음 finding

이 모듈은 Django를 import하지 않고 파일도 열지 않는다(텍스트를 받아 파싱만 — 파일 읽기는 격리 루트
검사와 함께 호출자가 한다, catalog/services.py). 어떤 입력에도 예외를 내지 않는다 — 오염 경로는
부가정보라 파싱이 깨져도 탐지 결과 저장은 계속돼야 한다. Semgrep 버전이 바뀌어 형식이 달라지면 결과는
"경로 없음"이 되고, ingest가 "taint 결과는 있는데 경로가 한 건도 안 붙음"을 경고 로그로 남긴다
(catalog/services.py). 반환하는 경로(path)는 Semgrep이 출력한 문자열 그대로다 — 격리 루트 기준
상대경로로 맞추는 것은 호출자(ingest) 몫이다.

결과 형식(자체 taint 구현도 같은 형식을 채운다):
    {(path, rule_id, sink_line): {'source': {'line', 'code'}, 'steps': [{'line', 'code'}, ...],
                                  'sink': {'line', 'code'}}}
"""

import re

CODE_LINE_RE = re.compile(r'^\s*(\d+)┆ ?(.*)$')
# 룰 헤더 표식은 심각도별로 다르다 — ERROR ❯❯❱, WARNING ❯❱, INFO ❱ (1.175.0 실측: IV-07이 WARNING이라
# ❯❯❱만 보던 첫 판이 그 룰의 경로를 전부 놓쳤다).
RULE_HEADER_RE = re.compile(r'^❯{0,2}❱\s*(.*)$')
RULE_HEADER_END = '❰❰'
FINDING_SEPARATOR = '⋮┆'
SOURCE_LABEL = 'Taint comes from:'
STEPS_LABEL = 'Taint flows through these intermediate variables:'
SINK_LABEL = 'This is how taint reaches the sink:'
# 파일 경로 줄의 들여쓰기(칸). 룰 헤더는 3칸, 이어지는 줄은 7칸, 메시지·라벨은 10칸 이상이다.
PATH_INDENT = 4
# 120칸에서 감긴 경로의 이어지는 줄 들여쓰기(칸) — 1.175.0 실측.
PATH_CONTINUATION_INDENT = 2


def bare_rule_id(text):
    """텍스트 헤더의 룰 id에서 설정 경로 접두사를 뗀다 (catalog.services.bare_check_id와 같은 규칙)."""
    return re.split(r'[\\/.]', text or '')[-1]


def _node(line, code):
    return {'line': int(line), 'code': code.strip()}


def _finish(traces, path, rule_id, current):
    """모아 둔 finding 하나를 결과에 넣는다. 싱크·소스가 없으면 버린다."""
    if not current or current.get('sink') is None or current.get('source') is None:
        return
    source = current['source']
    steps = [
        step for step in current.get('steps', [])
        if not (step['line'] == source['line'] and step['code'] == source['code'])
    ]
    traces[(path, rule_id, source and current['sink']['line'])] = {
        'source': source,
        'steps': steps,
        'sink': current['sink'],
    }


def parse_trace_text(text):
    """텍스트 출력을 {(path, rule_id, sink_line): trace}로 바꾼다. 어떤 입력에도 예외를 내지 않는다."""
    try:
        return _parse(text or '')
    except Exception:  # noqa: BLE001 — 부가정보 파싱 실패는 탐지 결과 저장을 막지 않는다
        return {}


def _parse(text):
    traces = {}
    path = None
    rule_id = None
    reading_rule_header = False
    reading_path = False
    current = None
    state = 'sink'  # 룰 블록·구분선 뒤 첫 코드 줄이 싱크

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            reading_path = False
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        # Semgrep은 텍스트를 120칸에서 강제로 감는다(COLUMNS 무시). 격리 작업 영역의 절대경로는
        # 그보다 길어 다음 줄(2칸 들여쓰기)로 이어진다 — 이어 붙인다. 감긴 자리에 공백이 있었다면
        # 사라질 수 있으므로 호출자는 공백을 무시하고 경로를 맞춘다 (catalog/services.py).
        if reading_path and indent == PATH_CONTINUATION_INDENT:
            path += stripped
            continue
        reading_path = False

        header = RULE_HEADER_RE.match(stripped)
        if header:
            _finish(traces, path, rule_id, current)
            current, state = None, 'sink'
            rule_id = header.group(1).strip()
            reading_rule_header = True
            continue
        if reading_rule_header:
            if stripped.startswith(RULE_HEADER_END):
                reading_rule_header = False
                rule_id = bare_rule_id(rule_id)
            else:
                rule_id += stripped  # 감긴 룰 id의 이어지는 조각
            continue
        if stripped.startswith(FINDING_SEPARATOR):
            _finish(traces, path, rule_id, current)
            current, state = None, 'sink'
            continue
        if stripped == SOURCE_LABEL:
            state = 'source'
            continue
        if stripped == STEPS_LABEL:
            state = 'steps'
            continue
        if stripped == SINK_LABEL:
            state = 'sink_confirm'
            continue

        match = CODE_LINE_RE.match(line)
        if match:
            node = _node(*match.groups())
            if state == 'sink':
                current = {'sink': node, 'steps': []}
                state = 'body'
            elif current is None:
                continue
            elif state == 'source':
                current['source'] = node
            elif state == 'steps':
                current['steps'].append(node)
            # 'sink_confirm'·'body'의 코드 줄은 이미 아는 싱크의 반복이라 무시한다
            continue

        if indent == PATH_INDENT and not stripped.startswith(('❰', '❯', '❱', '⋮')):
            _finish(traces, path, rule_id, current)
            current, state = None, 'sink'
            path = stripped
            reading_path = True
            continue
        # 그 밖(메시지 본문·요약 상자·헤더 박스)은 무시

    _finish(traces, path, rule_id, current)
    return traces

