"""코드 조각 읽기 — 소스 파일에서 취약 줄 범위와 앞뒤 문맥을 뽑는 규칙 (SFR-016, DAR-009).

이 규칙은 ingest(catalog/services.py)와 CI 게이트(scripts/sast_gate.py) 두 곳에서 쓰인다.
code_snippet은 핑거프린트(catalog/fingerprint.py)의 입력이라, 두 경로의 조각이 한 글자라도
다르면 같은 취약점의 키가 어긋나 diff가 전부 틀어진다. 그래서 읽기·절단·조합 규칙을 이
모듈 한 곳에만 두고, 양쪽이 같은 함수를 부른다 (docs/decisions.md 2026-09-04).

이 모듈은 Django를 import하지 않는다 — CI 러너에서 Django 설치 없이 쓰기 위해서다.
호출자는 열 수 있는 경로를 넘긴다 (격리 루트 검사·Windows 확장 경로 변환은 호출자 몫).
"""

from pathlib import Path

# 조각으로 저장할 최대 줄 수. Semgrep이 여러 줄 매치를 돌려줘도 이 이상은 자른다.
MAX_SNIPPET_LINES = 20
MAX_SNIPPET_CHARS = 2000
# 한 줄에서 남길 최대 길이. 줄 수만 제한하면 '한 줄짜리 거대 파일'을 막지 못한다.
MAX_SNIPPET_LINE_CHARS = 500
# 이 크기를 넘는 파일은 조각 추출을 건너뛴다. 줄 단위로 읽어도 한 줄의 길이는
# 제한되지 않으므로, 난독화·압축된 1줄 파일이면 그 한 줄이 통째로 메모리에 올라온다
# (압축 해제 상한이 100MB라 그만큼까지 가능). 그 정도 파일의 조각은 읽어도 쓸모없다.
MAX_SNIPPET_SOURCE_BYTES = 2 * 1024 * 1024
# 취약 줄 앞뒤로 함께 보여줄 문맥 줄 수. 한 줄만 보면 `cursor.execute(query)`처럼 값이
# 어디서 왔는지 알 수 없어 판정이 안 된다. 문맥은 표시용으로만 extra에 두고 code_snippet
# 과 핑거프린트에는 넣지 않는다 — 근처 줄이 바뀌었다고 같은 취약점이 '해결+신규'로
# 갈라지면 안 된다 (DAR-009 비교 안정성).
SNIPPET_CONTEXT_LINES = 3
# 문맥 전체(취약 줄 포함)의 상한. 조각 상한과 같은 이유로 둔다. 넘으면 문맥을 버리고
# 조각만 남긴다 — 화면은 문맥이 없으면 조각으로 되돌아간다.
MAX_CONTEXT_LINES = MAX_SNIPPET_LINES + 2 * SNIPPET_CONTEXT_LINES
MAX_CONTEXT_CHARS = 2 * MAX_SNIPPET_CHARS

# PostgreSQL text/jsonb는 NUL(U+0000)을 저장하지 못한다 (analysis.services.strip_nul과
# 같은 이유 — 그 모듈은 Django에 의존해 여기서 import하지 않는다).
NUL = chr(0)


def read_snippet(path, start_line, end_line):
    """파일에서 지정 줄 범위(조각)와 그 앞뒤 문맥을 한 번에 읽는다.

    반환은 (snippet, context). 읽을 수 없거나 조각이 비면 ('', None). context는
    {'start_line': 문맥 첫 줄 번호, 'lines': [...]} 또는 상한 초과 시 None.
    """
    target = Path(path)
    last_line = min(end_line or start_line, start_line + MAX_SNIPPET_LINES - 1)
    context_start = max(1, start_line - SNIPPET_CONTEXT_LINES)
    context_end = last_line + SNIPPET_CONTEXT_LINES

    picked = {}
    try:
        if not target.is_file():
            return '', None
        # 줄 단위로 읽기 전에 파일 크기부터 본다 — 줄 수를 제한해도 한 줄의 길이는
        # 제한되지 않으므로, 큰 파일에서는 한 줄을 읽는 것만으로 메모리가 튄다.
        if target.stat().st_size > MAX_SNIPPET_SOURCE_BYTES:
            return '', None

        # 분석 대상 소스의 인코딩은 우리가 정할 수 없으므로 깨진 바이트는 대체 문자로
        # 두고 계속한다 — 조각 하나 때문에 수집 전체가 실패하면 안 된다.
        with target.open('r', encoding='utf-8', errors='replace') as handle:
            for number, line in enumerate(handle, start=1):
                if number > context_end:
                    break
                if number >= context_start:
                    # NUL은 PostgreSQL text에 저장되지 않는다 — 바이너리 섞인 소스 방어.
                    picked[number] = (
                        line.rstrip('\n').replace(NUL, '')[:MAX_SNIPPET_LINE_CHARS]
                    )
    except OSError:
        return '', None

    snippet = '\n'.join(
        picked[n] for n in range(start_line, last_line + 1) if n in picked
    )[:MAX_SNIPPET_CHARS]
    if not snippet:
        return '', None

    context_lines = [picked[n] for n in sorted(picked)]
    # 문맥은 부가 정보다 — 상한을 넘으면 문맥만 버리고 조각은 남긴다.
    if (
        len(context_lines) > MAX_CONTEXT_LINES
        or sum(len(line) for line in context_lines) > MAX_CONTEXT_CHARS
    ):
        return snippet, None
    return snippet, {'start_line': context_start, 'lines': context_lines}
