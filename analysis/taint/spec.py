"""소스·싱크·sanitizer 정의 — Python (docs/decisions.md 2026-09-06 custom-taint 판단 2).

catalog/rules/taint_python.yaml의 정의를 재사용하지 않고 여기 선언적으로 다시 적는다. YAML 쪽은 Semgrep 패턴
언어(메타변수·`...`·focus·by-side-effect)라 재사용하려면 그 언어의 해석기가 필요하고, 그것이 분석기 본체보다
크다. 두 곳이 어긋나는 위험은 catalog/tests.py의 정합성 시험이 막는다 — YAML의 싱크·sanitizer·소스 이름을
뽑아 이 파일과 KISA 코드별로 대조한다. 그러니 **한쪽을 고치면 다른 쪽도 고친다.**

호출 이름 표기: 점 표기(`os.system`, `urllib.request.urlopen`). `*.execute`는 "어떤 객체의 execute 메서드",
`subprocess.*`는 "subprocess 모듈의 아무 함수". 싱크의 `arg`는 오염을 보는 위치 — 정수면 위치 인자,
BASE는 메서드 호출의 대상 객체(`path.read_text()`의 path).
"""

from dataclasses import dataclass

# 메서드 호출의 대상 객체를 싱크 인자로 보는 표시 (예: $PATH.read_text())
BASE = 'base'

# 결과의 extra.engine 값 — catalog/services.py의 ENGINE_CUSTOM_TAINT와 같은 문자열(문자열로만 공유, 의존 없음)
ENGINE = 'custom-taint'


@dataclass(frozen=True)
class Sink:
    kisa_code: str
    call: str
    arg: object = 0                 # int(위치 인자) | BASE | 'kw:<이름>'(키워드 인자)
    requires_kw: tuple = None       # (키워드 이름, 상수 값) — 예: ('shell', True)
    cwe: str = ''
    message: str = ''


@dataclass(frozen=True)
class Sanitizer:
    """이 호출의 반환값(또는 속성)은 깨끗하다. kisa_code=None이면 모든 항목 공통."""
    call: str
    kisa_code: str = None
    attribute: bool = False         # True면 호출이 아니라 속성 접근 (예: `$P.name`)


# --- 소스(외부 입력) — taint_python.yaml 머리말과 같은 목록 ---------------------------------
# (a) 함수 매개변수 — self·cls 제외. (b) 웹 요청 값. (c) 프로세스 밖 입력.
PARAM_SOURCE_EXCLUDE = ('self', 'cls')
# request.<M>.get(...) / request.<M>.getlist(...) / request.<M>[...] / request.body / request.get_json(...)
REQUEST_NAME = 'request'
REQUEST_GETTERS = ('get', 'getlist')
REQUEST_PLAIN_ATTRS = ('body',)
SOURCE_CALLS = ('input', 'os.getenv', 'os.environ.get', 'request.get_json')
SOURCE_NAMES = ('sys.argv', 'os.environ')

# --- sanitizer -------------------------------------------------------------------------------
SANITIZERS = (
    # 공통
    Sanitizer('int'),
    Sanitizer('float'),
    # IV-01: psycopg2.sql 조합·식별자 인용
    Sanitizer('sql.Identifier', 'KISA-IV-01'),
    Sanitizer('sql.Literal', 'KISA-IV-01'),
    Sanitizer('*.quote_name', 'KISA-IV-01'),
    # IV-03: 파일 이름만 남기기, 허용 디렉토리 기준 상대경로
    Sanitizer('os.path.basename', 'KISA-IV-03'),
    Sanitizer('secure_filename', 'KISA-IV-03'),
    Sanitizer('*.relative_to', 'KISA-IV-03'),
    Sanitizer('*.name', 'KISA-IV-03', attribute=True),
    # IV-04: 이스케이프
    Sanitizer('escape', 'KISA-IV-04'),
    Sanitizer('html.escape', 'KISA-IV-04'),
    Sanitizer('conditional_escape', 'KISA-IV-04'),
    Sanitizer('markupsafe.escape', 'KISA-IV-04'),
    Sanitizer('bleach.clean', 'KISA-IV-04'),
    Sanitizer('format_html', 'KISA-IV-04'),
    # IV-05: 셸 인용
    Sanitizer('shlex.quote', 'KISA-IV-05'),
)
# 이름 규약 — 본문을 보지 못하는 동안의 임시 규칙(YAML과 동일). 2단계(함수 간)에서 같은 파일 함수는 본문 요약이
# 이름보다 우선한다.
SANITIZER_NAME_PREFIXES = ('validate_', 'sanitize_', 'sanitise_', 'clean_', 'escape_')

# --- 검사(가드) — 검사를 지난 뒤의 변수를 깨끗하게 본다 (Semgrep by-side-effect와 같은 근사) ----------
# `if x in ALLOWED:` / `if x not in ALLOWED: raise` — 막 비교의 왼쪽
GUARD_MEMBERSHIP = True
# `if not re.fullmatch(p, x): raise` / `if re.fullmatch(p, x) is None:` — 두 번째 인자. 컴파일된 패턴
# (`$RE.fullmatch(x)`)은 첫 번째 인자.
GUARD_REGEX_FUNCTIONS = ('fullmatch', 'match', 'search')
# `if not p.is_relative_to(ROOT): raise` / `if p.is_relative_to(ROOT):` — 대상 객체
GUARD_METHODS = ('is_relative_to',)
# `if not url_has_allowed_host_and_scheme(url, ...):` — 첫 번째 인자 (IV-07)
GUARD_CALLS = {'url_has_allowed_host_and_scheme': 0}

# --- 싱크 -----------------------------------------------------------------------------------
_SQL = 'SQL 삽입 (KISA-IV-01). 외부 입력이 검증 없이 SQL 질의 문자열로 흘러 들어갑니다. 문자열 결합·포매팅 대신 파라미터 바인딩(placeholder)을 사용하세요.'
_CODE = '코드삽입 (KISA-IV-02). 외부에서 들어온 값이 코드로 해석되어 실행될 수 있습니다. eval/exec 대신 명시적인 분기나 안전한 파서를 사용하세요.'
_PATH = '경로 조작 및 자원 삽입 (KISA-IV-03). 외부 입력으로 만든 경로를 검증 없이 열고 있습니다. 허용된 디렉토리 기준으로 정규화(resolve)한 뒤 그 안에 있는지 확인하세요.'
_XSS = '크로스사이트 스크립트 (KISA-IV-04). 외부 입력이 이스케이프 없이 HTML 응답으로 흘러 들어갑니다. 템플릿의 자동 이스케이프를 쓰거나 escape()로 처리한 뒤 출력하세요.'
_CMD = '운영체제 명령어 삽입 (KISA-IV-05). 외부 입력이 검증 없이 셸 명령으로 흘러 들어갑니다. shell=True를 피하고 인자를 리스트로 전달하세요.'
_REDIRECT = '신뢰되지 않는 URL 주소로 자동접속 연결 (KISA-IV-07). 외부 입력이 검증 없이 리다이렉트 대상으로 흘러 들어갑니다. 허용 목록으로 대상 경로를 제한하세요.'
_SSRF = '서버사이드 요청 위조 (KISA-IV-12). 외부 입력이 검증 없이 서버가 요청을 보내는 주소로 흘러 들어갑니다. 허용 목록으로 대상 호스트를 제한하세요.'

SINKS = (
    Sink('KISA-IV-01', '*.execute', 0, cwe='CWE-89', message=_SQL),
    Sink('KISA-IV-01', '*.executemany', 0, cwe='CWE-89', message=_SQL),
    Sink('KISA-IV-01', '*.executescript', 0, cwe='CWE-89', message=_SQL),
    Sink('KISA-IV-01', '*.raw', 0, cwe='CWE-89', message=_SQL),

    Sink('KISA-IV-02', 'eval', 0, cwe='CWE-94', message=_CODE),
    Sink('KISA-IV-02', 'exec', 0, cwe='CWE-94', message=_CODE),

    Sink('KISA-IV-03', 'open', 0, cwe='CWE-22', message=_PATH),
    Sink('KISA-IV-03', 'io.open', 0, cwe='CWE-22', message=_PATH),
    Sink('KISA-IV-03', '*.read_text', BASE, cwe='CWE-22', message=_PATH),
    Sink('KISA-IV-03', '*.read_bytes', BASE, cwe='CWE-22', message=_PATH),
    Sink('KISA-IV-03', '*.write_text', BASE, cwe='CWE-22', message=_PATH),
    Sink('KISA-IV-03', '*.write_bytes', BASE, cwe='CWE-22', message=_PATH),
    Sink('KISA-IV-03', 'send_file', 0, cwe='CWE-22', message=_PATH),

    Sink('KISA-IV-04', 'HttpResponse', 0, cwe='CWE-79', message=_XSS),
    Sink('KISA-IV-04', 'HttpResponse', 'kw:content', cwe='CWE-79', message=_XSS),
    Sink('KISA-IV-04', 'mark_safe', 0, cwe='CWE-79', message=_XSS),
    Sink('KISA-IV-04', 'Markup', 0, cwe='CWE-79', message=_XSS),
    Sink('KISA-IV-04', 'render_template_string', 0, cwe='CWE-79', message=_XSS),

    Sink('KISA-IV-05', 'os.system', 0, cwe='CWE-78', message=_CMD),
    Sink('KISA-IV-05', 'os.popen', 0, cwe='CWE-78', message=_CMD),
    Sink('KISA-IV-05', 'subprocess.*', 0, requires_kw=('shell', True), cwe='CWE-78', message=_CMD),

    Sink('KISA-IV-07', 'redirect', 0, cwe='CWE-601', message=_REDIRECT),
    Sink('KISA-IV-07', 'HttpResponseRedirect', 0, cwe='CWE-601', message=_REDIRECT),
    Sink('KISA-IV-07', 'HttpResponsePermanentRedirect', 0, cwe='CWE-601', message=_REDIRECT),

    Sink('KISA-IV-12', 'urllib.request.urlopen', 0, cwe='CWE-918', message=_SSRF),
)
# requests.*/httpx.*의 HTTP 메서드 — YAML에서는 `requests.$METHOD` + metavariable-regex 하나로 적힌다.
SINK_METHOD_FAMILIES = ('get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request')
SINKS += tuple(
    Sink('KISA-IV-12', f'{module}.{method}', 0, cwe='CWE-918', message=_SSRF)
    for module in ('requests', 'httpx')
    for method in SINK_METHOD_FAMILIES
)


def matches_call(pattern, callee):
    """점 표기 호출 이름이 패턴에 맞는가. `*.name`은 끝 이름 일치, `mod.*`는 접두 일치, 그 외 정확 일치.

    `callee`는 코드에 적힌 그대로의 점 표기(`cursor.execute`, `subprocess.run`)다 — 별칭·import 해석은 하지
    않는다(Semgrep 패턴 매칭과 같은 수준).
    """
    if pattern.startswith('*.'):
        return callee.rsplit('.', 1)[-1] == pattern[2:] and '.' in callee
    if pattern.endswith('.*'):
        return callee.startswith(pattern[:-1]) and '.' not in callee[len(pattern) - 1:]
    return callee == pattern


def sinks_for_call(callee):
    return [sink for sink in SINKS if matches_call(sink.call, callee)]


def is_sanitizer_call(callee):
    """호출 반환값을 깨끗하게 보는가(공통 + 항목별). 항목별은 모든 항목에 적용하지 않고 해당 항목 싱크에서만
    걸러야 정확하지만, 1단계에서는 Semgrep YAML과 같은 단순화(해당 룰의 싱크에서만 의미가 있으므로 결과는 같다)로
    전역 적용한다 — 항목 A의 sanitizer가 항목 B의 오염을 지우는 경우는 목록상 없다."""
    if any(matches_call(s.call, callee) for s in SANITIZERS if not s.attribute):
        return True
    return callee.rsplit('.', 1)[-1].startswith(SANITIZER_NAME_PREFIXES)


def is_sanitizer_attribute(attr):
    return any(s.attribute and s.call == f'*.{attr}' for s in SANITIZERS)
