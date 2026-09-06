"""Python 소스의 taint 분석 — 함수 안 + 같은 파일 함수 간 + 클래스 필드 (docs/decisions.md 2026-09-06 custom-taint 1~3단계).

`ast`로 파싱한 뒤 함수마다 문장을 차례로 돌며 환경({접근 경로: Taint})을 흘린다. NodeVisitor를 쓰지 않는
이유: visit가 환경을 돌려주지 않아 분기 병합을 표현할 수 없다. 제어 흐름은 경로 비민감 합집합(may)이다 —
if는 두 갈래를 같은 환경 사본에서 분석해 합치고, 루프는 본문을 LOOP_PASSES번 돌려 루프 전달 오염을 근사하며,
try는 본문·핸들러·else·finally를 합친다. 검사 가드(`if x in ALLOWED:`, `if not re.fullmatch(p, x): raise`,
`if not p.is_relative_to(ROOT): raise`)는 그 뒤의 변수를 깨끗하게 본다(Semgrep by-side-effect와 같은 근사).

같은 파일 함수 간(2단계): 모듈 최상위 함수의 요약(Summary — 매개변수→반환, 매개변수→싱크, 본문 안 입력→반환)을
빈 요약에서 시작해 모양이 안 바뀔 때까지 반복 계산하고(고정점, 상한 SUMMARY_PASSES, 이전 패스와 합쳐 단조),
호출 지점에서 그 요약대로 전파·보고한다. 같은 파일 함수는 이름 규약(validate_ 등)이 아니라 **본문(요약)만** 본다.
요약이 아직 없는 함수는 빈 요약(전파 없음)이라 기저 사례 없는 재귀는 깨끗하게 안정된다.

클래스 필드(3단계): 최상위 클래스마다 메서드 요약과 필드 환경({('self', f): Taint} — 모든 메서드의 `self.f = …`
합집합, `__init__` 매개변수 포함)을 한 고정점에서 계산하고, 필드를 들고 각 메서드를 다시 돌려 **다른 메서드에서
대입된 필드**를 읽는 싱크를 보고한다(경로: 대입 메서드의 field 노드 → 읽는 메서드의 enter). `self.m(...)`은
같은 클래스 메서드 요약으로 본다. 흐름 비민감이다 — 호출 순서·`clear()` 되돌림은 보지 않는다(실측 비용은
decisions 참고).

포기한 것(문서화): 경로 민감도·호출 순서, 전역·클로저 변수, *args/**kwargs, 데코레이터 의미, 동적 기능, 상속·
super()·클래스 밖 대입의 함수 간 추적, 클래스 속성·property·classmethod의 cls.x, 중첩 클래스(메서드를 독립 함수로만
분석), 같은 싱크의 다수 경로 표시(대표 1개 + paths_count).
"""

import ast

from . import spec
from .state import (
    EMPTY_SUMMARY, KIND_INPUT, KIND_PARAM, Summary, Taint, lookup, merge, node, prefer,
)

# 루프 본문을 몇 번 돌려 루프 전달 오염을 근사할지. 고정점 대신 상한 — n번이면 n단계 역방향 체인
# (a = b; b = c; c = 입력)까지 잡고 그보다 긴 체인은 놓친다(상한이 어디든 한계는 남는다). 비용이 사실상 0이고
# 미탐은 오탐과 달리 아무도 모르는 채 지나가므로 2 → 3으로 올렸다 (docs/decisions.md 2026-09-06 custom-taint).
LOOP_PASSES = 3
# 함수 요약·클래스 필드 고정점 반복의 상한(안전장치). 요약을 이전 패스와 합쳐 단조 증가시키므로 반드시 안정된다 —
# 정상 코드는 3~5패스(실측). 한 패스에 체인이 한 단계 번지므로 k단계 반환 체인은 k+1패스에서 완성된다.
SUMMARY_PASSES = 16

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
SELF = 'self'


class Finding:
    """싱크 도달 1건 — kisa_code, 싱크 노드, 거기 닿은 Taint(대표 경로), 스펙의 메시지·CWE, 같은 싱크에 모인 경로 수."""

    __slots__ = ('kisa_code', 'sink', 'taint', 'message', 'cwe', 'paths_count')

    def __init__(self, kisa_code, sink, taint, message, cwe):
        self.kisa_code, self.sink, self.taint, self.message, self.cwe = kisa_code, sink, taint, message, cwe
        self.paths_count = 1

    @property
    def key(self):
        return (self.kisa_code, self.sink['line'])


def dotted(expr):
    """호출 대상을 점 표기로 (`os.path.join`, `conn.cursor().execute`). 체인 안의 호출은 `()`로 표시한다 —
    `$CURSOR.execute(...)`처럼 대상이 호출 결과여도 끝 이름(`*.execute`)으로 싱크가 맞아야 한다(2단계 샘플의
    `conn.cursor().execute(...)`가 첫 판에서 빠졌던 원인). Name·Attribute·Call 체인이 아니면 None."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = dotted(expr.value)
        return f'{base}.{expr.attr}' if base else None
    if isinstance(expr, ast.Call):
        base = dotted(expr.func)
        return f'{base}()' if base else None
    return None


def access_path(expr):
    """변수·속성 체인·상수 첨자를 접근 경로 튜플로. 그 밖(호출 결과 등)은 None."""
    if isinstance(expr, ast.Name):
        return (expr.id,)
    if isinstance(expr, ast.Attribute):
        base = access_path(expr.value)
        return base + (expr.attr,) if base else None
    if isinstance(expr, ast.Subscript):
        base = access_path(expr.value)
        if base is None:
            return None
        key = expr.slice
        return base + (f'[{key.value!r}]' if isinstance(key, ast.Constant) else '[*]',)
    return None


def root_name(expr):
    """접근 경로의 첫 이름 (request.GET.get → 'request')."""
    while isinstance(expr, (ast.Attribute, ast.Subscript, ast.Call)):
        expr = expr.func if isinstance(expr, ast.Call) else expr.value
    return expr.id if isinstance(expr, ast.Name) else None


def iter_calls(tree):
    """문장·식 안의 호출을 순회한다(식 자체가 호출이면 그것도). 중첩 함수·클래스·람다 안은 건너뛴다.

    `with open(p) as f:`처럼 컨텍스트 식·if 조건·for 순회 대상이 호출 그 자체인 경우가 있어 루트를 빠뜨리면
    싱크를 놓친다(자체 저장소 도그푸딩에서 `with open(path)` 6건이 통째로 빠졌던 원인).
    """
    if isinstance(tree, ast.Call):
        yield tree
    stack = [tree]
    while stack:
        current = stack.pop()
        for child in ast.iter_child_nodes(current):
            if isinstance(child, _SCOPE_NODES):
                continue
            if isinstance(child, ast.Call):
                yield child
            stack.append(child)


def param_names(func):
    """소스로 보는 매개변수 이름(정의 순서). self·cls 제외 — 요약의 '매개변수 위치'는 이 목록의 인덱스다."""
    return [
        arg.arg for arg in (*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs)
        if arg.arg not in spec.PARAM_SOURCE_EXCLUDE
    ]


class FunctionAnalyzer:
    """함수 하나의 문장을 돌며 싱크 도달을 모으고, 자기 요약(Summary)을 만든다."""

    def __init__(self, func, lines, rel_path, findings, summaries=None, functions=None):
        self.func = func
        self.lines = lines
        self.rel_path = rel_path
        self.findings = findings
        # 같은 파일 함수의 요약(이전 패스)과 정의. 없으면 함수 간 추적 없이 1단계처럼 돈다.
        self.summaries = summaries if summaries is not None else {}
        self.functions = functions if functions is not None else {}
        self.summary = Summary()
        self.params = param_names(func)

    # --- 노드 -------------------------------------------------------------------------
    def node(self, ast_node, role=None, method=None):
        line = ast_node.lineno
        return node(self.rel_path, line, self.lines[line - 1].strip() if line <= len(self.lines) else '',
                    role, method)

    # --- 소스 판정 ---------------------------------------------------------------------
    def _request_source(self, expr):
        """request.<M>.get(...) / request.<M>.getlist(...) / request.<M>[...] / request.body / request.get_json(...) 형태인가."""
        if root_name(expr) != spec.REQUEST_NAME:
            return False
        if isinstance(expr, ast.Call):
            callee = dotted(expr.func) or ''
            return callee in spec.SOURCE_CALLS or (
                callee.count('.') == 2 and callee.rsplit('.', 1)[-1] in spec.REQUEST_GETTERS
            )
        if isinstance(expr, ast.Subscript):
            return isinstance(expr.value, ast.Attribute) and isinstance(expr.value.value, ast.Name)
        if isinstance(expr, ast.Attribute):
            return expr.attr in spec.REQUEST_PLAIN_ATTRS and isinstance(expr.value, ast.Name)
        return False

    # --- 같은 파일 함수·메서드 호출 --------------------------------------------------------
    def resolve_callee(self, call):
        """요약으로 볼 수 있는 호출이면 (정의 사전, 요약 사전, 이름). 모듈 최상위 함수의 바로 부르기만."""
        name = call.func.id if isinstance(call.func, ast.Name) else None
        if name in self.functions:
            return self.functions, self.summaries, name
        return None

    def _mapped_args(self, call, definitions, callee_name, env):
        """[(피호출자 매개변수 위치, [인자 오염])] — 위치 인자는 순서, 키워드는 이름. 기본값은 상수로 본다.
        *args/**kwargs 풀기는 범위 밖."""
        names = param_names(definitions[callee_name])
        mapped = []
        for index, arg in enumerate(call.args):
            if index < len(names) and not isinstance(arg, ast.Starred):
                mapped.append((index, self.taints_of(arg, env)))
        for keyword in call.keywords:
            if keyword.arg in names:
                mapped.append((names.index(keyword.arg), self.taints_of(keyword.value, env)))
        return mapped

    def _through_summary(self, call, resolved, env):
        """요약이 있는 같은 파일 함수·메서드 호출의 결과 오염 전부. 요약이 '깨끗'이면 인자가 오염이어도 []."""
        definitions, summaries, callee_name = resolved
        summary = summaries.get(callee_name, EMPTY_SUMMARY)
        callee = definitions[callee_name]
        flowed_all = []
        for index, taints in self._mapped_args(call, definitions, callee_name, env):
            if index not in summary.param_to_return:
                continue
            for taint in taints:
                flowed = taint.step(self.node(call, 'call')).step(self.node(callee, 'enter'))
                for step in summary.param_to_return[index]:
                    flowed = flowed.step(step)
                flowed_all.append(flowed)
        if summary.return_taint is not None:
            # 헬퍼 안의 입력이 반환으로 나온다 — 소스는 헬퍼 안, 그 뒤 호출 줄로 돌아온다.
            flowed_all.append(summary.return_taint.step(self.node(call, 'return')))
        return flowed_all

    def _report_callee_sinks(self, call, resolved, env):
        """인자의 오염이 같은 파일 함수·메서드 안 싱크에 닿으면 그 싱크 위치에 호출자 경로로 보고한다."""
        definitions, summaries, callee_name = resolved
        summary = summaries.get(callee_name, EMPTY_SUMMARY)
        if not summary.param_to_sinks:
            return
        callee = definitions[callee_name]
        for index, taints in self._mapped_args(call, definitions, callee_name, env):
            for (p_index, kisa_code, _line), (sink_node, steps) in summary.param_to_sinks.items():
                if p_index != index:
                    continue
                for taint in taints:
                    flowed = taint.step(self.node(call, 'call')).step(self.node(callee, 'enter'))
                    for step in steps:
                        flowed = flowed.step(step)
                    sink = next(s for s in spec.SINKS if s.kisa_code == kisa_code)
                    self.findings.append(Finding(kisa_code, sink_node, flowed, sink.message, sink.cwe))
                    self._record_param_sink(flowed, kisa_code, sink_node)

    def _record_param_sink(self, taint, kisa_code, sink_node):
        if taint.kind == KIND_PARAM and taint.source.get('param') in self.params:
            key = (self.params.index(taint.source['param']), kisa_code, sink_node['line'])
            self.summary.param_to_sinks[key] = (sink_node, taint.steps)

    # --- 표현식의 오염 -------------------------------------------------------------------
    def taint_of(self, expr, env):
        """표현식에 닿은 오염 중 대표 하나(prefer 규칙). 없으면 None."""
        return self._first(self.taints_of(expr, env))

    def taints_of(self, expr, env):
        """표현식에 닿은 오염 전부(부분식의 합집합). 요약을 만들 때 `prefix + host + flag`처럼 여러 매개변수가
        한 반환값·싱크 인자에 섞이면 전부 기록해야 호출자의 어느 인자로도 흐름이 이어진다."""
        if expr is None or isinstance(expr, ast.Constant):
            return []

        if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript)):
            # 실제 입력이 매개변수(request)보다 우선 — 경로가 더 구체적이다.
            if self._request_source(expr):
                return [Taint(self.node(expr), kind=KIND_INPUT)]
            if isinstance(expr, ast.Attribute) and spec.is_sanitizer_attribute(expr.attr):
                return []
            name = dotted(expr)
            if name in spec.SOURCE_NAMES:
                return [Taint(self.node(expr), kind=KIND_INPUT)]
            path = access_path(expr)
            if path is not None:
                found = lookup(env, path)
                if found is not None:
                    return [found]
            if isinstance(expr, ast.Subscript):
                return self.taints_of(expr.value, env) + self.taints_of(expr.slice, env)
            if isinstance(expr, ast.Attribute):
                return self.taints_of(expr.value, env)
            return []

        if isinstance(expr, ast.Call):
            callee = dotted(expr.func) or ''
            if callee in spec.SOURCE_CALLS or self._request_source(expr):
                return [Taint(self.node(expr), kind=KIND_INPUT)]
            resolved = self.resolve_callee(expr)
            if resolved is not None:
                # 같은 파일 함수·메서드: 본문(요약)만 본다 — 이름 규약(validate_ 등)은 적용하지 않는다.
                return self._through_summary(expr, resolved, env)
            if callee and spec.is_sanitizer_call(callee):
                return []
            # 모르는 호출: 인자·대상 객체의 오염이 결과로 전파된다 (Semgrep과 같은 기본).
            found = []
            for arg in expr.args:
                found += self.taints_of(arg, env)
            for keyword in expr.keywords:
                found += self.taints_of(keyword.value, env)
            if isinstance(expr.func, ast.Attribute):
                found += self.taints_of(expr.func.value, env)
            return found

        if isinstance(expr, ast.JoinedStr):
            return self._concat(self.taints_of(v, env) for v in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self.taints_of(expr.value, env)
        if isinstance(expr, ast.BinOp):
            return self.taints_of(expr.left, env) + self.taints_of(expr.right, env)
        if isinstance(expr, ast.BoolOp):
            return self._concat(self.taints_of(v, env) for v in expr.values)
        if isinstance(expr, ast.UnaryOp):
            return self.taints_of(expr.operand, env)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return self._concat(self.taints_of(v, env) for v in expr.elts)
        if isinstance(expr, ast.Dict):
            return self._concat(self.taints_of(v, env) for v in (*expr.keys, *expr.values) if v is not None)
        if isinstance(expr, ast.IfExp):
            return self.taints_of(expr.body, env) + self.taints_of(expr.orelse, env)
        if isinstance(expr, (ast.Starred, ast.Await)):
            return self.taints_of(expr.value, env)
        if isinstance(expr, ast.NamedExpr):
            found = self.taints_of(expr.value, env)
            path = access_path(expr.target)
            if path and found:
                env[path] = self._first(found)
            return found
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            # 컴프리헨션: 순회 대상이 오염이면 원소도 오염, 원소식 자체의 오염도 본다(타깃 변수는 바깥 환경으로).
            comp_env = dict(env)
            for gen in expr.generators:
                iter_taint = self.taint_of(gen.iter, env)
                target = access_path(gen.target)
                if iter_taint and target:
                    comp_env[target] = iter_taint
            elts = (expr.key, expr.value) if isinstance(expr, ast.DictComp) else (expr.elt,)
            return self._concat(self.taints_of(e, comp_env) for e in elts)
        return []  # Compare(bool)·Lambda 등은 값이 아니다

    @staticmethod
    def _concat(lists):
        found = []
        for items in lists:
            found += items
        return found

    @staticmethod
    def _first(candidates):
        best = None
        for taint in candidates:
            if taint is not None:
                best = prefer(best, taint)
        return best

    # --- 싱크 -------------------------------------------------------------------------
    def check_calls(self, tree, env):
        for call in iter_calls(tree):
            self.check_call(call, env)

    def check_call(self, call, env):
        resolved = self.resolve_callee(call)
        if resolved is not None:
            self._report_callee_sinks(call, resolved, env)
            return  # 같은 파일 함수·메서드는 요약이 전부다 — 스펙의 싱크로 다시 보지 않는다(로컬 정의가 우선)
        callee = dotted(call.func) or ''
        for sink in spec.sinks_for_call(callee):
            if sink.requires_kw:
                name, value = sink.requires_kw
                if not any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value == value
                           for k in call.keywords):
                    continue
            target = self._sink_argument(call, sink)
            if target is None:
                continue
            taints = self.taints_of(target, env)
            if not taints:
                continue
            sink_node = self.node(call)
            self.findings.append(Finding(sink.kisa_code, sink_node, self._first(taints), sink.message, sink.cwe))
            for taint in taints:
                self._record_param_sink(taint, sink.kisa_code, sink_node)

    @staticmethod
    def _sink_argument(call, sink):
        if sink.arg == spec.BASE:
            return call.func.value if isinstance(call.func, ast.Attribute) else None
        if isinstance(sink.arg, str) and sink.arg.startswith('kw:'):
            name = sink.arg[3:]
            return next((k.value for k in call.keywords if k.arg == name), None)
        return call.args[sink.arg] if sink.arg < len(call.args) else None

    # --- 문장 순회 ------------------------------------------------------------------------
    def run(self, initial_env=None):
        env = dict(initial_env or {})
        def_node = self.node(self.func)
        for name in self.params:
            # 매개변수 소스 — 소스 노드는 def 줄(Semgrep 텍스트 출력과 같은 표시). 'param'은 요약의 위치 매핑용.
            env[(name,)] = Taint({**def_node, 'param': name}, kind=KIND_PARAM)
        return self.block(self.func.body, env)

    def block(self, stmts, env):
        for stmt in stmts:
            env = self.stmt(stmt, env)
        return env

    def assign(self, target, taint, env, at):
        """대입 대상(이름·속성·첨자·튜플 풀기)에 오염을 기록하거나 지운다."""
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, taint, env, at)
            return
        if isinstance(target, ast.Starred):
            self.assign(target.value, taint, env, at)
            return
        path = access_path(target)
        if path is None:
            return
        if taint is None:
            self._clear(env, path)
        else:
            env[path] = taint.step(self.node(at))

    def guard_path(self, test):
        """검사 가드가 깨끗하게 만드는 접근 경로. 가드가 아니면 None."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            if spec.GUARD_MEMBERSHIP and isinstance(op, (ast.In, ast.NotIn)):
                return access_path(test.left)
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(test.left, ast.Call):
                return self._guard_call_path(test.left)
            return None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.guard_path(test.operand)
        if isinstance(test, ast.Call):
            return self._guard_call_path(test)
        return None

    @staticmethod
    def _guard_call_path(call):
        callee = dotted(call.func) or ''
        head, _, tail = callee.rpartition('.')
        if tail in spec.GUARD_REGEX_FUNCTIONS:
            index = 1 if head == 're' else 0      # re.fullmatch(p, x) / compiled.fullmatch(x)
            return access_path(call.args[index]) if len(call.args) > index else None
        if tail in spec.GUARD_METHODS and isinstance(call.func, ast.Attribute):
            return access_path(call.func.value)
        if callee in spec.GUARD_CALLS:
            index = spec.GUARD_CALLS[callee]
            return access_path(call.args[index]) if len(call.args) > index else None
        return None

    @staticmethod
    def _clear(env, path):
        if path is None:
            return
        for key in [k for k in env if k[:len(path)] == path]:
            del env[key]

    def stmt(self, stmt, env):
        if isinstance(stmt, _SCOPE_NODES):
            return env  # 중첩 정의는 모듈 단위에서 따로 분석한다

        if isinstance(stmt, ast.If):
            self.check_calls(stmt.test, env)
            self.taint_of(stmt.test, env)
            sanitized = self.guard_path(stmt.test)
            body_env = dict(env)
            self._clear(body_env, sanitized)
            body_env = self.block(stmt.body, body_env)
            else_env = self.block(stmt.orelse, dict(env))
            merged = merge(body_env, else_env)
            # early return/raise 검증 뒤엔 깨끗 (Semgrep by-side-effect와 같은 근사 — 분기 모양은 보지 않는다)
            self._clear(merged, sanitized)
            return merged

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.check_calls(stmt.iter, env)
            self.assign(stmt.target, self.taint_of(stmt.iter, env), env, stmt)
            for _ in range(LOOP_PASSES):
                env = merge(self.block(stmt.body, dict(env)), env)
            return merge(self.block(stmt.orelse, dict(env)), env)

        if isinstance(stmt, ast.While):
            for _ in range(LOOP_PASSES):
                self.check_calls(stmt.test, env)
                env = merge(self.block(stmt.body, dict(env)), env)
            return merge(self.block(stmt.orelse, dict(env)), env)

        if isinstance(stmt, ast.Try):
            merged = self.block(stmt.body, dict(env))
            for handler in stmt.handlers:
                merged = merge(self.block(handler.body, dict(env)), merged)
            merged = self.block(stmt.orelse, merged)
            return self.block(stmt.finalbody, merged)

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.check_calls(item.context_expr, env)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, self.taint_of(item.context_expr, env), env, stmt)
            return self.block(stmt.body, env)

        if isinstance(stmt, ast.Match):
            self.check_calls(stmt.subject, env)
            merged = None
            for case in stmt.cases:
                case_env = self.block(case.body, dict(env))
                merged = case_env if merged is None else merge(merged, case_env)
            return merge(merged, env) if merged is not None else env

        # --- 단순 문장: 안의 호출을 먼저 싱크로 검사한 뒤 대입을 반영한다 ---
        self.check_calls(stmt, env)

        if isinstance(stmt, ast.Assign):
            taint = self.taint_of(stmt.value, env)
            for target in stmt.targets:
                self.assign(target, taint, env, stmt)
            return env
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.assign(stmt.target, self.taint_of(stmt.value, env), env, stmt)
            return env
        if isinstance(stmt, ast.AugAssign):
            path = access_path(stmt.target)
            taint = self.taint_of(stmt.value, env) or (lookup(env, path) if path else None)
            if path and taint:
                env[path] = taint.step(self.node(stmt))
            return env
        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                self._clear(env, access_path(target))
            return env
        if isinstance(stmt, ast.Return):
            returned = self.node(stmt, 'return')
            for taint in self.taints_of(stmt.value, env):
                if taint.kind == KIND_PARAM and taint.source.get('param') in self.params:
                    index = self.params.index(taint.source['param'])
                    self.summary.param_to_return.setdefault(index, taint.steps + (returned,))
                elif taint.kind == KIND_INPUT:
                    self.summary.return_taint = prefer(self.summary.return_taint, taint.step(returned))
            return env
        return env


class MethodAnalyzer(FunctionAnalyzer):
    """클래스 메서드 — `self.m(...)`은 같은 클래스 메서드 요약으로, 바로 부르는 이름은 모듈 함수 요약으로 본다."""

    def __init__(self, func, lines, rel_path, findings, summaries, functions, methods, method_summaries):
        super().__init__(func, lines, rel_path, findings, summaries, functions)
        self.methods = methods
        self.method_summaries = method_summaries

    def resolve_callee(self, call):
        f = call.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == SELF and f.attr in self.methods:
            return self.methods, self.method_summaries, f.attr
        return super().resolve_callee(call)


def module_functions(tree):
    """모듈 최상위 함수 — 같은 이름이면 마지막 정의(임포트 시점의 Python 의미와 같다)."""
    return {n.name: n for n in tree.body if isinstance(n, _FUNCTION_NODES)}


def module_classes(tree):
    """모듈 최상위 클래스(정의 순서). 중첩 클래스는 다루지 않는다."""
    return [n for n in tree.body if isinstance(n, ast.ClassDef)]


def class_methods(cls):
    """클래스 본문의 메서드 — 같은 이름이면 마지막 정의."""
    return {n.name: n for n in cls.body if isinstance(n, _FUNCTION_NODES)}


def all_functions(tree):
    """모듈의 모든 함수·메서드·중첩 함수 (각각 독립된 분석 단위)."""
    return [n for n in ast.walk(tree) if isinstance(n, _FUNCTION_NODES)]


def _longer(current, candidate):
    """(노드, 경유) 쌍 중 경유가 긴 쪽 — 요약을 패스마다 단조 증가시키는 병합 규칙. 한쪽이 없으면 있는 쪽.
    (없는 쪽이 생기는 경우: 클래스 필드 환경이 패스마다 바뀌어 요약의 싱크 키가 사라질 수 있다 — 3단계 프로토타입에서
    None 첨자로 죽었던 결함.)"""
    if current is None:
        return candidate
    if candidate is None:
        return current
    return candidate if len(candidate[1]) > len(current[1]) else current


def merge_summaries(previous, fresh):
    """이전 패스의 요약과 새 요약을 합쳐 단조 증가하게 만든다.

    키는 합집합, 경유 노드는 긴 쪽을 남긴다. 이렇게 해야 고정점이 보장된다 — 새 요약만 쓰면 상호 재귀 함수에서
    대표 경로가 패스마다 다른 것으로 바뀌어(경유 5개 ↔ 8개) 모양이 영원히 진동한다(Django `db/models/sql/query.py`의
    `rename_prefix_from_q`/`get_child_with_renamed_prefix`에서 실측 — 상한 16에 닿았다). 경유 노드는 줄 단위로
    중복 제거되므로 길이는 함수의 줄 수로 유한하고, 키 집합도 유한하다 → 반드시 안정된다.
    """
    if previous is None:
        return fresh
    merged = Summary()
    for index in set(previous.param_to_return) | set(fresh.param_to_return):
        a, b = previous.param_to_return.get(index), fresh.param_to_return.get(index)
        merged.param_to_return[index] = a if b is None else b if a is None else (b if len(b) > len(a) else a)
    for key in set(previous.param_to_sinks) | set(fresh.param_to_sinks):
        merged.param_to_sinks[key] = _longer(previous.param_to_sinks.get(key), fresh.param_to_sinks.get(key))
    merged.return_taint = prefer(previous.return_taint, fresh.return_taint) if fresh.return_taint else previous.return_taint
    return merged


def _shapes(summaries):
    return {name: summary.shape() for name, summary in summaries.items()}


def compute_summaries(functions, lines, rel_path):
    """모듈 함수 요약의 고정점. 반환: (요약, 반복 횟수). 상한 SUMMARY_PASSES는 안전장치일 뿐이다."""
    summaries = {}
    passes = 0
    for passes in range(1, SUMMARY_PASSES + 1):
        fresh = {}
        for name, func in functions.items():
            analyzer = FunctionAnalyzer(func, lines, rel_path, [], summaries, functions)
            analyzer.run()
            fresh[name] = merge_summaries(summaries.get(name), analyzer.summary)
        shapes_before, shapes_after = _shapes(summaries), _shapes(fresh)
        summaries = fresh
        if shapes_after == shapes_before:
            break
    return summaries, passes


def _field_entries(env):
    """환경에서 ('self', 필드) 항목만."""
    return {path: taint for path, taint in env.items() if path[0] == SELF and len(path) == 2}


def _mark_field(taint, method_name, rel_path, lines):
    """필드에 대입된 오염에 '어느 메서드의 어느 줄이 대입했나'(role=field) 노드를 남긴다.

    대입 줄은 경유의 마지막 노드다(assign이 붙임). 소스와 같은 줄이면(`self.q = request.GET.get("q")`) 중복 제거로
    노드가 없으므로 force로 붙인다 — 역할이 달라 읽는 데 혼동이 없다.
    """
    if taint.steps:
        last = taint.steps[-1]
        if last['line'] != taint.source['line'] or last['path'] != taint.source['path']:
            marked = {**last, 'role': 'field', 'method': method_name}
            return Taint(taint.source, taint.steps[:-1] + (marked,), taint.kind)
    marked = node(rel_path, taint.source['line'], taint.source['code'], 'field', method_name)
    return taint.step(marked, force=True)


def analyze_class(cls, lines, rel_path, functions, summaries, findings, stats=None):
    """클래스 하나 — 메서드 요약과 필드 환경을 한 고정점에서 계산하고, 다른 메서드에서 대입된 필드를 읽는 싱크를
    보고한다 (docs/decisions.md 2026-09-06 custom-taint 3단계)."""
    methods = class_methods(cls)
    if not methods:
        return
    fields = {}            # {('self', f): 대표 Taint}
    assigners = {}         # {('self', f): {(대입 메서드, 소스 줄)}} — 같은 필드에 닿은 경로 수(paths_count)
    method_summaries = {}
    passes = 0

    def field_shape(entries):
        return {path: (len(taint.steps), taint.kind) for path, taint in entries.items()}

    for passes in range(1, SUMMARY_PASSES + 1):
        fresh_summaries = {}
        fresh_fields = dict(fields)
        for name, method in methods.items():
            analyzer = MethodAnalyzer(method, lines, rel_path, [], summaries, functions, methods, method_summaries)
            env = analyzer.run(initial_env=fields)
            fresh_summaries[name] = merge_summaries(method_summaries.get(name), analyzer.summary)
            for path, taint in _field_entries(env).items():
                if fields.get(path) is taint:
                    continue  # 읽기만 한 필드 — 초기 환경 그대로
                assigners.setdefault(path, set()).add((name, taint.source['line']))
                fresh_fields[path] = prefer(fresh_fields.get(path), _mark_field(taint, name, rel_path, lines))
        changed = (
            field_shape(fresh_fields) != field_shape(fields)
            or _shapes(fresh_summaries) != _shapes(method_summaries)
        )
        fields, method_summaries = fresh_fields, fresh_summaries
        if not changed:
            break
    if stats is not None:
        stats['class_passes'] = max(stats.get('class_passes', 0), passes)

    # 보고 패스 — 필드 오염을 들고 각 메서드를 돈다. 읽는 메서드의 def 줄을 enter로 붙여 "대입 → 진입"이 보이게.
    first_new = len(findings)
    for name, method in methods.items():
        entering = {
            path: taint.step(node(rel_path, method.lineno, lines[method.lineno - 1].strip(), 'enter'))
            for path, taint in fields.items()
        }
        MethodAnalyzer(method, lines, rel_path, findings, summaries, functions, methods, method_summaries).run(
            initial_env=entering,
        )
    # 필드는 대표 경로 하나만 들고 돌았으므로, 다른 메서드·줄에서 대입된 후보 수를 paths_count에 더한다.
    for finding in findings[first_new:]:
        for step in finding.taint.steps:
            if step.get('role') == 'field':
                path = (SELF, step['code'].split('=', 1)[0].strip().removeprefix('self.'))
                finding.paths_count += max(0, len(assigners.get(path, ())) - 1)
                break


def analyze_module(source, rel_path, stats=None):
    """소스 텍스트 하나를 분석해 Finding 목록을 돌려준다. 같은 (kisa_code, 싱크 줄)엔 하나(prefer 규칙, paths_count에
    후보 수). stats(dict)를 주면 'summary_passes'·'class_passes'(최대 반복 횟수)를 갱신한다. SyntaxError는 호출자(engine)가
    다룬다."""
    tree = ast.parse(source)
    lines = source.splitlines()
    functions = module_functions(tree)
    summaries, passes = compute_summaries(functions, lines, rel_path)
    if stats is not None:
        stats['summary_passes'] = max(stats.get('summary_passes', 0), passes)

    findings = []
    classes = module_classes(tree)
    class_method_ids = {id(m) for cls in classes for m in class_methods(cls).values()}
    for func in all_functions(tree):
        if id(func) in class_method_ids:
            continue  # 최상위 클래스의 메서드는 클래스 패스가 (필드 환경과 함께) 분석한다
        FunctionAnalyzer(func, lines, rel_path, findings, summaries, functions).run()
    for cls in classes:
        analyze_class(cls, lines, rel_path, functions, summaries, findings, stats)

    best = {}
    for finding in findings:
        current = best.get(finding.key)
        if current is None:
            best[finding.key] = finding
            continue
        current.paths_count += 1
        if prefer(current.taint, finding.taint) is not current.taint:
            finding.paths_count = current.paths_count
            best[finding.key] = finding
    return sorted(best.values(), key=lambda f: (f.sink['line'], f.kisa_code))
